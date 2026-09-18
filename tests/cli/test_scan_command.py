import uuid
from unittest.mock import AsyncMock

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from typer.testing import CliRunner

import llmscan_engine.api.orchestrator as orchestrator
import llmscan_engine.cli.main as cli_main
from llmscan_engine.cli.main import _get_api_key, app
from llmscan_engine.core.connector import Provider, TargetProfile
from llmscan_engine.db.models import Scan, ScanStatus
from llmscan_engine.plugins.registry import clear_registry

_TEST_DB = "sqlite+aiosqlite:///:memory:"
runner = CliRunner()


def _profile() -> TargetProfile:
    return TargetProfile(
        provider=Provider.openai_compat,
        base_url="https://api.example.com",
        auth_header="Authorization: Bearer test",
        rate_limit_rpm=60,
        has_system_prompt=False,
        latency_p50_ms=100.0,
        model_name="gpt-4o",
    )


@pytest_asyncio.fixture
async def factory():
    engine = create_async_engine(_TEST_DB)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield session_factory
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
def _clean_registry():
    clear_registry()
    yield
    clear_registry()


class _FakeKeyring:
    """In-memory stand-in for the OS keychain."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def test_scan_invalid_profile_exits_1():
    result = runner.invoke(
        app, ["scan", "--target", "http://x", "--key", "k", "--profile", "bogus"]
    )
    assert result.exit_code == 1


def test_scan_offline_with_judge_key_configured_fails(monkeypatch):
    class _FakeSettings:
        judge_api_key = "sk-configured"

    monkeypatch.setattr(cli_main, "get_settings", lambda: _FakeSettings())
    result = runner.invoke(
        app, ["scan", "--target", "http://x", "--key", "k", "--offline"]
    )
    assert result.exit_code == 1


def test_scan_missing_key_and_nothing_in_keyring_exits_1(monkeypatch):
    monkeypatch.setattr(cli_main, "keyring", _FakeKeyring())
    result = runner.invoke(
        app, ["scan", "--target", "http://new-target", "--profile", "quick"]
    )
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# keyring round trip (unit-level, no CLI invocation needed)
# ---------------------------------------------------------------------------


def test_get_api_key_stores_and_reuses(monkeypatch):
    fake = _FakeKeyring()
    monkeypatch.setattr(cli_main, "keyring", fake)

    stored = _get_api_key("http://target", "sk-first-time")
    assert stored == "sk-first-time"

    reused = _get_api_key("http://target", None)
    assert reused == "sk-first-time"


def test_get_api_key_missing_raises_exit(monkeypatch):
    import typer

    monkeypatch.setattr(cli_main, "keyring", _FakeKeyring())
    try:
        _get_api_key("http://never-seen", None)
        assert False, "expected typer.Exit"
    except typer.Exit as exc:
        assert exc.exit_code == 1


# ---------------------------------------------------------------------------
# dry-run scan — exercises the real orchestrator with a mocked fingerprint
# ---------------------------------------------------------------------------


def test_scan_dry_run_completes(monkeypatch, factory):
    monkeypatch.setattr(cli_main, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(orchestrator, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(cli_main, "fingerprint", AsyncMock(return_value=_profile()))
    monkeypatch.setattr(cli_main, "keyring", _FakeKeyring())

    result = runner.invoke(
        app,
        [
            "scan", "--target", "http://target/v1", "--key", "k",
            "--profile", "quick", "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Scan complete" in result.stdout


def test_scan_dry_run_json_output(monkeypatch, factory):
    monkeypatch.setattr(cli_main, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(orchestrator, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(cli_main, "fingerprint", AsyncMock(return_value=_profile()))
    monkeypatch.setattr(cli_main, "keyring", _FakeKeyring())

    result = runner.invoke(
        app,
        [
            "scan", "--target", "http://target/v1", "--key", "k",
            "--profile", "quick", "--dry-run", "--json",
        ],
    )

    assert result.exit_code == 0
    import json

    data = json.loads(result.stdout)
    assert data["status"] == "complete"
    assert "findings" in data


# ---------------------------------------------------------------------------
# >100-request confirmation gate
# ---------------------------------------------------------------------------


def test_scan_confirmation_declined_cancels(monkeypatch, factory):
    monkeypatch.setattr(cli_main, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(cli_main, "fingerprint", AsyncMock(return_value=_profile()))
    monkeypatch.setattr(cli_main, "keyring", _FakeKeyring())
    run_scan_mock = AsyncMock()
    monkeypatch.setattr(cli_main, "run_scan", run_scan_mock)

    result = runner.invoke(
        app,
        ["scan", "--target", "http://target/v1", "--key", "k", "--profile", "full"],
        input="n\n",
    )

    assert result.exit_code == 0
    assert "cancelled" in result.stdout.lower()
    run_scan_mock.assert_not_called()


def test_scan_confirmation_bypassed_with_yes(monkeypatch, factory):
    monkeypatch.setattr(cli_main, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(cli_main, "fingerprint", AsyncMock(return_value=_profile()))
    monkeypatch.setattr(cli_main, "keyring", _FakeKeyring())
    run_scan_mock = AsyncMock()
    monkeypatch.setattr(cli_main, "run_scan", run_scan_mock)

    async def _fake_poll(scan_id: uuid.UUID, quiet: bool) -> Scan:
        return Scan(
            id=scan_id,
            target_url="http://target/v1",
            profile="full",
            status=ScanStatus.complete,
            risk_score=0.0,
        )

    monkeypatch.setattr(cli_main, "_poll_until_done", _fake_poll)

    result = runner.invoke(
        app,
        [
            "scan", "--target", "http://target/v1", "--key", "k",
            "--profile", "full", "--yes",
        ],
    )

    assert result.exit_code == 0
    run_scan_mock.assert_called_once()
