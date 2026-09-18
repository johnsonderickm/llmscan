import asyncio
import uuid
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, select

from llmscan_engine.api import orchestrator
from llmscan_engine.core.connector import Provider, TargetProfile
from llmscan_engine.db.models import Scan, ScanStatus
from llmscan_engine.plugins.registry import clear_registry

_TEST_DB = "sqlite+aiosqlite:///:memory:"


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


@pytest_asyncio.fixture
async def scan_id(factory) -> uuid.UUID:
    async with factory() as session:
        scan = Scan(
            target_url="http://target/v1", profile="quick", status=ScanStatus.pending
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan.id


@pytest_asyncio.fixture(autouse=True)
def _empty_registry():
    clear_registry()
    yield
    clear_registry()


async def _final_status(factory, scan_id: uuid.UUID) -> ScanStatus:
    async with factory() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        return result.scalar_one().status


async def test_target_profile_reuse_skips_fingerprint(monkeypatch, factory, scan_id):
    monkeypatch.setattr(orchestrator, "_AsyncSessionFactory", factory)
    fingerprint_mock = AsyncMock()
    monkeypatch.setattr(orchestrator, "fingerprint", fingerprint_mock)

    await orchestrator.run_scan(
        scan_id=scan_id,
        target_url="http://target/v1",
        api_key="k",
        profile_name="quick",
        dry_run=True,
        target_profile=_profile(),
    )

    fingerprint_mock.assert_not_called()
    assert await _final_status(factory, scan_id) == ScanStatus.complete


async def test_use_garak_override_forces_disabled_on_true_profile(
    monkeypatch, factory, scan_id
):
    monkeypatch.setattr(orchestrator, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(orchestrator, "fingerprint", AsyncMock(return_value=_profile()))
    set_garak_mock = Mock()
    monkeypatch.setattr(orchestrator, "set_garak_enabled", set_garak_mock)

    await orchestrator.run_scan(
        scan_id=scan_id,
        target_url="http://target/v1",
        api_key="k",
        profile_name="standard",  # standard.yaml: use_garak = true
        dry_run=True,
        use_garak=False,
    )

    set_garak_mock.assert_called_once_with(False)


# ---------------------------------------------------------------------------
# cancellation
# ---------------------------------------------------------------------------


def test_cancel_scan_returns_false_for_unknown_scan():
    assert orchestrator.cancel_scan(uuid.uuid4()) is False


async def test_cancel_scan_marks_scan_cancelled(monkeypatch, factory, scan_id):
    monkeypatch.setattr(orchestrator, "_AsyncSessionFactory", factory)

    async def _slow_fingerprint(*args, **kwargs):
        await asyncio.sleep(10)
        return _profile()

    monkeypatch.setattr(orchestrator, "fingerprint", _slow_fingerprint)

    task = asyncio.create_task(
        orchestrator.run_scan(
            scan_id=scan_id,
            target_url="http://target/v1",
            api_key="k",
            profile_name="quick",
            dry_run=True,
        )
    )
    orchestrator.register_task(scan_id, task)

    await asyncio.sleep(0.05)  # let the task reach the fingerprint await point
    assert orchestrator.cancel_scan(scan_id) is True

    with pytest.raises(asyncio.CancelledError):
        await task

    assert await _final_status(factory, scan_id) == ScanStatus.cancelled


async def test_cancel_scan_returns_false_once_task_finished(
    monkeypatch, factory, scan_id
):
    monkeypatch.setattr(orchestrator, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(orchestrator, "fingerprint", AsyncMock(return_value=_profile()))

    task = asyncio.create_task(
        orchestrator.run_scan(
            scan_id=scan_id,
            target_url="http://target/v1",
            api_key="k",
            profile_name="quick",
            dry_run=True,
        )
    )
    orchestrator.register_task(scan_id, task)
    await task

    assert orchestrator.cancel_scan(scan_id) is False
    assert scan_id not in orchestrator._running_tasks


async def test_use_garak_none_defers_to_profile_default(monkeypatch, factory, scan_id):
    monkeypatch.setattr(orchestrator, "_AsyncSessionFactory", factory)
    monkeypatch.setattr(orchestrator, "fingerprint", AsyncMock(return_value=_profile()))
    set_garak_mock = Mock()
    monkeypatch.setattr(orchestrator, "set_garak_enabled", set_garak_mock)

    await orchestrator.run_scan(
        scan_id=scan_id,
        target_url="http://target/v1",
        api_key="k",
        profile_name="quick",  # quick.yaml: use_garak = false
        dry_run=True,
        use_garak=None,
    )

    set_garak_mock.assert_called_once_with(False)
