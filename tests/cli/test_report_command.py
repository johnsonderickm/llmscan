import uuid

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from typer.testing import CliRunner

from llmscan_engine.cli.main import app
from llmscan_engine.db.models import FailureMode, Finding, Scan, ScanStatus
from llmscan_engine.plugins.registry import clear_registry, init_registry

_TEST_DB = "sqlite+aiosqlite:///:memory:"
runner = CliRunner()


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
            target_url="http://target/v1",
            profile="quick",
            status=ScanStatus.complete,
            risk_score=8.0,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        session.add(
            Finding(
                scan_id=scan.id,
                plugin_id="llm01_direct",
                owasp_id="LLM01",
                mitre_atlas_id="AML.T0051",
                failure_mode=FailureMode.COMPLIED,
                score=9.0,
                payload_hash="a" * 16,
                response_hash="b" * 16,
            )
        )
        await session.commit()
        return scan.id


def test_report_command_generates_html(monkeypatch, factory, scan_id, tmp_path):
    clear_registry()
    init_registry()
    monkeypatch.setattr("llmscan_engine.cli.main._AsyncSessionFactory", factory)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "report",
            "--scan-id",
            str(scan_id),
            "--audience",
            "pentester",
            "--format",
            "html",
        ],
    )

    assert result.exit_code == 0
    assert "Report generated" in result.stdout
    clear_registry()


def test_report_command_invalid_audience():
    result = runner.invoke(
        app, ["report", "--scan-id", str(uuid.uuid4()), "--audience", "bogus"]
    )
    assert result.exit_code == 1


def test_report_command_invalid_format():
    result = runner.invoke(
        app, ["report", "--scan-id", str(uuid.uuid4()), "--format", "bogus"]
    )
    assert result.exit_code == 1


def test_report_command_invalid_scan_id():
    result = runner.invoke(app, ["report", "--scan-id", "not-a-uuid"])
    assert result.exit_code == 1


def test_report_command_unknown_scan(monkeypatch, factory, tmp_path):
    monkeypatch.setattr("llmscan_engine.cli.main._AsyncSessionFactory", factory)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["report", "--scan-id", str(uuid.uuid4())])

    assert result.exit_code == 1
