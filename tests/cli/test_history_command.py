import json

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from typer.testing import CliRunner

import llmscan_engine.cli.main as cli_main
from llmscan_engine.cli.main import app
from llmscan_engine.db.models import Scan, ScanStatus

_TEST_DB = "sqlite+aiosqlite:///:memory:"
runner = CliRunner()


@pytest_asyncio.fixture
async def factory():
    engine = create_async_engine(_TEST_DB)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        session.add(
            Scan(
                target_url="http://target/v1",
                profile="quick",
                status=ScanStatus.complete,
                risk_score=7.5,
            )
        )
        session.add(
            Scan(
                target_url="http://other/v1",
                profile="standard",
                status=ScanStatus.pending,
            )
        )
        await session.commit()
    yield session_factory
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await engine.dispose()


def test_history_table(monkeypatch, factory):
    monkeypatch.setattr(cli_main, "_AsyncSessionFactory", factory)
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0
    assert "complete" in result.stdout
    assert "quick" in result.stdout


def test_history_json(monkeypatch, factory):
    monkeypatch.setattr(cli_main, "_AsyncSessionFactory", factory)
    result = runner.invoke(app, ["history", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data) == 2
    assert data[0]["status"] in ("complete", "pending")


def test_history_respects_limit(monkeypatch, factory):
    monkeypatch.setattr(cli_main, "_AsyncSessionFactory", factory)
    result = runner.invoke(app, ["history", "--limit", "1", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
