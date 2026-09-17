import uuid
from pathlib import Path
from unittest.mock import patch

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from llmscan_engine.api.main import create_app
from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import FailureMode, Finding, Scan, ScanStatus
from llmscan_engine.plugins.registry import clear_registry, init_registry

_TEST_DB = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine(_TEST_DB)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(session):
    clear_registry()
    init_registry()

    async def _noop() -> None:
        pass

    with patch("llmscan_engine.api.main.init_db", _noop):
        with patch("llmscan_engine.api.main.init_registry", lambda: None):
            app = create_app()

    async def _override_session():
        yield session

    app.dependency_overrides[get_session] = _override_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def complete_scan(session):
    scan = Scan(
        target_url="http://target/v1/chat/completions",
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
    return scan


@pytest_asyncio.fixture
async def pending_scan(session):
    scan = Scan(
        target_url="http://target/v1", profile="quick", status=ScanStatus.pending
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def test_report_scan_not_found(client):
    resp = await client.post(f"/api/scans/{uuid.uuid4()}/report", json={})
    assert resp.status_code == 404


async def test_report_scan_not_complete(client, pending_scan):
    resp = await client.post(f"/api/scans/{pending_scan.id}/report", json={})
    assert resp.status_code == 409


async def test_report_invalid_audience(client, complete_scan):
    resp = await client.post(
        f"/api/scans/{complete_scan.id}/report", json={"audience": "bogus"}
    )
    assert resp.status_code == 400


async def test_report_invalid_format(client, complete_scan):
    resp = await client.post(
        f"/api/scans/{complete_scan.id}/report", json={"format": "bogus"}
    )
    assert resp.status_code == 400


async def test_report_generates_pentester_html(
    client, complete_scan, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    resp = await client.post(
        f"/api/scans/{complete_scan.id}/report",
        json={"audience": "pentester", "format": "html"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["audience"] == "pentester"
    assert data["format"] == "html"
    assert Path(data["path"]).exists()


async def test_report_generates_manager_and_cxo(
    client, complete_scan, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    for audience in ("manager", "cxo"):
        resp = await client.post(
            f"/api/scans/{complete_scan.id}/report",
            json={"audience": audience, "format": "html"},
        )
        assert resp.status_code == 200
        assert Path(resp.json()["path"]).exists()
