import uuid
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def scan_with_findings(session):
    scan = Scan(target_url="http://target/v1", profile="quick", status=ScanStatus.complete)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    findings = [
        Finding(
            scan_id=scan.id,
            plugin_id="llm01_direct",
            owasp_id="LLM01",
            failure_mode=FailureMode.COMPLIED,
            score=8.5,
            payload_hash="abc123",
            response_hash="def456",
        ),
        Finding(
            scan_id=scan.id,
            plugin_id="llm02_pii",
            owasp_id="LLM02",
            failure_mode=FailureMode.PII_LEAKED,
            score=9.0,
            payload_hash="ghi789",
            response_hash="jkl012",
        ),
        Finding(
            scan_id=scan.id,
            plugin_id="llm01_direct",
            owasp_id="LLM01",
            failure_mode=FailureMode.PARTIAL,
            score=5.0,
            payload_hash="mno345",
            response_hash="pqr678",
        ),
    ]
    for f in findings:
        session.add(f)
    await session.commit()
    return scan


async def test_findings_not_found_scan(client):
    resp = await client.get(f"/api/scans/{uuid.uuid4()}/findings")
    assert resp.status_code == 404


async def test_findings_empty(client, session):
    scan = Scan(target_url="http://t/v1", profile="quick", status=ScanStatus.complete)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    resp = await client.get(f"/api/scans/{scan.id}/findings")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_findings_returns_all(client, scan_with_findings):
    resp = await client.get(f"/api/scans/{scan_with_findings.id}/findings")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


async def test_findings_ordered_by_score_desc(client, scan_with_findings):
    resp = await client.get(f"/api/scans/{scan_with_findings.id}/findings")
    scores = [f["score"] for f in resp.json()]
    assert scores == sorted(scores, reverse=True)


async def test_findings_filter_by_owasp_id(client, scan_with_findings):
    resp = await client.get(
        f"/api/scans/{scan_with_findings.id}/findings", params={"owasp_id": "LLM01"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert all(f["owasp_id"] == "LLM01" for f in data)


async def test_findings_filter_by_failure_mode(client, scan_with_findings):
    resp = await client.get(
        f"/api/scans/{scan_with_findings.id}/findings",
        params={"failure_mode": "PII_LEAKED"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["failure_mode"] == "PII_LEAKED"


async def test_findings_filter_by_min_score(client, scan_with_findings):
    resp = await client.get(
        f"/api/scans/{scan_with_findings.id}/findings", params={"min_score": 8.0}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert all(f["score"] >= 8.0 for f in data)
