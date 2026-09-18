import asyncio
import uuid
from unittest.mock import AsyncMock, patch

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from llmscan_engine.api.main import create_app
from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import Scan, ScanStatus
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
async def no_scan():
    """Patch run_scan so background tasks don't fire real HTTP during tests."""
    with patch("llmscan_engine.api.routers.scans.run_scan", new_callable=AsyncMock) as m:
        yield m


@pytest_asyncio.fixture
async def slow_scan():
    """Patch run_scan with a long sleep so its background task stays cancellable."""

    async def _sleep(*args, **kwargs):
        await asyncio.sleep(10)

    with patch("llmscan_engine.api.routers.scans.run_scan", side_effect=_sleep) as m:
        yield m


async def test_list_scans_empty(client):
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_get_scan_not_found(client):
    resp = await client.get(f"/api/scans/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_create_scan_returns_202(client, no_scan):
    resp = await client.post(
        "/api/scans",
        json={
            "target_url": "http://localhost:11434/v1/chat/completions",
            "api_key": "ollama",
            "profile": "quick",
        },
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == ScanStatus.pending.value
    assert data["profile"] == "quick"
    assert data["target_url"] == "http://localhost:11434/v1/chat/completions"
    assert "id" in data


async def test_create_scan_default_profile(client, no_scan):
    resp = await client.post(
        "/api/scans",
        json={"target_url": "http://target/v1/chat", "api_key": "key"},
    )
    assert resp.status_code == 202
    assert resp.json()["profile"] == "standard"


async def test_get_scan_after_create(client, no_scan):
    create = await client.post(
        "/api/scans",
        json={"target_url": "http://target/v1/chat", "api_key": "key", "profile": "quick"},
    )
    scan_id = create.json()["id"]

    get = await client.get(f"/api/scans/{scan_id}")
    assert get.status_code == 200
    assert get.json()["id"] == scan_id


async def test_list_scans_after_create(client, no_scan):
    for _ in range(3):
        await client.post(
            "/api/scans",
            json={"target_url": "http://target/v1", "api_key": "k"},
        )
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    assert len(resp.json()) == 3


async def test_create_scan_dry_run_flag(client, no_scan):
    resp = await client.post(
        "/api/scans",
        json={
            "target_url": "http://target/v1",
            "api_key": "k",
            "dry_run": True,
        },
    )
    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# cancel
# ---------------------------------------------------------------------------


async def test_cancel_scan_not_found(client):
    resp = await client.post(f"/api/scans/{uuid.uuid4()}/cancel")
    assert resp.status_code == 404


async def test_cancel_scan_not_running_returns_409(client, session):
    scan = Scan(target_url="http://x", profile="quick", status=ScanStatus.complete)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    resp = await client.post(f"/api/scans/{scan.id}/cancel")
    assert resp.status_code == 409


async def test_cancel_scan_no_registered_task_returns_409(client, session):
    scan = Scan(target_url="http://x", profile="quick", status=ScanStatus.running)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    resp = await client.post(f"/api/scans/{scan.id}/cancel")
    assert resp.status_code == 409


async def test_cancel_scan_success(client, slow_scan):
    create = await client.post(
        "/api/scans",
        json={"target_url": "http://target/v1", "api_key": "k", "profile": "quick"},
    )
    scan_id = create.json()["id"]
    await asyncio.sleep(0.05)  # let the background task start and get registered

    resp = await client.post(f"/api/scans/{scan_id}/cancel")

    assert resp.status_code == 200
    await asyncio.sleep(0.05)  # let the cancellation actually land
