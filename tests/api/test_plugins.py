import uuid
from unittest.mock import patch

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from llmscan_engine.api.main import create_app
from llmscan_engine.db.database import get_session
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


async def test_list_plugins_returns_all_10(client):
    resp = await client.get("/api/plugins")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 12  # 10 OWASP categories, LLM01 has 2 plugins


async def test_list_plugins_schema(client):
    resp = await client.get("/api/plugins")
    plugin = resp.json()[0]
    for field in ("id", "name", "version", "owasp_id", "severity_weight", "tags"):
        assert field in plugin


async def test_list_plugins_owasp_coverage(client):
    resp = await client.get("/api/plugins")
    owasp_ids = {p["owasp_id"] for p in resp.json()}
    expected = {f"LLM0{i}" for i in range(1, 10)} | {"LLM10"}
    assert expected == owasp_ids


async def test_update_plugins_reloads_registry(client):
    resp = await client.post("/api/plugins/update")
    assert resp.status_code == 200
    data = resp.json()
    assert "count" in data
    assert data["count"] >= 10
