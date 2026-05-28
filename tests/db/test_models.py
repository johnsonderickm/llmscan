import uuid
from datetime import datetime

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, select

from llmscan_engine.db.models import (
    FailureMode,
    Finding,
    Plugin,
    Scan,
    ScanEvent,
    ScanStatus,
)

_TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def session() -> AsyncSession:
    """Yield an async session backed by a fresh in-memory SQLite database."""
    engine = create_async_engine(_TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await engine.dispose()


async def test_scan_defaults(session: AsyncSession) -> None:
    """Scan rows use sensible defaults for status and timestamps."""
    scan = Scan(target_url="https://api.example.com/chat", profile="quick")
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    assert isinstance(scan.id, uuid.UUID)
    assert scan.status == ScanStatus.pending
    assert isinstance(scan.started_at, datetime)
    assert scan.finished_at is None
    assert scan.risk_score is None


async def test_scan_status_enum_roundtrip(session: AsyncSession) -> None:
    """All ScanStatus values survive a write/read cycle."""
    for status in ScanStatus:
        session.add(
            Scan(
                target_url="https://api.example.com/chat",
                profile="standard",
                status=status,
            )
        )
    await session.commit()

    result = await session.execute(select(Scan))
    stored = {row.status for row in result.scalars().all()}
    assert stored == set(ScanStatus)


async def test_finding_linked_to_scan(session: AsyncSession) -> None:
    """Finding FK scan_id correctly references its parent Scan."""
    scan = Scan(target_url="https://api.example.com/chat", profile="full")
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        plugin_id="llm01_direct",
        owasp_id="LLM01",
        failure_mode=FailureMode.COMPLIED,
        score=0.0,
        payload_hash="abc123",
        response_hash="def456",
    )
    session.add(finding)
    await session.commit()
    await session.refresh(finding)

    assert finding.scan_id == scan.id
    assert isinstance(finding.id, uuid.UUID)
    assert isinstance(finding.created_at, datetime)
    assert finding.mitre_atlas_id is None
    assert finding.evidence_path is None


async def test_failure_mode_enum_roundtrip(session: AsyncSession) -> None:
    """All FailureMode values survive a write/read cycle."""
    scan = Scan(target_url="https://api.example.com/chat", profile="quick")
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    for mode in FailureMode:
        session.add(
            Finding(
                scan_id=scan.id,
                plugin_id="llm01_direct",
                owasp_id="LLM01",
                failure_mode=mode,
                score=5.0,
                payload_hash=f"hash_{mode.value}",
                response_hash=f"resp_{mode.value}",
            )
        )
    await session.commit()

    result = await session.execute(
        select(Finding).where(Finding.scan_id == scan.id)
    )
    stored = {row.failure_mode for row in result.scalars().all()}
    assert stored == set(FailureMode)


async def test_plugin_with_tags(session: AsyncSession) -> None:
    """Plugin JSON tags field serializes and deserializes correctly."""
    plugin = Plugin(
        id="llm01_direct",
        name="LLM01 Direct Injection",
        version="1.0.0",
        owasp_id="LLM01",
        severity_weight=9.0,
        enabled=True,
        tags=["injection", "critical", "llm01"],
    )
    session.add(plugin)
    await session.commit()
    await session.refresh(plugin)

    assert plugin.tags == ["injection", "critical", "llm01"]
    assert plugin.enabled is True


async def test_plugin_tags_nullable(session: AsyncSession) -> None:
    """Plugin.tags defaults to None when omitted."""
    plugin = Plugin(
        id="llm02_pii",
        name="LLM02 PII Extraction",
        version="1.0.0",
        owasp_id="LLM02",
        severity_weight=8.5,
    )
    session.add(plugin)
    await session.commit()
    await session.refresh(plugin)

    assert plugin.tags is None
    assert plugin.enabled is True


async def test_scan_event_linked_to_scan(session: AsyncSession) -> None:
    """ScanEvent FK scan_id correctly references its parent Scan."""
    scan = Scan(target_url="https://api.example.com/chat", profile="standard")
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    event = ScanEvent(
        scan_id=scan.id,
        event_type="probe_sent",
        message="Sent payload #1 to LLM01 plugin",
    )
    session.add(event)
    await session.commit()
    await session.refresh(event)

    assert event.scan_id == scan.id
    assert isinstance(event.id, uuid.UUID)
    assert isinstance(event.created_at, datetime)


async def test_multiple_events_per_scan(session: AsyncSession) -> None:
    """Multiple ScanEvents can be associated with a single Scan."""
    scan = Scan(target_url="https://api.example.com/chat", profile="quick")
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    for i in range(5):
        session.add(
            ScanEvent(
                scan_id=scan.id,
                event_type="probe_sent",
                message=f"Payload #{i}",
            )
        )
    await session.commit()

    result = await session.execute(
        select(ScanEvent).where(ScanEvent.scan_id == scan.id)
    )
    assert len(result.scalars().all()) == 5
