import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from llmscan_engine.api.schemas import FindingEvidence, FindingRead
from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import FailureMode, Finding, Scan
from llmscan_engine.reports.generator import load_exchanges

router = APIRouter(tags=["findings"])


@router.get("/scans/{scan_id}/findings", response_model=List[FindingRead])
async def get_findings(
    scan_id: uuid.UUID,
    owasp_id: Optional[str] = Query(
        None, description="Filter by OWASP category, e.g. LLM01"
    ),
    failure_mode: Optional[FailureMode] = Query(
        None, description="Filter by failure mode"
    ),
    min_score: Optional[float] = Query(
        None, ge=0.0, le=10.0, description="Minimum risk score"
    ),
    session: AsyncSession = Depends(get_session),
) -> List[FindingRead]:
    """List findings for a scan with optional filters, ordered by score descending."""
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if owasp_id:
        stmt = stmt.where(Finding.owasp_id == owasp_id)
    if failure_mode:
        stmt = stmt.where(Finding.failure_mode == failure_mode)
    if min_score is not None:
        stmt = stmt.where(Finding.score >= min_score)
    stmt = stmt.order_by(Finding.score.desc())  # type: ignore[arg-type]

    result = await session.execute(stmt)
    return [FindingRead.model_validate(f) for f in result.scalars().all()]


@router.get(
    "/scans/{scan_id}/findings/{finding_id}/evidence",
    response_model=FindingEvidence,
)
async def get_finding_evidence(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> FindingEvidence:
    """Return the real prompt and response text behind a finding."""
    finding = await session.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    exchange = load_exchanges(scan_id, Path("reports/output")).get(
        (finding.payload_hash, finding.response_hash)
    )
    if exchange is None:
        raise HTTPException(
            status_code=404,
            detail="No evidence recorded for this finding (evidence file missing "
            "or written by an older version).",
        )
    return FindingEvidence(
        finding_id=finding.id,
        prompt_text=exchange.prompt_text,
        response_text=exchange.response_text,
        status_code=exchange.status_code,
        latency_ms=exchange.latency_ms,
        url=exchange.url,
        timestamp=exchange.timestamp,
    )
