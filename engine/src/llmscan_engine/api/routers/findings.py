import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from llmscan_engine.api.schemas import FindingRead
from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import FailureMode, Finding, Scan

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
