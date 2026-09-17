import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from llmscan_engine.api.schemas import ReportRequest, ReportResponse
from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import Scan, ScanStatus

router = APIRouter(tags=["reports"])


@router.post("/scans/{scan_id}/report", response_model=ReportResponse)
async def generate_report(
    scan_id: uuid.UUID,
    body: ReportRequest,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    """Generate a report for a completed scan. Full implementation in Phase 12."""
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.complete:
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not complete (status: {scan.status.value})",
        )
    return ReportResponse(
        scan_id=scan_id,
        audience=body.audience,
        format=body.format,
        path="",
        message="Report generator available in Phase 12.",
    )
