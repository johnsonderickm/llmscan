import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from llmscan_engine.api.schemas import ReportRequest, ReportResponse
from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import Scan, ScanStatus
from llmscan_engine.reports.generator import ReportGenerator

router = APIRouter(tags=["reports"])

_VALID_AUDIENCES = {"pentester", "manager", "cxo"}
_VALID_FORMATS = {"html", "pdf"}


@router.post("/scans/{scan_id}/report", response_model=ReportResponse)
async def generate_report(
    scan_id: uuid.UUID,
    body: ReportRequest,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    """Generate an audience-specific report (pentester/manager/cxo) for a scan."""
    if body.audience not in _VALID_AUDIENCES:
        raise HTTPException(
            status_code=400, detail=f"Invalid audience: {body.audience}"
        )
    if body.format not in _VALID_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format: {body.format}")

    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.complete:
        raise HTTPException(
            status_code=409,
            detail=f"Scan is not complete (status: {scan.status.value})",
        )

    generator = ReportGenerator(session)
    try:
        path = await generator.generate(
            scan_id, audience=body.audience, format=body.format
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return ReportResponse(
        scan_id=scan_id,
        audience=body.audience,
        format=body.format,
        path=str(path),
        message="Report generated successfully.",
    )
