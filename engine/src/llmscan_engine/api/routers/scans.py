import asyncio
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from llmscan_engine.api.orchestrator import run_scan
from llmscan_engine.api.schemas import ScanCreate, ScanRead
from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import Scan, ScanStatus

router = APIRouter(tags=["scans"])


@router.post("/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    body: ScanCreate,
    session: AsyncSession = Depends(get_session),
) -> ScanRead:
    """Start a new scan. Returns immediately with scan_id; scan runs as a background task."""
    scan = Scan(
        target_url=body.target_url,
        profile=body.profile,
        status=ScanStatus.pending,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    asyncio.create_task(
        run_scan(
            scan_id=scan.id,
            target_url=body.target_url,
            api_key=body.api_key,
            profile_name=body.profile,
            dry_run=body.dry_run,
        )
    )

    return ScanRead.model_validate(scan)


@router.get("/scans", response_model=List[ScanRead])
async def list_scans(
    session: AsyncSession = Depends(get_session),
) -> List[ScanRead]:
    """List all scans, newest first."""
    result = await session.exec(
        select(Scan).order_by(Scan.started_at.desc())  # type: ignore[arg-type]
    )
    return [ScanRead.model_validate(s) for s in result.all()]


@router.get("/scans/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ScanRead:
    """Get a single scan by ID."""
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRead.model_validate(scan)
