import asyncio
import uuid

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from llmscan_engine.db.database import get_session
from llmscan_engine.db.models import Scan, ScanEvent, ScanStatus

router = APIRouter()


@router.websocket("/ws/scan/{scan_id}")
async def ws_scan_feed(
    websocket: WebSocket,
    scan_id: str,
    session: AsyncSession = Depends(get_session),
) -> None:
    """Stream ScanEvents for a running scan via DB polling at 0.5 s intervals."""
    await websocket.accept()

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        await websocket.close(code=1008)
        return

    scan = await session.get(Scan, scan_uuid)
    if not scan:
        await websocket.close(code=1008)
        return

    # Replay all existing events
    result = await session.execute(
        select(ScanEvent)
        .where(ScanEvent.scan_id == scan_uuid)
        .order_by(ScanEvent.created_at)
    )
    events = result.scalars().all()
    offset = len(events)

    for event in events:
        try:
            await websocket.send_json({
                "scan_id": scan_id,
                "event_type": event.event_type,
                "message": event.message,
                "created_at": event.created_at.isoformat(),
            })
        except WebSocketDisconnect:
            return

    # If scan already finished, close cleanly
    if scan.status in (ScanStatus.complete, ScanStatus.failed):
        try:
            await websocket.close()
        except Exception:
            pass
        return

    # Poll for new events until scan ends
    try:
        while True:
            await asyncio.sleep(0.5)

            new_result = await session.execute(
                select(ScanEvent)
                .where(ScanEvent.scan_id == scan_uuid)
                .order_by(ScanEvent.created_at)
                .offset(offset)
            )
            new_events = new_result.scalars().all()

            for event in new_events:
                await websocket.send_json({
                    "scan_id": scan_id,
                    "event_type": event.event_type,
                    "message": event.message,
                    "created_at": event.created_at.isoformat(),
                })
                offset += 1

            # Re-fetch scan to check status (always goes to DB via fresh select)
            status_result = await session.execute(
                select(Scan).where(Scan.id == scan_uuid)
            )
            refreshed = status_result.scalar_one_or_none()
            if refreshed and refreshed.status in (
                ScanStatus.complete,
                ScanStatus.failed,
            ):
                await websocket.close()
                break

    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
