import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from llmscan_engine.core.classifier import Classifier
from llmscan_engine.core.config import get_settings
from llmscan_engine.core.connector import TargetProfile, fingerprint
from llmscan_engine.core.dispatcher import AsyncDispatcher
from llmscan_engine.db.database import _AsyncSessionFactory
from llmscan_engine.db.models import (
    FailureMode,
    Finding,
    Scan,
    ScanEvent,
    ScanStatus,
)
from llmscan_engine.plugins.garak_loader import set_garak_enabled
from llmscan_engine.plugins.registry import all_plugins
from llmscan_engine.profiles.loader import load_profile

_running_tasks: dict[uuid.UUID, asyncio.Task] = {}

_MIN_PARTIAL_CONFIDENCE = 0.6


def register_task(scan_id: uuid.UUID, task: asyncio.Task) -> None:
    """Track a scan's background task so it can later be cancelled."""
    _running_tasks[scan_id] = task
    task.add_done_callback(lambda _: _running_tasks.pop(scan_id, None))


def cancel_scan(scan_id: uuid.UUID) -> bool:
    """Request cancellation of a running scan's background task.

    Returns False if no running task is tracked for *scan_id* (already
    finished, unknown, or this process didn't start it).
    """
    task = _running_tasks.get(scan_id)
    if task is None or task.done():
        return False
    task.cancel()
    return True


async def run_scan(
    scan_id: uuid.UUID,
    target_url: str,
    api_key: str,
    profile_name: str,
    dry_run: bool = False,
    use_garak: Optional[bool] = None,
    target_profile: Optional[TargetProfile] = None,
    model: Optional[str] = None,
    endpoint_format: str = "openai",
    request_template: Optional[str] = None,
    response_path: Optional[str] = None,
) -> None:
    """Background task: fingerprint, run plugins, classify responses, save findings.

    ``use_garak=None`` defers to the scan profile's own ``use_garak`` setting;
    pass True/False to override it (e.g. CLI ``--no-garak``). ``target_profile``
    lets a caller that already fingerprinted the target (e.g. to estimate
    request volume) skip re-fingerprinting here.
    """
    async with _AsyncSessionFactory() as session:
        try:
            await _set_status(session, scan_id, ScanStatus.running)
            await _emit(
                session, scan_id, "scan_start", f"Scan started — target: {target_url}"
            )

            # Fingerprint (unless the caller already did it)
            if target_profile is None:
                await _emit(
                    session,
                    scan_id,
                    "fingerprint_start",
                    "Fingerprinting target endpoint",
                )
                target_profile = await fingerprint(
                    target_url,
                    api_key,
                    model,
                    endpoint_format,
                    request_template,
                    response_path,
                )
            model_label = target_profile.model_name or "unknown"
            await _emit(
                session,
                scan_id,
                "fingerprint_complete",
                f"Provider: {target_profile.provider.value}, model: {model_label}",
            )

            # Load scan profile + plugins
            scan_profile = load_profile(profile_name)
            set_garak_enabled(
                scan_profile.use_garak if use_garak is None else use_garak
            )
            registered = all_plugins()
            if scan_profile.plugin_ids is not None:
                plugins = {
                    k: v
                    for k, v in registered.items()
                    if v.metadata().id in scan_profile.plugin_ids
                }
            else:
                plugins = registered

            await _emit(
                session,
                scan_id,
                "plugins_loaded",
                f"Loaded {len(plugins)} plugin(s) for profile '{profile_name}'",
            )

            settings = get_settings()
            classifier = Classifier(settings)
            findings: list[Finding] = []

            for plugin in plugins.values():
                meta = plugin.metadata()
                await _emit(
                    session,
                    scan_id,
                    "plugin_start",
                    f"Plugin: {meta.name} ({meta.owasp_id})",
                )

                dispatcher = AsyncDispatcher(
                    target_url=target_url,
                    profile=target_profile,
                    api_key=api_key,
                    scan_id=str(scan_id),
                    max_concurrency=settings.max_concurrency,
                    dry_run=dry_run,
                )

                count = 0
                inconclusive = 0
                async for payload in plugin.payload_generator(target_profile):
                    if (
                        scan_profile.max_payloads_per_plugin is not None
                        and count >= scan_profile.max_payloads_per_plugin
                    ):
                        break

                    exchange = await dispatcher.dispatch(payload, session)
                    count += 1

                    if exchange is None:  # dry_run
                        continue

                    result = await classifier.classify(
                        payload, exchange.response_text, plugin
                    )

                    # Every plugin's "no signal matched" fallback is PARTIAL at
                    # confidence 0.50; genuine partial detections are >= 0.60.
                    # Recording the fallback as a finding produces a wall of
                    # 3.0-scored false positives, so treat it as inconclusive.
                    if (
                        result.failure_mode == FailureMode.PARTIAL
                        and result.confidence < _MIN_PARTIAL_CONFIDENCE
                    ):
                        inconclusive += 1
                        continue

                    if result.failure_mode != FailureMode.REFUSED:
                        finding = Finding(
                            scan_id=scan_id,
                            plugin_id=meta.id,
                            owasp_id=meta.owasp_id,
                            mitre_atlas_id=meta.mitre_atlas_id,
                            failure_mode=result.failure_mode,
                            # Plugins return a *safety* score (10 = safely
                            # refused, 0 = fully complied — see Classifier
                            # docs: "lower score = more severe" wins a merge).
                            # Finding.score is a *risk* score everywhere it's
                            # displayed (dashboard, reports): higher = worse.
                            # Invert once, here, at the single boundary
                            # between the two conventions.
                            score=10.0 - result.score,
                            payload_hash=_short_hash(payload.content),
                            response_hash=_short_hash(exchange.response_text),
                            evidence_path=str(
                                Path("reports/output")
                                / str(scan_id)
                                / "evidence.ndjson"
                            ),
                        )
                        session.add(finding)
                        await session.commit()
                        findings.append(finding)
                        await _emit(
                            session,
                            scan_id,
                            "finding",
                            f"[{meta.owasp_id}] {result.failure_mode.value} "
                            f"score={result.score:.1f}",
                        )

                plugin_findings = sum(1 for f in findings if f.plugin_id == meta.id)
                await _emit(
                    session,
                    scan_id,
                    "plugin_complete",
                    f"Plugin {meta.name}: {count} payloads sent, "
                    f"{plugin_findings} finding(s), {inconclusive} inconclusive",
                )

            risk_score = max((f.score for f in findings), default=0.0)

            result_row = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result_row.scalar_one()
            scan.status = ScanStatus.complete
            scan.finished_at = datetime.now(timezone.utc)
            scan.risk_score = risk_score
            session.add(scan)
            await session.commit()

            await _emit(
                session,
                scan_id,
                "scan_complete",
                f"Scan complete — {len(findings)} finding(s), "
                f"risk score: {risk_score:.1f}/10",
            )

        except asyncio.CancelledError:
            await _mark_cancelled(scan_id)
            raise
        except Exception as exc:
            await _mark_failed(scan_id, exc)
            raise


def _short_hash(text: str) -> str:
    """Return the first 16 hex chars of the SHA-256 of *text*."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]


async def _set_status(
    session: AsyncSession, scan_id: uuid.UUID, status: ScanStatus
) -> None:
    """Update scan status in place."""
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one()
    scan.status = status
    session.add(scan)
    await session.commit()


async def _emit(
    session: AsyncSession, scan_id: uuid.UUID, event_type: str, message: str
) -> None:
    """Persist a ScanEvent row."""
    session.add(ScanEvent(scan_id=scan_id, event_type=event_type, message=message))
    await session.commit()


async def _mark_failed(scan_id: uuid.UUID, exc: Exception) -> None:
    """Open a fresh session to mark a scan as failed after an error."""
    try:
        async with _AsyncSessionFactory() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.failed
                scan.finished_at = datetime.now(timezone.utc)
                session.add(scan)
                session.add(
                    ScanEvent(
                        scan_id=scan_id,
                        event_type="scan_error",
                        message=f"{type(exc).__name__}: {str(exc)[:200]}",
                    )
                )
                await session.commit()
    except Exception:
        pass


async def _mark_cancelled(scan_id: uuid.UUID) -> None:
    """Open a fresh session to mark a scan as cancelled by the user."""
    try:
        async with _AsyncSessionFactory() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.cancelled
                scan.finished_at = datetime.now(timezone.utc)
                session.add(scan)
                session.add(
                    ScanEvent(
                        scan_id=scan_id,
                        event_type="scan_cancelled",
                        message="Scan cancelled by user request.",
                    )
                )
                await session.commit()
    except Exception:
        pass
