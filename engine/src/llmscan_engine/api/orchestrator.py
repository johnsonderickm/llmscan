import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from llmscan_engine.core.classifier import Classifier
from llmscan_engine.core.config import get_settings
from llmscan_engine.core.connector import fingerprint
from llmscan_engine.core.dispatcher import AsyncDispatcher
from llmscan_engine.db.database import _AsyncSessionFactory
from llmscan_engine.db.models import (
    FailureMode,
    Finding,
    Scan,
    ScanEvent,
    ScanStatus,
)
from llmscan_engine.plugins.registry import all_plugins
from llmscan_engine.profiles.loader import load_profile


async def run_scan(
    scan_id: uuid.UUID,
    target_url: str,
    api_key: str,
    profile_name: str,
    dry_run: bool = False,
) -> None:
    """Background task: fingerprint target, run plugins, classify responses, save findings."""
    async with _AsyncSessionFactory() as session:
        try:
            await _set_status(session, scan_id, ScanStatus.running)
            await _emit(session, scan_id, "scan_start", f"Scan started — target: {target_url}")

            # Fingerprint
            await _emit(session, scan_id, "fingerprint_start", "Fingerprinting target endpoint")
            target_profile = await fingerprint(target_url, api_key)
            await _emit(
                session,
                scan_id,
                "fingerprint_complete",
                f"Provider: {target_profile.provider.value}, model: {target_profile.model_name or 'unknown'}",
            )

            # Load scan profile + plugins
            scan_profile = load_profile(profile_name)
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
                await _emit(session, scan_id, "plugin_start", f"Plugin: {meta.name} ({meta.owasp_id})")

                dispatcher = AsyncDispatcher(
                    target_url=target_url,
                    profile=target_profile,
                    api_key=api_key,
                    scan_id=str(scan_id),
                    max_concurrency=settings.max_concurrency,
                    dry_run=dry_run,
                )

                count = 0
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

                    result = await classifier.classify(payload, exchange.response_body, plugin)

                    if result.failure_mode != FailureMode.REFUSED:
                        finding = Finding(
                            scan_id=scan_id,
                            plugin_id=meta.id,
                            owasp_id=meta.owasp_id,
                            mitre_atlas_id=meta.mitre_atlas_id,
                            failure_mode=result.failure_mode,
                            score=result.score,
                            payload_hash=hashlib.sha256(payload.content.encode()).hexdigest()[:16],
                            response_hash=hashlib.sha256(exchange.response_body.encode()).hexdigest()[:16],
                            evidence_path=str(
                                Path("reports/output") / str(scan_id) / "evidence.ndjson"
                            ),
                        )
                        session.add(finding)
                        await session.commit()
                        findings.append(finding)
                        await _emit(
                            session,
                            scan_id,
                            "finding",
                            f"[{meta.owasp_id}] {result.failure_mode.value} score={result.score:.1f}",
                        )

                plugin_findings = sum(1 for f in findings if f.plugin_id == meta.id)
                await _emit(
                    session,
                    scan_id,
                    "plugin_complete",
                    f"Plugin {meta.name}: {count} payloads sent, {plugin_findings} finding(s)",
                )

            risk_score = max((f.score for f in findings), default=0.0)

            result_row = await session.exec(select(Scan).where(Scan.id == scan_id))
            scan = result_row.one()
            scan.status = ScanStatus.complete
            scan.finished_at = datetime.now(timezone.utc)
            scan.risk_score = risk_score
            session.add(scan)
            await session.commit()

            await _emit(
                session,
                scan_id,
                "scan_complete",
                f"Scan complete — {len(findings)} finding(s), risk score: {risk_score:.1f}/10",
            )

        except Exception as exc:
            await _mark_failed(scan_id, exc)
            raise


async def _set_status(
    session: AsyncSession, scan_id: uuid.UUID, status: ScanStatus
) -> None:
    """Update scan status in place."""
    result = await session.exec(select(Scan).where(Scan.id == scan_id))
    scan = result.one()
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
            result = await session.exec(select(Scan).where(Scan.id == scan_id))
            scan = result.one_or_none()
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
