import asyncio
import json
import uuid
from pathlib import Path
from typing import Optional

import keyring
import typer
from rich.console import Console
from rich.table import Table
from sqlmodel import select

from llmscan_engine.api.orchestrator import run_scan
from llmscan_engine.core.config import get_settings
from llmscan_engine.core.connector import TargetProfile, fingerprint
from llmscan_engine.db.database import _AsyncSessionFactory, engine
from llmscan_engine.db.init_db import init_db
from llmscan_engine.db.models import Finding, Scan, ScanEvent, ScanStatus
from llmscan_engine.plugins.base import AttackPlugin
from llmscan_engine.plugins.garak_loader import set_garak_enabled
from llmscan_engine.plugins.registry import all_plugins, clear_registry, init_registry
from llmscan_engine.profiles.loader import load_profile
from llmscan_engine.reports.generator import ReportGenerator

app = typer.Typer(help="LLMScan — automated OWASP LLM Top 10 penetration testing CLI")
plugins_app = typer.Typer(help="List or reload attack plugins")
app.add_typer(plugins_app, name="plugins")
console = Console()

_VALID_AUDIENCES = {"pentester", "manager", "cxo"}
_VALID_FORMATS = {"html", "pdf"}
_KEYRING_SERVICE = "llmscan"
_REQUEST_CONFIRM_THRESHOLD = 100

_EVENT_STYLES = {
    "scan_start": "cyan",
    "fingerprint_start": "cyan",
    "fingerprint_complete": "cyan",
    "plugins_loaded": "cyan",
    "plugin_start": "blue",
    "plugin_complete": "blue",
    "probe_dry_run": "yellow",
    "probe_failed": "red",
    "finding": "yellow",
    "scan_complete": "green",
    "scan_error": "red",
}


@app.callback()
def main() -> None:
    """LLMScan — automated OWASP LLM Top 10 penetration testing CLI."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _get_api_key(target_url: str, provided: Optional[str]) -> str:
    """Resolve the API key for *target_url*.

    If *provided*, it is used and remembered in the OS keychain (via
    ``keyring``) so future runs against the same target can omit ``--key``.
    Otherwise falls back to a previously stored key, or exits with an error.
    """
    if provided:
        try:
            keyring.set_password(_KEYRING_SERVICE, target_url, provided)
        except Exception:
            pass  # no usable keyring backend — key still works for this run
        return provided
    try:
        stored = keyring.get_password(_KEYRING_SERVICE, target_url)
    except Exception:
        stored = None
    if not stored:
        console.print(
            "[red]No API key provided and none stored for this target. "
            "Pass --key.[/red]"
        )
        raise typer.Exit(code=1)
    return stored


async def _estimate_payload_count(
    plugins: dict[str, AttackPlugin],
    target_profile: TargetProfile,
    cap: Optional[int],
) -> int:
    """Count payloads that would be dispatched, capped per plugin like run_scan does."""
    total = 0
    for plugin in plugins.values():
        count = 0
        async for _ in plugin.payload_generator(target_profile):
            count += 1
            if cap is not None and count >= cap:
                break
        total += count
    return total


async def _poll_until_done(scan_id: uuid.UUID, quiet: bool) -> Scan:
    """Stream ScanEvent rows to the console until the scan completes or fails."""
    async with _AsyncSessionFactory() as session:
        offset = 0
        while True:
            await asyncio.sleep(0.4)
            result = await session.execute(
                select(ScanEvent)
                .where(ScanEvent.scan_id == scan_id)
                .order_by(ScanEvent.created_at)
                .offset(offset)
            )
            events = result.scalars().all()
            for event in events:
                offset += 1
                if not quiet:
                    style = _EVENT_STYLES.get(event.event_type, "white")
                    console.print(
                        f"[{style}]{event.event_type:<18}[/{style}] {event.message}"
                    )

            scan_result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan_row = scan_result.scalar_one()
            if scan_row.status in (
                ScanStatus.complete,
                ScanStatus.failed,
                ScanStatus.cancelled,
            ):
                return scan_row


def _print_scan_summary(scan_row: Scan, findings: list[Finding]) -> None:
    """Print a Rich table summarising a completed scan's findings."""
    color = (
        "green"
        if scan_row.status == ScanStatus.complete
        else "yellow"
        if scan_row.status == ScanStatus.cancelled
        else "red"
    )
    console.print(
        f"\n[{color}]Scan {scan_row.status.value}[/{color}] — "
        f"risk score: {scan_row.risk_score or 0:.1f}/10, {len(findings)} finding(s)\n"
    )
    if not findings:
        return
    table = Table()
    table.add_column("OWASP")
    table.add_column("Plugin")
    table.add_column("Failure mode")
    table.add_column("Score", justify="right")
    table.add_column("MITRE")
    for f in findings:
        score_color = "red" if f.score >= 7 else "yellow" if f.score >= 4 else "green"
        table.add_row(
            f.owasp_id,
            f.plugin_id,
            f.failure_mode.value,
            f"[{score_color}]{f.score:.1f}[/{score_color}]",
            f.mitre_atlas_id or "—",
        )
    console.print(table)


@app.command()
def scan(
    target: str = typer.Option(..., "--target", help="Target LLM endpoint URL"),
    key: Optional[str] = typer.Option(
        None,
        "--key",
        help="API key for the target ('none' for unauthenticated). "
        "Stored in the OS keychain if given; omit to reuse a stored key.",
    ),
    profile: str = typer.Option(
        "standard", "--profile", help="quick | standard | full"
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Model name sent in every request (required by Ollama/vLLM/LM Studio)",
    ),
    endpoint_format: str = typer.Option(
        "openai",
        "--endpoint-format",
        help="Request/response shape: openai | ollama | custom",
    ),
    request_template: Optional[str] = typer.Option(
        None,
        "--request-template",
        help="Custom format only: JSON body with a {prompt} placeholder, "
        'e.g. \'{"message": "{prompt}", "student": "hacker01"}\'',
    ),
    response_path: Optional[str] = typer.Option(
        None,
        "--response-path",
        help="Custom format only: dot-path to the reply text in the JSON "
        'response, e.g. "response" or "choices.0.message.content"',
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Log payloads only; send no HTTP requests"
    ),
    no_garak: bool = typer.Option(
        False, "--no-garak", help="Skip Garak probes; use only built-in YAML templates"
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Assert no external calls will be made "
        "(fails if a judge API key is configured)",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the >100-request confirmation prompt"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Print machine-readable JSON to stdout (for CI)"
    ),
) -> None:
    """Run a scan against a target LLM endpoint."""
    if endpoint_format not in ("openai", "ollama", "custom"):
        console.print(
            f"[red]Invalid --endpoint-format '{endpoint_format}'. "
            "Choose from: openai, ollama, custom[/red]"
        )
        raise typer.Exit(code=1)
    if endpoint_format == "custom" and not (request_template and response_path):
        console.print(
            "[red]--endpoint-format custom requires both --request-template "
            "and --response-path[/red]"
        )
        raise typer.Exit(code=1)

    try:
        scan_profile = load_profile(profile)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    settings = get_settings()
    if offline and settings.judge_api_key:
        console.print(
            "[red]--offline was set but LLMSCAN_JUDGE_API_KEY is configured, "
            "which requires an external network call. Unset it or drop "
            "--offline.[/red]"
        )
        raise typer.Exit(code=1)

    api_key = _get_api_key(target, key)
    use_garak_override = False if no_garak else None

    async def _run() -> tuple[Scan, list[Finding]]:
        await init_db()
        clear_registry()
        init_registry()

        if json_output:
            target_profile = await fingerprint(
                target, api_key, model, endpoint_format, request_template, response_path
            )
        else:
            with console.status("Fingerprinting target endpoint…"):
                target_profile = await fingerprint(
                    target,
                    api_key,
                    model,
                    endpoint_format,
                    request_template,
                    response_path,
                )

        registered = all_plugins()
        plugins = (
            {
                k: v
                for k, v in registered.items()
                if v.metadata().id in scan_profile.plugin_ids
            }
            if scan_profile.plugin_ids is not None
            else registered
        )

        effective_use_garak = (
            scan_profile.use_garak if use_garak_override is None else use_garak_override
        )
        set_garak_enabled(effective_use_garak)

        if not dry_run:
            estimated = await _estimate_payload_count(
                plugins, target_profile, scan_profile.max_payloads_per_plugin
            )
            if estimated > _REQUEST_CONFIRM_THRESHOLD and not yes:
                if json_output:
                    print(
                        json.dumps(
                            {
                                "error": (
                                    f"This scan would send ~{estimated} requests. "
                                    "Re-run with --yes to confirm in non-interactive "
                                    "mode."
                                )
                            }
                        )
                    )
                    raise typer.Exit(code=1)
                proceed = typer.confirm(
                    f"This scan will send approximately {estimated} requests "
                    f"to {target}. Continue?"
                )
                if not proceed:
                    console.print("[yellow]Scan cancelled.[/yellow]")
                    raise typer.Exit(code=0)

        async with _AsyncSessionFactory() as session:
            scan_row = Scan(
                target_url=target, profile=profile, status=ScanStatus.pending
            )
            session.add(scan_row)
            await session.commit()
            await session.refresh(scan_row)
            scan_id = scan_row.id

        task = asyncio.create_task(
            run_scan(
                scan_id=scan_id,
                target_url=target,
                api_key=api_key,
                profile_name=profile,
                dry_run=dry_run,
                use_garak=use_garak_override,
                target_profile=target_profile,
            )
        )
        final_scan = await _poll_until_done(scan_id, quiet=json_output)
        try:
            await task
        except Exception:
            pass  # already reflected in final_scan.status / scan_error event

        async with _AsyncSessionFactory() as session:
            result = await session.execute(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(Finding.score.desc())  # type: ignore[arg-type]
            )
            findings = result.scalars().all()

        return final_scan, findings

    try:
        final_scan, findings = asyncio.run(_run())
    finally:
        asyncio.run(engine.dispose())

    if json_output:
        print(
            json.dumps(
                {
                    "scan_id": str(final_scan.id),
                    "status": final_scan.status.value,
                    "risk_score": final_scan.risk_score,
                    "findings": [
                        {
                            "owasp_id": f.owasp_id,
                            "plugin_id": f.plugin_id,
                            "failure_mode": f.failure_mode.value,
                            "score": f.score,
                            "mitre_atlas_id": f.mitre_atlas_id,
                        }
                        for f in findings
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_scan_summary(final_scan, findings)

    if final_scan.status in (ScanStatus.failed, ScanStatus.cancelled):
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# plugins
# ---------------------------------------------------------------------------


@plugins_app.command("list")
def plugins_list(
    json_output: bool = typer.Option(
        False, "--json", help="Print JSON instead of a table"
    ),
) -> None:
    """List all registered attack plugins."""
    init_registry()
    metas = sorted(
        (p.metadata() for p in all_plugins().values()), key=lambda m: m.owasp_id
    )
    if json_output:
        print(
            json.dumps(
                [
                    {
                        "id": m.id,
                        "name": m.name,
                        "owasp_id": m.owasp_id,
                        "mitre_atlas_id": m.mitre_atlas_id,
                        "severity_weight": m.severity_weight,
                        "tags": m.tags,
                    }
                    for m in metas
                ],
                indent=2,
            )
        )
        return
    table = Table(title=f"{len(metas)} registered plugin(s)")
    table.add_column("OWASP")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Severity", justify="right")
    table.add_column("MITRE")
    for m in metas:
        table.add_row(
            m.owasp_id,
            m.id,
            m.name,
            f"{m.severity_weight:.1f}",
            m.mitre_atlas_id or "—",
        )
    console.print(table)


@plugins_app.command("update")
def plugins_update() -> None:
    """Reload the plugin registry from disk (built-in + community plugins/)."""
    clear_registry()
    init_registry()
    count = len(all_plugins())
    console.print(f"[green]Registry reloaded.[/green] {count} plugin(s) loaded.")


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", help="Maximum number of scans to show"),
    json_output: bool = typer.Option(
        False, "--json", help="Print JSON instead of a table"
    ),
) -> None:
    """List past scans, most recent first."""

    async def _run() -> list[Scan]:
        await init_db()
        async with _AsyncSessionFactory() as session:
            result = await session.execute(
                select(Scan)
                .order_by(Scan.started_at.desc())  # type: ignore[arg-type]
                .limit(limit)
            )
            return list(result.scalars().all())

    try:
        scans = asyncio.run(_run())
    finally:
        asyncio.run(engine.dispose())

    if json_output:
        print(
            json.dumps(
                [
                    {
                        "id": str(s.id),
                        "target_url": s.target_url,
                        "profile": s.profile,
                        "status": s.status.value,
                        "risk_score": s.risk_score,
                        "started_at": s.started_at.isoformat(),
                        "finished_at": (
                            s.finished_at.isoformat() if s.finished_at else None
                        ),
                    }
                    for s in scans
                ],
                indent=2,
            )
        )
        return

    table = Table(title=f"{len(scans)} scan(s)")
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Profile")
    table.add_column("Status")
    table.add_column("Risk", justify="right")
    table.add_column("Started")
    status_color = {
        "pending": "white",
        "running": "yellow",
        "complete": "green",
        "failed": "red",
        "cancelled": "yellow",
    }
    for s in scans:
        color = status_color.get(s.status.value, "white")
        table.add_row(
            str(s.id)[:8],
            s.target_url,
            s.profile,
            f"[{color}]{s.status.value}[/{color}]",
            f"{s.risk_score:.1f}/10" if s.risk_score is not None else "—",
            s.started_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    scan_id: str = typer.Option(
        ..., "--scan-id", help="Scan UUID to generate a report for"
    ),
    audience: str = typer.Option(
        "pentester", "--audience", help="Report audience: pentester | manager | cxo"
    ),
    format: str = typer.Option(
        "html", "--format", help="Output format: html | pdf"
    ),
) -> None:
    """Generate an audience-specific report for a completed scan."""
    if audience not in _VALID_AUDIENCES:
        console.print(
            f"[red]Invalid audience '{audience}'. "
            "Choose from: pentester, manager, cxo[/red]"
        )
        raise typer.Exit(code=1)
    if format not in _VALID_FORMATS:
        console.print(f"[red]Invalid format '{format}'. Choose from: html, pdf[/red]")
        raise typer.Exit(code=1)
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        console.print(f"[red]Invalid scan id: {scan_id}[/red]")
        raise typer.Exit(code=1) from None

    async def _run() -> Path:
        await init_db()
        async with _AsyncSessionFactory() as session:
            generator = ReportGenerator(session)
            return await generator.generate(scan_uuid, audience=audience, format=format)

    try:
        try:
            path = asyncio.run(_run())
        except LookupError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from None
        except RuntimeError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from None
    finally:
        asyncio.run(engine.dispose())

    console.print(f"[green]Report generated:[/green] {path}")


if __name__ == "__main__":
    app()
