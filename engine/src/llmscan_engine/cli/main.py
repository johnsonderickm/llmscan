import asyncio
import uuid
from pathlib import Path

import typer
from rich.console import Console

from llmscan_engine.db.database import _AsyncSessionFactory
from llmscan_engine.reports.generator import ReportGenerator

app = typer.Typer(help="LLMScan — automated OWASP LLM Top 10 penetration testing CLI")
console = Console()

_VALID_AUDIENCES = {"pentester", "manager", "cxo"}
_VALID_FORMATS = {"html", "pdf"}


@app.callback()
def main() -> None:
    """LLMScan — automated OWASP LLM Top 10 penetration testing CLI."""


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
        async with _AsyncSessionFactory() as session:
            generator = ReportGenerator(session)
            return await generator.generate(scan_uuid, audience=audience, format=format)

    try:
        path = asyncio.run(_run())
    except LookupError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    console.print(f"[green]Report generated:[/green] {path}")


if __name__ == "__main__":
    app()
