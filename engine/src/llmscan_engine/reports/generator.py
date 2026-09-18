"""Audience-specific report generation: pentester / manager / cxo.

Renders Jinja2 HTML templates from a scan's findings, correlating each
Finding row (which stores only content hashes) back to its raw payload
and response text via the scan's evidence.ndjson file. Optionally
exports the rendered HTML to PDF using headless Chromium (Playwright).
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from llmscan_engine.core.dispatcher import Exchange
from llmscan_engine.db.models import Finding, Scan
from llmscan_engine.plugins.registry import all_plugins, init_registry
from llmscan_engine.reports.compliance_mapping import compliance_refs

Audience = Literal["pentester", "manager", "cxo"]
ReportFormat = Literal["html", "pdf"]

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_ALL_OWASP_IDS = [f"LLM{i:02d}" for i in range(1, 11)]

_SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}


def _severity_band(score: float) -> str:
    """Map a 0-10 risk score to a severity band."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def load_exchanges(
    scan_id: uuid.UUID, output_dir: Path
) -> dict[tuple[str, str], Exchange]:
    """Index a scan's evidence.ndjson by (payload_hash, response_hash).

    Lines that don't validate (e.g. evidence written before ``prompt_text`` /
    ``response_text`` existed) are skipped rather than failing the whole load.
    """
    path = output_dir / str(scan_id) / "evidence.ndjson"
    index: dict[tuple[str, str], Exchange] = {}
    if not path.exists():
        return index

    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            exchange = Exchange.model_validate_json(line)
        except ValidationError:
            continue
        payload_hash = hashlib.sha256(exchange.prompt_text.encode()).hexdigest()[:16]
        response_hash = hashlib.sha256(
            exchange.response_text.encode()
        ).hexdigest()[:16]
        index[(payload_hash, response_hash)] = exchange

    return index


def _enrich_finding(
    finding: Finding, exchanges: dict[tuple[str, str], Exchange]
) -> dict:
    """Attach raw payload/response text and reproduction details to a finding."""
    exchange = exchanges.get((finding.payload_hash, finding.response_hash))
    plugin = all_plugins().get(finding.plugin_id)

    return {
        "row": finding,
        "severity_band": _severity_band(finding.score),
        "plugin_name": plugin.metadata().name if plugin else finding.plugin_id,
        "remediation": {
            audience: plugin.remediation(audience) if plugin else ""
            for audience in ("pentester", "manager", "cxo")
        },
        "payload_content": exchange.prompt_text if exchange else None,
        "response_excerpt": (exchange.response_text[:500] if exchange else None),
        "reproduction": (
            {
                "method": exchange.method,
                "url": exchange.url,
                "status_code": exchange.status_code,
                "latency_ms": round(exchange.latency_ms, 1),
                "timestamp": exchange.timestamp,
            }
            if exchange
            else None
        ),
        "compliance": compliance_refs(finding.owasp_id),
    }


def _risk_heatmap(enriched: list[dict]) -> list[dict]:
    """Per-OWASP-category max score and finding count, including clean categories."""
    by_category: dict[str, list[dict]] = {owasp_id: [] for owasp_id in _ALL_OWASP_IDS}
    for item in enriched:
        by_category.setdefault(item["row"].owasp_id, []).append(item)

    heatmap = []
    for owasp_id in _ALL_OWASP_IDS:
        items = by_category.get(owasp_id, [])
        max_score = max((i["row"].score for i in items), default=0.0)
        heatmap.append(
            {
                "owasp_id": owasp_id,
                "count": len(items),
                "max_score": max_score,
                "severity_band": _severity_band(max_score) if items else "Clean",
            }
        )
    return heatmap


def _fix_priority_queue(enriched: list[dict], scan: Scan) -> list[dict]:
    """Findings ordered by severity with SLA due dates for the fix queue."""
    baseline = scan.finished_at or datetime.now(timezone.utc)
    if baseline.tzinfo is None:
        baseline = baseline.replace(tzinfo=timezone.utc)
    queue = []
    for item in sorted(enriched, key=lambda i: i["row"].score, reverse=True):
        band = item["severity_band"]
        sla_days = _SLA_DAYS[band]
        due = baseline + timedelta(days=sla_days)
        queue.append(
            {
                **item,
                "sla_days": sla_days,
                "due_date": due.date().isoformat(),
                "overdue": due < datetime.now(timezone.utc),
            }
        )
    return queue


def _gauge_dashoffset(score: float) -> float:
    """Stroke-dashoffset for an SVG ring gauge sized 0-10 over circumference 251.2."""
    circumference = 251.2
    fraction = max(0.0, min(1.0, score / 10.0))
    return circumference * (1 - fraction)


class ReportGenerator:
    """Generates audience-specific HTML/PDF reports for a completed scan."""

    def __init__(
        self,
        session: AsyncSession,
        output_dir: Path = Path("reports/output"),
    ) -> None:
        self._session = session
        self._output_dir = output_dir
        self._env = Environment(
            loader=FileSystemLoader(_TEMPLATES_DIR),
            autoescape=select_autoescape(["html"]),
        )

    async def generate(
        self,
        scan_id: uuid.UUID,
        audience: Audience,
        format: ReportFormat = "html",
    ) -> Path:
        """Render and write the report; returns the output file path."""
        scan = await self._session.get(Scan, scan_id)
        if scan is None:
            raise LookupError(f"Scan {scan_id} not found")

        if not all_plugins():
            init_registry()

        result = await self._session.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.score.desc())  # type: ignore[arg-type]
        )
        findings = result.scalars().all()

        exchanges = load_exchanges(scan_id, self._output_dir)
        enriched = [_enrich_finding(f, exchanges) for f in findings]

        context: dict = {
            "scan": scan,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": enriched,
        }
        if audience == "pentester":
            context["findings_by_owasp"] = _group_by_owasp(enriched)
        elif audience == "manager":
            context["heatmap"] = _risk_heatmap(enriched)
            context["fix_queue"] = _fix_priority_queue(enriched, scan)
            context["critical_high_count"] = sum(
                1 for i in enriched if i["severity_band"] in ("Critical", "High")
            )
        elif audience == "cxo":
            risk_score = scan.risk_score or 0.0
            context["risk_score"] = risk_score
            context["risk_band"] = _severity_band(risk_score)
            context["gauge_dashoffset"] = _gauge_dashoffset(risk_score)
            context["affected_categories"] = sorted(
                {item["row"].owasp_id for item in enriched}
            )
            context["compliance_gaps"] = [
                {"owasp_id": owasp_id, **compliance_refs(owasp_id)}
                for owasp_id in context["affected_categories"]
            ]
            context["impact_narrative"] = _impact_narrative(enriched)

        template = self._env.get_template(f"{audience}.html")
        html = template.render(**context)

        out_dir = self._output_dir / str(scan_id)
        out_dir.mkdir(parents=True, exist_ok=True)
        html_path = out_dir / f"report_{audience}.html"
        html_path.write_text(html, encoding="utf-8")

        if format == "html":
            return html_path

        pdf_path = out_dir / f"report_{audience}.pdf"
        await _render_pdf(html_path, pdf_path)
        return pdf_path


def _group_by_owasp(enriched: list[dict]) -> list[dict]:
    """Group enriched findings by OWASP category, in fixed LLM01-10 order."""
    by_category: dict[str, list[dict]] = {}
    for item in enriched:
        by_category.setdefault(item["row"].owasp_id, []).append(item)
    return [
        {"owasp_id": owasp_id, "entries": by_category[owasp_id]}
        for owasp_id in _ALL_OWASP_IDS
        if owasp_id in by_category
    ]


def _impact_narrative(enriched: list[dict]) -> Optional[str]:
    """One-paragraph narrative built from the highest-severity finding, if any."""
    if not enriched:
        return None
    worst = max(enriched, key=lambda i: i["row"].score)
    return worst["remediation"]["cxo"]


async def _render_pdf(html_path: Path, pdf_path: Path) -> None:
    """Render an HTML file to PDF using headless Chromium via Playwright."""
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "PDF export requires Playwright. Install with "
            "`uv sync --extra pdf` then `uv run playwright install chromium`."
        ) from exc

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            page = await browser.new_page()
            await page.goto(html_path.resolve().as_uri())
            await page.pdf(path=str(pdf_path), format="A4", print_background=True)
        finally:
            await browser.close()
