import asyncio
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from llmscan_engine.core.connector import Provider, TargetProfile
from llmscan_engine.db.models import ScanEvent
from llmscan_engine.plugins.schemas import Payload


class Exchange(BaseModel):
    """Complete record of one HTTP request/response cycle."""

    scan_id: str
    payload_id: str
    method: str = "POST"
    url: str
    request_headers: dict[str, str]
    request_body: dict
    status_code: int
    response_headers: dict[str, str]
    response_body: str
    latency_ms: float
    timestamp: str


def _is_retryable(exc: BaseException) -> bool:
    """True for 429 / 503 responses that should trigger a retry."""
    return (
        isinstance(exc, httpx.HTTPStatusError)
        and exc.response.status_code in (429, 503)
    )


class AsyncDispatcher:
    """
    Dispatches attack payloads to a target LLM endpoint with:
    - asyncio.Semaphore concurrency control
    - tenacity retry on 429 / 503 with exponential back-off
    - full exchange capture written to NDJSON evidence files
    - ScanEvent emission for the live WebSocket feed
    """

    def __init__(
        self,
        target_url: str,
        profile: TargetProfile,
        api_key: str,
        scan_id: str,
        max_concurrency: int = 3,
        dry_run: bool = False,
        output_dir: Path = Path("reports/output"),
        retry_wait=None,
        retry_stop=None,
    ) -> None:
        self._target_url = target_url
        self._profile = profile
        self._api_key = api_key
        self._scan_id = scan_id
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._dry_run = dry_run
        self._evidence_path = Path(output_dir) / scan_id / "evidence.ndjson"
        self._retry_wait = retry_wait or wait_exponential(
            multiplier=1, min=1, max=60
        )
        self._retry_stop = retry_stop or stop_after_attempt(3)

    async def dispatch(
        self, payload: Payload, session: AsyncSession
    ) -> Optional[Exchange]:
        """
        Send one payload to the target and return the Exchange record.
        Returns None in dry-run mode — no HTTP request is sent.
        """
        if self._dry_run:
            await self._emit_event(
                session,
                "probe_dry_run",
                f"[dry-run] {payload.plugin_id}:{payload.template_id}"
                f" — {payload.content[:60]}",
            )
            return None

        async with self._semaphore:
            body, headers = self._build_request(payload)
            await self._emit_event(
                session,
                "probe_sent",
                f"{payload.plugin_id} payload {payload.id[:8]} dispatched",
            )
            try:
                exchange = await self._post_with_retry(payload, body, headers)
            except Exception as exc:
                await self._emit_event(
                    session,
                    "probe_failed",
                    f"{type(exc).__name__}: {str(exc)[:120]}",
                )
                raise

            await self._emit_event(
                session,
                "probe_complete",
                f"HTTP {exchange.status_code} in {exchange.latency_ms:.0f} ms",
            )
            await asyncio.to_thread(self._append_evidence, exchange)
            return exchange

    async def _post_with_retry(
        self, payload: Payload, body: dict, headers: dict
    ) -> Exchange:
        """POST to the target URL with tenacity retry on 429 / 503."""
        last_response: Optional[httpx.Response] = None
        last_latency: float = 0.0

        async with httpx.AsyncClient(timeout=30.0) as client:
            async for attempt in AsyncRetrying(
                retry=retry_if_exception(_is_retryable),
                wait=self._retry_wait,
                stop=self._retry_stop,
                reraise=True,
            ):
                with attempt:
                    t0 = time.perf_counter()
                    resp = await client.post(
                        self._target_url, json=body, headers=headers
                    )
                    last_latency = (time.perf_counter() - t0) * 1000
                    last_response = resp
                    if resp.status_code in (429, 503):
                        resp.raise_for_status()

        assert last_response is not None
        return Exchange(
            scan_id=self._scan_id,
            payload_id=payload.id,
            url=self._target_url,
            request_headers=self._redact_headers(headers),
            request_body=body,
            status_code=last_response.status_code,
            response_headers=dict(last_response.headers),
            response_body=last_response.text,
            latency_ms=last_latency,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _build_request(self, payload: Payload) -> tuple[dict, dict]:
        """Build a provider-appropriate request body and auth headers."""
        if self._profile.provider == Provider.anthropic:
            body: dict = {
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": payload.content}],
            }
            if self._profile.model_name:
                body["model"] = self._profile.model_name
            headers = {
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
        else:
            body = {
                "messages": [{"role": "user", "content": payload.content}],
                "max_tokens": 1024,
            }
            if self._profile.model_name:
                body["model"] = self._profile.model_name
            headers = {
                "Authorization": f"Bearer {self._api_key}",
                "content-type": "application/json",
            }
        return body, headers

    def _redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Replace credential values before writing to evidence files."""
        _SENSITIVE = {"authorization", "x-api-key"}
        return {
            k: "[REDACTED]" if k.lower() in _SENSITIVE else v
            for k, v in headers.items()
        }

    def _append_evidence(self, exchange: Exchange) -> None:
        """Append one exchange as a JSON line to the evidence NDJSON file."""
        self._evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with self._evidence_path.open("a", encoding="utf-8") as fh:
            fh.write(exchange.model_dump_json() + "\n")

    async def _emit_event(
        self, session: AsyncSession, event_type: str, message: str
    ) -> None:
        """Insert a ScanEvent row and commit to the database."""
        session.add(
            ScanEvent(
                scan_id=uuid.UUID(self._scan_id),
                event_type=event_type,
                message=message,
            )
        )
        await session.commit()
