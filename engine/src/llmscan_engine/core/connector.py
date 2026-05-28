import statistics
import time
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel


class Provider(str, Enum):
    openai_compat = "openai_compat"
    anthropic = "anthropic"
    custom = "custom"


class TargetProfile(BaseModel):
    """Fingerprinted profile of the target LLM endpoint."""

    provider: Provider
    base_url: str
    auth_header: str
    rate_limit_rpm: Optional[int]
    has_system_prompt: bool
    latency_p50_ms: float
    model_name: Optional[str]


class Fingerprinter:
    """
    Sends three benign probe requests to a target LLM endpoint and returns a
    TargetProfile describing its provider, rate limits, and observed behaviour.
    """

    _PROBE_MESSAGES = [
        "Reply with exactly one word: hello.",
        "What is 1+1? Reply with just the number.",
        "Repeat after me, one word only: test.",
    ]

    async def run(self, target_url: str, api_key: str) -> TargetProfile:
        """Probe the target and return its TargetProfile."""
        hint = self._hint_from_url(target_url)

        responses: list[dict] = []
        latencies: list[float] = []
        last_headers: dict[str, str] = {}

        async with httpx.AsyncClient(timeout=30.0) as client:
            for message in self._PROBE_MESSAGES:
                body = self._build_request(message, hint)
                headers = self._build_headers(api_key, hint)

                t0 = time.perf_counter()
                resp = await client.post(target_url, json=body, headers=headers)
                latencies.append((time.perf_counter() - t0) * 1000)
                last_headers = dict(resp.headers)

                try:
                    responses.append(resp.json())
                except Exception:
                    responses.append({})

        provider = self._detect_provider(responses[0], hint)
        model_name = self._extract_model_name(responses[0])
        rate_limit_rpm = self._parse_rate_limit(last_headers)
        texts = [self._extract_text(r, provider) for r in responses]
        has_system_prompt = self._detect_system_prompt(texts)
        latency_p50_ms = statistics.median(latencies)
        auth_header = self._build_auth_header_str(api_key, provider)
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        return TargetProfile(
            provider=provider,
            base_url=base_url,
            auth_header=auth_header,
            rate_limit_rpm=rate_limit_rpm,
            has_system_prompt=has_system_prompt,
            latency_p50_ms=latency_p50_ms,
            model_name=model_name,
        )

    def _hint_from_url(self, url: str) -> Provider:
        """Guess provider from URL path before any network call."""
        lower = url.lower()
        if "/v1/messages" in lower:
            return Provider.anthropic
        return Provider.openai_compat

    def _build_request(self, message: str, hint: Provider) -> dict:
        """Build a minimal probe request body suited to the provider hint."""
        if hint == Provider.anthropic:
            return {
                "model": "claude-3-haiku-20240307",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": message}],
            }
        return {
            "messages": [{"role": "user", "content": message}],
            "max_tokens": 64,
        }

    def _build_headers(self, api_key: str, hint: Provider) -> dict:
        """Build authentication headers suited to the provider hint."""
        if hint == Provider.anthropic:
            return {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
        return {
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json",
        }

    def _detect_provider(self, body: dict, hint: Provider) -> Provider:
        """Confirm the provider from the response body structure."""
        if "choices" in body:
            return Provider.openai_compat
        content = body.get("content")
        if isinstance(content, list) and content and "type" in content[0]:
            return Provider.anthropic
        # Ambiguous response (e.g. error body) — trust the URL hint
        return hint

    def _extract_model_name(self, body: dict) -> Optional[str]:
        """Extract model name from the response if the endpoint echoes it back."""
        return body.get("model")

    def _extract_text(self, body: dict, provider: Provider) -> str:
        """Pull the assistant reply text from a response body."""
        try:
            if provider == Provider.anthropic:
                return body["content"][0]["text"]
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return ""

    def _parse_rate_limit(self, headers: dict[str, str]) -> Optional[int]:
        """
        Infer requests-per-minute from rate-limit headers.
        Checks OpenAI, Anthropic, and generic header conventions.
        Header lookup is case-insensitive.
        """
        normalized = {k.lower(): v for k, v in headers.items()}
        candidates = [
            "x-ratelimit-limit-requests",
            "anthropic-ratelimit-requests-limit",
            "x-ratelimit-requests-limit",
        ]
        for key in candidates:
            value = normalized.get(key)
            if value:
                try:
                    return int(value)
                except ValueError:
                    pass
        return None

    def _detect_system_prompt(self, texts: list[str]) -> bool:
        """
        Heuristic: low lexical diversity across three varied probes suggests a
        constraining system prompt is steering responses toward similar output.
        """
        all_words = " ".join(texts).lower().split()
        if len(all_words) < 2:
            return False
        unique_ratio = len(set(all_words)) / len(all_words)
        return unique_ratio < 0.4

    def _build_auth_header_str(self, api_key: str, provider: Provider) -> str:
        """Return the canonical auth header string for use in future requests."""
        if provider == Provider.anthropic:
            return f"x-api-key: {api_key}"
        return f"Authorization: Bearer {api_key}"


async def fingerprint(target_url: str, api_key: str) -> TargetProfile:
    """Fingerprint a target LLM endpoint and return its TargetProfile."""
    return await Fingerprinter().run(target_url, api_key)
