import json
import statistics
import time
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel


class Provider(str, Enum):
    openai_compat = "openai_compat"
    anthropic = "anthropic"
    custom = "custom"


#: Dot-notation path (with numeric list indices) used to pull the assistant's
#: reply text out of a target's JSON response, per endpoint format. Real
#: OpenAI-compatible servers — including Ollama's and vLLM's compat layers —
#: all return this same "choices[0].message.content" shape.
_DEFAULT_RESPONSE_PATHS: dict[str, str] = {
    "openai": "choices.0.message.content",
    "ollama": "choices.0.message.content",
}


class TargetProfile(BaseModel):
    """Fingerprinted profile of the target LLM endpoint."""

    provider: Provider
    base_url: str
    auth_header: str
    rate_limit_rpm: Optional[int]
    has_system_prompt: bool
    latency_p50_ms: float
    model_name: Optional[str]
    endpoint_format: str = "openai"
    request_template: Optional[str] = None
    response_path: Optional[str] = None


def _resolve_json_path(data: Any, path: str) -> Any:
    """Walk a dot-notation path (numeric parts index into lists) through *data*."""
    node = data
    for part in path.split("."):
        if isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(node, dict):
            node = node.get(part)
        else:
            return None
        if node is None:
            return None
    return node


def extract_text_from_dict(
    data: dict, response_path: Optional[str], endpoint_format: str = "openai"
) -> str:
    """Extract the assistant reply text from an already-parsed JSON body."""
    path = response_path or _DEFAULT_RESPONSE_PATHS.get(
        endpoint_format, "choices.0.message.content"
    )
    value = _resolve_json_path(data, path)
    return str(value) if value is not None else ""


def extract_response_text(
    response_body: str, response_path: Optional[str], endpoint_format: str = "openai"
) -> str:
    """Extract the assistant reply text from a raw JSON response body string.

    Falls back to the raw body on any parse/extraction failure, so a
    misconfigured response_path degrades gracefully instead of crashing
    the scan.
    """
    try:
        data = json.loads(response_body)
    except (json.JSONDecodeError, TypeError):
        return response_body
    text = extract_text_from_dict(data, response_path, endpoint_format)
    return text if text else response_body


def build_request_body(
    content: str,
    endpoint_format: str,
    model: Optional[str] = None,
    request_template: Optional[str] = None,
    max_tokens: int = 1024,
) -> dict:
    """Build the JSON request body to send to the target, per endpoint format.

    - "openai": ``{"messages": [...], "max_tokens": N, "model"?: ...}``
    - "ollama": ``{"messages": [...], "model"?: ...}`` (no ``max_tokens`` —
      Ollama's OpenAI-compat layer accepts it but many native setups don't
      need it and some strict proxies reject unknown fields)
    - "custom": *request_template* is a JSON string with a ``{prompt}``
      placeholder inside a string value; *content* is safely JSON-escaped
      before substitution so quotes/newlines in attack payloads can't break
      the template's structure.
    """
    if endpoint_format == "custom":
        if not request_template:
            raise ValueError("custom endpoint format requires a request_template")
        escaped = json.dumps(content)[1:-1]
        rendered = request_template.replace("{prompt}", escaped)
        try:
            return json.loads(rendered)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"request_template did not render to valid JSON: {exc}"
            ) from exc
    if endpoint_format == "ollama":
        body: dict = {"messages": [{"role": "user", "content": content}]}
        if model:
            body["model"] = model
        return body
    # openai (default)
    body = {
        "messages": [{"role": "user", "content": content}],
        "max_tokens": max_tokens,
    }
    if model:
        body["model"] = model
    return body


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

    async def run(
        self,
        target_url: str,
        api_key: str,
        model: Optional[str] = None,
        endpoint_format: str = "openai",
        request_template: Optional[str] = None,
        response_path: Optional[str] = None,
    ) -> TargetProfile:
        """Probe the target and return its TargetProfile.

        *model* is sent in every probe body; OpenAI-compatible local servers
        (Ollama, vLLM, LM Studio) reject requests without it with HTTP 400.
        *endpoint_format* / *request_template* / *response_path* configure a
        non-standard target (see ``build_request_body`` / ``extract_response_text``).
        """
        hint = self._hint_from_url(target_url)

        responses: list[dict] = []
        latencies: list[float] = []
        last_headers: dict[str, str] = {}

        async with httpx.AsyncClient(timeout=30.0) as client:
            for message in self._PROBE_MESSAGES:
                body = self._build_request(
                    message, hint, model, endpoint_format, request_template
                )
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
        model_name = model or self._extract_model_name(responses[0])
        rate_limit_rpm = self._parse_rate_limit(last_headers)
        texts = [
            self._extract_text(r, provider, endpoint_format, response_path)
            for r in responses
        ]
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
            endpoint_format=endpoint_format,
            request_template=request_template,
            response_path=response_path,
        )

    def _hint_from_url(self, url: str) -> Provider:
        """Guess provider from URL path before any network call."""
        lower = url.lower()
        if "/v1/messages" in lower:
            return Provider.anthropic
        return Provider.openai_compat

    def _build_request(
        self,
        message: str,
        hint: Provider,
        model: Optional[str] = None,
        endpoint_format: str = "openai",
        request_template: Optional[str] = None,
    ) -> dict:
        """Build a minimal probe request body suited to the endpoint format."""
        if endpoint_format == "custom":
            return build_request_body(message, "custom", model, request_template)
        if hint == Provider.anthropic:
            return {
                "model": model or "claude-3-haiku-20240307",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": message}],
            }
        return build_request_body(message, endpoint_format, model, max_tokens=64)

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

    def _extract_text(
        self,
        body: dict,
        provider: Provider,
        endpoint_format: str = "openai",
        response_path: Optional[str] = None,
    ) -> str:
        """Pull the assistant reply text from a response body."""
        if provider == Provider.anthropic and endpoint_format == "openai":
            try:
                return body["content"][0]["text"]
            except (KeyError, IndexError, TypeError):
                return ""
        return extract_text_from_dict(body, response_path, endpoint_format)

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


async def fingerprint(
    target_url: str,
    api_key: str,
    model: Optional[str] = None,
    endpoint_format: str = "openai",
    request_template: Optional[str] = None,
    response_path: Optional[str] = None,
) -> TargetProfile:
    """Fingerprint a target LLM endpoint and return its TargetProfile."""
    return await Fingerprinter().run(
        target_url, api_key, model, endpoint_format, request_template, response_path
    )
