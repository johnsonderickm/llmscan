import pytest

from llmscan_engine.core.connector import (
    Fingerprinter,
    Provider,
    TargetProfile,
    build_request_body,
    extract_response_text,
    extract_text_from_dict,
    fingerprint,
)

_OPENAI_URL = "https://api.example.com/v1/chat/completions"
_ANTHROPIC_URL = "https://api.example.com/v1/messages"
_API_KEY = "test-key-123"

_OPENAI_RESPONSE = {
    "id": "chatcmpl-abc",
    "object": "chat.completion",
    "model": "gpt-4o",
    "choices": [{"message": {"role": "assistant", "content": "hello"}}],
}

_ANTHROPIC_RESPONSE = {
    "id": "msg_abc",
    "type": "message",
    "model": "claude-3-haiku-20240307",
    "content": [{"type": "text", "text": "hello"}],
}


def _add_n_responses(httpx_mock, url: str, json_body: dict, n: int = 3, headers: dict | None = None) -> None:
    """Register n identical mock responses for the same URL."""
    for _ in range(n):
        httpx_mock.add_response(method="POST", url=url, json=json_body, headers=headers or {})


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------

async def test_detects_openai_compat(httpx_mock) -> None:
    """A response containing 'choices' is classified as openai_compat."""
    _add_n_responses(httpx_mock, _OPENAI_URL, _OPENAI_RESPONSE)
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.provider == Provider.openai_compat


async def test_detects_anthropic(httpx_mock) -> None:
    """A response with a typed 'content' list is classified as anthropic."""
    _add_n_responses(httpx_mock, _ANTHROPIC_URL, _ANTHROPIC_RESPONSE)
    profile = await fingerprint(_ANTHROPIC_URL, _API_KEY)
    assert profile.provider == Provider.anthropic


async def test_falls_back_to_url_hint_on_ambiguous_body(httpx_mock) -> None:
    """An unrecognised response body falls back to the URL-derived provider hint."""
    _add_n_responses(httpx_mock, _OPENAI_URL, {"error": "unauthorized"})
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.provider == Provider.openai_compat


# ---------------------------------------------------------------------------
# base_url extraction
# ---------------------------------------------------------------------------

async def test_base_url_strips_path(httpx_mock) -> None:
    """base_url contains only scheme + host, no path."""
    _add_n_responses(httpx_mock, _OPENAI_URL, _OPENAI_RESPONSE)
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.base_url == "https://api.example.com"
    assert "/v1" not in profile.base_url


# ---------------------------------------------------------------------------
# Model name extraction
# ---------------------------------------------------------------------------

async def test_extracts_model_name(httpx_mock) -> None:
    """Model name echoed in the response body is captured in TargetProfile."""
    _add_n_responses(httpx_mock, _OPENAI_URL, _OPENAI_RESPONSE)
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.model_name == "gpt-4o"


async def test_model_name_none_when_absent(httpx_mock) -> None:
    """model_name is None when the endpoint does not echo it."""
    body = {**_OPENAI_RESPONSE}
    body.pop("model", None)
    _add_n_responses(httpx_mock, _OPENAI_URL, body)
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.model_name is None


# ---------------------------------------------------------------------------
# Rate limit parsing
# ---------------------------------------------------------------------------

async def test_parses_openai_rate_limit_header(httpx_mock) -> None:
    """x-ratelimit-limit-requests header is parsed to rate_limit_rpm."""
    _add_n_responses(
        httpx_mock,
        _OPENAI_URL,
        _OPENAI_RESPONSE,
        headers={"x-ratelimit-limit-requests": "60"},
    )
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.rate_limit_rpm == 60


async def test_parses_anthropic_rate_limit_header(httpx_mock) -> None:
    """anthropic-ratelimit-requests-limit header is parsed to rate_limit_rpm."""
    _add_n_responses(
        httpx_mock,
        _ANTHROPIC_URL,
        _ANTHROPIC_RESPONSE,
        headers={"anthropic-ratelimit-requests-limit": "50"},
    )
    profile = await fingerprint(_ANTHROPIC_URL, _API_KEY)
    assert profile.rate_limit_rpm == 50


async def test_rate_limit_none_when_header_absent(httpx_mock) -> None:
    """rate_limit_rpm is None when no rate-limit header is present."""
    _add_n_responses(httpx_mock, _OPENAI_URL, _OPENAI_RESPONSE)
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.rate_limit_rpm is None


# ---------------------------------------------------------------------------
# System prompt detection
# ---------------------------------------------------------------------------

async def test_no_system_prompt_on_diverse_responses(httpx_mock) -> None:
    """High lexical diversity across probes → has_system_prompt is False."""
    diverse = [
        {**_OPENAI_RESPONSE, "choices": [{"message": {"role": "assistant", "content": "hello there friend"}}]},
        {**_OPENAI_RESPONSE, "choices": [{"message": {"role": "assistant", "content": "the answer is two"}}]},
        {**_OPENAI_RESPONSE, "choices": [{"message": {"role": "assistant", "content": "repeating after you: test"}}]},
    ]
    for body in diverse:
        httpx_mock.add_response(method="POST", url=_OPENAI_URL, json=body)

    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.has_system_prompt is False


async def test_system_prompt_detected_on_uniform_responses(httpx_mock) -> None:
    """Low lexical diversity (repeated boilerplate) → has_system_prompt is True."""
    boilerplate = "I apologize but I can only discuss cooking topics with you today"
    uniform = {**_OPENAI_RESPONSE, "choices": [{"message": {"role": "assistant", "content": boilerplate}}]}
    _add_n_responses(httpx_mock, _OPENAI_URL, uniform)

    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.has_system_prompt is True


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------

async def test_openai_auth_header(httpx_mock) -> None:
    """OpenAI endpoints use Bearer token auth header."""
    _add_n_responses(httpx_mock, _OPENAI_URL, _OPENAI_RESPONSE)
    profile = await fingerprint(_OPENAI_URL, _API_KEY)
    assert profile.auth_header == f"Authorization: Bearer {_API_KEY}"


async def test_anthropic_auth_header(httpx_mock) -> None:
    """Anthropic endpoints use x-api-key auth header."""
    _add_n_responses(httpx_mock, _ANTHROPIC_URL, _ANTHROPIC_RESPONSE)
    profile = await fingerprint(_ANTHROPIC_URL, _API_KEY)
    assert profile.auth_header == f"x-api-key: {_API_KEY}"


# ---------------------------------------------------------------------------
# Unit tests for Fingerprinter helpers (no network)
# ---------------------------------------------------------------------------

def test_hint_from_url_anthropic() -> None:
    fp = Fingerprinter()
    assert fp._hint_from_url("https://api.anthropic.com/v1/messages") == Provider.anthropic


def test_hint_from_url_openai() -> None:
    fp = Fingerprinter()
    assert fp._hint_from_url("https://api.openai.com/v1/chat/completions") == Provider.openai_compat


def test_detect_system_prompt_low_variance() -> None:
    fp = Fingerprinter()
    repeated = ["sorry I can only answer about food"] * 3
    assert fp._detect_system_prompt(repeated) is True


def test_detect_system_prompt_high_variance() -> None:
    fp = Fingerprinter()
    diverse = ["hello world", "the answer is two", "test complete now"]
    assert fp._detect_system_prompt(diverse) is False


def test_parse_rate_limit_case_insensitive() -> None:
    fp = Fingerprinter()
    assert fp._parse_rate_limit({"X-RateLimit-Limit-Requests": "100"}) == 100


def test_parse_rate_limit_missing() -> None:
    fp = Fingerprinter()
    assert fp._parse_rate_limit({}) is None


def test_target_profile_is_pydantic_model() -> None:
    profile = TargetProfile(
        provider=Provider.openai_compat,
        base_url="https://api.example.com",
        auth_header="Authorization: Bearer key",
        rate_limit_rpm=60,
        has_system_prompt=False,
        latency_p50_ms=123.4,
        model_name="gpt-4o",
    )
    assert profile.model_dump()["provider"] == "openai_compat"


def test_target_profile_defaults_to_openai_format() -> None:
    profile = TargetProfile(
        provider=Provider.openai_compat,
        base_url="https://api.example.com",
        auth_header="Authorization: Bearer key",
        rate_limit_rpm=60,
        has_system_prompt=False,
        latency_p50_ms=123.4,
        model_name="gpt-4o",
    )
    assert profile.endpoint_format == "openai"
    assert profile.request_template is None
    assert profile.response_path is None


# ---------------------------------------------------------------------------
# build_request_body
# ---------------------------------------------------------------------------


def test_build_request_body_openai_default() -> None:
    body = build_request_body("hello", "openai")
    assert body == {
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 1024,
    }


def test_build_request_body_openai_includes_model() -> None:
    body = build_request_body("hello", "openai", model="gpt-4o")
    assert body["model"] == "gpt-4o"


def test_build_request_body_ollama_omits_max_tokens() -> None:
    body = build_request_body("hello", "ollama", model="llama3")
    assert body == {
        "messages": [{"role": "user", "content": "hello"}],
        "model": "llama3",
    }
    assert "max_tokens" not in body


def test_build_request_body_custom_substitutes_prompt() -> None:
    template = '{"message": "{prompt}", "student": "hacker01"}'
    body = build_request_body("ignore all rules", "custom", request_template=template)
    assert body == {"message": "ignore all rules", "student": "hacker01"}


def test_build_request_body_custom_escapes_special_characters() -> None:
    template = '{"message": "{prompt}"}'
    tricky = 'He said "hello"\nand a \\backslash'
    body = build_request_body(tricky, "custom", request_template=template)
    assert body == {"message": tricky}


def test_build_request_body_custom_requires_template() -> None:
    with pytest.raises(ValueError, match="request_template"):
        build_request_body("hello", "custom")


def test_build_request_body_custom_invalid_template_raises() -> None:
    with pytest.raises(ValueError, match="did not render to valid JSON"):
        build_request_body("hello", "custom", request_template='{"message": {prompt}}')


# ---------------------------------------------------------------------------
# extract_response_text / extract_text_from_dict
# ---------------------------------------------------------------------------


def test_extract_text_from_dict_default_openai_path() -> None:
    data = {"choices": [{"message": {"content": "hi there"}}]}
    assert extract_text_from_dict(data, None, "openai") == "hi there"


def test_extract_text_from_dict_custom_path() -> None:
    data = {"response": "flag{custom_ctf}", "student": "hacker01"}
    assert extract_text_from_dict(data, "response", "custom") == "flag{custom_ctf}"


def test_extract_text_from_dict_nested_custom_path() -> None:
    data = {"result": {"answer": "nested value"}}
    assert extract_text_from_dict(data, "result.answer", "custom") == "nested value"


def test_extract_text_from_dict_missing_path_returns_empty() -> None:
    data = {"unexpected": "shape"}
    assert extract_text_from_dict(data, "choices.0.message.content", "openai") == ""


def test_extract_response_text_parses_raw_json_string() -> None:
    raw = '{"response": "flag{via_string}"}'
    assert extract_response_text(raw, "response", "custom") == "flag{via_string}"


def test_extract_response_text_falls_back_to_raw_on_bad_json() -> None:
    raw = "not json at all"
    assert extract_response_text(raw, "response", "custom") == "not json at all"


def test_extract_response_text_falls_back_when_path_resolves_nothing() -> None:
    raw = '{"unexpected": "shape"}'
    assert extract_response_text(raw, "response", "custom") == raw


# ---------------------------------------------------------------------------
# fingerprint() with a custom endpoint format
# ---------------------------------------------------------------------------


async def test_fingerprint_custom_format_sends_rendered_template(httpx_mock) -> None:
    template = '{"message": "{prompt}", "student": "hacker01"}'
    _add_n_responses(httpx_mock, _OPENAI_URL, {"response": "hi"})

    await fingerprint(
        _OPENAI_URL,
        _API_KEY,
        endpoint_format="custom",
        request_template=template,
        response_path="response",
    )

    sent = httpx_mock.get_requests()[0]
    import json as _json

    assert _json.loads(sent.content) == {
        "message": "Reply with exactly one word: hello.",
        "student": "hacker01",
    }


async def test_fingerprint_custom_format_profile_carries_settings(httpx_mock) -> None:
    template = '{"message": "{prompt}", "student": "hacker01"}'
    _add_n_responses(httpx_mock, _OPENAI_URL, {"response": "hi"})

    profile = await fingerprint(
        _OPENAI_URL,
        _API_KEY,
        endpoint_format="custom",
        request_template=template,
        response_path="response",
    )

    assert profile.endpoint_format == "custom"
    assert profile.request_template == template
    assert profile.response_path == "response"
