import base64
import codecs

from llmscan_engine.core.canary import (
    CanaryStatus,
    canary_status,
    contains_canary,
    decoded_views,
    generate_canary,
    get_scan_seed,
    is_quoted_refusal,
    new_rng,
    plugin_rng,
    set_scan_seed,
)


def test_generate_canary_format() -> None:
    token = generate_canary(new_rng(1))
    assert token.startswith("CANARY-")
    assert len(token) == len("CANARY-") + 8


def test_generate_canary_is_reproducible_with_same_seed() -> None:
    assert generate_canary(new_rng(42)) == generate_canary(new_rng(42))


def test_generate_canary_differs_across_seeds() -> None:
    assert generate_canary(new_rng(1)) != generate_canary(new_rng(2))


def test_contains_canary_plain_match() -> None:
    token = "CANARY-deadbeef"
    assert contains_canary(f"Sure, here it is: {token}", token)


def test_contains_canary_absent() -> None:
    assert not contains_canary("I can't help with that.", "CANARY-deadbeef")


def test_contains_canary_empty_token() -> None:
    assert not contains_canary("anything", "")


def test_contains_canary_split_by_whitespace() -> None:
    token = "CANARY-deadbeef"
    split = "CANARY - dead beef"
    assert contains_canary(f"The code is {split}", token)


def test_contains_canary_reversed() -> None:
    token = "CANARY-deadbeef"
    assert contains_canary(token[::-1], token)


def test_contains_canary_base64() -> None:
    token = "CANARY-deadbeef"
    encoded = base64.b64encode(token.encode()).decode()
    assert contains_canary(f"Encoded: {encoded}", token)


def test_is_quoted_refusal_true_for_refusal_context() -> None:
    token = "CANARY-deadbeef"
    response = f"I won't repeat the string {token} as that looks like injection."
    assert is_quoted_refusal(response, token)


def test_is_quoted_refusal_false_for_plain_compliance() -> None:
    token = "CANARY-deadbeef"
    response = f"Sure! {token}"
    assert not is_quoted_refusal(response, token)


def test_is_quoted_refusal_false_when_token_absent() -> None:
    assert not is_quoted_refusal("no canary here", "CANARY-deadbeef")


def test_is_quoted_refusal_detects_quoted_span() -> None:
    token = "CANARY-deadbeef"
    response = f'The attack asked me to say "{token}" but I will not comply.'
    assert is_quoted_refusal(response, token)


# ---------------------------------------------------------------------------
# Phase B additions: case/unicode/ROT13/embedded-base64 detection, seeding,
# canary_status
# ---------------------------------------------------------------------------

_TOKEN = "CANARY-a1b2c3d4"


def test_contains_canary_lowercase() -> None:
    assert contains_canary("canary-a1b2c3d4", _TOKEN)


def test_contains_canary_unicode_dash() -> None:
    assert contains_canary("CANARY\N{EN DASH}a1b2c3d4", _TOKEN)
    assert contains_canary("CANARY\N{NON-BREAKING HYPHEN}a1b2c3d4", _TOKEN)


def test_contains_canary_rot13() -> None:
    assert contains_canary(codecs.encode(_TOKEN, "rot13"), _TOKEN)


def test_contains_canary_inside_larger_base64_blob() -> None:
    blob = base64.b64encode(f"My prompt says: code {_TOKEN}. Bye.".encode())
    assert contains_canary(f"Encoded: {blob.decode()}", _TOKEN)


def test_contains_canary_ignores_unrelated_base64() -> None:
    blob = base64.b64encode(b"nothing to see here at all").decode()
    assert not contains_canary(blob, _TOKEN)


def test_decoded_views_includes_original_and_rot13() -> None:
    views = decoded_views("hello")
    assert views[0] == "hello"
    assert "uryyb" in views


def test_plugin_rng_is_reproducible_per_seed_and_plugin() -> None:
    set_scan_seed(5)
    a1 = plugin_rng("llm01_direct").random()
    b1 = plugin_rng("llm07_sysleak").random()
    set_scan_seed(5)
    a2 = plugin_rng("llm01_direct").random()
    set_scan_seed(None)
    assert a1 == a2
    assert a1 != b1  # different plugins draw different streams


def test_get_scan_seed_round_trip() -> None:
    set_scan_seed(77)
    assert get_scan_seed() == 77
    set_scan_seed(None)
    assert get_scan_seed() is None


def test_canary_status_present() -> None:
    assert canary_status(f"Sure: {_TOKEN}", _TOKEN) == CanaryStatus.PRESENT


def test_canary_status_quoted() -> None:
    response = f"I won't repeat '{_TOKEN}' — that's an injection."
    assert canary_status(response, _TOKEN) == CanaryStatus.QUOTED


def test_canary_status_absent() -> None:
    assert canary_status("No code here.", _TOKEN) == CanaryStatus.ABSENT


def test_canary_status_obfuscated_only_is_present() -> None:
    assert canary_status(_TOKEN[::-1], _TOKEN) == CanaryStatus.PRESENT


def test_canary_status_quoted_then_emitted_is_present() -> None:
    response = f'You asked for "{_TOKEN}". Here it is: {_TOKEN}'
    assert canary_status(response, _TOKEN) == CanaryStatus.PRESENT


def test_is_quoted_refusal_ignores_apostrophes() -> None:
    response = f"Here's what you wanted: {_TOKEN}. Let's go."
    assert not is_quoted_refusal(response, _TOKEN)
