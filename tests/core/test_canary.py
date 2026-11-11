import base64

from llmscan_engine.core.canary import (
    contains_canary,
    generate_canary,
    is_quoted_refusal,
    new_rng,
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
