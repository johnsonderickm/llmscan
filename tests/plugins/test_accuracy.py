"""
Layer 1 accuracy against hand-labelled target responses.

Each ``tests/fixtures/labelled_responses/<plugin_id>.yaml`` holds realistic
responses with the verdict a human reviewer would give. This runs the
plugin's own classifier (Layer 1 only — no embeddings, Garak or judge) over
every case and checks precision and recall on the *finding* class: verdicts
that the orchestrator records as a finding (COMPLIED, PII_LEAKED, PARTIAL)
versus those it doesn't (REFUSED, INCONCLUSIVE).

Run with ``-s`` to see each plugin's confusion matrix and misclassified
cases. Never delete a case or loosen a threshold to make this pass — a
failure here means the classifier is wrong on realistic input.
"""
import base64
import codecs
from collections import Counter
from pathlib import Path

import pytest
import yaml

from llmscan_engine.db.models import FailureMode
from llmscan_engine.plugins.base import AttackPlugin
from llmscan_engine.plugins.builtin.llm01_direct import LLM01DirectInjection
from llmscan_engine.plugins.builtin.llm01_indirect import LLM01IndirectInjection
from llmscan_engine.plugins.builtin.llm01_multimodal import LLM01MultimodalInjection
from llmscan_engine.plugins.builtin.llm07_sysleak import LLM07SystemPromptLeak
from llmscan_engine.plugins.schemas import Payload

CORPUS_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "labelled_responses"

MIN_CASES = 20
MIN_PRECISION = 0.9
MIN_RECALL = 0.8

_FINDING_MODES = {FailureMode.COMPLIED, FailureMode.PII_LEAKED, FailureMode.PARTIAL}

_PLUGINS: dict[str, type[AttackPlugin]] = {
    "llm01_direct": LLM01DirectInjection,
    "llm01_indirect": LLM01IndirectInjection,
    "llm01_multimodal": LLM01MultimodalInjection,
    "llm07_sysleak": LLM07SystemPromptLeak,
}

_CANARY = "CANARY-7e57c0de"


def _canary_variants(canary: str) -> dict[str, str]:
    """Placeholder -> obfuscated form of *canary*."""
    return {
        "{canary_lower}": canary.lower(),
        "{canary_spaced}": " ".join(canary),
        "{canary_endash}": canary.replace("-", "\N{EN DASH}"),
        "{canary_b64}": base64.b64encode(canary.encode()).decode(),
        "{canary_rev}": canary[::-1],
        "{canary_rot13}": codecs.encode(canary, "rot13"),
        "{canary}": canary,
    }


def _fill(text: str, system_prompt: str | None) -> str:
    """Substitute every placeholder in *text*."""
    if system_prompt is not None:
        text = text.replace("{system_prompt_b64}", base64.b64encode(
            system_prompt.encode()
        ).decode())
        text = text.replace(
            "{system_prompt_rot13}", codecs.encode(system_prompt, "rot13")
        )
        text = text.replace("{system_prompt}", system_prompt)
    for placeholder, value in _canary_variants(_CANARY).items():
        text = text.replace(placeholder, value)
    return text


def _load(plugin_id: str) -> dict:
    with (CORPUS_DIR / f"{plugin_id}.yaml").open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _evaluate(plugin_id: str) -> list[tuple[str, FailureMode, FailureMode]]:
    """Return ``(case_id, expected, predicted)`` for every corpus case."""
    corpus = _load(plugin_id)
    plugin = _PLUGINS[plugin_id]()
    system_prompt = (
        _fill(corpus["system_prompt"], None) if corpus.get("system_prompt") else None
    )
    payload = Payload(
        plugin_id=plugin_id,
        owasp_id=plugin.metadata().owasp_id,
        template_id="corpus",
        content=_fill(corpus["payload"], system_prompt),
        canary=_CANARY,
        system_prompt=system_prompt,
    )
    results = []
    for case in corpus["cases"]:
        response = _fill(case["response"], system_prompt)
        predicted = plugin.response_classifier(payload, response).failure_mode
        results.append((case["id"], FailureMode(case["expected"]), predicted))
    return results


def _report(plugin_id: str, results) -> tuple[float, float]:
    """Print the confusion matrix; return (precision, recall) on findings."""
    tp = sum(1 for _, e, p in results if e in _FINDING_MODES and p in _FINDING_MODES)
    fp = sum(
        1 for _, e, p in results if e not in _FINDING_MODES and p in _FINDING_MODES
    )
    fn = sum(
        1 for _, e, p in results if e in _FINDING_MODES and p not in _FINDING_MODES
    )
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0

    matrix = Counter((e.value, p.value) for _, e, p in results)
    print(f"\n{plugin_id}: {len(results)} cases, precision={precision:.2f}, "
          f"recall={recall:.2f}")
    for (expected, predicted), n in sorted(matrix.items()):
        print(f"  expected {expected:<12} predicted {predicted:<12} x{n}")
    for case_id, expected, predicted in results:
        if expected != predicted:
            print(f"  MISS {case_id}: expected {expected.value}, "
                  f"got {predicted.value}")
    return precision, recall


@pytest.mark.parametrize("plugin_id", sorted(_PLUGINS))
def test_corpus_has_enough_cases_of_each_kind(plugin_id: str) -> None:
    cases = _load(plugin_id)["cases"]
    assert len(cases) >= MIN_CASES
    expected = {FailureMode(c["expected"]) for c in cases}
    assert expected & _FINDING_MODES, "corpus needs positive cases"
    assert FailureMode.REFUSED in expected, "corpus needs negative cases"
    assert len({c["id"] for c in cases}) == len(cases), "case ids must be unique"


@pytest.mark.parametrize("plugin_id", sorted(_PLUGINS))
def test_layer1_precision_and_recall(plugin_id: str) -> None:
    precision, recall = _report(plugin_id, _evaluate(plugin_id))
    assert precision >= MIN_PRECISION, f"{plugin_id} precision {precision:.2f}"
    assert recall >= MIN_RECALL, f"{plugin_id} recall {recall:.2f}"
