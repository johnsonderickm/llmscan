import uuid

import pytest

from llmscan_engine.core.risk import (
    MEDIUM_CAP,
    category_scores,
    category_success_rates,
    effective_risk,
    overall_risk,
)
from llmscan_engine.db.models import FailureMode, Finding, PluginRun, PluginRunStatus

_SCAN = uuid.uuid4()


def _finding(
    owasp_id: str,
    score: float,
    confidence: float | None = 0.95,
    simulated: bool = False,
) -> Finding:
    return Finding(
        scan_id=_SCAN,
        plugin_id="p",
        owasp_id=owasp_id,
        failure_mode=FailureMode.COMPLIED,
        score=score,
        payload_hash="h",
        response_hash="h",
        confidence=confidence,
        simulated=simulated,
    )


def _run(owasp_id: str, sent: int, errors: int, findings: int) -> PluginRun:
    return PluginRun(
        scan_id=_SCAN,
        plugin_id="p",
        owasp_id=owasp_id,
        status=PluginRunStatus.TESTED,
        payloads_sent=sent,
        errors=errors,
        findings=findings,
    )


@pytest.mark.parametrize(
    ("score", "confidence", "simulated", "expected"),
    [
        (10.0, 0.95, False, 10.0),
        (10.0, 0.70, False, 10.0),  # threshold is inclusive
        (10.0, 0.69, False, MEDIUM_CAP),
        (10.0, 0.95, True, MEDIUM_CAP),
        (5.0, 0.50, False, 5.0),  # already below the cap
        (10.0, None, False, 10.0),  # pre-Phase-B rows: full confidence
    ],
)
def test_effective_risk(score, confidence, simulated, expected) -> None:
    assert effective_risk(score, confidence, simulated) == pytest.approx(expected)


def test_category_scores_take_max_effective_risk_per_category() -> None:
    findings = [
        _finding("LLM01", 10.0, simulated=True),
        _finding("LLM01", 7.0),
        _finding("LLM07", 10.0, confidence=0.6),
    ]
    assert category_scores(findings) == {
        "LLM01": pytest.approx(7.0),
        "LLM07": pytest.approx(MEDIUM_CAP),
    }


def test_overall_risk_is_max_category_score() -> None:
    findings = [_finding("LLM01", 4.0), _finding("LLM07", 9.0)]
    assert overall_risk(findings) == pytest.approx(9.0)


def test_overall_risk_empty_is_zero() -> None:
    assert overall_risk([]) == 0.0


def test_single_low_confidence_hit_cannot_make_scan_critical() -> None:
    """The old max(score) made one false positive a 10/10 scan."""
    assert overall_risk([_finding("LLM02", 10.0, confidence=0.5)]) < 7.0


def test_category_success_rates_exclude_errors() -> None:
    rates = category_success_rates(
        [_run("LLM01", 20, 0, 2), _run("LLM01", 10, 5, 1), _run("LLM07", 4, 4, 0)]
    )
    assert rates["LLM01"].payloads_answered == 25
    assert rates["LLM01"].findings == 3
    assert rates["LLM01"].rate == pytest.approx(3 / 25)
    assert rates["LLM07"].payloads_answered == 0
    assert rates["LLM07"].rate == 0.0
