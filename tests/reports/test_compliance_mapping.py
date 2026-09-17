from llmscan_engine.reports.compliance_mapping import (
    COMPLIANCE_MAPPING,
    compliance_refs,
)


def test_all_ten_owasp_categories_present() -> None:
    expected = {f"LLM{i:02d}" for i in range(1, 11)}
    assert set(COMPLIANCE_MAPPING.keys()) == expected


def test_each_entry_has_three_frameworks() -> None:
    for refs in COMPLIANCE_MAPPING.values():
        assert set(refs.keys()) == {"soc2", "iso27001", "eu_ai_act"}
        assert all(isinstance(v, str) and v for v in refs.values())


def test_compliance_refs_known_category() -> None:
    refs = compliance_refs("LLM01")
    assert "CC6.1" in refs["soc2"]


def test_compliance_refs_unknown_category_returns_placeholder() -> None:
    refs = compliance_refs("LLM99")
    assert refs == {"soc2": "—", "iso27001": "—", "eu_ai_act": "—"}
