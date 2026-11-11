from llmscan_engine.core.taxonomy import TAXONOMY
from llmscan_engine.reports.compliance_mapping import compliance_refs


def test_all_ten_owasp_categories_present() -> None:
    expected = {f"LLM{i:02d}" for i in range(1, 11)}
    assert set(TAXONOMY.keys()) == expected


def test_each_entry_has_three_frameworks() -> None:
    for entry in TAXONOMY.values():
        refs = entry.compliance
        assert refs.soc2 and refs.iso27001 and refs.eu_ai_act


def test_compliance_refs_known_category() -> None:
    refs = compliance_refs("LLM01")
    assert "CC6.1" in refs.soc2


def test_compliance_refs_unknown_category_returns_placeholder() -> None:
    refs = compliance_refs("LLM99")
    assert refs.soc2 == refs.iso27001 == refs.eu_ai_act == "—"
