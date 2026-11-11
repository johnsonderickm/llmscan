from llmscan_engine.core.taxonomy import (
    ALL_OWASP_IDS,
    TAXONOMY,
    compliance_refs,
    get_taxonomy_entry,
)


def test_all_owasp_ids_are_llm01_through_llm10() -> None:
    assert ALL_OWASP_IDS == [f"LLM{i:02d}" for i in range(1, 11)]


def test_taxonomy_has_exactly_ten_entries() -> None:
    assert set(TAXONOMY.keys()) == set(ALL_OWASP_IDS)


def test_each_entry_id_matches_its_key() -> None:
    for owasp_id, entry in TAXONOMY.items():
        assert entry.id == owasp_id


def test_each_entry_has_name_and_description() -> None:
    for entry in TAXONOMY.values():
        assert entry.name
        assert entry.description
        assert entry.short_label


def test_get_taxonomy_entry_known() -> None:
    entry = get_taxonomy_entry("LLM01")
    assert entry is not None
    assert entry.name == "Prompt Injection"


def test_get_taxonomy_entry_unknown_returns_none() -> None:
    assert get_taxonomy_entry("LLM99") is None


def test_llm07_and_llm08_have_no_2023_equivalent() -> None:
    """LLM07 (System Prompt Leakage) and LLM08 (Vector/Embedding Weaknesses)
    are new in the 2025 list with no 1.1 (2023) predecessor."""
    assert TAXONOMY["LLM07"].v1_1_equivalent == []
    assert TAXONOMY["LLM08"].v1_1_equivalent == []


def test_llm09_misinformation_maps_from_2023_overreliance() -> None:
    assert TAXONOMY["LLM09"].v1_1_equivalent == ["LLM09"]


def test_llm10_unbounded_consumption_maps_from_2023_dos() -> None:
    assert TAXONOMY["LLM10"].v1_1_equivalent == ["LLM04"]


def test_compliance_refs_known_category() -> None:
    refs = compliance_refs("LLM02")
    assert refs == TAXONOMY["LLM02"].compliance


def test_compliance_refs_unknown_category_is_placeholder() -> None:
    refs = compliance_refs("not-a-real-id")
    assert refs.soc2 == refs.iso27001 == refs.eu_ai_act == "—"
