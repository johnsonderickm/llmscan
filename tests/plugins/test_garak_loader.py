import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from llmscan_engine.plugins.garak_loader import load_garak_probes, load_yaml_templates

_YAML_DIR = (
    Path(__file__).parent.parent.parent
    / "engine"
    / "src"
    / "llmscan_engine"
    / "plugins"
    / "templates"
)


# ---------------------------------------------------------------------------
# load_garak_probes — Garak not installed
# ---------------------------------------------------------------------------


def test_returns_empty_list_when_garak_missing() -> None:
    with patch.dict(sys.modules, {"garak.probes.prompt_injection": None}):
        result = load_garak_probes("garak.probes.prompt_injection")
    assert result == []


def test_returns_empty_list_on_import_error() -> None:
    with patch("importlib.import_module", side_effect=ImportError("no garak")):
        result = load_garak_probes("garak.probes.prompt_injection")
    assert result == []


def test_returns_empty_list_on_unexpected_error() -> None:
    with patch("importlib.import_module", side_effect=RuntimeError("boom")):
        result = load_garak_probes("garak.probes.prompt_injection")
    assert result == []


# ---------------------------------------------------------------------------
# load_garak_probes — Garak installed (mocked)
# ---------------------------------------------------------------------------


def _make_module(*probe_classes) -> types.ModuleType:
    """Create a real module object containing the given classes."""
    mod = types.ModuleType("garak.probes.fake")
    for cls in probe_classes:
        setattr(mod, cls.__name__, cls)
    return mod


def test_collects_prompts_from_probe_class() -> None:
    class FakeProbe:
        prompts = ["ignore instructions", "pwned"]

    with patch("importlib.import_module", return_value=_make_module(FakeProbe)):
        result = load_garak_probes("garak.probes.fake")

    assert "ignore instructions" in result
    assert "pwned" in result


def test_filters_by_probe_class_name() -> None:
    class ProbeA:
        prompts = ["prompt_a"]

    class ProbeB:
        prompts = ["prompt_b"]

    with patch(
        "importlib.import_module", return_value=_make_module(ProbeA, ProbeB)
    ):
        result = load_garak_probes("garak.probes.fake", probe_class="ProbeA")

    assert "prompt_a" in result
    assert "prompt_b" not in result


def test_skips_classes_without_prompts_attribute() -> None:
    class NoPrompts:
        pass

    with patch("importlib.import_module", return_value=_make_module(NoPrompts)):
        result = load_garak_probes("garak.probes.fake")

    assert result == []


def test_skips_non_type_module_members() -> None:
    mod = types.ModuleType("garak.probes.fake")
    mod.some_string = "not a class"  # type: ignore[attr-defined]
    mod.some_int = 42  # type: ignore[attr-defined]

    with patch("importlib.import_module", return_value=mod):
        result = load_garak_probes("garak.probes.fake")

    assert result == []


# ---------------------------------------------------------------------------
# load_yaml_templates
# ---------------------------------------------------------------------------


def test_loads_llm01_direct_yaml() -> None:
    result = load_yaml_templates(_YAML_DIR / "llm01_direct.yaml")
    assert len(result) >= 15
    assert all(isinstance(t, str) for t in result)


def test_loads_llm01_indirect_yaml() -> None:
    result = load_yaml_templates(_YAML_DIR / "llm01_indirect.yaml")
    assert len(result) >= 15


def test_loads_llm02_pii_yaml() -> None:
    result = load_yaml_templates(_YAML_DIR / "llm02_pii.yaml")
    assert len(result) >= 15


def test_loads_llm02_exfil_yaml() -> None:
    result = load_yaml_templates(_YAML_DIR / "llm02_exfil.yaml")
    assert len(result) >= 15


def test_returns_empty_list_for_missing_file() -> None:
    result = load_yaml_templates(Path("/nonexistent/path/file.yaml"))
    assert result == []


def test_returns_empty_list_for_invalid_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("{{{{invalid yaml{{{{")
    result = load_yaml_templates(bad)
    assert result == []


def test_returns_empty_list_when_templates_key_missing(tmp_path: Path) -> None:
    f = tmp_path / "no_key.yaml"
    f.write_text("other_key:\n  - value\n")
    result = load_yaml_templates(f)
    assert result == []
