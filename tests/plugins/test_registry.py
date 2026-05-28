import pytest

from llmscan_engine.plugins.registry import (
    all_plugins,
    clear_registry,
    get_plugin,
    init_registry,
    register_plugin,
)
from llmscan_engine.plugins.builtin.llm01_direct import LLM01DirectInjection


@pytest.fixture(autouse=True)
def clean_registry():
    """Ensure the registry is empty before and after each test."""
    clear_registry()
    yield
    clear_registry()


def test_init_registry_loads_builtin_plugins() -> None:
    init_registry()
    plugins = all_plugins()
    assert "llm01_direct" in plugins


def test_get_plugin_returns_correct_instance() -> None:
    init_registry()
    plugin = get_plugin("llm01_direct")
    assert plugin.metadata().id == "llm01_direct"


def test_get_plugin_raises_for_unknown_id() -> None:
    init_registry()
    with pytest.raises(KeyError):
        get_plugin("nonexistent_plugin")


def test_register_plugin_manual() -> None:
    plugin = LLM01DirectInjection()
    register_plugin(plugin)
    assert get_plugin("llm01_direct") is plugin


def test_all_plugins_returns_snapshot() -> None:
    init_registry()
    snapshot = all_plugins()
    assert isinstance(snapshot, dict)
    assert len(snapshot) >= 1


def test_clear_registry_empties_registry() -> None:
    init_registry()
    assert len(all_plugins()) >= 1
    clear_registry()
    assert all_plugins() == {}


def test_init_registry_with_nonexistent_community_dir(tmp_path) -> None:
    """A missing community dir is silently ignored."""
    init_registry(community_dir=tmp_path / "no_such_dir")
    assert "llm01_direct" in all_plugins()


def test_init_registry_loads_community_plugin(tmp_path) -> None:
    """A valid plugin file placed in a community dir is loaded."""
    plugin_src = """\
from typing import AsyncIterator, Literal
from llmscan_engine.plugins.base import AttackPlugin
from llmscan_engine.plugins.schemas import ClassifierResult, Payload, PluginMetadata
from llmscan_engine.core.connector import TargetProfile
from llmscan_engine.db.models import FailureMode

class CommunityPlugin(AttackPlugin):
    def metadata(self):
        return PluginMetadata(id="community_test", name="Community Test",
                              version="0.1.0", owasp_id="LLM01", severity_weight=5.0)
    async def payload_generator(self, profile):
        yield Payload(plugin_id="community_test", owasp_id="LLM01",
                      template_id="tpl_000", content="test")
    def response_classifier(self, payload, response):
        return ClassifierResult(failure_mode=FailureMode.REFUSED,
                                score=10.0, confidence=1.0, evidence_snippet="")
    def remediation(self, audience):
        return "fix it"
"""
    (tmp_path / "community_plugin.py").write_text(plugin_src)
    init_registry(community_dir=tmp_path)
    assert "community_test" in all_plugins()
