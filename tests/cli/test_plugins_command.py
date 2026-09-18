import json

from typer.testing import CliRunner

from llmscan_engine.cli.main import app
from llmscan_engine.plugins.registry import all_plugins, clear_registry

runner = CliRunner()


def setup_function() -> None:
    clear_registry()


def teardown_function() -> None:
    clear_registry()


def test_plugins_list_table() -> None:
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert "LLM01" in result.stdout


def test_plugins_list_json() -> None:
    result = runner.invoke(app, ["plugins", "list", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data) == 12
    assert all("owasp_id" in p for p in data)


def test_plugins_update_reloads_registry() -> None:
    result = runner.invoke(app, ["plugins", "update"])
    assert result.exit_code == 0
    assert "12 plugin(s) loaded" in result.stdout
    assert len(all_plugins()) == 12
