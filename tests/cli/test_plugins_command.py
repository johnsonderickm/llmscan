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


def test_plugins_update_offline_by_default_makes_no_network_calls(httpx_mock) -> None:
    """No --registry-url means local-only sync: zero HTTP requests."""
    result = runner.invoke(app, ["plugins", "update"])
    assert result.exit_code == 0
    assert len(httpx_mock.get_requests()) == 0


def test_plugins_update_json_output_includes_sync_fields() -> None:
    result = runner.invoke(app, ["plugins", "update", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["downloaded"] == []
    assert data["errors"] == []
    assert data["plugin_count"] == 12


def test_plugins_update_reports_unreachable_registry(httpx_mock) -> None:
    httpx_mock.add_response(url="https://example.invalid/index.json", status_code=503)
    result = runner.invoke(
        app, ["plugins", "update", "--registry-url", "https://example.invalid/index.json"]
    )
    assert result.exit_code == 0
    assert "Could not fetch manifest" in result.stdout
