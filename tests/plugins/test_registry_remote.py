import hashlib
import json
from pathlib import Path

import pytest

from llmscan_engine.plugins.registry_remote import (
    Manifest,
    ManifestEntry,
    load_local_manifest,
    sync_registry,
)

_PLUGIN_SOURCE = b"# a community plugin\n"
_PLUGIN_SHA256 = hashlib.sha256(_PLUGIN_SOURCE).hexdigest()
_MANIFEST_URL = "https://example.invalid/registry/index.json"
_PLUGIN_URL = "https://example.invalid/registry/community_plugin.py"


def _manifest_json(sha256: str = _PLUGIN_SHA256) -> dict:
    return {
        "manifest_version": 1,
        "plugins": [
            {
                "id": "community_plugin",
                "filename": "community_plugin.py",
                "version": "1.0.0",
                "sha256": sha256,
                "url": _PLUGIN_URL,
                "description": "example",
            }
        ],
    }


# ---------------------------------------------------------------------------
# load_local_manifest
# ---------------------------------------------------------------------------


def test_load_local_manifest_missing_file_returns_empty(tmp_path: Path) -> None:
    manifest = load_local_manifest(tmp_path / "no_such_index.json")
    assert manifest.plugins == []


def test_load_local_manifest_bad_json_returns_empty(tmp_path: Path) -> None:
    bad = tmp_path / "index.json"
    bad.write_text("{not valid json")
    manifest = load_local_manifest(bad)
    assert manifest.plugins == []


def test_load_local_manifest_parses_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_text(json.dumps(_manifest_json()))
    manifest = load_local_manifest(path)
    assert manifest.plugins[0].id == "community_plugin"


# ---------------------------------------------------------------------------
# sync_registry — offline (no manifest_url)
# ---------------------------------------------------------------------------


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
async def test_sync_registry_offline_makes_no_network_calls(
    tmp_path: Path, httpx_mock
) -> None:
    """With no manifest_url, only the local cache is read — no requests allowed."""
    httpx_mock.add_response(url=_MANIFEST_URL, json=_manifest_json())
    result = await sync_registry(
        manifest_url=None,
        dest_dir=tmp_path,
        manifest_path=tmp_path / "index.json",
    )
    assert result.downloaded == []
    assert result.errors == []
    assert len(httpx_mock.get_requests()) == 0


# ---------------------------------------------------------------------------
# sync_registry — remote manifest
# ---------------------------------------------------------------------------


async def test_sync_registry_downloads_and_verifies_new_plugin(
    tmp_path: Path, httpx_mock
) -> None:
    httpx_mock.add_response(url=_MANIFEST_URL, json=_manifest_json())
    httpx_mock.add_response(url=_PLUGIN_URL, content=_PLUGIN_SOURCE)

    dest_dir = tmp_path / "plugins"
    manifest_path = tmp_path / "index.json"
    result = await sync_registry(
        manifest_url=_MANIFEST_URL, dest_dir=dest_dir, manifest_path=manifest_path
    )

    assert result.downloaded == ["community_plugin"]
    assert result.errors == []
    assert (dest_dir / "community_plugin.py").read_bytes() == _PLUGIN_SOURCE
    assert manifest_path.exists()


async def test_sync_registry_rejects_sha256_mismatch(
    tmp_path: Path, httpx_mock
) -> None:
    httpx_mock.add_response(
        url=_MANIFEST_URL, json=_manifest_json(sha256="0" * 64)
    )
    httpx_mock.add_response(url=_PLUGIN_URL, content=_PLUGIN_SOURCE)

    dest_dir = tmp_path / "plugins"
    result = await sync_registry(
        manifest_url=_MANIFEST_URL,
        dest_dir=dest_dir,
        manifest_path=tmp_path / "index.json",
    )

    assert result.downloaded == []
    assert any("sha256 mismatch" in e for e in result.errors)
    assert not (dest_dir / "community_plugin.py").exists()


async def test_sync_registry_skips_already_installed_matching_version(
    tmp_path: Path, httpx_mock
) -> None:
    dest_dir = tmp_path / "plugins"
    dest_dir.mkdir()
    (dest_dir / "community_plugin.py").write_bytes(_PLUGIN_SOURCE)
    manifest_path = tmp_path / "index.json"
    manifest_path.write_text(json.dumps(_manifest_json()))

    httpx_mock.add_response(url=_MANIFEST_URL, json=_manifest_json())

    result = await sync_registry(
        manifest_url=_MANIFEST_URL, dest_dir=dest_dir, manifest_path=manifest_path
    )

    assert result.downloaded == []
    assert result.skipped == ["community_plugin"]
    # No GET to the plugin's own URL should have been made.
    requested_urls = {str(r.url) for r in httpx_mock.get_requests()}
    assert _PLUGIN_URL not in requested_urls


async def test_sync_registry_unreachable_manifest_falls_back_gracefully(
    tmp_path: Path, httpx_mock
) -> None:
    httpx_mock.add_response(url=_MANIFEST_URL, status_code=503)

    result = await sync_registry(
        manifest_url=_MANIFEST_URL,
        dest_dir=tmp_path / "plugins",
        manifest_path=tmp_path / "index.json",
    )

    assert result.downloaded == []
    assert any("Could not fetch manifest" in e for e in result.errors)


async def test_sync_registry_malformed_manifest_json(
    tmp_path: Path, httpx_mock
) -> None:
    httpx_mock.add_response(
        url=_MANIFEST_URL,
        content=b"not json at all",
        headers={"content-type": "application/json"},
    )

    result = await sync_registry(
        manifest_url=_MANIFEST_URL,
        dest_dir=tmp_path / "plugins",
        manifest_path=tmp_path / "index.json",
    )

    assert result.downloaded == []
    assert any("Malformed manifest" in e for e in result.errors)


async def test_sync_registry_download_failure_recorded_not_raised(
    tmp_path: Path, httpx_mock
) -> None:
    httpx_mock.add_response(url=_MANIFEST_URL, json=_manifest_json())
    httpx_mock.add_response(url=_PLUGIN_URL, status_code=404)

    result = await sync_registry(
        manifest_url=_MANIFEST_URL,
        dest_dir=tmp_path / "plugins",
        manifest_path=tmp_path / "index.json",
    )

    assert result.downloaded == []
    assert any("download failed" in e for e in result.errors)


def test_manifest_entry_and_manifest_roundtrip() -> None:
    manifest = Manifest(
        plugins=[
            ManifestEntry(
                id="x",
                filename="x.py",
                version="1.0.0",
                sha256="a" * 64,
                url="https://example.invalid/x.py",
            )
        ]
    )
    dumped = json.loads(manifest.model_dump_json())
    restored = Manifest.model_validate(dumped)
    assert restored.plugins[0].id == "x"
