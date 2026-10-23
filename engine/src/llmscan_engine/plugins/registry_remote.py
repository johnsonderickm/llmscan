"""
Remote plugin registry sync.

LLMScan is offline-by-default: with no manifest URL configured, sync_registry()
only re-reads the local manifest cache (`plugins/index.json`) and makes zero
network calls. A remote registry is strictly opt-in via `manifest_url` (CLI
`--registry-url` / `LLMSCAN_PLUGIN_REGISTRY_URL`, or the API's `registry_url`
query param). Every downloaded plugin file's sha256 is checked against the
manifest before it is staged; a mismatch, unreachable URL, or malformed
manifest is recorded in the returned SyncResult.errors list instead of
raised, so a broken or hostile registry can never block a scan.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

import httpx
from pydantic import BaseModel, Field

from llmscan_engine.plugins.registry import COMMUNITY_PLUGINS_DIR

_log = logging.getLogger(__name__)

DEFAULT_MANIFEST_PATH = COMMUNITY_PLUGINS_DIR / "index.json"


class ManifestEntry(BaseModel):
    """One plugin entry in a registry manifest."""

    id: str
    filename: str
    version: str
    sha256: str
    url: str
    description: str = ""


class Manifest(BaseModel):
    """A registry manifest, as found in `plugins/index.json` or served remotely."""

    manifest_version: int = 1
    plugins: list[ManifestEntry] = Field(default_factory=list)


class SyncResult(BaseModel):
    """Outcome of a sync_registry() call."""

    downloaded: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_local_manifest(manifest_path: Path = DEFAULT_MANIFEST_PATH) -> Manifest:
    """Load the cached manifest from disk. Returns an empty manifest on any error."""
    try:
        with manifest_path.open(encoding="utf-8") as fh:
            return Manifest.model_validate(json.load(fh))
    except Exception as exc:
        _log.debug("No usable local manifest at %s: %s", manifest_path, exc)
        return Manifest()


def _save_local_manifest(manifest: Manifest, manifest_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")


async def sync_registry(
    manifest_url: Optional[str] = None,
    dest_dir: Path = COMMUNITY_PLUGINS_DIR,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
) -> SyncResult:
    """Sync community plugins from a registry manifest into `dest_dir`.

    With `manifest_url=None`, this only re-validates already-staged files
    against the local manifest cache and makes zero network calls. See the
    module docstring for the full degradation contract.
    """
    result = SyncResult()
    local_manifest = load_local_manifest(manifest_path)
    manifest = local_manifest
    installed = {entry.id: entry for entry in local_manifest.plugins}

    async with httpx.AsyncClient(timeout=10.0) as client:
        if manifest_url is not None:
            try:
                response = await client.get(manifest_url)
                response.raise_for_status()
                manifest = Manifest.model_validate(response.json())
            except httpx.HTTPError as exc:
                _log.warning(
                    "Could not reach plugin registry %s: %s", manifest_url, exc
                )
                result.errors.append(f"Could not fetch manifest: {exc}")
            except Exception as exc:
                _log.warning("Malformed manifest from %s: %s", manifest_url, exc)
                result.errors.append(f"Malformed manifest: {exc}")

        for entry in manifest.plugins:
            dest_path = dest_dir / entry.filename
            current = installed.get(entry.id)
            if (
                current is not None
                and current.version == entry.version
                and current.sha256 == entry.sha256
                and dest_path.exists()
            ):
                result.skipped.append(entry.id)
                continue

            try:
                response = await client.get(entry.url)
                response.raise_for_status()
                content = response.content
            except httpx.HTTPError as exc:
                _log.warning("Failed to download plugin %s: %s", entry.id, exc)
                result.errors.append(f"{entry.id}: download failed ({exc})")
                continue

            if _sha256(content) != entry.sha256.lower():
                _log.warning(
                    "sha256 mismatch for plugin %s — refusing to stage", entry.id
                )
                result.errors.append(f"{entry.id}: sha256 mismatch")
                continue

            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(content)
            result.downloaded.append(entry.id)

    _save_local_manifest(manifest, manifest_path)
    return result
