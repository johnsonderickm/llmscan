from typing import List, Optional

from fastapi import APIRouter

from llmscan_engine.api.schemas import PluginRead
from llmscan_engine.plugins.registry import all_plugins, init_registry
from llmscan_engine.plugins.registry_remote import sync_registry

router = APIRouter(tags=["plugins"])


@router.get("/plugins", response_model=List[PluginRead])
async def list_plugins() -> List[PluginRead]:
    """List all registered attack plugins with their metadata."""
    return [
        PluginRead(
            id=meta.id,
            name=meta.name,
            version=meta.version,
            owasp_id=meta.owasp_id,
            mitre_atlas_id=meta.mitre_atlas_id,
            severity_weight=meta.severity_weight,
            tags=meta.tags,
        )
        for plugin in all_plugins().values()
        for meta in [plugin.metadata()]
    ]


@router.post("/plugins/update")
async def update_plugins(registry_url: Optional[str] = None) -> dict:
    """Sync community plugins from a registry manifest, then reload the registry.

    `registry_url` is optional; omitting it only reloads built-in plugins
    plus whatever is already staged in `plugins/`, with zero network calls.
    """
    result = await sync_registry(manifest_url=registry_url)
    init_registry()
    count = len(all_plugins())
    return {
        "message": f"Registry reloaded. {count} plugin(s) loaded.",
        "count": count,
        "downloaded": result.downloaded,
        "skipped": result.skipped,
        "errors": result.errors,
    }
