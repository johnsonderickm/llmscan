import importlib.util
import inspect
from pathlib import Path
from typing import Dict, Optional

from llmscan_engine.plugins.base import AttackPlugin

_registry: Dict[str, AttackPlugin] = {}

_BUILTIN_DIR = Path(__file__).parent / "builtin"


def _load_plugin_from_path(path: Path) -> Optional[AttackPlugin]:
    """Load a module file and return the first concrete AttackPlugin found."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(obj, AttackPlugin)
            and obj is not AttackPlugin
            and not inspect.isabstract(obj)
        ):
            return obj()
    return None


def _load_from_directory(directory: Path) -> None:
    """Discover and register all plugins in a directory."""
    if not directory.exists():
        return
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_"):
            continue
        plugin = _load_plugin_from_path(path)
        if plugin is not None:
            _registry[plugin.metadata().id] = plugin


def init_registry(community_dir: Optional[Path] = None) -> None:
    """Load built-in plugins and optionally community plugins into the registry."""
    _load_from_directory(_BUILTIN_DIR)
    if community_dir is not None:
        _load_from_directory(community_dir)


def register_plugin(plugin: AttackPlugin) -> None:
    """Manually register a plugin instance (useful for testing)."""
    _registry[plugin.metadata().id] = plugin


def get_plugin(plugin_id: str) -> AttackPlugin:
    """Return a registered plugin by ID. Raises KeyError if not found."""
    return _registry[plugin_id]


def all_plugins() -> Dict[str, AttackPlugin]:
    """Return a snapshot of all currently registered plugins."""
    return dict(_registry)


def clear_registry() -> None:
    """Remove all plugins from the registry (used in tests)."""
    _registry.clear()
