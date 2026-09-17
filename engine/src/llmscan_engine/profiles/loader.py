from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

_PROFILES_DIR = Path(__file__).parent


@dataclass
class ProfileConfig:
    """Configuration for a named scan profile."""

    name: str
    plugin_ids: Optional[List[str]]
    max_payloads_per_plugin: Optional[int]
    use_garak: bool


def load_profile(name: str) -> ProfileConfig:
    """Load a scan profile by name from its YAML file."""
    yaml_path = _PROFILES_DIR / f"{name}.yaml"
    if not yaml_path.exists():
        available = [p.stem for p in _PROFILES_DIR.glob("*.yaml")]
        raise ValueError(
            f"Unknown profile: {name!r}. Available: {available}"
        )
    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    return ProfileConfig(
        name=data["name"],
        plugin_ids=data.get("plugin_ids"),
        max_payloads_per_plugin=data.get("max_payloads_per_plugin"),
        use_garak=data.get("use_garak", True),
    )
