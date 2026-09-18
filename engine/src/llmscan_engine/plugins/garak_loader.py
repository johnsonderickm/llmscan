"""
Garak probe bridge — loads prompts from Garak probe modules.

Garak is an optional local dependency; if it is not installed every
load_garak_probes() call returns [] and each plugin falls back to its
own YAML templates.
"""
from __future__ import annotations

import importlib
import logging
from contextvars import ContextVar
from pathlib import Path
from typing import Optional

import yaml

_log = logging.getLogger(__name__)

_garak_enabled: ContextVar[bool] = ContextVar("garak_enabled", default=True)


def set_garak_enabled(enabled: bool) -> None:
    """
    Enable or disable Garak probe merging for the current async context.

    Used by ``--no-garak`` / ``use_garak=False`` to force every plugin's
    ``load_garak_probes()`` call to return [] regardless of whether the
    Garak package is installed. Scoped via ContextVar so concurrent scans
    (each its own asyncio task) don't stomp on each other's setting.
    """
    _garak_enabled.set(enabled)


def load_garak_probes(
    module_path: str, probe_class: Optional[str] = None
) -> list[str]:
    """
    Return all prompts from a Garak probe module.

    Iterates over every class in *module_path* that carries a ``prompts``
    attribute (list[str]).  If *probe_class* is given, only that class is
    inspected.

    Returns [] when Garak is not installed, disabled via
    ``set_garak_enabled(False)``, or the module cannot be loaded.
    """
    if not _garak_enabled.get():
        return []
    try:
        module = importlib.import_module(module_path)
    except ImportError:
        _log.debug("Garak not installed — skipping %s", module_path)
        return []
    except Exception as exc:
        _log.warning("Failed to import Garak module %s: %s", module_path, exc)
        return []

    prompts: list[str] = []
    for name, obj in vars(module).items():
        if not isinstance(obj, type):
            continue
        if probe_class and name != probe_class:
            continue
        raw = getattr(obj, "prompts", None)
        if isinstance(raw, list):
            prompts.extend(str(p) for p in raw if p)
    return prompts


def load_yaml_templates(yaml_path: Path) -> list[str]:
    """
    Load template strings from a YAML file.

    Expected format::

        templates:
          - "first template {goal}"
          - "second template"

    Returns [] on any error so callers never need to handle exceptions.
    """
    try:
        with yaml_path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return [str(t) for t in (data or {}).get("templates", [])]
    except Exception as exc:
        _log.warning(
            "Could not load YAML templates from %s: %s", yaml_path, exc
        )
        return []
