"""Plugin system for loading custom secret patterns from external Python modules."""

import importlib.util
import os
from pathlib import Path
from typing import List

from hexpose.patterns import SecretPattern


PLUGIN_ENTRY_POINT = "get_patterns"


class PluginError(Exception):
    """Raised when a plugin fails to load or is malformed."""


def load_plugin(path: str) -> List[SecretPattern]:
    """Load a single plugin file and return its patterns.

    The plugin module must expose a callable ``get_patterns() -> list[SecretPattern]``.

    Args:
        path: Filesystem path to the plugin ``.py`` file.

    Returns:
        List of SecretPattern instances provided by the plugin.

    Raises:
        PluginError: If the file does not exist, cannot be imported, or does
            not expose the required entry point.
    """
    plugin_path = Path(path)
    if not plugin_path.is_file():
        raise PluginError(f"Plugin file not found: {path}")

    module_name = plugin_path.stem
    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    if spec is None or spec.loader is None:
        raise PluginError(f"Cannot create module spec for plugin: {path}")

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception as exc:
        raise PluginError(f"Error executing plugin {path}: {exc}") from exc

    if not hasattr(module, PLUGIN_ENTRY_POINT):
        raise PluginError(
            f"Plugin {path!r} must define a '{PLUGIN_ENTRY_POINT}()' function."
        )

    try:
        patterns = module.get_patterns()
    except Exception as exc:
        raise PluginError(f"Plugin {path!r} raised an error in get_patterns(): {exc}") from exc

    if not isinstance(patterns, list):
        raise PluginError(
            f"Plugin {path!r} get_patterns() must return a list, got {type(patterns).__name__}."
        )

    return patterns


def load_plugins(paths: List[str]) -> List[SecretPattern]:
    """Load multiple plugin files and aggregate their patterns.

    Args:
        paths: List of filesystem paths to plugin files.

    Returns:
        Combined list of SecretPattern instances from all plugins.
    """
    all_patterns: List[SecretPattern] = []
    for path in paths:
        all_patterns.extend(load_plugin(path))
    return all_patterns
