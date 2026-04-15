"""Tests for hexpose.plugin and hexpose.plugin_registry."""

import re
import textwrap
from pathlib import Path

import pytest

from hexpose.patterns import SecretPattern
from hexpose.plugin import load_plugin, load_plugins, PluginError
from hexpose.plugin_registry import PatternRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_plugin(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content))
    return p


VALID_PLUGIN = """\
    import re
    from hexpose.patterns import SecretPattern

    def get_patterns():
        return [
            SecretPattern(
                name="test_token",
                pattern=re.compile(rb"TEST-[A-Z0-9]{8}"),
                severity="medium",
                description="A test token.",
            )
        ]
"""


# ---------------------------------------------------------------------------
# load_plugin tests
# ---------------------------------------------------------------------------

def test_load_plugin_returns_patterns(tmp_path):
    plugin_file = _write_plugin(tmp_path, "myplugin.py", VALID_PLUGIN)
    patterns = load_plugin(str(plugin_file))
    assert isinstance(patterns, list)
    assert len(patterns) == 1
    assert patterns[0].name == "test_token"


def test_load_plugin_missing_file(tmp_path):
    with pytest.raises(PluginError, match="not found"):
        load_plugin(str(tmp_path / "nonexistent.py"))


def test_load_plugin_missing_entry_point(tmp_path):
    plugin_file = _write_plugin(tmp_path, "bad.py", "x = 1\n")
    with pytest.raises(PluginError, match="get_patterns"):
        load_plugin(str(plugin_file))


def test_load_plugin_entry_point_raises(tmp_path):
    plugin_file = _write_plugin(
        tmp_path,
        "err.py",
        "def get_patterns():\n    raise RuntimeError('boom')\n",
    )
    with pytest.raises(PluginError, match="boom"):
        load_plugin(str(plugin_file))


def test_load_plugin_returns_non_list(tmp_path):
    plugin_file = _write_plugin(
        tmp_path,
        "bad_return.py",
        "def get_patterns():\n    return 'oops'\n",
    )
    with pytest.raises(PluginError, match="must return a list"):
        load_plugin(str(plugin_file))


def test_load_plugins_aggregates(tmp_path):
    p1 = _write_plugin(tmp_path, "p1.py", VALID_PLUGIN)
    p2 = _write_plugin(tmp_path, "p2.py", VALID_PLUGIN)
    patterns = load_plugins([str(p1), str(p2)])
    assert len(patterns) == 2


# ---------------------------------------------------------------------------
# PatternRegistry tests
# ---------------------------------------------------------------------------

def test_registry_includes_builtin():
    registry = PatternRegistry()
    assert len(registry) > 0


def test_registry_no_builtin():
    registry = PatternRegistry(include_builtin=False)
    assert len(registry) == 0


def test_registry_with_plugin(tmp_path):
    plugin_file = _write_plugin(tmp_path, "myplugin.py", VALID_PLUGIN)
    registry = PatternRegistry(plugin_paths=[str(plugin_file)], include_builtin=False)
    assert len(registry) == 1
    assert "test_token" in registry.names()


def test_registry_add_pattern():
    registry = PatternRegistry(include_builtin=False)
    sp = SecretPattern(
        name="manual",
        pattern=re.compile(rb"MANUAL"),
        severity="low",
        description="manual pattern",
    )
    registry.add(sp)
    assert len(registry) == 1


def test_registry_patterns_property_is_copy(tmp_path):
    registry = PatternRegistry(include_builtin=False)
    copy1 = registry.patterns
    copy1.append(None)  # type: ignore[arg-type]
    assert len(registry) == 0  # internal list unaffected
