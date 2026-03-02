"""Tests für das Plugin-System."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from arborpress.plugins.capabilities import Capability
from arborpress.plugins.manifest import PluginManifest


# ---------------------------------------------------------------------------
# Manifest-Validierung
# ---------------------------------------------------------------------------


def test_manifest_parses_valid(tmp_path: Path) -> None:
    (tmp_path / "manifest.toml").write_text(
        textwrap.dedent(
            """
            [plugin]
            id           = "test_plugin"
            name         = "Test Plugin"
            version      = "1.0.0"
            min_core     = "0.1.0"
            capabilities = ["importer"]

            [entry_points]
            importer = "my_plugin.importer:MyImporter"
            """
        )
    )
    m = PluginManifest.from_file(tmp_path / "manifest.toml")
    assert m.plugin.id == "test_plugin"
    assert Capability.IMPORTER in m.plugin.capabilities


def test_manifest_unknown_capability_raises(tmp_path: Path) -> None:
    (tmp_path / "manifest.toml").write_text(
        textwrap.dedent(
            """
            [plugin]
            id           = "bad"
            name         = "Bad"
            version      = "1.0.0"
            min_core     = "0.1.0"
            capabilities = ["unknown_thing"]
            """
        )
    )
    with pytest.raises(Exception, match="Unbekannte Capability"):
        PluginManifest.from_file(tmp_path / "manifest.toml")


def test_manifest_missing_entry_point_detected(tmp_path: Path) -> None:
    (tmp_path / "manifest.toml").write_text(
        textwrap.dedent(
            """
            [plugin]
            id           = "incomplete"
            name         = "Incomplete"
            version      = "1.0.0"
            min_core     = "0.1.0"
            capabilities = ["importer"]
            """
        )
    )
    m = PluginManifest.from_file(tmp_path / "manifest.toml")
    missing = m.validate_entry_points()
    assert "importer" in missing


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_load_valid_plugin(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "my_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "manifest.toml").write_text(
        textwrap.dedent(
            """
            [plugin]
            id           = "my_plugin"
            name         = "My Plugin"
            version      = "1.0.0"
            min_core     = "0.1.0"
            capabilities = ["importer"]

            [entry_points]
            importer = "arborpress.plugins.registry:PluginRegistry"
            """
        )
    )

    from arborpress.plugins.registry import PluginRegistry
    reg = PluginRegistry()
    reg.load_directory(tmp_path)
    assert reg.get("my_plugin") is not None


def test_registry_rejects_incompatible_core(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "future_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "manifest.toml").write_text(
        textwrap.dedent(
            """
            [plugin]
            id           = "future_plugin"
            name         = "Future Plugin"
            version      = "1.0.0"
            min_core     = "99.0.0"
            capabilities = ["importer"]

            [entry_points]
            importer = "arborpress.plugins.registry:PluginRegistry"
            """
        )
    )
    from arborpress.plugins.registry import PluginRegistry
    reg = PluginRegistry()
    reg.load_directory(tmp_path)
    # Plugin darf nicht geladen worden sein
    assert reg.get("future_plugin") is None
