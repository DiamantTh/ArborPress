"""Plugin-Registry – lädt Plugins aus konfigurierten Verzeichnissen.

Regeln (Spec §15):
- Nur manuelle Installation (kein Marketplace/Remote-Store)
- Core validiert Kompatibilitätsversion beim Laden
- UI-Integration nur über Core-Slots
- Kein Plugin darf eigenständige Security-Seiten definieren
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

from packaging.version import Version

from arborpress import __version__ as CORE_VERSION
from arborpress.plugins.capabilities import Capability
from arborpress.plugins.manifest import PluginManifest

log = logging.getLogger("arborpress.plugins")


class PluginLoadError(Exception):
    """Wird geworfen wenn ein Plugin nicht geladen werden kann."""


class LoadedPlugin:
    """Repräsentiert ein geladenes Plugin zur Laufzeit."""

    def __init__(self, manifest: PluginManifest, directory: Path) -> None:
        self.manifest = manifest
        self.directory = directory
        self._instances: dict[Capability, Any] = {}

    @property
    def id(self) -> str:
        return self.manifest.plugin.id

    @property
    def name(self) -> str:
        return self.manifest.plugin.name

    @property
    def capabilities(self) -> list[Capability]:
        return self.manifest.plugin.capabilities

    def get_instance(self, cap: Capability) -> Any:
        """Gibt die Capability-Implementierung zurück (lazy import)."""
        if cap not in self._instances:
            ep_data = self.manifest.entry_points.model_dump()
            dotpath: str | None = ep_data.get(cap.value)
            if not dotpath:
                raise PluginLoadError(
                    f"Plugin {self.id!r} hat keinen Entry-Point für {cap.value!r}"
                )
            module_path, _, attr = dotpath.rpartition(":")
            try:
                mod = importlib.import_module(module_path)
                self._instances[cap] = getattr(mod, attr)
            except (ImportError, AttributeError) as exc:
                raise PluginLoadError(
                    f"Konnte Entry-Point {dotpath!r} für Plugin {self.id!r} nicht laden: {exc}"
                ) from exc
        return self._instances[cap]

    def __repr__(self) -> str:
        caps = ", ".join(c.value for c in self.capabilities)
        return f"<LoadedPlugin id={self.id!r} caps=[{caps}]>"


class PluginRegistry:
    """Singleton-Registry aller geladenen Plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, LoadedPlugin] = {}

    # ------------------------------------------------------------------
    # Laden
    # ------------------------------------------------------------------

    def load_directory(self, directory: Path) -> None:
        """Lädt alle Plugins aus einem Verzeichnis.

        Erwartet: ``<directory>/<plugin_id>/manifest.toml``
        """
        if not directory.is_dir():
            log.warning("Plugin-Verzeichnis existiert nicht: %s", directory)
            return

        for subdir in sorted(directory.iterdir()):
            if not subdir.is_dir():
                continue
            manifest_path = subdir / "manifest.toml"
            if not manifest_path.exists():
                log.debug("Überspringe %s (kein manifest.toml)", subdir.name)
                continue
            try:
                self._load_one(manifest_path, subdir)
            except PluginLoadError as exc:
                log.error("Plugin-Ladefehler: %s", exc)

    def _load_one(self, manifest_path: Path, directory: Path) -> None:
        manifest = PluginManifest.from_file(manifest_path)
        plugin_id = manifest.plugin.id

        # Kompatibilitäts-Check
        min_core = Version(manifest.plugin.min_core)
        core_ver = Version(CORE_VERSION)
        if core_ver < min_core:
            raise PluginLoadError(
                f"Plugin {plugin_id!r} benötigt Core >= {manifest.plugin.min_core}"
                f" (aktuell: {CORE_VERSION})"
            )

        # Entry-Point-Vollständigkeit prüfen
        missing = manifest.validate_entry_points()
        if missing:
            raise PluginLoadError(
                f"Plugin {plugin_id!r}: fehlende Entry-Points für {missing}"
            )

        self._plugins[plugin_id] = LoadedPlugin(manifest, directory)
        log.info(
            "Plugin geladen: %s v%s (%s)",
            plugin_id,
            manifest.plugin.version,
            ", ".join(c.value for c in manifest.plugin.capabilities),
        )

    # ------------------------------------------------------------------
    # Abfragen
    # ------------------------------------------------------------------

    def all(self) -> list[LoadedPlugin]:
        return list(self._plugins.values())

    def by_capability(self, cap: Capability) -> list[LoadedPlugin]:
        return [p for p in self._plugins.values() if cap in p.capabilities]

    def get(self, plugin_id: str) -> LoadedPlugin | None:
        return self._plugins.get(plugin_id)


# Globale Singleton-Instanz
_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry
