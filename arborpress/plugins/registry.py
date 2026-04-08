"""Plugin registry – loads plugins from configured directories.

Rules (spec §15):
- Manual installation only (no marketplace/remote store)
- Core validates compatibility version on load
- UI integration only via core slots
- No plugin may define standalone security pages
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
    """Raised when a plugin cannot be loaded."""


class LoadedPlugin:
    """Represents a loaded plugin at runtime."""

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
        """Return the capability implementation (lazy import)."""
        if cap not in self._instances:
            ep_data = self.manifest.entry_points.model_dump()
            dotpath: str | None = ep_data.get(cap.value)
            if not dotpath:
                raise PluginLoadError(
                    f"Plugin {self.id!r} has no entry point for {cap.value!r}"
                )
            module_path, _, attr = dotpath.rpartition(":")
            try:
                mod = importlib.import_module(module_path)
                self._instances[cap] = getattr(mod, attr)
            except (ImportError, AttributeError) as exc:
                raise PluginLoadError(
                    f"Could not load entry point {dotpath!r} for plugin {self.id!r}: {exc}"
                ) from exc
        return self._instances[cap]

    def __repr__(self) -> str:
        caps = ", ".join(c.value for c in self.capabilities)
        return f"<LoadedPlugin id={self.id!r} caps=[{caps}]>"


class PluginRegistry:
    """Singleton registry of all loaded plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, LoadedPlugin] = {}

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_directory(self, directory: Path) -> None:
        """Load all plugins from a directory.

        Expects: ``<directory>/<plugin_id>/manifest.toml``
        """
        if not directory.is_dir():
            log.warning("Plugin directory does not exist: %s", directory)
            return

        for subdir in sorted(directory.iterdir()):
            if not subdir.is_dir():
                continue
            manifest_path = subdir / "manifest.toml"
            if not manifest_path.exists():
                log.debug("Skipping %s (no manifest.toml)", subdir.name)
                continue
            try:
                self._load_one(manifest_path, subdir)
            except PluginLoadError as exc:
                log.error("Plugin load error: %s", exc)

    def _load_one(self, manifest_path: Path, directory: Path) -> None:
        manifest = PluginManifest.from_file(manifest_path)
        plugin_id = manifest.plugin.id

        # Compatibility check
        min_core = Version(manifest.plugin.min_core)
        core_ver = Version(CORE_VERSION)
        if core_ver < min_core:
            raise PluginLoadError(
                f"Plugin {plugin_id!r} requires core >= {manifest.plugin.min_core}"
                f" (current: {CORE_VERSION})"
            )

        # Verify entry point completeness
        missing = manifest.validate_entry_points()
        if missing:
            raise PluginLoadError(
                f"Plugin {plugin_id!r}: missing entry points for {missing}"
            )

        self._plugins[plugin_id] = LoadedPlugin(manifest, directory)
        log.info(
            "Plugin loaded: %s v%s (%s)",
            plugin_id,
            manifest.plugin.version,
            ", ".join(c.value for c in manifest.plugin.capabilities),
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def all(self) -> list[LoadedPlugin]:
        return list(self._plugins.values())

    def by_capability(self, cap: Capability) -> list[LoadedPlugin]:
        return [p for p in self._plugins.values() if cap in p.capabilities]

    def get(self, plugin_id: str) -> LoadedPlugin | None:
        return self._plugins.get(plugin_id)


# Global singleton instance
_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry
