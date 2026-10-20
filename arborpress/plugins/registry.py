"""Deterministic discovery of third-party plugins without importing them."""

from __future__ import annotations

import logging
import sys
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version
from pydantic import ValidationError

from arborpress import __version__ as CORE_VERSION
from arborpress.plugins.manifest import PluginManifest
from arborpress.plugins.state import PluginStateStore

log = logging.getLogger("arborpress.plugins")


class PluginStatus(StrEnum):
    DISCOVERED = "discovered"
    INVALID = "invalid"
    INCOMPATIBLE = "incompatible"
    DISABLED = "disabled"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    UNKNOWN = "unknown"


class PluginSource(StrEnum):
    BUILT_IN = "built_in"
    THIRD_PARTY = "third_party"


@dataclass(slots=True)
class PluginRecord:
    manifest: PluginManifest | None
    directory: Path
    source: PluginSource = PluginSource.THIRD_PARTY
    status: PluginStatus = PluginStatus.DISCOVERED
    error: str | None = None
    enabled: bool = False
    runtime_status: PluginStatus = PluginStatus.STOPPED
    interpreter: str = sys.executable
    exit_status: int | None = None
    last_error: str | None = None
    granted_capabilities: tuple[str, ...] = ()
    grantable_capabilities: tuple[str, ...] = ()
    missing_required_capabilities: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.manifest.id if self.manifest else self.directory.name

    @property
    def name(self) -> str:
        return self.manifest.name if self.manifest else self.directory.name

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self.manifest.requested_capabilities if self.manifest else ()

    @property
    def compatible(self) -> bool:
        return self.status not in {PluginStatus.INVALID, PluginStatus.INCOMPATIBLE}


class PluginLoadError(Exception):
    """Raised when a plugin cannot be discovered or started safely."""


class PluginRegistry:
    """Registry contains metadata only; plugin entrypoints are child-process-only."""

    def __init__(self) -> None:
        self._plugins: dict[str, PluginRecord] = {}
        self._seen_directories: set[Path] = set()

    def load_directory(self, directory: Path) -> None:
        if not directory.is_dir():
            return
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            if not child.is_dir() or child.is_symlink():
                continue
            canonical = child.resolve()
            if canonical in self._seen_directories:
                continue
            self._seen_directories.add(canonical)
            manifest_path = child / "plugin.toml"
            if not manifest_path.is_file():
                # Preserve a visible diagnostic for pre-8A layouts, without
                # executing or trusting their old manifest format.
                legacy = child / "manifest.toml"
                if legacy.exists():
                    self._plugins[child.name] = PluginRecord(
                        None,
                        child,
                        status=PluginStatus.INVALID,
                        error="legacy manifest.toml is unsupported; migrate to plugin.toml",
                    )
                continue
            try:
                if manifest_path.is_symlink() or manifest_path.resolve().parent != canonical:
                    raise ValueError("plugin.toml must be a regular file inside its plugin root")
                manifest = PluginManifest.from_file(manifest_path)
                record = PluginRecord(manifest, child)
                if manifest.id != child.name:
                    record.status = PluginStatus.INVALID
                    record.error = "manifest id does not match plugin directory name"
                elif not SpecifierSet(manifest.requires_arborpress).contains(
                    Version(CORE_VERSION), prereleases=True
                ):
                    record.status = PluginStatus.INCOMPATIBLE
                    record.error = "requires_arborpress excludes this ArborPress version"
                elif not SpecifierSet(manifest.python).contains(
                    Version(
                        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                    ),
                    prereleases=True,
                ):
                    record.status = PluginStatus.INCOMPATIBLE
                    record.error = "plugin does not support this Python runtime"
            except ValidationError as exc:
                details = "; ".join(
                    f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                    for error in exc.errors(include_input=False)
                )
                record = PluginRecord(
                    None,
                    child,
                    status=PluginStatus.INVALID,
                    error=f"invalid plugin manifest: {details[:300]}",
                )
            except tomllib.TOMLDecodeError:
                record = PluginRecord(
                    None,
                    child,
                    status=PluginStatus.INVALID,
                    error="invalid plugin manifest: malformed TOML",
                )
            except Exception as exc:
                record = PluginRecord(
                    None,
                    child,
                    status=PluginStatus.INVALID,
                    error=f"invalid plugin manifest: {type(exc).__name__}",
                )

            existing = self._plugins.get(record.id)
            if existing is not None:
                existing.status = PluginStatus.INVALID
                existing.error = "duplicate plugin ID; discovery collision"
                record.status = PluginStatus.INVALID
                record.error = "duplicate plugin ID; discovery collision"
                log.error("Plugin ID collision: %s", record.id)
            else:
                self._plugins[record.id] = record

    def discover(self, roots: tuple[Path, ...] | list[Path]) -> None:
        for root in roots:
            self.load_directory(root)

    def all(self) -> list[PluginRecord]:
        return [self._plugins[key] for key in sorted(self._plugins)]

    def by_capability(self, cap: object) -> list[PluginRecord]:
        value = str(getattr(cap, "value", cap))
        return [plugin for plugin in self.all() if value in plugin.capabilities]

    def get(self, plugin_id: str) -> PluginRecord | None:
        return self._plugins.get(plugin_id)


_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry


def discover_instance_plugins(roots: tuple[Path, ...] | list[Path] | None = None) -> PluginRegistry:
    from arborpress.core.config import get_settings
    from arborpress.runtime.paths import get_runtime_paths

    paths = get_runtime_paths()
    registry = PluginRegistry()
    registry.discover(list(roots) if roots is not None else get_settings().plugin_dirs())
    enabled_ids = PluginStateStore(paths.data / "plugin-state.toml").enabled_ids()
    from arborpress.plugins.capabilities import (
        GRANTABLE_CAPABILITIES,
        CapabilityGrantStore,
        missing_required_grants,
    )

    grants = CapabilityGrantStore(paths.data / "plugin-grants.toml")
    from arborpress.plugins.runtime_state import read_status

    for record in registry.all():
        record.enabled = record.id in enabled_ids
        if record.manifest is not None:
            for stale_grant in grants.grants_for(record.id) - set(
                record.manifest.requested_capabilities
            ):
                grants.set_grant(record.id, stale_grant, False)
        record.granted_capabilities = tuple(sorted(grants.grants_for(record.id)))
        record.grantable_capabilities = tuple(
            sorted(capability.value for capability in GRANTABLE_CAPABILITIES)
        )
        if record.manifest is not None:
            record.missing_required_capabilities = missing_required_grants(
                record.id, record.manifest.required_capabilities, grants
            )
            if record.enabled and record.missing_required_capabilities:
                record.last_error = "missing_required_capabilities: " + ", ".join(
                    record.missing_required_capabilities
                )
        runtime_info = read_status(paths.plugin_run, record.id)
        if runtime_info and isinstance(runtime_info.get("runtime_status"), str):
            try:
                old_status = PluginStatus(runtime_info["runtime_status"])
            except ValueError:
                old_status = PluginStatus.UNKNOWN
            record.runtime_status = (
                PluginStatus.UNKNOWN
                if old_status
                in {PluginStatus.STARTING, PluginStatus.RUNNING, PluginStatus.STOPPING}
                else old_status
            )
            last_error = runtime_info.get("last_error")
            if isinstance(last_error, str):
                record.last_error = last_error[:200]
        if record.enabled and record.status == PluginStatus.DISCOVERED:
            record.status = PluginStatus.DISCOVERED
        elif not record.enabled and record.status == PluginStatus.DISCOVERED:
            record.status = PluginStatus.DISABLED
    global _registry
    _registry = registry
    return registry


def reset_registry_for_tests() -> None:
    global _registry
    _registry = None
