"""Typed capability catalog and instance-local plugin grants."""

from __future__ import annotations

import os
import re
import tempfile
import tomllib
from enum import StrEnum
from pathlib import Path


class Capability(StrEnum):
    STORAGE_KV = "storage.kv"
    STORAGE_FILES = "storage.files"
    CONTENT_READ = "data.content.read"
    COMMENTS_READ = "data.comments.read"
    EVENTS_SUBSCRIBE = "events.subscribe"
    JOBS_SCHEDULE = "jobs.schedule"
    NETWORK_HTTP = "network.http"
    ADMIN_DECLARATIVE = "admin.declarative"
    # Legacy 8A declarations remain parseable but have no RPC or grant surface.
    MFA_PROVIDER = "mfa_provider"
    AUTH_PROVIDER = "auth_provider"
    IMPORTER = "importer"
    EXPORTER = "exporter"
    FEDERATION_EXTENSION = "federation_extension"
    COMMENTS_EXTENSION = "comments_extension"
    MAIL_BACKEND = "mail_backend"


GRANTABLE_CAPABILITIES = frozenset(
    {
        Capability.STORAGE_KV,
        Capability.CONTENT_READ,
        Capability.COMMENTS_READ,
        Capability.EVENTS_SUBSCRIBE,
        Capability.JOBS_SCHEDULE,
        Capability.ADMIN_DECLARATIVE,
    }
)
_PLUGIN_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class CapabilityError(ValueError):
    """A local capability grant is invalid or unavailable."""


class CapabilityGrantStore:
    """Atomically persisted per-instance grants, separate from plugin metadata."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def grants_for(self, plugin_id: str) -> frozenset[str]:
        if not _PLUGIN_ID.fullmatch(plugin_id):
            return frozenset()
        try:
            with self.path.open("rb") as source:
                data = tomllib.load(source)
        except FileNotFoundError:
            return frozenset()
        grants = data.get("grants", {}).get(plugin_id, [])
        if not isinstance(grants, list):
            return frozenset()
        valid = {item.value for item in GRANTABLE_CAPABILITIES}
        return frozenset(value for value in grants if isinstance(value, str) and value in valid)

    def set_grant(self, plugin_id: str, capability: str, allowed: bool) -> None:
        if not _PLUGIN_ID.fullmatch(plugin_id):
            raise CapabilityError("invalid plugin id")
        try:
            cap = Capability(capability)
        except ValueError as exc:
            raise CapabilityError("unknown capability") from exc
        if cap not in GRANTABLE_CAPABILITIES:
            raise CapabilityError("capability is unsupported")
        try:
            with self.path.open("rb") as source:
                data = tomllib.load(source)
        except FileNotFoundError:
            data = {}
        grants = data.setdefault("grants", {})
        values = set(grants.get(plugin_id, []))
        if allowed:
            values.add(cap.value)
        else:
            values.discard(cap.value)
        if values:
            grants[plugin_id] = sorted(values)
        else:
            grants.pop(plugin_id, None)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lines = ["[grants]"]
        for key in sorted(grants):
            if _PLUGIN_ID.fullmatch(key):
                encoded = ", ".join(f'"{value}"' for value in sorted(set(grants[key])))
                lines.append(f'"{key}" = [{encoded}]')
        fd, temporary_name = tempfile.mkstemp(prefix=".plugin-grants-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as target:
                target.write("\n".join(lines) + "\n")
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary_name, self.path)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def missing_required_grants(
    plugin_id: str, required: tuple[str, ...], store: CapabilityGrantStore
) -> tuple[str, ...]:
    granted = store.grants_for(plugin_id)
    return tuple(item for item in required if item not in granted)
