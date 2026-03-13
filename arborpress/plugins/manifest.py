"""Plugin-Manifest-Schema und Validierung (Spec §15).

Jedes Plugin liefert eine ``manifest.toml`` mit mindestens:

    [plugin]
    id          = "my_plugin"
    name        = "My Plugin"
    version     = "1.0.0"
    min_core    = "0.1.0"
    capabilities = ["importer"]

    [entry_points]
    importer = "my_plugin.importer:MyImporter"
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, field_validator

from arborpress.plugins.capabilities import Capability


# Mindest-Core-Versionsformat: "MAJOR.MINOR.PATCH"
_SEMVER_RE = r"^\d+\.\d+\.\d+$"


class PluginMeta(BaseModel):
    id: str
    name: str
    version: str
    min_core: str
    capabilities: list[Capability]
    description: str = ""
    author: str = ""
    url: str = ""

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Plugin-ID darf nur Buchstaben, Zahlen, - und _ enthalten: {v!r}")
        return v

    @field_validator("capabilities", mode="before")
    @classmethod
    def _coerce_capabilities(cls, v: list[str]) -> list[Capability]:
        try:
            return [Capability(c) for c in v]
        except ValueError as exc:
            known = [c.value for c in Capability]
            raise ValueError(f"Unbekannte Capability. Bekannte: {known}") from exc


class EntryPoints(BaseModel):
    """Optionale Entry-Points pro Capability (Klassen- oder Funktionspfad)."""

    mfa_provider: str | None = None
    auth_provider: str | None = None
    importer: str | None = None
    exporter: str | None = None
    federation_extension: str | None = None
    comments_extension: str | None = None
    mail_backend: str | None = None
    # CLI-Erweiterungsmodul (optional)
    cli: str | None = None


class PluginManifest(BaseModel):
    plugin: PluginMeta
    entry_points: EntryPoints = EntryPoints()

    @classmethod
    def from_file(cls, path: Path) -> "PluginManifest":
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        return cls.model_validate(data)

    def validate_entry_points(self) -> list[str]:
        """Gibt fehlende Entry-Points für deklarierte Capabilities zurück."""
        missing: list[str] = []
        ep_data = self.entry_points.model_dump()
        for cap in self.plugin.capabilities:
            if not ep_data.get(cap.value):
                missing.append(cap.value)
        return missing
