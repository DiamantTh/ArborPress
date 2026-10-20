"""Versioned, declarative third-party plugin manifest contract."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arborpress.plugins.capabilities import Capability

PLUGIN_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_PYTHON_IDENTIFIER = r"[A-Za-z][A-Za-z0-9_]*"
ENTRYPOINT_RE = re.compile(
    rf"^{_PYTHON_IDENTIFIER}(?:\.{_PYTHON_IDENTIFIER})*:{_PYTHON_IDENTIFIER}$"
)
SUPPORTED_MANIFEST_VERSION = 1


class PluginManifest(BaseModel):
    """The only supported manifest for third-party packages is ``plugin.toml``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: int
    id: str
    name: str = Field(min_length=1, max_length=120)
    version: str
    author: str = Field(min_length=1, max_length=160)
    license: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=2000)
    requires_arborpress: str
    entrypoint: str
    requested_capabilities: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    python: str = ">=3.14,<3.15"
    events: tuple[str, ...] = ()
    tasks: tuple[str, ...] = ()
    admin_ui: dict[str, object] | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not PLUGIN_ID_RE.fullmatch(value):
            raise ValueError("plugin id must match ^[a-z0-9]+(?:-[a-z0-9]+)*$")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        try:
            Version(value)
        except InvalidVersion as exc:
            raise ValueError("version must be a valid PEP 440 version") from exc
        return value

    @field_validator("requires_arborpress", "python")
    @classmethod
    def validate_specifier(cls, value: str) -> str:
        try:
            SpecifierSet(value)
        except InvalidSpecifier as exc:
            raise ValueError("must be a valid version constraint") from exc
        if not value.strip():
            raise ValueError("version constraint must not be empty")
        return value

    @field_validator("entrypoint")
    @classmethod
    def validate_entrypoint(cls, value: str) -> str:
        if not ENTRYPOINT_RE.fullmatch(value):
            raise ValueError("entrypoint must be a Python module:object reference")
        return value

    @field_validator("requested_capabilities", "required_capabilities")
    @classmethod
    def validate_capabilities(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        known = {cap.value for cap in Capability}
        unknown = sorted(set(values) - known)
        if unknown:
            raise ValueError(f"unknown capability name(s): {', '.join(unknown)}")
        if len(set(values)) != len(values):
            raise ValueError("capability names must be unique")
        return values

    @model_validator(mode="after")
    def validate_contract(self) -> PluginManifest:
        if self.manifest_version != SUPPORTED_MANIFEST_VERSION:
            raise ValueError(
                f"unsupported manifest_version {self.manifest_version}; "
                f"supported version is {SUPPORTED_MANIFEST_VERSION}"
            )
        if not set(self.required_capabilities).issubset(self.requested_capabilities):
            raise ValueError("required_capabilities must also be requested")
        return self

    @classmethod
    def from_file(cls, path: Path) -> PluginManifest:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
        return cls.model_validate(data)

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        return tuple(Capability(item) for item in self.requested_capabilities)
