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
PLUGIN_EVENTS = frozenset({"post.published", "comment.approved"})
_TASK_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


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
    subscriptions: tuple[str, ...] = ()
    tasks: tuple[str, ...] = ()
    admin_ui: dict[str, object] | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if len(value) > 128 or not PLUGIN_ID_RE.fullmatch(value):
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
        if self.events and self.subscriptions:
            raise ValueError("use subscriptions, not both events and subscriptions")
        subscriptions = self.subscriptions or self.events
        if len(set(subscriptions)) != len(subscriptions) or set(subscriptions) - PLUGIN_EVENTS:
            raise ValueError("subscriptions contain duplicate or unsupported event names")
        if len(set(self.tasks)) != len(self.tasks) or any(
            not _TASK_RE.fullmatch(item) for item in self.tasks
        ):
            raise ValueError("task names must be unique conservative identifiers")
        if subscriptions and "events.subscribe" not in self.requested_capabilities:
            raise ValueError("event subscriptions require events.subscribe")
        if self.tasks and "jobs.schedule" not in self.requested_capabilities:
            raise ValueError("task declarations require jobs.schedule")
        if self.admin_ui is not None:
            if "admin.declarative" not in self.requested_capabilities:
                raise ValueError("admin_ui requires admin.declarative")
            _validate_admin_descriptor(self.admin_ui)
        return self

    @property
    def event_subscriptions(self) -> tuple[str, ...]:
        return self.subscriptions or self.events

    @classmethod
    def from_file(cls, path: Path) -> PluginManifest:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
        return cls.model_validate(data)

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        return tuple(Capability(item) for item in self.requested_capabilities)


def _validate_admin_descriptor(value: dict[str, object]) -> None:
    """Accept only a small declarative schema; never plugin HTML/JS/CSS."""
    pages_value = value.get("pages")
    if set(value) != {"pages"} or not isinstance(pages_value, list) or len(pages_value) > 20:
        raise ValueError("admin_ui must contain only a bounded pages list")
    pages = pages_value
    page_ids: set[str] = set()
    for page in pages:
        if not isinstance(page, dict) or set(page) - {
            "id",
            "title",
            "description",
            "fields",
            "actions",
        }:
            raise ValueError("invalid declarative admin page")
        page_id, title = page.get("id"), page.get("title")
        if (
            not isinstance(page_id, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", page_id)
            or page_id in page_ids
        ):
            raise ValueError("invalid or duplicate admin page id")
        page_ids.add(page_id)
        if not isinstance(title, str) or not title.strip() or len(title) > 120:
            raise ValueError("admin page title is required")
        fields = page.get("fields", [])
        actions = page.get("actions", [])
        if (
            not isinstance(fields, list)
            or len(fields) > 50
            or not isinstance(actions, list)
            or len(actions) > 30
        ):
            raise ValueError("admin page has too many fields or actions")
        field_ids: set[str] = set()
        for field in fields:
            if not isinstance(field, dict) or set(field) - {
                "id",
                "label",
                "type",
                "required",
                "choices",
                "readonly",
            }:
                raise ValueError("invalid admin field descriptor")
            field_id, label, kind = field.get("id"), field.get("label"), field.get("type")
            if (
                not isinstance(field_id, str)
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", field_id)
                or field_id in field_ids
            ):
                raise ValueError("invalid or duplicate admin field id")
            if not isinstance(label, str) or not label.strip() or len(label) > 120:
                raise ValueError("admin field label is required")
            if kind not in {"text", "textarea", "number", "boolean", "select", "readonly"}:
                raise ValueError("unsupported admin field type")
            if kind == "select" and (
                not isinstance(field.get("choices"), list) or not field["choices"]
            ):
                raise ValueError("select fields require choices")
            if kind == "select":
                choices = field["choices"]
                if (
                    len(choices) > 100
                    or any(
                        not isinstance(choice, str) or not choice or len(choice) > 160
                        for choice in choices
                    )
                    or len(set(choices)) != len(choices)
                ):
                    raise ValueError("select choices must be unique bounded strings")
            field_ids.add(field_id)
        action_ids: set[str] = set()
        for action in actions:
            if not isinstance(action, dict) or set(action) != {"id", "label"}:
                raise ValueError("invalid admin action descriptor")
            action_id, label = action["id"], action["label"]
            if (
                not isinstance(action_id, str)
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", action_id)
                or action_id in action_ids
            ):
                raise ValueError("invalid or duplicate admin action id")
            if not isinstance(label, str) or not label.strip() or len(label) > 120:
                raise ValueError("admin action label is required")
            action_ids.add(action_id)
