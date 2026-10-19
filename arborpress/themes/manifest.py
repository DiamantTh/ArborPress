"""Theme manifest validation, discovery and safe runtime resolution.

Theme IDs are directory names. Themes are discovered only from this package's
theme directory and the active prefix's ``instance/themes`` directory. Theme
templates and assets are declarative presentation resources; they never grant
Python, database, shell, network, or admin-script capabilities.
"""

from __future__ import annotations

import logging
import math
import re
import tomllib
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

log = logging.getLogger("arborpress.themes")

ThemeType = Literal["public", "admin"]
ThemeStatus = Literal[
    "valid",
    "invalid",
    "incompatible",
    "missing_parent",
    "cyclic_parent",
    "duplicate_id",
]
THEME_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_PARENT_DEPTH = 8
ALLOWED_CAPABILITIES = frozenset({"templates", "styles", "public_assets"})
_BUILTIN_THEMES_DIR = Path(__file__).parent
_PUBLIC_TEMPLATE_OVERRIDES = frozenset(
    {
        "index.html",
        "post.html",
        "author_profile.html",
        "page.html",
        "tag.html",
        "search.html",
        "comment_confirmed.html",
        "comment_confirmation_result.html",
    }
)
_ADMIN_TEMPLATE_OVERRIDES = frozenset(
    {
        "admin/dashboard.html",
        "admin/posts.html",
        "admin/post_edit.html",
        "admin/pages.html",
        "admin/media.html",
        "admin/comments.html",
        "admin/plugins.html",
        "admin/settings.html",
        "admin/captcha.html",
    }
)


class ThemeFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dark_mode_toggle: bool = False
    code_highlight: bool = True
    reading_time: bool = True
    table_of_contents: bool = False


class ThemeAssets(BaseModel):
    model_config = ConfigDict(extra="forbid")

    css: list[str] = Field(default_factory=list)
    fonts: list[str] = Field(default_factory=list)
    images: list[str] = Field(default_factory=list)
    icons: list[str] = Field(default_factory=list)

    @field_validator("css", "fonts", "images", "icons")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        for value in values:
            _validate_theme_relative_path(value, prefix="static/")
        if len(values) != len(set(values)):
            raise ValueError("asset paths must be unique within each category")
        return values

    def all_paths(self) -> frozenset[str]:
        return frozenset(self.css + self.fonts + self.images + self.icons)


class ThemeOptionDefinition(BaseModel):
    """Small declarative option contract; values never execute as code."""

    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "string", "text", "boolean", "integer", "number", "select", "color", "url", "asset"
    ]
    label: str
    description: str = ""
    default: Any = None
    required: bool = False
    choices: list[str] = Field(default_factory=list)
    minimum: float | None = None
    maximum: float | None = None

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("option label must not be empty")
        return value.strip()

    @model_validator(mode="after")
    def validate_option_contract(self) -> ThemeOptionDefinition:
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("option minimum must not exceed maximum")
        if (self.minimum is not None or self.maximum is not None) and self.type not in {
            "integer",
            "number",
        }:
            raise ValueError("minimum and maximum are only valid for numeric options")
        if self.type == "select":
            if not self.choices or len(self.choices) != len(set(self.choices)):
                raise ValueError("select options require unique choices")
        elif self.choices:
            raise ValueError("choices are only valid for select options")
        if self.default is not None:
            self.validate_value(self.default)
        return self

    def validate_value(self, value: Any) -> Any:
        """Return a validated value using strict type checks."""
        valid = True
        if self.type in {"string", "text", "url", "asset"}:
            valid = isinstance(value, str)
        elif self.type == "boolean":
            valid = type(value) is bool
        elif self.type == "integer":
            valid = type(value) is int
        elif self.type == "number":
            valid = type(value) in {int, float} and math.isfinite(value)
        elif self.type == "select":
            valid = isinstance(value, str) and value in self.choices
        elif self.type == "color":
            valid = isinstance(value, str) and re.fullmatch(r"#[0-9A-Fa-f]{6}", value) is not None
        if not valid:
            raise ValueError(f"value does not match theme option type {self.type!r}")
        if isinstance(value, str):
            limits = {"string": 4096, "text": 65536, "url": 2048, "asset": 512}
            if len(value) > limits.get(self.type, 65536):
                raise ValueError("theme option value exceeds its size limit")
            if any(ord(character) < 0x20 and character not in "\n\r\t" for character in value):
                raise ValueError("theme option strings must not contain control characters")
        if self.type == "url" and value:
            from urllib.parse import urlsplit

            parsed_url = urlsplit(value)
            if (
                parsed_url.scheme not in {"http", "https"}
                or not parsed_url.hostname
                or parsed_url.username is not None
                or parsed_url.password is not None
            ):
                raise ValueError("theme option URLs must use http or https")
        if self.type == "asset" and value:
            _validate_theme_relative_path(value, prefix="static/")
        if self.type in {"integer", "number"}:
            if self.minimum is not None and value < self.minimum:
                raise ValueError("theme option value is below its minimum")
            if self.maximum is not None and value > self.maximum:
                raise ValueError("theme option value is above its maximum")
        return value


class ThemeManifest(BaseModel):
    """Validated ``theme.toml`` contents plus its trusted filesystem root."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    type: ThemeType
    author: str = ""
    license: str = "unknown"
    description: str = ""
    requires_arborpress: str = ">=0.1.0"
    tested_with: str | None = None
    parent: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    features: ThemeFeatures = Field(default_factory=ThemeFeatures)
    dark_companion: str | None = None
    light_companion: str | None = None
    preview: str | None = None
    assets: ThemeAssets = Field(default_factory=ThemeAssets)
    entry_points: dict[str, str] = Field(default_factory=dict)
    templates: list[str] = Field(default_factory=list)
    options: dict[str, ThemeOptionDefinition] = Field(default_factory=dict)
    # Informational marker only. It grants no trust or runtime capability.
    derived: bool = False

    _path: Path = PrivateAttr()
    _id: str = PrivateAttr()
    _source: Literal["builtin", "instance"] = PrivateAttr(default="instance")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must not be empty")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("name must not contain control characters")
        return value.strip()

    @field_validator("author", "license", "description")
    @classmethod
    def validate_human_metadata(cls, value: str) -> str:
        if any(ord(character) < 0x20 and character not in "\n\t" for character in value):
            raise ValueError("theme metadata must not contain control characters")
        if "\x1b" in value:
            raise ValueError("theme metadata must not contain terminal escape codes")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        try:
            Version(value)
        except InvalidVersion as exc:
            raise ValueError("version must be a valid PEP 440 version") from exc
        return value

    @field_validator("tested_with")
    @classmethod
    def validate_tested_with(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                Version(value)
            except InvalidVersion as exc:
                raise ValueError("tested_with must be a valid version") from exc
        return value

    @field_validator("requires_arborpress")
    @classmethod
    def validate_requirement(cls, value: str) -> str:
        try:
            SpecifierSet(value)
        except InvalidSpecifier as exc:
            raise ValueError("requires_arborpress must be a valid version specifier") from exc
        return value

    @field_validator("parent", "dark_companion", "light_companion")
    @classmethod
    def validate_theme_reference(cls, value: str | None) -> str | None:
        if value is not None and not THEME_ID_RE.fullmatch(value):
            raise ValueError(f"invalid theme ID reference: {value!r}")
        return value

    @field_validator("preview")
    @classmethod
    def validate_preview(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_theme_relative_path(value, prefix="static/")
        return value

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: list[str]) -> list[str]:
        unknown = sorted(set(values) - ALLOWED_CAPABILITIES)
        if unknown:
            raise ValueError(f"unsupported capabilities: {', '.join(unknown)}")
        if len(values) != len(set(values)):
            raise ValueError("capabilities must be unique")
        return values

    @field_validator("templates")
    @classmethod
    def validate_template_names(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("template overrides must be unique")
        for value in values:
            _validate_theme_relative_path(value)
        return values

    @field_validator("entry_points")
    @classmethod
    def validate_entry_points(cls, values: dict[str, str]) -> dict[str, str]:
        unknown = sorted(set(values) - {"public_css", "admin_css"})
        if unknown:
            raise ValueError(f"unsupported theme entry points: {', '.join(unknown)}")
        for value in values.values():
            _validate_theme_relative_path(value, prefix="static/")
        return values

    @model_validator(mode="after")
    def validate_contract(self) -> ThemeManifest:
        unknown_templates = set(self.templates) - (
            _PUBLIC_TEMPLATE_OVERRIDES if self.type == "public" else _ADMIN_TEMPLATE_OVERRIDES
        )
        if unknown_templates:
            raise ValueError(
                f"template overrides are not allowed for type {self.type!r}: "
                f"{', '.join(sorted(unknown_templates))}"
            )
        if self.templates and "templates" not in self.capabilities:
            raise ValueError("template overrides require the 'templates' capability")
        if self.assets.css and "styles" not in self.capabilities:
            raise ValueError("CSS assets require the 'styles' capability")
        if (self.assets.fonts or self.assets.images or self.assets.icons) and (
            "public_assets" not in self.capabilities
        ):
            raise ValueError("font, image, and icon assets require 'public_assets'")
        if self.preview and self.preview not in self.assets.images + self.assets.icons:
            raise ValueError("preview must be declared in assets.images or assets.icons")
        for key, option in self.options.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
                raise ValueError("theme option keys must be lowercase identifiers")
            if (
                option.type == "asset"
                and option.default
                and option.default not in self.assets.all_paths()
            ):
                raise ValueError(
                    f"default asset for theme option {key!r} must be declared in assets"
                )
        for entry_point, expected_type in (
            ("public_css", "public"),
            ("admin_css", "admin"),
        ):
            if entry_point not in self.entry_points:
                continue
            if self.type != expected_type:
                raise ValueError(
                    f"{entry_point} entry points are only valid for {expected_type} themes"
                )
            if self.entry_points[entry_point] not in self.assets.css:
                raise ValueError(f"{entry_point} entry point must be declared in assets.css")
        return self

    @classmethod
    def from_file(
        cls, path: Path, *, source: Literal["builtin", "instance"] = "instance"
    ) -> ThemeManifest:
        theme_root = path.parent.resolve(strict=True)
        theme_id = path.parent.name
        if not THEME_ID_RE.fullmatch(theme_id):
            raise ValueError(f"invalid theme directory ID: {theme_id!r}")
        resolved_manifest = path.resolve(strict=True)
        if resolved_manifest.parent != theme_root or resolved_manifest.name != "theme.toml":
            raise ValueError("theme.toml must be a regular file inside its theme root")
        if not resolved_manifest.is_file():
            raise ValueError("theme.toml is not a regular file")
        with resolved_manifest.open("rb") as handle:
            manifest = cls.model_validate(tomllib.load(handle))
        manifest._path = theme_root
        manifest._id = theme_id
        manifest._source = source
        manifest._validate_filesystem_references()
        return manifest

    def _validate_filesystem_references(self) -> None:
        assert self._path
        for relative in self.assets.all_paths() | frozenset(self.entry_points.values()):
            _resolve_inside(self._path, relative)
        for template in self.templates:
            _resolve_inside(self._path / "templates", template)

    @property
    def id(self) -> str:
        return self._id

    @property
    def source(self) -> Literal["builtin", "instance"]:
        return self._source

    @property
    def theme_dir(self) -> Path:
        return self._path

    @property
    def static_dir(self) -> Path:
        return self._path / "static"

    @property
    def template_dir(self) -> Path:
        return self._path / "templates"

    @property
    def css_url(self) -> str:
        """Compatibility URL for the theme's own declared CSS entry."""
        entry = self.entry_points.get("public_css")
        return _asset_url(self.id, entry) if entry else ""

    @property
    def theme(self) -> ThemeMetaView:
        """Read-only compatibility view for existing theme-picker/template code."""
        return ThemeMetaView(
            id=self.id,
            name=self.name,
            version=self.version,
            author=self.author,
            license=self.license,
            description=self.description,
            min_core=self.requires_arborpress,
            preview=self.preview or "preview.png",
            features=self.features,
            dark_companion=self.dark_companion,
            light_companion=self.light_companion,
        )


@dataclass(frozen=True)
class ThemeMetaView:
    id: str
    name: str
    version: str
    author: str
    license: str
    description: str
    min_core: str
    preview: str
    features: ThemeFeatures
    dark_companion: str | None
    light_companion: str | None


@dataclass
class ThemeRecord:
    id: str
    name: str
    version: str | None
    type: str | None
    source: Literal["builtin", "instance"]
    status: ThemeStatus
    diagnostics: list[str] = field(default_factory=list)
    manifest: ThemeManifest | None = None
    duplicate_of: str | None = None


def _validate_theme_relative_path(value: str, *, prefix: str | None = None) -> None:
    if (
        not value
        or "\\" in value
        or ":" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError(f"invalid theme-relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError(f"theme path must be a normalized relative path: {value!r}")
    if prefix is not None and not value.startswith(prefix):
        raise ValueError(f"theme path must be under {prefix!r}: {value!r}")


def _resolve_inside(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    _validate_theme_relative_path(relative)
    resolved_root = root.resolve(strict=True)
    candidate = (resolved_root / Path(*PurePosixPath(relative).parts)).resolve(strict=must_exist)
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"theme path escapes its root: {relative!r}") from exc
    if must_exist and not candidate.is_file():
        raise ValueError(f"theme asset is not a regular file: {relative!r}")
    return candidate


def _asset_url(theme_id: str, path: str) -> str:
    relative = PurePosixPath(path).relative_to("static")
    return f"/static/themes/{theme_id}/{relative.as_posix()}"


def _running_version() -> Version:
    try:
        return Version(version("arborpress"))
    except PackageNotFoundError, InvalidVersion:
        return Version("0.1.0")


def _safe_diagnostic(error: Exception) -> str:
    message = " ".join(str(error).split())
    message = re.sub(r"[\x00-\x1f\x7f]", " ", message)
    return message[:2000]


class ThemeRegistry:
    """Deterministic registry for package themes and one prefix's themes."""

    def __init__(
        self,
        extra_dirs: list[Path] | None = None,
        *,
        builtin_dir: Path = _BUILTIN_THEMES_DIR,
        running_version: Version | None = None,
    ) -> None:
        self._builtin_dir = builtin_dir
        self._extra_dirs = extra_dirs
        self._running_version = running_version or _running_version()
        self._records: list[ThemeRecord] = []
        self._primary: dict[str, ThemeRecord] = {}
        self._loaded = False
        self._filesystem_stamp: tuple[tuple[str, int, int, int], ...] | None = None

    def _current_filesystem_stamp(
        self, extra_dirs: list[Path] | None = None
    ) -> tuple[tuple[str, int, int, int], ...]:
        stamps: list[tuple[str, int, int, int]] = []
        for root in (self._builtin_dir, *self._instance_dirs(extra_dirs)):
            try:
                root_stat = root.stat()
                stamps.append(
                    (str(root), root_stat.st_ino, root_stat.st_mtime_ns, root_stat.st_size)
                )
                for theme_root in sorted(root.iterdir(), key=lambda path: path.name):
                    manifest = theme_root / "theme.toml"
                    if not theme_root.is_dir() or not manifest.exists():
                        continue
                    directory_stat = theme_root.stat()
                    manifest_stat = manifest.stat()
                    stamps.append(
                        (
                            str(manifest),
                            directory_stat.st_ino ^ manifest_stat.st_ino,
                            manifest_stat.st_mtime_ns,
                            manifest_stat.st_size,
                        )
                    )
            except OSError:
                stamps.append((str(root), 0, 0, 0))
        return tuple(stamps)

    def load(self, extra_dirs: list[Path] | None = None) -> None:
        if extra_dirs is not None:
            self._extra_dirs = extra_dirs
        dirs = self._instance_dirs(extra_dirs)
        records: list[ThemeRecord] = []
        builtin_records = self._read_directory(self._builtin_dir, "builtin")
        instance_records = [
            record for directory in dirs for record in self._read_directory(directory, "instance")
        ]

        primary: dict[str, ThemeRecord] = {}
        # Package themes own their IDs. An operator collision is visible but
        # can never shadow package code or resources.
        for record in builtin_records:
            if record.id in primary:
                record.status = "duplicate_id"
                record.diagnostics.append("duplicate built-in theme ID")
            else:
                primary[record.id] = record
        for record in instance_records:
            if record.id in primary:
                record.status = "duplicate_id"
                record.duplicate_of = primary[record.id].source
                record.diagnostics.append(f"theme ID collides with {record.duplicate_of} theme")
            elif record.id in {item.id for item in records if item.source == "instance"}:
                record.status = "duplicate_id"
                record.diagnostics.append("duplicate instance theme ID")
            else:
                primary[record.id] = record
            records.append(record)
        records = builtin_records + records
        self._primary = primary
        self._records = records
        self._validate_graph()
        self._loaded = True
        self._filesystem_stamp = self._current_filesystem_stamp(dirs)
        log.debug("Theme registry loaded: %s", sorted(self._primary))

    def _instance_dirs(self, extra_dirs: list[Path] | None) -> list[Path]:
        if extra_dirs is not None:
            return extra_dirs
        if self._extra_dirs is not None:
            return self._extra_dirs
        from arborpress.runtime.paths import get_runtime_paths

        return [get_runtime_paths().themes]

    @staticmethod
    def _read_directory(
        directory: Path, source: Literal["builtin", "instance"]
    ) -> list[ThemeRecord]:
        if not directory.exists():
            return []
        try:
            root = directory.resolve(strict=True)
        except OSError as exc:
            return [
                ThemeRecord(
                    directory.name or "themes",
                    str(directory),
                    None,
                    None,
                    source,
                    "invalid",
                    [f"theme root unavailable: {exc}"],
                )
            ]
        records: list[ThemeRecord] = []
        for theme_root in sorted(root.iterdir(), key=lambda path: path.name):
            if not theme_root.is_dir() or theme_root.name.startswith("."):
                continue
            manifest_path = theme_root / "theme.toml"
            if not manifest_path.exists():
                continue
            theme_id = theme_root.name
            try:
                resolved_root = theme_root.resolve(strict=True)
                resolved_root.relative_to(root)
                manifest = ThemeManifest.from_file(manifest_path, source=source)
                records.append(
                    ThemeRecord(
                        id=theme_id,
                        name=manifest.name,
                        version=manifest.version,
                        type=manifest.type,
                        source=source,
                        status="valid",
                        manifest=manifest,
                    )
                )
            except Exception as exc:
                # Keep broken manifests visible to diagnostics, but never make
                # them eligible for activation or rendering.
                records.append(
                    ThemeRecord(
                        id=theme_id,
                        name=theme_id,
                        version=None,
                        type=None,
                        source=source,
                        status="invalid",
                        diagnostics=[_safe_diagnostic(exc)],
                    )
                )
        return records

    def _validate_graph(self) -> None:
        states: dict[str, int] = {}
        stack: list[str] = []

        def visit(theme_id: str) -> int | None:
            record = self._primary.get(theme_id)
            if record is None or record.status != "valid" or record.manifest is None:
                return None
            if states.get(theme_id) == 1:
                start = stack.index(theme_id)
                cycle = stack[start:] + [theme_id]
                message = "parent cycle: " + " -> ".join(cycle)
                for member in set(cycle):
                    cyclic = self._primary.get(member)
                    if cyclic and cyclic.status == "valid":
                        cyclic.status = "cyclic_parent"
                        cyclic.diagnostics.append(message)
                return None
            if states.get(theme_id) == 2:
                return self._chain_depth(theme_id)
            states[theme_id] = 1
            stack.append(theme_id)
            manifest = record.manifest
            try:
                requirement = SpecifierSet(manifest.requires_arborpress)
                if self._running_version not in requirement:
                    record.status = "incompatible"
                    record.diagnostics.append(
                        f"requires ArborPress {manifest.requires_arborpress}; "
                        f"running {self._running_version}"
                    )
                depth = 1
                if manifest.parent:
                    parent = self._primary.get(manifest.parent)
                    if parent is None:
                        record.status = "missing_parent"
                        record.diagnostics.append(f"parent {manifest.parent!r} was not found")
                    elif parent.status != "valid" or parent.manifest is None:
                        if record.status == "valid":
                            record.status = "incompatible"
                            record.diagnostics.append(
                                f"parent {manifest.parent!r} is not a valid theme"
                            )
                    elif parent.manifest.type != manifest.type:
                        record.status = "incompatible"
                        record.diagnostics.append(
                            f"parent {manifest.parent!r} has type {parent.manifest.type!r}, "
                            f"expected {manifest.type!r}"
                        )
                    else:
                        parent_depth = visit(manifest.parent)
                        parent_status = cast(ThemeStatus, parent.status)
                        if parent_status == "cyclic_parent":
                            if record.status == "valid":
                                record.status = "incompatible"
                                record.diagnostics.append(
                                    f"parent chain through {manifest.parent!r} contains a cycle"
                                )
                        elif parent_depth is None:
                            if record.status == "valid":
                                record.status = "incompatible"
                                record.diagnostics.append(
                                    f"parent {manifest.parent!r} cannot be resolved"
                                )
                        else:
                            depth += parent_depth
                if depth > MAX_PARENT_DEPTH and record.status == "valid":
                    record.status = "incompatible"
                    record.diagnostics.append(
                        f"parent chain exceeds maximum depth {MAX_PARENT_DEPTH}"
                    )
                return depth if record.status == "valid" else None
            finally:
                stack.pop()
                states[theme_id] = 2

        for theme_id in sorted(self._primary):
            visit(theme_id)

        # Dark/light companion references are presentation relationships, not
        # parents; validate them after graph traversal so declaration order
        # cannot affect their result. In particular, a Public theme must never
        # cause an Admin theme's stylesheet to be included in a Public page.
        for record in self._primary.values():
            manifest = record.manifest
            if record.status != "valid" or manifest is None:
                continue
            for companion_id in (manifest.dark_companion, manifest.light_companion):
                if companion_id is None:
                    continue
                companion = self._primary.get(companion_id)
                if companion is None or companion.manifest is None:
                    record.status = "incompatible"
                    record.diagnostics.append(f"companion theme {companion_id!r} is unavailable")
                    break
                if companion.manifest.type != manifest.type:
                    record.status = "incompatible"
                    record.diagnostics.append(
                        f"companion theme {companion_id!r} has type "
                        f"{companion.manifest.type!r}, expected {manifest.type!r}"
                    )
                    break

    def _chain_depth(self, theme_id: str) -> int | None:
        depth = 0
        current = self._primary.get(theme_id)
        seen: set[str] = set()
        while current and current.manifest:
            if current.id in seen:
                return None
            seen.add(current.id)
            depth += 1
            if not current.manifest.parent:
                return depth
            current = self._primary.get(current.manifest.parent)
        return None

    def _ensure_loaded(self) -> None:
        if not self._loaded or self._filesystem_stamp != self._current_filesystem_stamp():
            self.load()

    def records(self) -> list[ThemeRecord]:
        self._ensure_loaded()
        return list(self._records)

    def record(self, theme_id: str) -> ThemeRecord | None:
        self._ensure_loaded()
        return next((record for record in self._records if record.id == theme_id), None)

    def all(self, theme_type: ThemeType | None = None) -> list[ThemeManifest]:
        self._ensure_loaded()
        return [
            record.manifest
            for record in self._primary.values()
            if record.status == "valid"
            and record.manifest is not None
            and (theme_type is None or record.manifest.type == theme_type)
        ]

    def get(self, theme_id: str) -> ThemeManifest | None:
        self._ensure_loaded()
        record = self._primary.get(theme_id)
        return record.manifest if record and record.status == "valid" else None

    def chain(self, theme_id: str) -> list[ThemeManifest]:
        theme = self.get(theme_id)
        if theme is None:
            return []
        result: list[ThemeManifest] = []
        seen: set[str] = set()
        current: ThemeManifest | None = theme
        while current is not None:
            if current.id in seen or len(result) >= MAX_PARENT_DEPTH:
                return []
            seen.add(current.id)
            result.append(current)
            current = self.get(current.parent) if current.parent else None
        return result

    def get_or_default(self, theme_id: str, theme_type: ThemeType = "public") -> ThemeManifest:
        theme = self.get(theme_id)
        if theme is None or theme.type != theme_type:
            log.warning(
                "Configured %s theme %r is unavailable or incompatible; using built-in fallback.",
                theme_type,
                theme_id,
            )
            theme = self.get("default" if theme_type == "public" else "arbor-admin")
        if theme is None or theme.type != theme_type:
            raise RuntimeError(f"No valid built-in {theme_type} theme is available")
        return theme

    def active(self, theme_type: ThemeType = "public") -> ThemeManifest:
        from arborpress.core.site_settings import get_cached, get_defaults

        settings = None
        try:
            from quart import g

            settings = getattr(g, "_theme_runtime_settings", None)
        except RuntimeError:
            pass
        if not isinstance(settings, dict):
            settings = get_cached("theme") or get_defaults("theme")
        key = "active" if theme_type == "public" else "admin_active"
        default_id = "default" if theme_type == "public" else "arbor-admin"
        selected = str(settings.get(key, default_id) or default_id)
        return self.get_or_default(selected, theme_type)

    def asset_url(self, theme_id: str, entry_point: str | None = None) -> str:
        selected = self.get(theme_id)
        if selected is None:
            return ""
        if entry_point is None:
            entry_point = "admin_css" if selected.type == "admin" else "public_css"
        for theme in self.chain(theme_id):
            path = theme.entry_points.get(entry_point)
            if path:
                # Keep the selected child ID in the URL so relative assets
                # within inherited CSS can also resolve child overrides.
                return _asset_url(selected.id, path)
        return ""

    def resolve_asset(self, theme_id: str, filename: str) -> tuple[ThemeManifest, Path] | None:
        """Resolve only a manifest-declared static asset within the theme chain."""
        _validate_theme_relative_path(filename)
        relative = f"static/{filename}"
        for theme in self.chain(theme_id):
            if relative not in theme.assets.all_paths():
                continue
            try:
                return theme, _resolve_inside(theme.theme_dir, relative)
            except OSError, ValueError:
                return None
        return None


_registry: ThemeRegistry | None = None


def get_theme_registry() -> ThemeRegistry:
    global _registry
    if _registry is None:
        from arborpress.runtime.paths import get_runtime_paths

        _registry = ThemeRegistry(extra_dirs=[get_runtime_paths().themes])
        _registry.load()
    return _registry


def reset_theme_registry() -> None:
    """Discard the cached registry after a controlled CLI/runtime prefix change."""
    global _registry
    _registry = None


def reset_theme_registry_for_tests() -> None:
    """Compatibility alias used by tests that switch temporary prefixes."""
    reset_theme_registry()


def get_active_theme(theme_type: ThemeType = "public") -> ThemeManifest:
    return get_theme_registry().active(theme_type)
