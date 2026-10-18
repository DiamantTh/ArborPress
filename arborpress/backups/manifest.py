"""Versioned backup-set metadata and strict TOML encoding."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_NAME = "manifest.toml"
CHECKSUMS_NAME = "checksums.sha256"
FORMAT_VERSION = 1
DATABASE_FORMAT_VERSION = 1
BACKUP_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}(?:-[0-9]{2,})?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMPONENTS = frozenset({"database", "config", "data", "themes", "plugins", "media"})


class BackupVerificationError(ValueError):
    """A backup set is malformed, incomplete, or fails integrity checks."""


def validate_relative_path(value: str) -> str:
    """Validate a manifest/archive path without consulting the host filesystem."""
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BackupVerificationError(f"Invalid backup-relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BackupVerificationError(f"Unsafe backup-relative path: {value!r}")
    if path.as_posix() != value:
        raise BackupVerificationError(f"Non-canonical backup-relative path: {value!r}")
    return value


def _toml_string(value: str) -> str:
    # JSON basic strings use the same escapes needed by our TOML string fields.
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


@dataclass(frozen=True, slots=True)
class BackupFile:
    path: str
    size_bytes: int
    sha256: str
    archive_format: str
    uncompressed_size_bytes: int
    segment: int | None = None
    members: int = 0
    member_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_relative_path(self.path)
        if self.size_bytes < 0 or self.uncompressed_size_bytes < 0 or self.members < 0:
            raise ValueError("Backup file sizes and member counts must be non-negative")
        if not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("Backup file checksum must be a lowercase SHA-256 digest")
        if self.segment is not None and self.segment < 1:
            raise ValueError("Backup media segment numbers start at one")
        for member_path in self.member_paths:
            validate_relative_path(member_path)
        if self.archive_format.startswith("tar-pax+") and len(self.member_paths) != self.members:
            raise ValueError("PAX archive manifest must list every member path")
        if self.member_paths and len(self.member_paths) != self.members:
            raise ValueError("Backup member path inventory does not match its member count")


@dataclass(frozen=True, slots=True)
class BackupComponent:
    name: str
    files: tuple[BackupFile, ...]

    def __post_init__(self) -> None:
        if self.name not in COMPONENTS:
            raise ValueError(f"Unknown backup component: {self.name!r}")


@dataclass(frozen=True, slots=True)
class BackupManifest:
    backup_id: str
    created_at: str
    arborpress_version: str
    database_system: str | None
    alembic_revisions: tuple[str, ...]
    consistency_mode: str
    compression_backend: str
    compression_profile: str
    compression_level: int | None
    compression_threads: int | None
    compression_block_size_bytes: int | None
    components: tuple[BackupComponent, ...]
    omitted_sensitive: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    encryption: str = "none"
    status: str = "complete"
    format_version: int = FORMAT_VERSION
    python_version: str | None = None

    def __post_init__(self) -> None:
        if not BACKUP_ID_RE.fullmatch(self.backup_id):
            raise ValueError("Invalid backup ID")
        if "-" in self.backup_id[15:]:
            suffix = self.backup_id[16:]
            if not suffix.isdigit() or int(suffix) < 1 or f"{int(suffix):02d}" != suffix:
                raise ValueError("Backup ID collision suffix is not canonical")
        if self.format_version != FORMAT_VERSION:
            raise ValueError("Unsupported backup manifest format version")
        if self.status != "complete":
            raise ValueError("Only complete backup manifests may be finalized")
        if not self.arborpress_version or not self.consistency_mode:
            raise ValueError("Backup version and consistency metadata are required")
        if self.encryption != "none":
            raise ValueError("Phase 6A only writes unencrypted backup sets")
        if self.compression_backend not in {"bz2", "bz3"}:
            raise ValueError("Unknown backup compression backend")
        if self.compression_profile not in {"fast", "medium", "strong", "custom"}:
            raise ValueError("Unknown backup compression profile")
        if self.compression_backend == "bz2":
            expected_level = (
                self.compression_level
                if self.compression_profile == "custom"
                else {"fast": 1, "medium": 6, "strong": 9}[self.compression_profile]
            )
            if expected_level is None or not 1 <= expected_level <= 9:
                raise ValueError("BZip2 compression level must be between 1 and 9")
            if (
                self.compression_threads is not None
                or self.compression_block_size_bytes is not None
            ):
                raise ValueError("BZip2 manifests cannot claim threads or block sizing")
        else:
            if self.compression_level is not None:
                raise ValueError("BZip3 manifests record block size, not a BZip2 level")
            if self.compression_threads is None or not 1 <= self.compression_threads <= 64:
                raise ValueError("BZip3 manifests require a valid thread count")
            if (
                self.compression_block_size_bytes is None
                or not 1 <= self.compression_block_size_bytes <= 512 * 1024**2
            ):
                raise ValueError("BZip3 manifests require a valid block size")
        try:
            parsed = datetime.fromisoformat(self.created_at)
        except ValueError as exc:
            raise ValueError("created_at must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError("created_at must include a UTC offset")
        names = [component.name for component in self.components]
        if not names:
            raise ValueError("A complete backup manifest must contain at least one component")
        if len(names) != len(set(names)):
            raise ValueError("A backup manifest may contain each component only once")
        for item in self.omitted_sensitive:
            validate_relative_path(item)
        for component in self.components:
            if not component.files:
                raise ValueError(f"Complete component {component.name!r} has no archive files")
            if component.name == "database":
                if len(component.files) != 1 or not component.files[0].archive_format.startswith(
                    "ndjson-v1+"
                ):
                    raise ValueError("Database component must contain one supported logical export")
            elif any(not file.archive_format.startswith("tar-pax+") for file in component.files):
                raise ValueError(f"File component {component.name!r} must use PAX TAR archives")
            elif component.name != "media" and any(
                file.segment is not None for file in component.files
            ):
                raise ValueError("Only media component files may have segment numbers")
        if parsed.strftime("%Y%m%d-%H%M%S") != self.backup_id[:15]:
            raise ValueError("Backup ID timestamp must match created_at")
        if self.database_system not in {None, "sqlite", "postgresql", "mariadb", "mysql"}:
            raise ValueError("Unsupported database system in backup manifest")
        if ("database" in names) != (self.database_system is not None):
            raise ValueError("Database component and database_system metadata disagree")
        if "database" not in names and self.alembic_revisions:
            raise ValueError("Alembic revisions require a database component")

    def to_toml(self) -> str:
        """Serialize the intentionally small manifest schema as UTF-8 TOML."""
        lines = [
            f"format_version = {self.format_version}",
            f"backup_id = {_toml_string(self.backup_id)}",
            f"created_at = {_toml_string(self.created_at)}",
            f"arborpress_version = {_toml_string(self.arborpress_version)}",
            f"python_version = {_toml_string(self.python_version or '')}",
            f"database_system = {_toml_string(self.database_system or '')}",
            f"alembic_revisions = {_toml_array(self.alembic_revisions)}",
            f"consistency_mode = {_toml_string(self.consistency_mode)}",
            f"compression_backend = {_toml_string(self.compression_backend)}",
            f"compression_profile = {_toml_string(self.compression_profile)}",
            f"encryption = {_toml_string(self.encryption)}",
            f"status = {_toml_string(self.status)}",
            f"omitted_sensitive = {_toml_array(self.omitted_sensitive)}",
            f"warnings = {_toml_array(self.warnings)}",
        ]
        for key, value in (
            ("compression_level", self.compression_level),
            ("compression_threads", self.compression_threads),
            ("compression_block_size_bytes", self.compression_block_size_bytes),
        ):
            if value is not None:
                lines.append(f"{key} = {value}")
        for component in self.components:
            lines.extend(("", "[[components]]", f"name = {_toml_string(component.name)}"))
            for item in component.files:
                lines.extend(
                    (
                        "",
                        "[[components.files]]",
                        f"path = {_toml_string(item.path)}",
                        f"size_bytes = {item.size_bytes}",
                        f"sha256 = {_toml_string(item.sha256)}",
                        f"archive_format = {_toml_string(item.archive_format)}",
                        f"uncompressed_size_bytes = {item.uncompressed_size_bytes}",
                        f"members = {item.members}",
                        f"member_paths = {_toml_array(item.member_paths)}",
                    )
                )
                if item.segment is not None:
                    lines.append(f"segment = {item.segment}")
        return "\n".join(lines) + "\n"

    @classmethod
    def from_toml(cls, content: bytes | str) -> BackupManifest:
        try:
            raw = tomllib.loads(content.decode("utf-8") if isinstance(content, bytes) else content)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise BackupVerificationError(f"Invalid backup manifest TOML: {exc}") from exc
        try:
            version = raw["format_version"]
            if type(version) is not int or version != FORMAT_VERSION:
                raise BackupVerificationError(f"Unsupported manifest version: {version!r}")
            component_values = raw["components"]
            if not isinstance(component_values, list):
                raise TypeError("components must be an array of tables")
            components: list[BackupComponent] = []
            for component_value in component_values:
                if not isinstance(component_value, dict):
                    raise TypeError("component entry must be a table")
                name = _required_str(component_value, "name")
                files_value = component_value.get("files", [])
                if not isinstance(files_value, list):
                    raise TypeError("component files must be an array of tables")
                files = tuple(_parse_file(file_value) for file_value in files_value)
                components.append(BackupComponent(name=name, files=files))
            manifest = cls(
                backup_id=_required_str(raw, "backup_id"),
                created_at=_required_str(raw, "created_at"),
                arborpress_version=_required_str(raw, "arborpress_version"),
                python_version=_optional_str(raw, "python_version"),
                database_system=_optional_str(raw, "database_system"),
                alembic_revisions=_string_tuple(raw, "alembic_revisions"),
                consistency_mode=_required_str(raw, "consistency_mode"),
                compression_backend=_required_str(raw, "compression_backend"),
                compression_profile=_required_str(raw, "compression_profile"),
                compression_level=_optional_int(raw, "compression_level"),
                compression_threads=_optional_int(raw, "compression_threads"),
                compression_block_size_bytes=_optional_int(raw, "compression_block_size_bytes"),
                encryption=_required_str(raw, "encryption"),
                status=_required_str(raw, "status"),
                omitted_sensitive=_string_tuple(raw, "omitted_sensitive"),
                warnings=_string_tuple(raw, "warnings"),
                format_version=version,
                components=tuple(components),
            )
            return manifest
        except BackupVerificationError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise BackupVerificationError(f"Malformed backup manifest: {exc}") from exc


def _required_str(table: dict[str, Any], key: str) -> str:
    value = table[key]
    if not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    return value


def _optional_str(table: dict[str, Any], key: str) -> str | None:
    value = _required_str(table, key)
    return value or None


def _required_int(table: dict[str, Any], key: str) -> int:
    value = table[key]
    if type(value) is not int:
        raise TypeError(f"{key} must be an integer")
    return value


def _optional_int(table: dict[str, Any], key: str) -> int | None:
    if key not in table:
        return None
    return _required_int(table, key)


def _string_tuple(table: dict[str, Any], key: str) -> tuple[str, ...]:
    values = table[key]
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise TypeError(f"{key} must be an array of strings")
    return tuple(values)


def _parse_file(raw: object) -> BackupFile:
    if not isinstance(raw, dict):
        raise TypeError("file entry must be a table")
    return BackupFile(
        path=_required_str(raw, "path"),
        size_bytes=_required_int(raw, "size_bytes"),
        sha256=_required_str(raw, "sha256"),
        archive_format=_required_str(raw, "archive_format"),
        uncompressed_size_bytes=_required_int(raw, "uncompressed_size_bytes"),
        segment=_optional_int(raw, "segment"),
        members=_required_int(raw, "members"),
        member_paths=_string_tuple(raw, "member_paths"),
    )


def checksum_line(path: str, digest: str) -> str:
    validate_relative_path(path)
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("Invalid SHA-256 digest")
    return f"{digest}  {path}\n"


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def parse_checksums(content: str) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line:
            continue
        if len(line) < 67 or line[64:66] != "  ":
            raise BackupVerificationError(f"Malformed checksum line {line_number}")
        digest, path = line[:64], line[66:]
        if not SHA256_RE.fullmatch(digest):
            raise BackupVerificationError(f"Malformed SHA-256 digest on line {line_number}")
        validate_relative_path(path)
        if path in checksums:
            raise BackupVerificationError(f"Duplicate checksum path: {path}")
        checksums[path] = digest
    return checksums
