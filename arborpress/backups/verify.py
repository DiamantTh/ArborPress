"""Read-only integrity verification for finalized ArborPress backup sets."""

from __future__ import annotations

import hashlib
import os
import posixpath
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, cast

from arborpress.backups.compression import CompressionBackend, open_compressed_reader
from arborpress.backups.database import validate_database_stream
from arborpress.backups.manifest import (
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    BackupFile,
    BackupManifest,
    BackupVerificationError,
    parse_checksums,
    validate_relative_path,
)

VERIFY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class VerificationReport:
    backup_id: str
    checked_files: int
    checked_bytes: int
    component_names: tuple[str, ...]
    database_rows: int


def verify_backup_set(
    directory: Path,
    *,
    require_directory_id: bool = True,
) -> VerificationReport:
    """Verify metadata, checksums, archive structure and database stream.

    This function never extracts files and never mutates a live ArborPress
    instance. ``require_directory_id=False`` is intended only for the service's
    private ``.incomplete-*`` staging directory before its atomic rename.
    """
    if directory.is_symlink() or not directory.is_dir():
        raise BackupVerificationError("Backup set path is not a real directory")
    root = directory.resolve(strict=True)
    manifest_path = root / MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BackupVerificationError("Backup manifest is missing or not a regular file")
    manifest = BackupManifest.from_toml(manifest_path.read_bytes())
    if require_directory_id and root.name != manifest.backup_id:
        raise BackupVerificationError("Backup directory name does not match manifest backup_id")
    expected: dict[str, tuple[str, int]] = {}
    component_files: dict[str, list[BackupFile]] = {}
    for component in manifest.components:
        component_files[component.name] = list(component.files)
        if not component.files:
            raise BackupVerificationError(f"Component {component.name!r} has no archive files")
        for item in component.files:
            if PurePosixPath(item.path).parts[0] != component.name:
                raise BackupVerificationError(
                    f"Component file path is outside {component.name!r}: {item.path}"
                )
            if item.path in expected:
                raise BackupVerificationError(f"Duplicate component file path: {item.path}")
            expected[item.path] = (item.sha256, item.size_bytes)

    checksums_path = root / CHECKSUMS_NAME
    if checksums_path.is_symlink() or not checksums_path.is_file():
        raise BackupVerificationError("Backup checksums file is missing or not regular")
    checksums = parse_checksums(checksums_path.read_text(encoding="utf-8"))
    if checksums != {path: values[0] for path, values in expected.items()}:
        raise BackupVerificationError("Checksum list does not match manifest component files")
    _verify_set_inventory(root, set(expected))

    total_bytes = 0
    database_rows = 0
    for component in manifest.components:
        for item in component.files:
            candidate = _safe_component_file(root, item.path)
            digest, size = _sha256(candidate)
            if size != item.size_bytes:
                raise BackupVerificationError(f"Size mismatch for {item.path}")
            if digest != item.sha256 or checksums[item.path] != digest:
                raise BackupVerificationError(f"SHA-256 mismatch for {item.path}")
            total_bytes += size
            if component.name == "database":
                if not item.archive_format.startswith("ndjson-v1+"):
                    raise BackupVerificationError("Database component has an unknown stream format")
                backend = _backend_from_format(item.archive_format)
                if backend != manifest.compression_backend:
                    raise BackupVerificationError("Database compression differs from manifest")
                result = validate_database_stream(candidate, backend)
                if result["row_count"] != item.members:
                    raise BackupVerificationError("Database row count does not match manifest")
                database_rows += result["row_count"]
            else:
                if not item.archive_format.startswith("tar-pax+"):
                    raise BackupVerificationError(
                        f"Component {component.name!r} has an unknown archive format"
                    )
                backend = _backend_from_format(item.archive_format)
                if backend != manifest.compression_backend:
                    raise BackupVerificationError("Component compression differs from manifest")
                member_count, uncompressed_size, member_paths = _verify_tar(candidate, backend)
                if member_count != item.members:
                    raise BackupVerificationError(f"TAR member count mismatch for {item.path}")
                if item.member_paths != member_paths:
                    raise BackupVerificationError(f"TAR member inventory mismatch for {item.path}")
                if uncompressed_size != item.uncompressed_size_bytes:
                    raise BackupVerificationError(f"TAR size mismatch for {item.path}")
    media = component_files.get("media")
    if media is not None:
        segments = [item.segment for item in media]
        if segments != list(range(1, len(media) + 1)):
            raise BackupVerificationError("Media segments are missing, duplicated, or out of order")
    return VerificationReport(
        backup_id=manifest.backup_id,
        checked_files=len(expected),
        checked_bytes=total_bytes,
        component_names=tuple(component.name for component in manifest.components),
        database_rows=database_rows,
    )


def _safe_component_file(root: Path, relative_path: str) -> Path:
    validate_relative_path(relative_path)
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise BackupVerificationError(f"Component file is missing: {relative_path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BackupVerificationError(f"Component path is not a regular file: {relative_path}")
    if not resolved.is_relative_to(root):
        raise BackupVerificationError(f"Component file escapes backup set: {relative_path}")
    return candidate


def _sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(VERIFY_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _verify_set_inventory(root: Path, component_paths: set[str]) -> None:
    expected_files = component_paths | {MANIFEST_NAME, CHECKSUMS_NAME}
    expected_directories: set[str] = set()
    for name in expected_files:
        parent = PurePosixPath(name).parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        for name in list(directories):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise BackupVerificationError(f"Unexpected symlink in backup set: {relative}")
            actual_directories.add(relative)
        for name in files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file():
                raise BackupVerificationError(
                    f"Unexpected non-regular path in backup set: {relative}"
                )
            actual_files.add(relative)
    if actual_files != expected_files:
        raise BackupVerificationError("Backup set contains missing or unlisted files")
    if actual_directories != expected_directories:
        raise BackupVerificationError("Backup set contains unexpected or missing directories")


def _backend_from_format(value: str) -> CompressionBackend:
    backend = value.rsplit("+", 1)[-1]
    if backend not in {"bz2", "bz3"}:
        raise BackupVerificationError(f"Unsupported component compression: {backend!r}")
    return cast(CompressionBackend, backend)


def _verify_tar(path: Path, backend: CompressionBackend) -> tuple[int, int, tuple[str, ...]]:
    count = 0
    uncompressed_size = 0
    names: set[str] = set()
    ordered_names: list[str] = []
    with open_compressed_reader(path, backend) as compressed:
        with tarfile.open(fileobj=compressed, mode="r|") as archive:
            for member in archive:
                name = validate_relative_path(member.name.rstrip("/"))
                if name in names:
                    raise BackupVerificationError(f"Duplicate TAR member path: {name}")
                names.add(name)
                ordered_names.append(name)
                if member.islnk():
                    raise BackupVerificationError("Hard links are not supported in backup archives")
                if member.issym():
                    _validate_archive_symlink(name, member.linkname)
                elif member.isdir():
                    pass
                elif member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise BackupVerificationError(f"Cannot read TAR member: {name}")
                    uncompressed_size += _drain(stream)
                else:
                    raise BackupVerificationError(f"Unsupported TAR member type: {name}")
                count += 1
        # Force the compressor to its end marker so truncated/corrupt streams
        # are detected even if TAR end blocks appeared before compressed EOF.
        while compressed.read(VERIFY_CHUNK_SIZE):
            pass
    return count, uncompressed_size, tuple(ordered_names)


def _validate_archive_symlink(member_name: str, target: str) -> None:
    if not target or "\\" in target or "\x00" in target or target.startswith("/"):
        raise BackupVerificationError(f"Unsafe TAR symlink target for {member_name}")
    resolved = posixpath.normpath(posixpath.join(str(PurePosixPath(member_name).parent), target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise BackupVerificationError(f"TAR symlink escapes component root: {member_name}")


def _drain(stream: IO[bytes]) -> int:
    size = 0
    with stream:
        while chunk := stream.read(VERIFY_CHUNK_SIZE):
            size += len(chunk)
    return size
