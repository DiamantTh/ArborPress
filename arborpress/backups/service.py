"""Atomic backup-set creation and per-instance backup coordination."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import shutil
import sys
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine

from arborpress.backups.archive import (
    DEFAULT_MEDIA_SEGMENT_SIZE,
    create_component_archives,
)
from arborpress.backups.compression import CompressionSettings
from arborpress.backups.database import DatabaseExportResult, export_database
from arborpress.backups.manifest import (
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    BackupComponent,
    BackupFile,
    BackupManifest,
    BackupVerificationError,
    checksum_line,
    sha256_file,
)
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout, get_runtime_paths

if TYPE_CHECKING:
    from arborpress.backups.verify import VerificationReport

DEFAULT_COMPONENTS = ("database", "config", "data", "themes", "plugins", "media")
BACKUP_LOCK_NAME = "backup.lock"
LOCK_DIAGNOSTIC_BYTES = 4096


class BackupError(RuntimeError):
    """An ArborPress backup operation could not be completed safely."""


class BackupLockError(BackupError):
    """Another backup operation currently owns the instance backup lock."""


@dataclass(frozen=True, slots=True)
class BackupSummary:
    backup_id: str
    directory: Path
    manifest: BackupManifest
    verification_ok: bool
    verification_error: str | None = None


@contextlib.contextmanager
def backup_lock(paths: ArborPressPaths) -> Iterator[None]:
    """Take an advisory process lock scoped to this instance's runtime area."""
    ensure_instance_layout(paths)
    _require_instance_directory(paths.run, paths.instance, "runtime lock")
    lock_path = paths.run / BACKUP_LOCK_NAME
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.lseek(descriptor, 0, os.SEEK_SET)
            diagnostic = (
                os.read(descriptor, LOCK_DIAGNOSTIC_BYTES).decode("utf-8", errors="replace").strip()
            )
            detail = f" ({diagnostic})" if diagnostic else ""
            raise BackupLockError(f"Another backup is running for this instance{detail}") from exc
        os.ftruncate(descriptor, 0)
        os.write(
            descriptor,
            json.dumps(
                {
                    "pid": os.getpid(),
                    "started_at": datetime.now(UTC).isoformat(),
                },
                sort_keys=True,
            ).encode("utf-8"),
        )
        os.fsync(descriptor)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


async def create_backup(
    *,
    paths: ArborPressPaths | None = None,
    engine: AsyncEngine | None = None,
    components: Iterable[str] = DEFAULT_COMPONENTS,
    compression: CompressionSettings | None = None,
    media_segment_size: int = DEFAULT_MEDIA_SEGMENT_SIZE,
    created_at: datetime | None = None,
    keep_incomplete: bool = False,
) -> BackupSummary:
    """Create, internally verify, then atomically publish a complete set."""
    selected_paths = paths or get_runtime_paths()
    ensure_instance_layout(selected_paths)
    _require_instance_directory(selected_paths.backups, selected_paths.instance, "backup root")
    _require_instance_directory(selected_paths.tmp, selected_paths.instance, "temporary root")
    selected_components = tuple(dict.fromkeys(components))
    if not selected_components:
        raise ValueError("At least one backup component must be selected")
    unknown = set(selected_components) - set(DEFAULT_COMPONENTS)
    if unknown:
        raise ValueError(f"Unknown backup component(s): {', '.join(sorted(unknown))}")
    settings = compression or CompressionSettings()
    if media_segment_size < 1:
        raise ValueError("Media segment size must be positive")
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Backup creation timestamp must be timezone-aware")
    timestamp = timestamp.astimezone(UTC)
    base_id = timestamp.strftime("%Y%m%d-%H%M%S")

    with backup_lock(selected_paths):
        backup_id = _available_backup_id(selected_paths.backups, base_id)
        staging = selected_paths.backups / (f".incomplete-{backup_id}-{uuid.uuid4().hex}")
        staging.mkdir(mode=0o700)
        db_result: DatabaseExportResult | None = None
        try:
            component_records: list[BackupComponent] = []
            omitted_sensitive: list[str] = []
            warnings = [
                "Filesystem components use stable per-file reads; "
                "the filesystem namespace is not a global atomic snapshot."
            ]
            if "database" in selected_components:
                if engine is None:
                    from arborpress.core.db import get_engine

                    engine = get_engine()
                db_dir = staging / "database"
                db_dir.mkdir(mode=0o700)
                backend = settings.backend
                extension = settings.extension
                relative = f"database/database-{backup_id}.ndjson.{extension}"
                database_path = staging / relative
                db_result = await export_database(
                    engine,
                    database_path,
                    compression=settings,
                    temporary_root=selected_paths.tmp,
                )
                digest, size = sha256_file(database_path)
                component_records.append(
                    BackupComponent(
                        "database",
                        (
                            BackupFile(
                                path=relative,
                                size_bytes=size,
                                sha256=digest,
                                archive_format=f"ndjson-v1+{backend}",
                                uncompressed_size_bytes=db_result.uncompressed_size_bytes,
                                members=sum(db_result.row_counts.values()),
                            ),
                        ),
                    )
                )
            for component in selected_components:
                if component == "database":
                    continue
                root = getattr(selected_paths, component)
                ignored: tuple[Path, ...] = ()
                if component == "config":
                    ignored, omitted = _config_sensitive_paths(root)
                    omitted_sensitive.extend(omitted)
                if component == "data":
                    ignored = _sqlite_database_sidecars(selected_paths, engine)
                results = create_component_archives(
                    root=root,
                    destination=staging,
                    component=component,
                    backup_id=backup_id,
                    compression=settings,
                    temporary_root=selected_paths.tmp,
                    media_segment_size=media_segment_size,
                    ignored_paths=ignored,
                )
                component_records.append(
                    BackupComponent(component, tuple(result.file for result in results))
                )
            if omitted_sensitive:
                warnings.append(
                    "Bootstrap configuration files were omitted because "
                    "unencrypted backups cannot safely preserve secrets."
                )
            created = timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
            manifest = BackupManifest(
                backup_id=backup_id,
                created_at=created,
                arborpress_version=_arborpress_version(),
                python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                database_system=db_result.database_system if db_result else None,
                alembic_revisions=db_result.alembic_revisions if db_result else (),
                consistency_mode=(
                    db_result.consistency_mode
                    if db_result
                    else "stable-file-reads; no database component requested"
                ),
                compression_backend=settings.backend,
                compression_profile=settings.profile,
                compression_level=settings.effective_level,
                compression_threads=settings.effective_threads,
                compression_block_size_bytes=settings.effective_block_size,
                components=tuple(component_records),
                omitted_sensitive=tuple(sorted(set(omitted_sensitive))),
                warnings=tuple(warnings),
            )
            _write_checksums(staging, manifest)
            _write_atomic_bytes(staging / MANIFEST_NAME, manifest.to_toml().encode("utf-8"))
            _fsync_tree_directories(staging)
            from arborpress.backups.verify import verify_backup_set

            verify_backup_set(staging, require_directory_id=False)
            final = selected_paths.backups / backup_id
            if final.exists():
                raise BackupError(f"Backup ID collision would overwrite existing data: {backup_id}")
            os.rename(staging, final)
            _fsync_directory(selected_paths.backups)
            return BackupSummary(backup_id, final, manifest, True)
        except Exception:
            if not keep_incomplete:
                _remove_staging_directory(selected_paths.backups, staging)
            raise


def list_backups(paths: ArborPressPaths | None = None) -> list[BackupSummary]:
    """List only finalized directories with a structurally valid manifest."""
    selected_paths = paths or get_runtime_paths()
    root = selected_paths.backups
    summaries: list[BackupSummary] = []
    if root.is_symlink():
        raise BackupError("The instance backup root must not be a symlink")
    if not root.exists():
        return summaries
    _require_instance_directory(root, selected_paths.instance, "backup root")
    for candidate in sorted(root.iterdir(), key=lambda item: item.name):
        if (
            candidate.is_symlink()
            or not candidate.is_dir()
            or candidate.name.startswith(".incomplete-")
        ):
            continue
        try:
            manifest = _load_manifest(candidate)
        except OSError, ValueError:
            continue
        if manifest.backup_id != candidate.name or manifest.status != "complete":
            continue
        summaries.append(BackupSummary(candidate.name, candidate, manifest, False))
    return summaries


def inspect_backup(backup_id: str, paths: ArborPressPaths | None = None) -> BackupSummary:
    """Load metadata and compute a verification status without extraction."""
    directory = _backup_directory(backup_id, paths or get_runtime_paths())
    manifest = _load_manifest(directory)
    from arborpress.backups.verify import verify_backup_set

    try:
        verify_backup_set(directory)
    except (OSError, ValueError) as exc:
        return BackupSummary(backup_id, directory, manifest, False, str(exc))
    return BackupSummary(backup_id, directory, manifest, True)


def verify_backup(backup_id: str, paths: ArborPressPaths | None = None) -> VerificationReport:
    """Verify a named set without extracting or mutating its contents."""
    directory = _backup_directory(backup_id, paths or get_runtime_paths())
    from arborpress.backups.verify import verify_backup_set

    return verify_backup_set(directory)


def _backup_directory(backup_id: str, paths: ArborPressPaths) -> Path:
    from arborpress.backups.manifest import BACKUP_ID_RE

    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise ValueError(f"Invalid backup ID: {backup_id!r}")
    _require_instance_directory(paths.backups, paths.instance, "backup root")
    directory = paths.backups / backup_id
    if not directory.is_dir() or directory.is_symlink():
        raise FileNotFoundError(f"Backup set not found: {backup_id}")
    return directory


def _require_instance_directory(path: Path, instance_root: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise BackupError(f"The instance {label} must be a real directory: {path}")
    try:
        resolved_path = path.resolve(strict=True)
        resolved_instance = instance_root.resolve(strict=True)
    except OSError as exc:
        raise BackupError(f"Could not resolve the instance {label}: {path}") from exc
    if not resolved_path.is_relative_to(resolved_instance):
        raise BackupError(f"The instance {label} escapes the instance root: {path}")


def _available_backup_id(root: Path, base_id: str) -> str:
    candidate = base_id
    suffix = 1
    while (root / candidate).exists():
        candidate = f"{base_id}-{suffix:02d}"
        suffix += 1
    return candidate


def _sqlite_database_sidecars(
    paths: ArborPressPaths, engine: AsyncEngine | None
) -> tuple[Path, ...]:
    if engine is None:
        from arborpress.core.config import get_settings

        database_url = make_url(get_settings().db.url)
    else:
        database_url = engine.url
    if not database_url.drivername.startswith("sqlite"):
        return ()
    database = database_url.database
    if not database or database == ":memory:":
        return ()
    db_path = Path(database).resolve(strict=False)
    data_root = paths.data.resolve(strict=False)
    if not db_path.is_relative_to(data_root):
        return ()
    return tuple(Path(str(db_path) + suffix) for suffix in ("", "-wal", "-shm", "-journal"))


def _config_sensitive_paths(root: Path) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    if not root.is_dir():
        return (), ()
    excluded: list[Path] = []
    names: list[str] = []
    for current, directories, files in os.walk(root, followlinks=False):
        base = Path(current)
        safe_directories: list[str] = []
        for name in directories:
            path = base / name
            if path.is_symlink():
                excluded.append(path)
                names.append((PurePosixPath("config") / path.relative_to(root)).as_posix())
            else:
                safe_directories.append(name)
        directories[:] = safe_directories
        for name in files:
            path = base / name
            excluded.append(path)
            names.append((PurePosixPath("config") / path.relative_to(root)).as_posix())
    return tuple(excluded), tuple(sorted(names))


def _write_checksums(staging: Path, manifest: BackupManifest) -> None:
    lines = [
        checksum_line(file.path, file.sha256)
        for component in manifest.components
        for file in component.files
    ]
    content = "".join(sorted(lines)).encode("utf-8")
    _write_atomic_bytes(staging / CHECKSUMS_NAME, content)


def _write_atomic_bytes(path: Path, content: bytes) -> None:
    temporary = path.with_name(path.name + ".part")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _load_manifest(directory: Path) -> BackupManifest:
    path = directory / MANIFEST_NAME
    if path.is_symlink() or not path.is_file():
        raise BackupVerificationError("Backup manifest is missing or not a regular file")
    return BackupManifest.from_toml(path.read_bytes())


def _remove_staging_directory(backup_root: Path, staging: Path) -> None:
    if staging.parent.resolve(strict=False) != backup_root.resolve(strict=False):
        raise BackupError("Refusing to remove a staging directory outside the backup root")
    if staging.name.startswith(".incomplete-") and staging.is_dir() and not staging.is_symlink():
        shutil.rmtree(staging)


def _fsync_directory(directory: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree_directories(root: Path) -> None:
    if os.name != "posix":
        return
    directories = [path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()]
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)
    _fsync_directory(root)


def _arborpress_version() -> str:
    try:
        return version("arborpress")
    except PackageNotFoundError:
        return "0.1.0"
