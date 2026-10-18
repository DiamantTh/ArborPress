"""Restore planning and isolated staging for manifest-defined backup sets."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

import sqlalchemy as sa
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from arborpress.backups.compression import CompressionBackend, open_compressed_reader
from arborpress.backups.encryption import (
    BackupKey,
    EncryptionContext,
    context_from_manifest,
    decrypt_file_to_path,
    decrypted_component_file,
)
from arborpress.backups.manifest import (
    BACKUP_ID_RE,
    MANIFEST_NAME,
    BackupFile,
    BackupManifest,
    BackupVerificationError,
    sha256_file,
    validate_relative_path,
)
from arborpress.backups.service import (
    BackupError,
    backup_lock,
    create_backup,
    inspect_backup,
)
from arborpress.backups.verify import verify_backup_set
from arborpress.runtime.paths import ArborPressPaths, get_runtime_paths

log = logging.getLogger("arborpress.backups.restore")

RESTORE_FORMAT_VERSION = 1
RESTORE_STAGING_PREFIX = "restore-"
RESTORE_JOURNAL_NAME = "restore-journal.json"
RESTORE_MAINTENANCE_NAME = "restore-maintenance.json"
RESTORE_HISTORY_DIRNAME = "restore-history"
RESTORE_ROLLBACK_PREFIX = ".restore-rollback-"
RESTORE_COMPONENTS = ("config", "data", "themes", "plugins", "media")
COPY_CHUNK_SIZE = 1024 * 1024

COMPONENT_TARGETS: dict[str, str] = {
    "config": "config",
    "data": "data",
    "themes": "themes",
    "plugins": "plugins",
    "media": "media",
}


class RestoreError(RuntimeError):
    """A restore cannot safely continue or complete."""


class RestoreCompatibilityError(RestoreError):
    """A backup is valid but incompatible with this ArborPress instance."""


class UnsafeRestoreEntryError(RestoreError):
    """A backup archive contains a path or member type unsafe to stage."""


class RestoreRecoveryRequired(RestoreError):
    """An interrupted restore needs recovery before another operation."""


@dataclass(frozen=True, slots=True)
class RestorePlan:
    backup_id: str
    created_at: str
    format_version: int
    arborpress_version: str
    backup_database_system: str | None
    backup_alembic_revisions: tuple[str, ...]
    target_database_system: str | None
    target_alembic_revisions: tuple[str, ...]
    target_schema_state: str | None
    selected_components: tuple[str, ...]
    available_components: tuple[str, ...]
    config_coverage: Literal["not-selected", "absent", "complete", "partial"]
    omitted_sensitive: tuple[str, ...]
    target_paths: dict[str, str]
    estimated_uncompressed_bytes: int
    compatible: bool
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]
    verification_ok: bool
    incomplete_restore: bool

    def as_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class StagedRestore:
    backup_id: str
    restore_id: str
    staging_root: Path
    component_roots: dict[str, Path]
    database_stream: Path | None
    database_staged_path: Path | None
    database_target_path: Path | None
    database_row_counts: dict[str, int] | None
    database_system: str | None
    alembic_revisions: tuple[str, ...]
    config_coverage: str
    manifest: BackupManifest
    warnings: tuple[str, ...]


async def plan_restore(
    backup_id: str,
    *,
    paths: ArborPressPaths | None = None,
    components: tuple[str, ...] | None = None,
    engine: AsyncEngine | None = None,
    key: BackupKey | None = None,
) -> RestorePlan:
    """Build a fully verified, read-only restore plan for one instance."""
    selected_paths = paths or get_runtime_paths()
    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise ValueError(f"Invalid backup ID: {backup_id!r}")
    summary = inspect_backup(backup_id, selected_paths, key=key)
    if not summary.verification_ok:
        raise BackupVerificationError(
            f"Backup set {backup_id} failed verification: {summary.verification_error}"
        )
    manifest = summary.manifest
    available = tuple(component.name for component in manifest.components)
    selected = available if components is None else tuple(dict.fromkeys(components))
    if not selected:
        raise ValueError("At least one restore component must be selected")
    unknown = set(selected) - set(available)
    if unknown:
        raise ValueError(f"Backup does not contain component(s): {', '.join(sorted(unknown))}")
    if any(component not in {*RESTORE_COMPONENTS, "database"} for component in selected):
        raise ValueError("Restore selection contains an unsupported component")

    blockers: list[str] = []
    warnings: list[str] = list(manifest.warnings)
    if manifest.encryption != "none" and key is None:
        warnings.append(
            "Encrypted backup has structural-only verification; provide its key for full "
            "cryptographic verification before apply."
        )
    target_paths = {
        component: str(getattr(selected_paths, target))
        for component, target in COMPONENT_TARGETS.items()
        if component in selected
    }
    database_system: str | None = None
    target_revisions: tuple[str, ...] = ()
    schema_state: str | None = None
    if "database" in selected:
        (
            database_system,
            target_revisions,
            schema_state,
            db_blockers,
        ) = await _inspect_target_database(engine, manifest, selected_paths)
        blockers.extend(db_blockers)
        try:
            _foreign_key_restore_plan()
        except RestoreCompatibilityError as exc:
            blockers.append(str(exc))
        database_target = Path(_database_target_path(engine, selected_paths))
        target_paths["database"] = str(database_target)
        if schema_state == "empty" and database_system == "sqlite":
            warnings.append(
                "A staged SQLite database will be migrated to this release's Alembic head "
                "before import."
            )
        if database_system == "sqlite":
            if _path_has_symlink_ancestor(database_target):
                blockers.append("SQLite database target path must not contain symlinks.")
            if not database_target.parent.is_dir():
                blockers.append("SQLite database parent directory does not exist.")
            elif not os.access(database_target.parent, os.W_OK):
                blockers.append("SQLite database parent directory is not writable.")
            elif database_target.parent.stat().st_dev != selected_paths.instance.stat().st_dev:
                blockers.append(
                    "SQLite database target is on a different filesystem from the instance; "
                    "atomic replacement is unavailable."
                )

    config_coverage: Literal["not-selected", "absent", "complete", "partial"]
    if "config" not in selected:
        config_coverage = "not-selected"
    elif "config" not in available:
        config_coverage = "absent"
    elif manifest.omitted_sensitive:
        config_coverage = "partial"
        warnings.append(
            "Configuration is partial; omitted secret-bearing files will be preserved "
            "from the target."
        )
    else:
        config_coverage = "complete"

    estimated = sum(
        file.uncompressed_size_bytes
        for component in manifest.components
        if component.name in selected
        for file in component.files
    )
    if "config" in selected and config_coverage == "partial":
        estimated += _tree_size(selected_paths.config)
    for component in selected:
        if component == "database":
            continue
        target = getattr(selected_paths, component)
        if target.is_symlink():
            blockers.append(f"Target component {component!r} is a symlink.")
        if target.exists() and not target.is_dir():
            blockers.append(f"Target component {component!r} is not a directory.")
        if target.exists() and selected_paths.instance.exists():
            if target.stat().st_dev != selected_paths.instance.stat().st_dev:
                blockers.append(
                    f"Target component {component!r} is on another filesystem and cannot be "
                    "swapped safely."
                )

    if "data" in selected and "database" not in selected:
        preserved_database = _configured_sqlite_database_path(selected_paths, engine)
        if preserved_database is not None:
            for candidate in (
                preserved_database,
                *(Path(f"{preserved_database}{suffix}") for suffix in ("-wal", "-shm", "-journal")),
            ):
                try:
                    if candidate.is_file() and not candidate.is_symlink():
                        estimated += candidate.stat().st_size
                except OSError:
                    pass
    staging_bytes = estimated
    staging_base = _staging_base(selected_paths)
    if (
        staging_bytes
        and shutil.disk_usage(_nearest_existing_directory(staging_base)).free < staging_bytes
    ):
        blockers.append("Insufficient free space for the selected restore staging data.")

    journal = restore_journal_path(selected_paths)
    incomplete = _path_exists_or_symlink(journal)
    if incomplete:
        warnings.append(
            "An incomplete restore journal exists; recover it before applying another restore."
        )
        blockers.append("A previous restore is incomplete and requires recovery.")
    if _path_exists_or_symlink(restore_maintenance_path(selected_paths)):
        warnings.append(
            "A restore maintenance marker exists; recover before applying another restore."
        )
        blockers.append("A previous restore is still marked in maintenance mode.")

    return RestorePlan(
        backup_id=manifest.backup_id,
        created_at=manifest.created_at,
        format_version=manifest.format_version,
        arborpress_version=manifest.arborpress_version,
        backup_database_system=manifest.database_system,
        backup_alembic_revisions=manifest.alembic_revisions,
        target_database_system=database_system,
        target_alembic_revisions=target_revisions,
        target_schema_state=schema_state,
        selected_components=selected,
        available_components=available,
        config_coverage=config_coverage,
        omitted_sensitive=tuple(manifest.omitted_sensitive) if config_coverage == "partial" else (),
        target_paths=target_paths,
        estimated_uncompressed_bytes=estimated,
        compatible=not blockers,
        blockers=tuple(dict.fromkeys(blockers)),
        warnings=tuple(dict.fromkeys(warnings)),
        verification_ok=True,
        incomplete_restore=incomplete,
    )


async def stage_restore(
    plan: RestorePlan,
    *,
    paths: ArborPressPaths | None = None,
    engine: AsyncEngine | None = None,
    restore_id: str | None = None,
    key: BackupKey | None = None,
) -> StagedRestore:
    """Verify again, then extract selected file components only into private staging."""
    selected_paths = paths or get_runtime_paths()
    if not plan.compatible:
        raise RestoreCompatibilityError("Restore plan is blocked: " + "; ".join(plan.blockers))
    backup_dir = _backup_directory(plan.backup_id, selected_paths)
    manifest = BackupManifest.from_toml((backup_dir / MANIFEST_NAME).read_bytes())
    verify_backup_set(backup_dir, key=key)
    encryption_context = (
        context_from_manifest(key, manifest.encryption_parameters.as_parameters())
        if key is not None and manifest.encryption_parameters is not None
        else None
    )
    if manifest.encryption != "none" and encryption_context is None:
        raise RestoreError("Encrypted backup apply requires its passphrase or keyfile.")
    selected_restore_id = restore_id or uuid.uuid4().hex
    staging_root = _create_staging_root(selected_paths, plan.backup_id, selected_restore_id)
    component_roots: dict[str, Path] = {}
    database_stream: Path | None = None
    database_staged_path: Path | None = None
    database_target_path: Path | None = None
    database_row_counts: dict[str, int] | None = None
    warnings: list[str] = []
    try:
        for component in manifest.components:
            if component.name not in plan.selected_components:
                continue
            if component.name == "database":
                if len(component.files) != 1:
                    raise BackupVerificationError(
                        "Database component must contain exactly one logical stream."
                    )
                database_stream = await _stage_database_stream(
                    backup_dir,
                    staging_root,
                    component.files[0],
                    encryption_context=encryption_context,
                    manifest=manifest,
                )
                _validate_database_header(
                    database_stream,
                    cast(CompressionBackend, manifest.compression_backend),
                    manifest.alembic_revisions,
                )
                database_target_path = Path(plan.target_paths["database"])
                if plan.target_database_system == "sqlite":
                    database_staged_path, database_row_counts = await _prepare_sqlite_database(
                        database_stream,
                        selected_paths,
                        database_target_path,
                        cast(CompressionBackend, manifest.compression_backend),
                        manifest.alembic_revisions,
                        selected_restore_id,
                    )
                continue
            target_root = staging_root / component.name
            target_root.mkdir(mode=0o700)
            component_roots[component.name] = target_root
            seen: set[str] = set()
            for file in component.files:
                archive_path = _safe_backup_file(backup_dir, file.path)
                if encryption_context is not None:
                    with decrypted_component_file(
                        archive_path,
                        context=encryption_context,
                        backup_id=manifest.backup_id,
                        relative_path=file.path,
                        manifest_version=manifest.format_version,
                    ) as decrypted_path:
                        _extract_archive(
                            decrypted_path,
                            target_root,
                            file,
                            cast(CompressionBackend, manifest.compression_backend),
                            seen,
                        )
                else:
                    _extract_archive(
                        archive_path,
                        target_root,
                        file,
                        cast(CompressionBackend, manifest.compression_backend),
                        seen,
                    )
                digest, size = sha256_file(archive_path)
                if digest != file.sha256 or size != file.size_bytes:
                    raise BackupVerificationError(
                        f"Backup component changed while staging: {file.path}"
                    )
            expected_paths = {path for file in component.files for path in file.member_paths}
            if _staged_member_paths(target_root) != expected_paths:
                raise BackupVerificationError(
                    f"Staged {component.name} inventory does not match its manifest."
                )

        if "config" in component_roots and plan.config_coverage == "partial":
            component_roots["config"] = _merge_partial_config(
                selected_paths.config,
                component_roots["config"],
                staging_root,
            )
        if "data" in component_roots and "database" not in plan.selected_components:
            _preserve_sqlite_database(
                selected_paths,
                component_roots["data"],
                engine=engine,
            )
        history_root = component_roots.get("data", selected_paths.data)
        _validate_restore_history_root(history_root)
        if "themes" in component_roots:
            warnings.extend(_validate_staged_themes(component_roots["themes"]))
        return StagedRestore(
            backup_id=plan.backup_id,
            restore_id=selected_restore_id,
            staging_root=staging_root,
            component_roots=component_roots,
            database_stream=database_stream,
            database_staged_path=database_staged_path,
            database_target_path=database_target_path,
            database_row_counts=database_row_counts,
            database_system=manifest.database_system,
            alembic_revisions=manifest.alembic_revisions,
            config_coverage=plan.config_coverage,
            manifest=manifest,
            warnings=tuple(warnings),
        )
    except Exception:
        if database_staged_path is not None:
            _remove_path(database_staged_path)
            for suffix in ("-wal", "-shm", "-journal"):
                Path(str(database_staged_path) + suffix).unlink(missing_ok=True)
        _remove_staging_root(selected_paths, staging_root)
        raise


async def validate_restore_staging(
    plan: RestorePlan,
    *,
    paths: ArborPressPaths | None = None,
    engine: AsyncEngine | None = None,
    key: BackupKey | None = None,
) -> tuple[str, ...]:
    """Exercise safe extraction and staged DB preparation, then discard staging.

    This is suitable for ``restore apply --dry-run``: it verifies the complete
    set and all selected staged content without switching any live roots.
    Server databases are validated structurally but not imported into a live
    or temporary server database.
    """
    selected_paths = paths or get_runtime_paths()
    with backup_lock(selected_paths):
        if _restore_markers_present(selected_paths):
            raise RestoreRecoveryRequired(
                "An incomplete restore is present; run restore recover before dry-run staging."
            )
        staged = await stage_restore(plan, paths=selected_paths, engine=engine, key=key)
        try:
            return staged.warnings
        finally:
            if staged.database_staged_path is not None:
                _remove_path(staged.database_staged_path)
                for suffix in ("-wal", "-shm", "-journal"):
                    Path(f"{staged.database_staged_path}{suffix}").unlink(missing_ok=True)
            _remove_staging_root(selected_paths, staged.staging_root)


async def _inspect_target_database(
    supplied_engine: AsyncEngine | None,
    manifest: BackupManifest,
    paths: ArborPressPaths,
) -> tuple[str | None, tuple[str, ...], str, list[str]]:
    from arborpress.core.migrations import SchemaStatus, migration_history, schema_status

    engine = supplied_engine
    owns_engine = False
    if engine is None:
        from arborpress.core.config import get_settings

        url = make_url(get_settings().db.url)
    else:
        url = engine.url

    if url.drivername.startswith("sqlite"):
        if not url.database or url.database == ":memory:":
            return (
                "sqlite",
                (),
                "unsupported",
                ["Restore to an in-memory SQLite database is not supported."],
            )
        db_file = _absolute_path_without_symlink_resolution(Path(url.database))
        if not db_file.exists():
            head = migration_history()[0][0]
            status = SchemaStatus("empty", (), head, "SQLite target file does not exist.")
            engine = None
        elif supplied_engine is None:
            readonly_url = url.update_query_dict({"mode": "ro", "uri": "true"})
            engine = create_async_engine(
                readonly_url,
                poolclass=NullPool,
                connect_args={"timeout": 30},
            )
            owns_engine = True
    elif engine is None:
        engine = create_async_engine(url)
        owns_engine = True
    blockers: list[str] = []
    try:
        if engine is not None:
            status = await schema_status(engine)
            backend = await _engine_backend(engine)
        else:
            backend = "sqlite"
        backup_backend = manifest.database_system or ""
        if backend != backup_backend:
            blockers.append(
                f"Cross-backend restore is disabled ({backup_backend} backup to {backend} target)."
            )
        revisions = manifest.alembic_revisions
        history = {revision for revision, _, _ in migration_history()}
        if len(revisions) != 1 or revisions[0] not in history:
            blockers.append("Backup does not name one known ArborPress Alembic revision.")
        elif status.head_revision != revisions[0]:
            blockers.append(
                "This release can restore only backups at its current Alembic head; "
                "the backup revision is not the current release head."
            )
        if status.state not in {"current", "empty"}:
            blockers.append(
                f"Target database schema state {status.state!r} is not safe for restore."
            )
        if status.state == "current" and status.current_revisions != revisions:
            blockers.append("Target database revision does not exactly match the backup revision.")
        if status.state == "empty" and backend != "sqlite":
            blockers.append("Server database restore requires an existing current schema.")
        return backend, status.current_revisions, status.state, blockers
    finally:
        if owns_engine and engine is not None:
            await engine.dispose()


async def _engine_backend(engine: AsyncEngine) -> str:
    dialect = engine.dialect.name
    if dialect == "sqlite":
        return "sqlite"
    if dialect == "postgresql":
        return "postgresql"
    if dialect in {"mysql", "mariadb"}:
        async with engine.connect() as connection:
            value = str(await connection.scalar(sa.text("SELECT VERSION()")) or "")
        return "mariadb" if "mariadb" in value.lower() else "mysql"
    return dialect


def _foreign_key_restore_plan() -> dict[str, tuple[str, ...]]:
    """Return nullable FK columns needed to safely break schema cycles.

    Every edge participating in a cycle is cleared before delete and restored
    after all rows are inserted. A non-nullable cycle cannot be restored with
    the supported cross-backend DML-only algorithm and is rejected.
    """
    import arborpress.models  # noqa: F401 - register all application tables
    from arborpress.core.db import Base

    tables = list(Base.metadata.sorted_tables)
    by_name = {table.name: table for table in tables}
    graph: dict[str, set[str]] = {name: set() for name in by_name}
    edges: list[tuple[str, str, str, bool | None]] = []
    for table in tables:
        for foreign_key in table.foreign_keys:
            source = table.name
            target = foreign_key.column.table.name
            graph[source].add(target)
            edges.append((source, target, foreign_key.parent.name, foreign_key.parent.nullable))

    def reaches(start: str, target: str) -> bool:
        pending = [start]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current == target:
                return True
            if current in visited:
                continue
            visited.add(current)
            pending.extend(graph[current] - visited)
        return False

    deferred: dict[str, set[str]] = {}
    for source, target, column, nullable in edges:
        if source != target and not reaches(target, source):
            continue
        if not nullable:
            raise RestoreCompatibilityError(
                f"Database foreign-key cycle includes non-nullable {source}.{column}."
            )
        deferred.setdefault(source, set()).add(column)

    table_order = {table.name: index for index, table in enumerate(tables)}
    for source, target, column, _nullable in edges:
        if column in deferred.get(source, set()):
            continue
        if table_order[target] >= table_order[source]:
            raise RestoreCompatibilityError(
                f"Database table order cannot satisfy foreign key {source}.{column}."
            )
    return {name: tuple(sorted(columns)) for name, columns in deferred.items()}


def _database_target_path(engine: AsyncEngine | None, paths: ArborPressPaths) -> str:
    if engine is not None:
        url = engine.url
    else:
        from arborpress.core.config import get_settings

        url = make_url(get_settings().db.url)
    if url.drivername.startswith("sqlite") and url.database and url.database != ":memory:":
        return str(_absolute_path_without_symlink_resolution(Path(url.database)))
    return f"configured {url.get_backend_name()} database (credentials omitted)"


def _backup_directory(backup_id: str, paths: ArborPressPaths) -> Path:
    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise ValueError(f"Invalid backup ID: {backup_id!r}")
    root = paths.backups
    if root.is_symlink() or not root.is_dir():
        raise BackupError("The active prefix has no safe backup root.")
    candidate = root / backup_id
    if candidate.is_symlink() or not candidate.is_dir():
        raise FileNotFoundError(f"Backup set not found: {backup_id}")
    return candidate


def restore_journal_path(paths: ArborPressPaths) -> Path:
    return paths.run / RESTORE_JOURNAL_NAME


def restore_maintenance_path(paths: ArborPressPaths) -> Path:
    return paths.run / RESTORE_MAINTENANCE_NAME


def _path_exists_or_symlink(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _restore_markers_present(paths: ArborPressPaths) -> bool:
    return any(
        _path_exists_or_symlink(path)
        for path in (restore_journal_path(paths), restore_maintenance_path(paths))
    )


def restore_history_path(paths: ArborPressPaths, restore_id: str) -> Path:
    if not restore_id or any(character not in "0123456789abcdef-" for character in restore_id):
        raise ValueError("Invalid restore ID")
    return paths.data / RESTORE_HISTORY_DIRNAME / f"{restore_id}.json"


def _create_staging_root(paths: ArborPressPaths, backup_id: str, restore_id: str) -> Path:
    _assert_real_instance_directory(paths.instance, paths.prefix)
    _assert_real_instance_directory(paths.run, paths.instance)
    _assert_real_instance_directory(paths.tmp, paths.instance)
    base = _staging_base(paths)
    prefix = (
        f".{RESTORE_STAGING_PREFIX}{backup_id}-{restore_id[:12]}-"
        if base == paths.instance
        else f"{RESTORE_STAGING_PREFIX}{backup_id}-{restore_id[:12]}-"
    )
    created = Path(tempfile.mkdtemp(prefix=prefix, dir=base))
    os.chmod(created, 0o700)
    return created


def _staging_base(paths: ArborPressPaths) -> Path:
    """Use a private temp root on the same filesystem as instance root swaps."""
    instance_device = paths.instance.stat().st_dev
    return paths.tmp if paths.tmp.stat().st_dev == instance_device else paths.instance


def _assert_real_instance_directory(path: Path, allowed_root: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise RestoreError(f"Instance restore directory is not a real directory: {path.name}")
    try:
        if not path.resolve(strict=True).is_relative_to(allowed_root.resolve(strict=True)):
            raise RestoreError(f"Instance restore directory escapes its prefix: {path.name}")
    except OSError as exc:
        raise RestoreError(f"Cannot resolve instance restore directory: {path.name}") from exc


def _extract_archive(
    archive_path: Path,
    destination: Path,
    metadata: BackupFile,
    backend: CompressionBackend,
    seen_paths: set[str],
) -> None:
    initial_count = len(seen_paths)
    with open_compressed_reader(archive_path, backend) as compressed:
        with tarfile.open(fileobj=compressed, mode="r|") as archive:
            for member in archive:
                relative = _validate_member_path(member.name)
                if relative in seen_paths:
                    raise UnsafeRestoreEntryError(f"Duplicate archive member: {relative}")
                _check_member_ancestors(relative, member, seen_paths)
                seen_paths.add(relative)
                target = destination.joinpath(*PurePosixPath(relative).parts)
                _ensure_staging_parent(destination, target.parent)
                if member.isdir():
                    if target.exists() and not target.is_dir():
                        raise UnsafeRestoreEntryError(f"Conflicting archive path: {relative}")
                    target.mkdir(mode=0o700, exist_ok=True)
                    target.chmod(
                        _safe_mode(member.mode, config=destination.name == "config", directory=True)
                    )
                    os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
                elif member.issym():
                    _validate_symlink_target(relative, member.linkname)
                    if target.exists() or target.is_symlink():
                        raise UnsafeRestoreEntryError(f"Conflicting archive path: {relative}")
                    os.symlink(member.linkname, target)
                elif member.isreg():
                    if target.exists() or target.is_symlink():
                        raise UnsafeRestoreEntryError(f"Conflicting archive path: {relative}")
                    source = archive.extractfile(member)
                    if source is None:
                        raise UnsafeRestoreEntryError(f"Cannot read archive member: {relative}")
                    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(
                        target, flags, _safe_mode(member.mode, config=destination.name == "config")
                    )
                    with source, os.fdopen(descriptor, "wb") as output:
                        remaining = member.size
                        while remaining:
                            chunk = source.read(min(COPY_CHUNK_SIZE, remaining))
                            if not chunk:
                                raise UnsafeRestoreEntryError(
                                    f"Truncated archive member: {relative}"
                                )
                            output.write(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    target.chmod(_safe_mode(member.mode, config=destination.name == "config"))
                    os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
                else:
                    raise UnsafeRestoreEntryError(f"Unsupported archive member type: {relative}")
    if len(seen_paths) - initial_count != metadata.members:
        raise BackupVerificationError("TAR member count does not match the manifest")


def _validate_member_path(value: str) -> str:
    path = value.rstrip("/")
    validate_relative_path(path)
    if ":" in path or "\\" in value:
        raise UnsafeRestoreEntryError(f"Unsafe archive member path: {value!r}")
    return path


def _check_member_ancestors(relative: str, member: tarfile.TarInfo, seen_paths: set[str]) -> None:
    parents = PurePosixPath(relative).parents
    for parent in parents:
        name = parent.as_posix()
        if name == ".":
            continue
        if name in seen_paths:
            # Explicit directory entries are safe; files and symlinks are not.
            # The caller checks their actual staged type before creating children.
            continue
    if member.islnk() or member.isdev() or member.isfifo():
        raise UnsafeRestoreEntryError(f"Unsupported TAR member type: {relative}")


def _ensure_staging_parent(root: Path, parent: Path) -> None:
    relative = parent.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise UnsafeRestoreEntryError("Archive member traverses a staged symlink")
        if current.exists():
            if not current.is_dir():
                raise UnsafeRestoreEntryError("Archive member traverses a non-directory path")
        else:
            current.mkdir(mode=0o700)


def _validate_symlink_target(member_name: str, target: str) -> None:
    if not target or target.startswith("/") or "\\" in target or "\x00" in target or ":" in target:
        raise UnsafeRestoreEntryError(f"Unsafe symlink target for {member_name}")
    resolved = posixpath.normpath(posixpath.join(str(PurePosixPath(member_name).parent), target))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise UnsafeRestoreEntryError(f"Symlink escapes component staging root: {member_name}")


def _safe_mode(mode: int, *, config: bool = False, directory: bool = False) -> int:
    sanitized = stat.S_IMODE(mode) & ~0o6000
    if config:
        sanitized &= ~0o077
    if directory:
        sanitized |= 0o700
    else:
        sanitized |= 0o600
    return sanitized


def _staged_member_paths(root: Path) -> set[str]:
    paths: set[str] = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        for name in list(directories):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                paths.add(relative)
                directories.remove(name)
            else:
                paths.add(relative)
        for name in files:
            paths.add((base / name).relative_to(root).as_posix())
    return paths


async def _stage_database_stream(
    backup_dir: Path,
    staging_root: Path,
    file: BackupFile,
    *,
    encryption_context: EncryptionContext | None = None,
    manifest: BackupManifest | None = None,
) -> Path:
    source = _safe_backup_file(backup_dir, file.path)
    target_root = staging_root / "database"
    target_root.mkdir(mode=0o700)
    filename = PurePosixPath(file.path).name.removesuffix(".apenc")
    target = target_root / filename
    if encryption_context is not None and manifest is not None:
        decrypt_file_to_path(
            source,
            target,
            context=encryption_context,
            backup_id=manifest.backup_id,
            relative_path=file.path,
            manifest_version=manifest.format_version,
        )
        return target
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as input_stream, target.open("xb") as output_stream:
        while chunk := input_stream.read(COPY_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
            output_stream.write(chunk)
        output_stream.flush()
        os.fsync(output_stream.fileno())
    if digest.hexdigest() != file.sha256 or size != file.size_bytes:
        raise BackupVerificationError(f"Database backup changed while staging: {file.path}")
    return target


def _validate_database_header(
    stream_path: Path,
    compression_backend: CompressionBackend,
    expected_revisions: tuple[str, ...],
) -> None:
    """Compare the logical stream declaration with this release's metadata."""
    import io

    import arborpress.models  # noqa: F401
    from arborpress.backups.database import DATABASE_HEADER_KIND, DATABASE_STREAM_VERSION
    from arborpress.core.db import Base

    with open_compressed_reader(stream_path, compression_backend) as compressed:
        text = io.TextIOWrapper(compressed, encoding="utf-8", newline="\n")
        try:
            header = json.loads(text.readline())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BackupVerificationError("Database stream header is malformed") from exc
        finally:
            text.detach()
    if (
        not isinstance(header, dict)
        or header.get("kind") != DATABASE_HEADER_KIND
        or header.get("format_version") != DATABASE_STREAM_VERSION
        or header.get("alembic_revisions") != list(expected_revisions)
    ):
        raise RestoreCompatibilityError("Database stream format or revision is unsupported.")
    declarations = header.get("tables")
    if not isinstance(declarations, list):
        raise BackupVerificationError("Database stream has no table declarations")
    expected_tables = Base.metadata.sorted_tables
    names: list[str] = []
    for declaration in declarations:
        if not isinstance(declaration, dict) or not isinstance(declaration.get("name"), str):
            raise BackupVerificationError("Malformed database table declaration")
        name = declaration["name"]
        names.append(name)
        table = next((candidate for candidate in expected_tables if candidate.name == name), None)
        columns = declaration.get("columns")
        if table is None or not isinstance(columns, list):
            raise RestoreCompatibilityError(f"Unknown database table in stream: {name!r}")
        column_names = [item.get("name") for item in columns if isinstance(item, dict)]
        if column_names != [column.name for column in table.columns]:
            raise RestoreCompatibilityError(f"Database columns differ for table {name!r}.")
    if names != [table.name for table in expected_tables]:
        raise RestoreCompatibilityError(
            "Database tables do not exactly match this ArborPress release."
        )


async def _prepare_sqlite_database(
    stream_path: Path,
    paths: ArborPressPaths,
    target_path: Path,
    compression_backend: CompressionBackend,
    expected_revisions: tuple[str, ...],
    restore_id: str,
) -> tuple[Path, dict[str, int]]:
    """Build and verify a complete SQLite replacement beside its live file."""
    from sqlalchemy import event
    from sqlalchemy.engine import URL

    from arborpress.core.migrations import schema_status, upgrade_database

    staged_path = paths.instance / f".restore-db-{restore_id}.tmp"
    if _path_has_symlink_ancestor(target_path) or not target_path.parent.is_dir():
        raise RestoreError("SQLite database parent is not a safe real directory.")
    descriptor = os.open(
        staged_path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    os.close(descriptor)
    engine = create_async_engine(
        URL.create("sqlite+aiosqlite", database=str(staged_path)), poolclass=NullPool
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_restore_pragmas(connection: Any, _: Any) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA journal_mode=DELETE")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    try:
        status = await upgrade_database(engine)
        if status.state != "current" or tuple(expected_revisions) != (status.head_revision,):
            raise RestoreCompatibilityError(
                "The SQLite backup revision is not the packaged Alembic head."
            )
        row_counts = await _import_database_stream(
            engine,
            stream_path,
            compression_backend,
            expected_revisions=expected_revisions,
            replace_existing=False,
        )
        final_status = await schema_status(engine)
        if final_status.state != "current" or final_status.current_revisions != expected_revisions:
            raise RestoreError("Staged SQLite database did not pass the schema end check.")
        async with engine.connect() as connection:
            integrity = str(await connection.scalar(sa.text("PRAGMA integrity_check")) or "")
            if integrity.lower() != "ok":
                raise RestoreError("Staged SQLite database failed PRAGMA integrity_check.")
        if staged_path.is_symlink() or not staged_path.is_file():
            raise RestoreError("Staged SQLite database file was not created safely.")
        return staged_path, row_counts
    except Exception:
        _remove_path(staged_path)
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(staged_path) + suffix).unlink(missing_ok=True)
        raise
    finally:
        # NullPool has no persistent connections; disposal closes the last
        # SQLite connection before the file is atomically swapped.
        await engine.dispose()


def _preserve_sqlite_database(
    paths: ArborPressPaths,
    staged_data: Path,
    *,
    engine: AsyncEngine | None = None,
) -> None:
    """Keep a SQLite DB untouched when the user selects only the data root."""
    database = _configured_sqlite_database_path(paths, engine)
    if database is None:
        return
    try:
        relative = database.relative_to(paths.data.resolve(strict=False))
    except ValueError:
        return
    source = paths.data / relative
    if source.is_symlink():
        raise RestoreError("SQLite database file is a symlink and cannot be preserved safely.")
    if source.exists():
        if not source.is_file():
            raise RestoreError("SQLite database target is not a regular file.")
        _copy_stable_file(source, staged_data / relative, paths.data, staged_data)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(source) + suffix)
        if sidecar.is_symlink():
            raise RestoreError("SQLite database sidecar is a symlink.")
        if sidecar.exists():
            if not sidecar.is_file():
                raise RestoreError("SQLite database sidecar is not a regular file.")
            _copy_stable_file(
                sidecar,
                Path(str(staged_data / relative) + suffix),
                paths.data,
                staged_data,
            )


def _configured_sqlite_database_path(
    paths: ArborPressPaths, engine: AsyncEngine | None = None
) -> Path | None:
    if engine is not None:
        url = engine.url
    else:
        from arborpress.core.config import get_settings

        url = make_url(get_settings().db.url)
    if not url.drivername.startswith("sqlite") or not url.database or url.database == ":memory:":
        return None
    return _absolute_path_without_symlink_resolution(Path(url.database))


def _absolute_path_without_symlink_resolution(path: Path) -> Path:
    """Normalize a path lexically while preserving symlinks for safety checks."""
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _path_has_symlink_ancestor(path: Path) -> bool:
    absolute = _absolute_path_without_symlink_resolution(path)
    return any(candidate.is_symlink() for candidate in (absolute, *absolute.parents))


def _copy_stable_file(
    source: Path, destination: Path, source_root: Path, destination_root: Path
) -> None:
    """Copy one stable regular file without following a source symlink."""
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise RestoreError("A preserved database file is not regular.")
    if not source.resolve(strict=True).is_relative_to(source_root.resolve(strict=True)):
        raise RestoreError("A preserved database path escapes its data root.")
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(source_fd)
        if _stat_signature(opened) != _stat_signature(before):
            raise RestoreError("A database file changed before staging.")
        _ensure_staging_parent(destination_root, destination.parent)
        output_fd = os.open(
            destination,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with (
            os.fdopen(os.dup(source_fd), "rb") as input_stream,
            os.fdopen(output_fd, "wb") as output_stream,
        ):
            shutil.copyfileobj(input_stream, output_stream, COPY_CHUNK_SIZE)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        after = source.lstat()
        if _stat_signature(before) != _stat_signature(after):
            destination.unlink(missing_ok=True)
            raise RestoreError("A database file changed while staging.")
    finally:
        os.close(source_fd)


def _stat_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


async def import_database_stream(
    engine: AsyncEngine,
    stream_path: Path,
    compression_backend: CompressionBackend,
    *,
    expected_revisions: tuple[str, ...],
    replace_existing: bool = True,
    before_commit: Callable[[], None] | None = None,
) -> dict[str, int]:
    """Replace ArborPress table rows from the 6A typed NDJSON stream.

    The caller owns the enclosing rollback/apply policy. Server databases use
    one DML transaction; SQLite callers should use a fresh migrated staging DB.
    """
    async with engine.begin() as connection:
        if connection.dialect.name in {"mysql", "mariadb"}:
            await _require_innodb_tables(connection)
        await _import_database_stream(
            engine,
            stream_path,
            compression_backend,
            expected_revisions=expected_revisions,
            replace_existing=replace_existing,
            connection=connection,
        )
        counts = await _application_row_counts(connection)
        if connection.dialect.name == "postgresql":
            await _reset_postgresql_sequences(connection)
        elif connection.dialect.name == "sqlite":
            foreign_key_errors = await connection.exec_driver_sql("PRAGMA foreign_key_check")
            if foreign_key_errors.first() is not None:
                raise RestoreError("Database import failed SQLite foreign-key validation.")
        if before_commit is not None:
            before_commit()
        return counts


async def _import_database_stream(
    engine: AsyncEngine,
    stream_path: Path,
    compression_backend: CompressionBackend,
    *,
    expected_revisions: tuple[str, ...],
    replace_existing: bool,
    connection: AsyncConnection | None = None,
) -> dict[str, int]:
    import io

    import arborpress.models  # noqa: F401 - register all application tables
    from arborpress.backups.database import (
        DATABASE_HEADER_KIND,
        DATABASE_STREAM_VERSION,
        decode_value,
    )
    from arborpress.core.db import Base

    owns_connection = connection is None
    if connection is None:
        connection = await engine.connect()
    assert connection is not None
    transaction_context: Any = connection.begin() if owns_connection else contextlib.nullcontext()
    counts: dict[str, int] = {}
    expected_counts: dict[str, int] = {}
    tables_by_name = {table.name: table for table in Base.metadata.sorted_tables}
    deferred_columns = _foreign_key_restore_plan()
    try:
        async with transaction_context:
            if replace_existing:
                for table_name, column_names in deferred_columns.items():
                    table = tables_by_name[table_name]
                    await connection.execute(
                        table.update().values(**{name: None for name in column_names})
                    )
                for table in reversed(Base.metadata.sorted_tables):
                    await connection.execute(table.delete())
            with open_compressed_reader(stream_path, compression_backend) as compressed:
                text = io.TextIOWrapper(compressed, encoding="utf-8", newline="\n")
                deferred = tempfile.TemporaryFile(
                    mode="w+t", encoding="utf-8", dir=stream_path.parent
                )
                try:
                    first = text.readline()
                    header = json.loads(first) if first else None
                    if (
                        not isinstance(header, dict)
                        or header.get("kind") != DATABASE_HEADER_KIND
                        or header.get("format_version") != DATABASE_STREAM_VERSION
                    ):
                        raise BackupVerificationError("Unsupported logical database stream header")
                    raw_revisions = header.get("alembic_revisions")
                    if raw_revisions != list(expected_revisions):
                        raise RestoreCompatibilityError("Database stream Alembic revision mismatch")
                    table_headers = header.get("tables")
                    if not isinstance(table_headers, list):
                        raise BackupVerificationError("Database stream has no table declarations")
                    declared: dict[str, list[str]] = {}
                    for item in table_headers:
                        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                            raise BackupVerificationError("Malformed database table declaration")
                        name = item["name"]
                        columns = item.get("columns")
                        if name not in tables_by_name or not isinstance(columns, list):
                            raise BackupVerificationError(
                                f"Unknown ArborPress database table in stream: {name!r}"
                            )
                        names = [
                            column.get("name") for column in columns if isinstance(column, dict)
                        ]
                        if names != [column.name for column in tables_by_name[name].columns]:
                            raise RestoreCompatibilityError(
                                f"Database columns differ for ArborPress table {name!r}."
                            )
                        declared[name] = names
                    expected_names = [table.name for table in Base.metadata.sorted_tables]
                    if list(declared) != expected_names:
                        raise RestoreCompatibilityError(
                            "Database stream tables do not exactly match this ArborPress schema."
                        )

                    batch_size = 250
                    batches: dict[str, list[dict[str, object]]] = {
                        name: [] for name in expected_names
                    }
                    counts = {name: 0 for name in expected_names}
                    deferred_count = 0
                    while line := text.readline():
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise BackupVerificationError("Malformed database row JSON") from exc
                        if (
                            not isinstance(record, dict)
                            or record.get("kind") != "row"
                            or record.get("table") not in declared
                            or not isinstance(record.get("values"), list)
                        ):
                            raise BackupVerificationError("Malformed database row record")
                        table_name = record["table"]
                        encoded_values = record["values"]
                        row_columns = declared[table_name]
                        if len(encoded_values) != len(row_columns):
                            raise BackupVerificationError("Database row column count mismatch")
                        decoded_values = [decode_value(value) for value in encoded_values]
                        row = dict(zip(row_columns, decoded_values, strict=True))
                        self_columns = deferred_columns.get(table_name, ())
                        if self_columns:
                            original = {name: row[name] for name in self_columns}
                            for name in self_columns:
                                row[name] = None
                            primary_key = {
                                column.name: row[column.name]
                                for column in tables_by_name[table_name].primary_key.columns
                            }
                            deferred.write(
                                json.dumps(
                                    {
                                        "table": table_name,
                                        "primary_key": {
                                            key: _json_value_for_deferred(value)
                                            for key, value in primary_key.items()
                                        },
                                        "values": {
                                            key: _json_value_for_deferred(value)
                                            for key, value in original.items()
                                        },
                                    },
                                    separators=(",", ":"),
                                )
                                + "\n"
                            )
                            deferred_count += 1
                        batches[table_name].append(row)
                        counts[table_name] += 1
                        if len(batches[table_name]) >= batch_size:
                            await connection.execute(
                                tables_by_name[table_name].insert(), batches[table_name]
                            )
                            batches[table_name].clear()
                    for name in expected_names:
                        if batches[name]:
                            await connection.execute(tables_by_name[name].insert(), batches[name])
                    deferred.seek(0)
                    while line := deferred.readline():
                        item = json.loads(line)
                        table = tables_by_name[item["table"]]
                        primary_key = {
                            key: _decode_deferred(value)
                            for key, value in item["primary_key"].items()
                        }
                        values = {
                            key: _decode_deferred(value) for key, value in item["values"].items()
                        }
                        predicate = sa.and_(
                            *(table.c[key] == value for key, value in primary_key.items())
                        )
                        await connection.execute(table.update().where(predicate).values(**values))
                    if deferred_count and connection.dialect.name == "postgresql":
                        await connection.exec_driver_sql("SET CONSTRAINTS ALL IMMEDIATE")
                    text.detach()
                finally:
                    deferred.close()
                    with contextlib.suppress(Exception):
                        text.detach()
            expected_counts = counts
            actual_counts = await _application_row_counts(connection)
            if actual_counts != expected_counts:
                raise RestoreError("Imported database row counts failed end validation.")
            await _validate_current_revision(connection, expected_revisions)
        return counts
    finally:
        if owns_connection:
            await connection.close()


def _json_value_for_deferred(value: object) -> dict[str, Any]:
    from arborpress.backups.database import encode_value

    return encode_value(value)


def _decode_deferred(value: object) -> object:
    from arborpress.backups.database import decode_value

    return decode_value(value)


async def _application_row_counts(connection: AsyncConnection) -> dict[str, int]:
    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base

    return {
        table.name: int(await connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0)
        for table in Base.metadata.sorted_tables
    }


async def _require_innodb_tables(connection: AsyncConnection) -> None:
    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base

    rows = await connection.execute(
        sa.text(
            "SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = DATABASE()"
        )
    )
    engines = {str(row[0]): str(row[1] or "").lower() for row in rows}
    unsupported = [
        table.name for table in Base.metadata.sorted_tables if engines.get(table.name) != "innodb"
    ]
    if unsupported:
        raise RestoreCompatibilityError(
            "Transactional restore requires InnoDB ArborPress tables: "
            + ", ".join(sorted(unsupported))
        )


async def _reset_postgresql_sequences(connection: AsyncConnection) -> None:
    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base

    preparer = connection.dialect.identifier_preparer
    for table in Base.metadata.sorted_tables:
        primary_key = list(table.primary_key.columns)
        if len(primary_key) != 1 or not isinstance(primary_key[0].type, sa.Integer):
            continue
        sequence = await connection.execute(
            sa.text(
                "SELECT namespaces.nspname, sequences.relname "
                "FROM pg_class AS sequences "
                "JOIN pg_namespace AS namespaces ON namespaces.oid = sequences.relnamespace "
                "WHERE sequences.oid = pg_get_serial_sequence(:table_name, :column_name)::regclass"
            ),
            {"table_name": table.fullname, "column_name": primary_key[0].name},
        )
        sequence_row = sequence.first()
        if sequence_row is None:
            continue
        maximum = await connection.scalar(sa.select(sa.func.max(primary_key[0])))
        next_value = int(maximum) + 1 if maximum is not None else None
        qualified_sequence = (
            f"{preparer.quote_schema(str(sequence_row[0]))}.{preparer.quote(str(sequence_row[1]))}"
        )
        restart = f" RESTART WITH {next_value}" if next_value is not None else " RESTART"
        # RESTART is transactional (unlike setval), preserving PostgreSQL's
        # rollback guarantee for the surrounding application-table import.
        await connection.exec_driver_sql(f"ALTER SEQUENCE {qualified_sequence}{restart}")


async def _reset_mariadb_autoincrements(engine: AsyncEngine) -> None:
    """Reset MariaDB/MySQL counters after the committed DML-only import."""
    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base

    preparer = engine.dialect.identifier_preparer
    async with engine.connect() as connection:
        for table in Base.metadata.sorted_tables:
            primary_key = list(table.primary_key.columns)
            if (
                len(primary_key) != 1
                or not isinstance(primary_key[0].type, sa.Integer)
                or primary_key[0].autoincrement is False
            ):
                continue
            maximum = await connection.scalar(sa.select(sa.func.max(primary_key[0])))
            next_value = int(maximum) + 1 if maximum is not None else 1
            qualified_table = preparer.format_table(table, use_schema=False)
            # MariaDB AUTO_INCREMENT is DDL and commits implicitly. Keep it out
            # of the transactional row replacement; failures are journaled as
            # post-commit recovery-required by apply_restore.
            await connection.exec_driver_sql(
                f"ALTER TABLE {qualified_table} AUTO_INCREMENT = {next_value}"
            )


async def _validate_current_revision(
    connection: AsyncConnection, expected_revisions: tuple[str, ...]
) -> None:
    """Inspect the Alembic stamp using the existing connection and transaction."""
    from alembic.runtime.migration import MigrationContext

    revisions = tuple(
        sorted(
            await connection.run_sync(
                lambda sync_connection: MigrationContext.configure(
                    sync_connection
                ).get_current_heads()
            )
        )
    )
    if revisions != expected_revisions:
        raise RestoreCompatibilityError(
            "Imported database revision differs from the backup revision."
        )


def _safe_backup_file(root: Path, relative: str) -> Path:
    validate_relative_path(relative)
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BackupVerificationError(f"Backup component is not a regular file: {relative}")
    if not resolved.is_relative_to(root.resolve(strict=True)):
        raise BackupVerificationError(f"Backup component escapes its set: {relative}")
    return candidate


def _merge_partial_config(live: Path, overlay: Path, staging_root: Path) -> Path:
    extracted = staging_root / "config-overlay"
    os.replace(overlay, extracted)
    merged = staging_root / "config"
    merged.mkdir(mode=0o700)
    if live.exists():
        _copy_config_tree(live, merged)
    _overlay_config_tree(extracted, merged)
    shutil.rmtree(extracted)
    return merged


def _copy_config_tree(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise RestoreError("Cannot preserve partial configuration from an unsafe target root.")
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        base = Path(current)
        relative_dir = base.relative_to(source)
        target_dir = destination / relative_dir
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        safe_dirs: list[str] = []
        for name in sorted(directories):
            item = base / name
            output = target_dir / name
            if item.is_symlink():
                _copy_safe_symlink(item, output, source)
            else:
                output.mkdir(mode=0o700, exist_ok=True)
                safe_dirs.append(name)
        directories[:] = safe_dirs
        for name in sorted(files):
            item = base / name
            output = target_dir / name
            if item.is_symlink():
                _copy_safe_symlink(item, output, source)
            elif item.is_file():
                _copy_config_file(item, output)
            else:
                raise RestoreError(
                    "Partial configuration contains an unsupported filesystem entry."
                )


def _copy_safe_symlink(source: Path, target: Path, root: Path) -> None:
    link = os.readlink(source)
    if os.path.isabs(link):
        raise RestoreError("Cannot preserve an absolute configuration symlink.")
    try:
        if (
            not (source.parent / link)
            .resolve(strict=False)
            .is_relative_to(root.resolve(strict=True))
        ):
            raise RestoreError("Cannot preserve a configuration symlink escaping its root.")
    except (OSError, RuntimeError) as exc:
        raise RestoreError("Cannot resolve a configuration symlink safely.") from exc
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.symlink(link, target)


def _copy_config_file(source: Path, target: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RestoreError("Cannot preserve a non-regular configuration file.")
        output_descriptor = os.open(
            target,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with (
            os.fdopen(os.dup(descriptor), "rb") as input_stream,
            os.fdopen(output_descriptor, "wb") as output_stream,
        ):
            shutil.copyfileobj(input_stream, output_stream, COPY_CHUNK_SIZE)
            output_stream.flush()
            os.fsync(output_stream.fileno())
    finally:
        os.close(descriptor)


def _overlay_config_tree(overlay: Path, destination: Path) -> None:
    for current, directories, files in os.walk(overlay, topdown=True, followlinks=False):
        base = Path(current)
        relative_dir = base.relative_to(overlay)
        target_dir = destination / relative_dir
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        safe_dirs: list[str] = []
        for name in sorted(directories):
            item = base / name
            output = target_dir / name
            if item.is_symlink():
                if output.exists() or output.is_symlink():
                    _remove_path(output)
                _copy_safe_symlink(item, output, overlay)
            else:
                if output.exists() and not output.is_dir():
                    _remove_path(output)
                output.mkdir(mode=0o700, exist_ok=True)
                safe_dirs.append(name)
        directories[:] = safe_dirs
        for name in sorted(files):
            item = base / name
            output = target_dir / name
            if output.exists() or output.is_symlink():
                _remove_path(output)
            if item.is_symlink():
                _copy_safe_symlink(item, output, overlay)
            else:
                _copy_config_file(item, output)


def _remove_path(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path)


def _validate_staged_themes(root: Path) -> list[str]:
    from arborpress.themes.manifest import ThemeRegistry

    registry = ThemeRegistry(extra_dirs=[root])
    registry.load()
    diagnostics = []
    for record in registry.records():
        if record.source == "instance" and record.status != "valid":
            diagnostics.append(
                f"Theme {record.id!r} is {record.status}: {'; '.join(record.diagnostics)}"
            )
    return diagnostics


def _validate_restore_history_root(data_root: Path) -> None:
    if data_root.is_symlink() or not data_root.is_dir():
        raise RestoreError("Restore history requires a real ArborPress data directory.")
    history = data_root / RESTORE_HISTORY_DIRNAME
    if history.is_symlink() or (history.exists() and not history.is_dir()):
        raise RestoreError("Restore history path must be a real directory, not a link or file.")


def _tree_size(root: Path) -> int:
    if root.is_symlink() or not root.is_dir():
        return 0
    total = 0
    for current, _, files in os.walk(root, followlinks=False):
        for name in files:
            path = Path(current) / name
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
    return total


def _nearest_existing_directory(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        candidate = candidate.parent
    return candidate


def _remove_staging_root(paths: ArborPressPaths, root: Path) -> None:
    try:
        if (
            root.is_dir()
            and not root.is_symlink()
            and root.resolve(strict=True).is_relative_to(paths.instance.resolve(strict=True))
        ):
            shutil.rmtree(root)
    except OSError, RuntimeError:
        log.exception("Could not safely remove restore staging root")


async def apply_restore(
    backup_id: str,
    *,
    paths: ArborPressPaths | None = None,
    components: tuple[str, ...] | None = None,
    engine: AsyncEngine | None = None,
    offline: bool = False,
    safety_backup: bool = False,
    key: BackupKey | None = None,
) -> dict[str, Any]:
    """Verify, stage and apply a restore while holding the per-instance lock.

    ``offline`` is an explicit operator attestation: ArborPress cannot reliably
    quiesce arbitrary external ASGI workers. The maintenance marker blocks
    requests in workers which remain alive, but a full restore must be run
    with the web service stopped.
    """
    if not offline:
        raise RestoreError("Restore apply requires --offline; stop all web workers first.")
    selected_paths = paths or get_runtime_paths()
    restore_id = uuid.uuid4().hex
    started_at = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    report: dict[str, Any] = {
        "restore_id": restore_id,
        "backup_id": backup_id,
        "actor": "cli",
        "started_at": started_at,
        "finished_at": None,
        "components": list(components or ()),
        "verify": {"ok": False},
        "file_roots": [],
        "warnings": [],
        "database": {"backend": None, "revision_before": None, "revision_after": None},
        "safety_backup_id": None,
        "end_checks": {},
        "rollback_performed": False,
        "result": "failed",
        "last_safe_phase": "preflight",
    }
    staged: StagedRestore | None = None
    journal: dict[str, Any] | None = None
    plan: RestorePlan | None = None
    db_committed = False
    database_engine = engine
    owns_database_engine = False
    with backup_lock(selected_paths):
        if _restore_markers_present(selected_paths):
            raise RestoreRecoveryRequired(
                "An incomplete restore is present; run restore recover before applying "
                "another restore."
            )
        try:
            plan = await plan_restore(
                backup_id,
                paths=selected_paths,
                components=components,
                engine=engine,
                key=key,
            )
            report["components"] = list(plan.selected_components)
            report["verify"] = {"ok": plan.verification_ok}
            report["database"] = {
                "backend": plan.target_database_system,
                "revision_before": list(plan.target_alembic_revisions),
                "revision_after": None,
            }
            report["last_safe_phase"] = "verified"
            if not plan.compatible:
                raise RestoreCompatibilityError(
                    "Restore plan is blocked: " + "; ".join(plan.blockers)
                )
            staged = await stage_restore(
                plan,
                paths=selected_paths,
                engine=engine,
                restore_id=restore_id,
                key=key,
            )
            report["warnings"] = list(plan.warnings) + list(staged.warnings)
            report["last_safe_phase"] = "staged-and-validated"

            if safety_backup:
                safety = await create_backup(
                    paths=selected_paths,
                    engine=engine,
                    _lock_already_held=True,
                )
                report["safety_backup_id"] = safety.backup_id

            journal = {
                "format_version": RESTORE_FORMAT_VERSION,
                "restore_id": restore_id,
                "backup_id": backup_id,
                "started_at": started_at,
                "staging_root": str(staged.staging_root),
                "phase": "applying-files",
                "selected_components": list(plan.selected_components),
                "swaps": [],
                "database_backend": plan.target_database_system,
                "database_staged_path": (
                    str(staged.database_staged_path)
                    if staged.database_staged_path is not None
                    else None
                ),
                "database_committed": False,
                "database_commit_started": False,
            }
            _write_restore_journal(selected_paths, journal)
            _write_restore_marker(selected_paths, journal)
            report["last_safe_phase"] = "maintenance-enabled"

            replace_sqlite_file = (
                "database" in plan.selected_components and plan.target_database_system == "sqlite"
            )
            configured_sqlite_path = _configured_sqlite_database_path(selected_paths, engine)
            replace_data_around_sqlite = (
                "data" in plan.selected_components
                and "database" not in plan.selected_components
                and configured_sqlite_path is not None
                and configured_sqlite_path.is_relative_to(selected_paths.data.resolve(strict=False))
            )
            if replace_sqlite_file or replace_data_around_sqlite:
                if database_engine is not None:
                    await database_engine.dispose()
                else:
                    from arborpress.core import db as db_module

                    if db_module._engine is not None:
                        await db_module._engine.dispose()

            for component in plan.selected_components:
                if component == "database":
                    continue
                staged_root = staged.component_roots[component]
                target = getattr(selected_paths, component)
                rollback = (
                    selected_paths.instance / f"{RESTORE_ROLLBACK_PREFIX}{restore_id}-{component}"
                )
                entry = {
                    "component": component,
                    "target": str(target),
                    "rollback": str(rollback),
                    "staged": str(staged_root),
                    "kind": "directory",
                    "had_original": target.exists() or target.is_symlink(),
                    "old_moved": False,
                    "new_moved": False,
                }
                journal["swaps"].append(entry)
                _write_restore_journal(selected_paths, journal)
                _switch_path(staged_root, target, rollback, entry, selected_paths, journal)
                report["file_roots"].append(str(target))
                report["last_safe_phase"] = f"files-switched:{component}"

            if "database" in plan.selected_components:
                assert staged.database_stream is not None
                if plan.target_database_system == "sqlite":
                    assert staged.database_staged_path is not None
                    assert staged.database_target_path is not None
                    await _switch_sqlite_database(
                        staged.database_staged_path,
                        staged.database_target_path,
                        selected_paths,
                        restore_id,
                        journal,
                    )
                    report["last_safe_phase"] = "sqlite-database-switched"
                    db_committed = True
                    _write_restore_journal(selected_paths, journal)
                    report["database"]["revision_after"] = list(staged.alembic_revisions)
                    report["end_checks"]["sqlite_integrity"] = "ok"
                    report["end_checks"]["foreign_key_check"] = "passed"
                    report["end_checks"]["schema"] = "current"
                    report["end_checks"]["row_counts"] = staged.database_row_counts or {}
                else:
                    if database_engine is None:
                        from arborpress.core.db import create_engine_for_cli

                        database_engine = create_engine_for_cli()
                        owns_database_engine = True

                    def _mark_database_commit_started() -> None:
                        journal["database_commit_started"] = True
                        journal["phase"] = "database-commit-started"
                        _write_restore_journal(selected_paths, journal)

                    counts = await import_database_stream(
                        database_engine,
                        staged.database_stream,
                        cast(CompressionBackend, staged.manifest.compression_backend),
                        expected_revisions=staged.alembic_revisions,
                        replace_existing=True,
                        before_commit=_mark_database_commit_started,
                    )
                    db_committed = True
                    journal["database_committed"] = True
                    journal["phase"] = "database-committed"
                    _write_restore_journal(selected_paths, journal)
                    report["database"]["revision_after"] = list(staged.alembic_revisions)
                    report["end_checks"]["row_counts"] = counts
                    report["last_safe_phase"] = "database-committed"
                    if plan.target_database_system in {"mariadb", "mysql"}:
                        await _reset_mariadb_autoincrements(database_engine)
                        report["end_checks"]["auto_increment_reset"] = True
                    from arborpress.core.migrations import schema_status

                    status = await schema_status(database_engine)
                    if (
                        status.state != "current"
                        or status.current_revisions != staged.alembic_revisions
                    ):
                        raise RestoreRecoveryRequired(
                            "Database committed but its post-commit schema check failed."
                        )
                    report["end_checks"]["schema"] = status.state

            report["end_checks"]["selected_file_roots_exist"] = all(
                getattr(selected_paths, component).is_dir()
                for component in plan.selected_components
                if component != "database"
            )
            if report["end_checks"]["selected_file_roots_exist"] is False:
                raise RestoreRecoveryRequired("A restored file root failed its existence check.")
            report["last_safe_phase"] = "end-checks-passed"
            report["result"] = "success"
            report["finished_at"] = _utc_now()
            report["last_safe_phase"] = "complete"
            journal["phase"] = "complete"
            _write_restore_journal(selected_paths, journal)
            _write_restore_history(selected_paths, report)
            _cleanup_restore_swaps(journal)
            _clear_restore_markers(selected_paths)
            if staged.database_staged_path is not None:
                Path(staged.database_staged_path).unlink(missing_ok=True)
            _remove_staging_root(selected_paths, staged.staging_root)
            log.info("Restore %s for backup %s completed", restore_id, backup_id)
            return report
        except Exception as exc:
            report["finished_at"] = _utc_now()
            report["error"] = type(exc).__name__
            if journal is not None and _path_exists_or_symlink(
                restore_maintenance_path(selected_paths)
            ):
                if journal.get("phase") == "complete":
                    report["result"] = "recovery-required"
                elif (
                    plan is not None
                    and plan.target_database_system != "sqlite"
                    and journal.get("database_commit_started")
                    and not db_committed
                ):
                    journal["phase"] = "recovery-required-database-commit-uncertain"
                    report["result"] = "recovery-required"
                    report["rollback_performed"] = False
                elif db_committed and plan is not None and plan.target_database_system != "sqlite":
                    journal["phase"] = "recovery-required-after-database-commit"
                    journal["database_committed"] = True
                    report["result"] = "recovery-required"
                    report["rollback_performed"] = False
                else:
                    try:
                        _rollback_swaps(selected_paths, journal)
                        report["rollback_performed"] = bool(journal["swaps"])
                        report["result"] = "rolled-back"
                        journal["phase"] = "rolled-back"
                    except Exception as rollback_error:
                        log.error(
                            "Restore %s rollback failed (%s); maintenance remains enabled",
                            restore_id,
                            type(rollback_error).__name__,
                        )
                        journal["phase"] = "recovery-required"
                        report["result"] = "recovery-required"
                    _write_restore_journal(selected_paths, journal)
                    if report["result"] == "rolled-back":
                        _clear_restore_markers(selected_paths)
            elif journal is not None:
                # No maintenance marker means no live mutation began.
                restore_journal_path(selected_paths).unlink(missing_ok=True)
            _write_restore_history(selected_paths, report)
            if staged is not None and report["result"] != "recovery-required":
                if staged.database_staged_path is not None:
                    Path(staged.database_staged_path).unlink(missing_ok=True)
                _remove_staging_root(selected_paths, staged.staging_root)
            log.error(
                "Restore %s for backup %s failed in phase %s (%s)",
                restore_id,
                backup_id,
                report["last_safe_phase"],
                type(exc).__name__,
            )
            if report["result"] == "recovery-required":
                raise RestoreRecoveryRequired(
                    f"Restore {restore_id} requires recovery; the maintenance marker remains."
                ) from None
            if isinstance(exc, BackupVerificationError):
                raise
            if isinstance(exc, RestoreError):
                raise
            raise RestoreError(
                f"Restore failed in phase {report['last_safe_phase']} ({type(exc).__name__})."
            ) from None
        finally:
            if owns_database_engine and database_engine is not None:
                await database_engine.dispose()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _atomic_json(path: Path, value: dict[str, Any], *, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise RestoreError(f"Restore metadata path must not be a symlink: {path.name}")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _write_restore_journal(paths: ArborPressPaths, journal: dict[str, Any]) -> None:
    _atomic_json(restore_journal_path(paths), journal)


def _write_restore_marker(paths: ArborPressPaths, journal: dict[str, Any]) -> None:
    _atomic_json(
        restore_maintenance_path(paths),
        {
            "restore_id": journal["restore_id"],
            "backup_id": journal["backup_id"],
            "started_at": journal["started_at"],
            "pid": os.getpid(),
        },
    )


def _clear_restore_markers(paths: ArborPressPaths) -> None:
    restore_maintenance_path(paths).unlink(missing_ok=True)
    restore_journal_path(paths).unlink(missing_ok=True)
    _fsync_directory(paths.run)


def _switch_path(
    staged: Path,
    target: Path,
    rollback: Path,
    entry: dict[str, Any],
    paths: ArborPressPaths,
    journal: dict[str, Any],
) -> None:
    if _path_has_symlink_ancestor(target) or rollback.exists() or rollback.is_symlink():
        raise RestoreError("Unsafe or pre-existing restore target/rollback path.")
    if not target.parent.is_dir() or target.parent.is_symlink():
        raise RestoreError("Restore target parent is not a safe directory.")
    if entry["had_original"]:
        os.replace(target, rollback)
        entry["old_moved"] = True
        _write_restore_journal(paths, journal)
    os.replace(staged, target)
    entry["new_moved"] = True
    _write_restore_journal(paths, journal)


async def _switch_sqlite_database(
    staged: Path,
    target: Path,
    paths: ArborPressPaths,
    restore_id: str,
    journal: dict[str, Any],
) -> None:
    if _path_has_symlink_ancestor(target):
        raise RestoreError("SQLite database target path must not contain symlinks.")
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(target) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            if sidecar.is_symlink() or not sidecar.is_file():
                raise RestoreError("SQLite WAL/SHM sidecar is not a regular file.")
            rollback = sidecar.with_name(f".{sidecar.name}{RESTORE_ROLLBACK_PREFIX}{restore_id}")
            entry = {
                "component": f"database{suffix}",
                "target": str(sidecar),
                "rollback": str(rollback),
                "kind": "file",
                "had_original": True,
                "old_moved": False,
                "new_moved": False,
            }
            journal["swaps"].append(entry)
            _write_restore_journal(paths, journal)
            os.replace(sidecar, rollback)
            entry["old_moved"] = True
            _write_restore_journal(paths, journal)
    rollback = target.with_name(f".{target.name}{RESTORE_ROLLBACK_PREFIX}{restore_id}")
    entry = {
        "component": "database",
        "target": str(target),
        "rollback": str(rollback),
        "staged": str(staged),
        "kind": "file",
        "had_original": target.exists(),
        "old_moved": False,
        "new_moved": False,
    }
    journal["swaps"].append(entry)
    journal["phase"] = "switching-sqlite-database"
    _write_restore_journal(paths, journal)
    _switch_path(staged, target, rollback, entry, paths, journal)
    journal["database_committed"] = True
    journal["phase"] = "sqlite-database-switched"
    _write_restore_journal(paths, journal)


def _rollback_swaps(paths: ArborPressPaths, journal: dict[str, Any]) -> None:
    for entry in reversed(journal.get("swaps", [])):
        if not isinstance(entry, dict):
            raise RestoreRecoveryRequired("Restore journal contains an invalid swap entry.")
        target = Path(str(entry["target"]))
        rollback = Path(str(entry["rollback"]))
        _validate_journal_paths(
            paths,
            entry,
            journal,
        )
        staged_raw = entry.get("staged")
        staged_was_moved = (
            isinstance(staged_raw, str)
            and not Path(staged_raw).exists()
            and (target.exists() or target.is_symlink())
            and (rollback.exists() or not entry.get("had_original"))
        )
        if entry.get("new_moved") or staged_was_moved:
            _remove_path(target)
            entry["new_moved"] = False
            _write_restore_journal(paths, journal)
        if entry.get("old_moved") or rollback.exists() or rollback.is_symlink():
            if not rollback.exists() and not rollback.is_symlink():
                raise RestoreRecoveryRequired(
                    f"Missing rollback path for {entry.get('component')}."
                )
            os.replace(rollback, target)
            entry["old_moved"] = False
            _write_restore_journal(paths, journal)


def _validate_journal_paths(
    paths: ArborPressPaths,
    entry: dict[str, Any],
    journal: dict[str, Any],
) -> None:
    target = Path(str(entry.get("target", "")))
    rollback = Path(str(entry.get("rollback", "")))
    component = str(entry.get("component", ""))
    restore_id = str(journal.get("restore_id", ""))
    if any(
        type(entry.get(name)) is not bool for name in ("had_original", "old_moved", "new_moved")
    ):
        raise RestoreRecoveryRequired("Restore journal contains invalid swap state flags.")
    if component in RESTORE_COMPONENTS:
        if entry.get("kind") != "directory":
            raise RestoreRecoveryRequired("Restore journal component kind is invalid.")
        if target != getattr(paths, component):
            raise RestoreRecoveryRequired("Restore journal target does not match this instance.")
        expected_rollback = paths.instance / f"{RESTORE_ROLLBACK_PREFIX}{restore_id}-{component}"
        stage_root = Path(str(journal.get("staging_root", "")))
        staged = Path(str(entry.get("staged", "")))
        expected_staged = stage_root / component
        valid_stage_parent = stage_root.parent in {paths.instance, paths.tmp}
        backup_id = str(journal.get("backup_id", ""))
        expected_stage_prefix = (
            f".{RESTORE_STAGING_PREFIX}{backup_id}-{restore_id[:12]}-"
            if stage_root.parent == paths.instance
            else f"{RESTORE_STAGING_PREFIX}{backup_id}-{restore_id[:12]}-"
        )
        if (
            rollback != expected_rollback
            or not valid_stage_parent
            or not BACKUP_ID_RE.fullmatch(backup_id)
            or not stage_root.name.startswith(expected_stage_prefix)
            or staged != expected_staged
            or not stage_root.resolve(strict=False).is_relative_to(
                paths.instance.resolve(strict=True)
            )
        ):
            raise RestoreRecoveryRequired("Restore rollback path escapes the instance root.")
    elif component.startswith("database"):
        if entry.get("kind") != "file":
            raise RestoreRecoveryRequired("Restore journal database kind is invalid.")
        target_db = Path(_database_target_path(None, paths))
        suffix = component.removeprefix("database")
        if suffix not in {"", "-wal", "-shm", "-journal"}:
            raise RestoreRecoveryRequired("Restore journal names an unknown database file.")
        expected_target = Path(str(target_db) + suffix)
        if target != expected_target:
            raise RestoreRecoveryRequired("Restore journal database target does not match config.")
        expected_rollback = target.with_name(f".{target.name}{RESTORE_ROLLBACK_PREFIX}{restore_id}")
        if rollback != expected_rollback:
            raise RestoreRecoveryRequired("Database rollback path does not match its target.")
        staged_raw = entry.get("staged")
        if component == "database" and (
            not isinstance(staged_raw, str)
            or Path(staged_raw) != paths.instance / f".restore-db-{restore_id}.tmp"
        ):
            raise RestoreRecoveryRequired("Staged database path does not match this instance.")
    else:
        raise RestoreRecoveryRequired("Restore journal names an unknown component.")


def recover_restore(paths: ArborPressPaths | None = None) -> dict[str, Any]:
    """Roll back an interrupted pre-commit restore, never guessing after DB commit."""
    selected_paths = paths or get_runtime_paths()
    journal_path = restore_journal_path(selected_paths)
    marker_path = restore_maintenance_path(selected_paths)
    with backup_lock(selected_paths):
        if not journal_path.is_file() or journal_path.is_symlink():
            raise RestoreRecoveryRequired(
                "Restore maintenance marker has no safe journal; manual inspection is required."
            )
        try:
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RestoreRecoveryRequired(
                "Restore journal is unreadable; manual recovery is required."
            ) from exc
        if (
            not isinstance(journal, dict)
            or journal.get("format_version") != RESTORE_FORMAT_VERSION
            or not isinstance(journal.get("restore_id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", journal.get("restore_id", ""))
            or not isinstance(journal.get("swaps"), list)
            or type(journal.get("database_committed")) is not bool
            or type(journal.get("database_commit_started")) is not bool
            or not isinstance(journal.get("selected_components"), list)
            or any(
                not isinstance(component, str) or component not in {*RESTORE_COMPONENTS, "database"}
                for component in journal.get("selected_components", [])
            )
        ):
            raise RestoreRecoveryRequired("Restore journal format is unsupported.")
        if (
            journal.get("phase") != "complete"
            and journal.get("database_backend") != "sqlite"
            and (journal.get("database_committed") or journal.get("database_commit_started"))
        ):
            raise RestoreRecoveryRequired(
                "The server database commit completed or its outcome is uncertain; automatic "
                "rollback is unsafe. Keep the service offline and inspect the restore report."
            )
        restore_id = journal["restore_id"]
        for entry in journal["swaps"]:
            if not isinstance(entry, dict):
                raise RestoreRecoveryRequired("Restore journal contains an invalid swap entry.")
            _validate_journal_paths(selected_paths, entry, journal)
        if journal.get("phase") != "complete":
            _rollback_swaps(selected_paths, journal)
            result = "rolled-back"
        else:
            result = "completed-cleanup"
        _cleanup_restore_swaps(journal)
        staging_root = journal.get("staging_root")
        if isinstance(staging_root, str):
            staged_path = Path(staging_root)
            if not staged_path.resolve(strict=False).is_relative_to(
                selected_paths.instance.resolve(strict=True)
            ):
                raise RestoreRecoveryRequired("Restore staging root escapes the active instance.")
            _remove_staging_root(selected_paths, staged_path)
        database_staged_path = journal.get("database_staged_path")
        if isinstance(database_staged_path, str):
            staged_database = Path(database_staged_path)
            if staged_database != selected_paths.instance / f".restore-db-{restore_id}.tmp":
                raise RestoreRecoveryRequired("Staged database path does not match this instance.")
            _remove_path(staged_database)
        report = {
            "restore_id": restore_id,
            "backup_id": journal.get("backup_id"),
            "actor": "cli",
            "started_at": journal.get("started_at"),
            "finished_at": _utc_now(),
            "components": journal.get("selected_components", []),
            "verify": {"ok": True},
            "file_roots": [],
            "warnings": [],
            "database": {
                "backend": journal.get("database_backend"),
                "revision_before": None,
                "revision_after": None,
            },
            "safety_backup_id": None,
            "end_checks": {"recovery": result},
            "rollback_performed": result == "rolled-back",
            "result": result,
            "last_safe_phase": "recovery",
        }
        _write_restore_history(selected_paths, report)
        marker_path.unlink(missing_ok=True)
        journal_path.unlink(missing_ok=True)
        _fsync_directory(selected_paths.run)
        return report


def _cleanup_restore_swaps(journal: dict[str, Any]) -> None:
    for entry in journal.get("swaps", []):
        rollback = Path(str(entry["rollback"]))
        if rollback.exists() or rollback.is_symlink():
            _remove_path(rollback)


def _write_restore_history(paths: ArborPressPaths, report: dict[str, Any]) -> None:
    _assert_real_instance_directory(paths.data, paths.instance)
    history_dir = paths.data / RESTORE_HISTORY_DIRNAME
    if history_dir.is_symlink():
        raise RestoreError("Restore history directory must not be a symlink.")
    history_dir.mkdir(mode=0o700, exist_ok=True)
    _assert_real_instance_directory(history_dir, paths.data)
    history = restore_history_path(paths, str(report["restore_id"]))
    _atomic_json(history, report)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
