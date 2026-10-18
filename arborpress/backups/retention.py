"""Explicit local pin, prune and abandoned-set cleanup operations."""

from __future__ import annotations

import os
import re
import shutil
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from arborpress.backups.manifest import BACKUP_ID_RE, BackupVerificationError
from arborpress.backups.service import BackupError, _require_instance_directory, backup_lock
from arborpress.backups.verify import verify_backup_set
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout, get_runtime_paths

INCOMPLETE_NAME_RE = re.compile(r"^\.incomplete-([0-9]{8}-[0-9]{6}(?:-[0-9]{2,})?)-([0-9a-f]{32})$")
RETENTION_STATE_DIR = "backup-local-state"
INCOMPLETE_MIN_AGE = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class PrunePlan:
    backup_ids: tuple[str, ...]
    kept_ids: tuple[str, ...]
    pinned_ids: tuple[str, ...]
    dry_run: bool


def _state_root(paths: ArborPressPaths) -> Path:
    if paths.var.is_symlink() or paths.instance.is_symlink():
        raise BackupError("Backup retention state parent must not be a symlink")
    root = paths.var / RETENTION_STATE_DIR
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise BackupError("Backup retention state path is not a safe directory")
    try:
        if not root.resolve(strict=False).is_relative_to(paths.instance.resolve(strict=True)):
            raise BackupError("Backup retention state escapes the instance root")
    except OSError as exc:
        raise BackupError("Could not resolve backup retention state root") from exc
    return root


def _state_path(paths: ArborPressPaths, backup_id: str) -> Path:
    if not BACKUP_ID_RE.fullmatch(backup_id):
        raise ValueError(f"Invalid backup ID: {backup_id!r}")
    return _state_root(paths) / f"{backup_id}.toml"


def _is_pinned(paths: ArborPressPaths, backup_id: str) -> bool:
    path = _state_path(paths, backup_id)
    if not path.exists() and not path.is_symlink():
        return False
    if path.is_symlink() or not path.is_file():
        # A malformed or redirected state must never make a set deletable.
        return True
    try:
        state = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return True
    return state.get("backup_id") != backup_id or state.get("pinned") is not False


def pin_backup(
    backup_id: str, *, paths: ArborPressPaths | None = None, pinned: bool = True
) -> Path:
    selected = paths or get_runtime_paths()
    ensure_instance_layout(selected)
    with backup_lock(selected):
        from arborpress.backups.service import _backup_directory

        directory = _backup_directory(backup_id, selected)
        verify_backup_set(directory)
        state_root = _state_root(selected)
        state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = _state_path(selected, backup_id)
        content = f'backup_id = "{backup_id}"\npinned = {str(pinned).lower()}\n'
        temporary = path.with_name(path.name + ".part")
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return path


def plan_prune(
    *,
    keep_last: int | None = None,
    keep_days: int | None = None,
    paths: ArborPressPaths | None = None,
    now: datetime | None = None,
) -> PrunePlan:
    if keep_last is None and keep_days is None:
        raise ValueError("Specify --keep-last or --keep-days")
    if keep_last is not None and keep_last < 0:
        raise ValueError("--keep-last must be non-negative")
    if keep_days is not None and keep_days < 0:
        raise ValueError("--keep-days must be non-negative")
    selected = paths or get_runtime_paths()
    root = selected.backups
    if root.is_symlink():
        raise BackupError("The instance backup root must not be a symlink")
    if not root.exists():
        return PrunePlan((), (), (), True)
    _require_instance_directory(root, selected.instance, "backup root")
    candidates: list[tuple[str, datetime]] = []
    for directory in root.iterdir():
        if directory.is_symlink() or not directory.is_dir() or directory.name.startswith("."):
            continue
        if not BACKUP_ID_RE.fullmatch(directory.name):
            continue
        try:
            report = verify_backup_set(directory)
            manifest_path = directory / "manifest.toml"
            from arborpress.backups.manifest import BackupManifest

            manifest = BackupManifest.from_toml(manifest_path.read_bytes())
            if report.backup_id != directory.name:
                continue
            created = datetime.fromisoformat(manifest.created_at.replace("Z", "+00:00"))
            candidates.append((directory.name, created))
        except (OSError, ValueError, BackupVerificationError):
            continue
    candidates.sort(key=lambda item: (item[1], item[0]), reverse=True)
    protected: set[str] = set()
    if keep_last:
        protected.update(backup_id for backup_id, _ in candidates[:keep_last])
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("Retention clock must be timezone-aware")
    if keep_days is not None:
        cutoff = instant.astimezone(UTC) - timedelta(days=keep_days)
        protected.update(backup_id for backup_id, created in candidates if created >= cutoff)
    pinned = {backup_id for backup_id, _ in candidates if _is_pinned(selected, backup_id)}
    protected.update(pinned)
    if candidates:
        protected.add(candidates[0][0])
    remove = tuple(backup_id for backup_id, _ in candidates if backup_id not in protected)
    kept = tuple(backup_id for backup_id, _ in candidates if backup_id in protected)
    return PrunePlan(remove, kept, tuple(sorted(pinned)), True)


def prune_backups(
    *,
    keep_last: int | None = None,
    keep_days: int | None = None,
    paths: ArborPressPaths | None = None,
    now: datetime | None = None,
    dry_run: bool = True,
) -> PrunePlan:
    selected = paths or get_runtime_paths()
    ensure_instance_layout(selected)
    with backup_lock(selected):
        plan = plan_prune(keep_last=keep_last, keep_days=keep_days, paths=selected, now=now)
        if not dry_run:
            root = selected.backups.resolve(strict=True)
            for backup_id in plan.backup_ids:
                candidate = selected.backups / backup_id
                if (
                    candidate.is_symlink()
                    or not candidate.is_dir()
                    or candidate.resolve(strict=True).parent != root
                ):
                    raise BackupError(f"Refusing to prune unsafe backup path: {backup_id}")
                shutil.rmtree(candidate)
                _state_path(selected, backup_id).unlink(missing_ok=True)
        return PrunePlan(plan.backup_ids, plan.kept_ids, plan.pinned_ids, dry_run)


def cleanup_incomplete(
    *,
    older_than: timedelta = INCOMPLETE_MIN_AGE,
    paths: ArborPressPaths | None = None,
    now: datetime | None = None,
    dry_run: bool = True,
) -> tuple[str, ...]:
    if older_than < INCOMPLETE_MIN_AGE:
        raise ValueError("Incomplete sets must be at least 24 hours old before cleanup")
    selected = paths or get_runtime_paths()
    ensure_instance_layout(selected)
    with backup_lock(selected):
        root = selected.backups
        if root.is_symlink():
            raise BackupError("The instance backup root must not be a symlink")
        if not root.exists():
            return ()
        _require_instance_directory(root, selected.instance, "backup root")
        cutoff = (now or datetime.now(UTC)).timestamp() - older_than.total_seconds()
        found: list[Path] = []
        for candidate in root.iterdir():
            if (
                candidate.is_symlink()
                or not candidate.is_dir()
                or INCOMPLETE_NAME_RE.fullmatch(candidate.name) is None
            ):
                continue
            try:
                metadata = candidate.lstat()
                if metadata.st_mtime <= cutoff and candidate.resolve(
                    strict=True
                ).parent == root.resolve(strict=True):
                    found.append(candidate)
            except OSError:
                continue
        if not dry_run:
            for candidate in found:
                shutil.rmtree(candidate)
        return tuple(sorted(candidate.name for candidate in found))
