"""Safe, stable-file PAX archive creation using Python's tarfile module."""

from __future__ import annotations

import os
import stat
import tarfile
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from arborpress.backups.compression import CompressionSettings, open_compressed_writer
from arborpress.backups.manifest import BackupFile, sha256_file, validate_relative_path

DEFAULT_MEDIA_SEGMENT_SIZE = 2 * 1024**3
STABLE_READ_ATTEMPTS = 3
COPY_CHUNK_SIZE = 1024 * 1024


class UnsafeArchiveEntryError(ValueError):
    """An instance tree contains an unsupported or escaping filesystem entry."""


class UnstableFileError(OSError):
    """A source file changed during repeated attempts to read it stably."""


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    relative_path: PurePosixPath
    source_path: Path
    kind: str
    size_bytes: int
    mode: int
    mtime: int
    symlink_target: str | None = None


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    file: BackupFile
    archive_path: Path


def scan_tree(
    root: Path,
    *,
    ignored_paths: Iterable[Path] = (),
) -> list[ArchiveEntry]:
    """Walk a component root deterministically without following symlinks."""
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise NotADirectoryError(f"Backup component root is not a directory: {root}")
    resolved_root = root.resolve(strict=True)
    ignored = {path.resolve(strict=False) for path in ignored_paths}
    entries: list[ArchiveEntry] = []

    def visit(directory: Path, relative: PurePosixPath) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise OSError(f"Cannot read backup directory {directory}: {exc}") from exc
        for child in children:
            source = directory / child.name
            child_relative = relative / child.name
            if source.resolve(strict=False) in ignored:
                continue
            try:
                metadata = source.lstat()
            except OSError as exc:
                raise OSError(f"Cannot inspect backup path {source}: {exc}") from exc
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                entries.append(
                    ArchiveEntry(
                        child_relative, source, "directory", 0, mode, int(metadata.st_mtime)
                    )
                )
                visit(source, child_relative)
            elif stat.S_ISREG(metadata.st_mode):
                entries.append(
                    ArchiveEntry(
                        child_relative,
                        source,
                        "file",
                        metadata.st_size,
                        mode,
                        int(metadata.st_mtime),
                    )
                )
            elif stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(source)
                if os.path.isabs(target):
                    raise UnsafeArchiveEntryError(
                        f"Absolute symlink is not backup-safe: {child_relative}"
                    )
                try:
                    resolved_target = (source.parent / target).resolve(strict=False)
                except (OSError, RuntimeError) as exc:
                    raise UnsafeArchiveEntryError(
                        f"Could not safely resolve symlink {child_relative}: {exc}"
                    ) from exc
                if not resolved_target.is_relative_to(resolved_root):
                    raise UnsafeArchiveEntryError(
                        f"Symlink escapes component root: {child_relative}"
                    )
                entries.append(
                    ArchiveEntry(
                        child_relative,
                        source,
                        "symlink",
                        0,
                        mode,
                        int(metadata.st_mtime),
                        target,
                    )
                )
            else:
                raise UnsafeArchiveEntryError(
                    f"Unsupported special file in backup component: {child_relative}"
                )

    visit(root, PurePosixPath())
    return entries


def create_component_archives(
    *,
    root: Path,
    destination: Path,
    component: str,
    backup_id: str,
    compression: CompressionSettings,
    temporary_root: Path,
    media_segment_size: int = DEFAULT_MEDIA_SEGMENT_SIZE,
    ignored_paths: Iterable[Path] = (),
) -> list[ArchiveResult]:
    """Create one archive per component, or valid independent media segments."""
    if media_segment_size < 1:
        raise ValueError("Media segment size must be positive")
    entries = scan_tree(root, ignored_paths=ignored_paths)
    groups = _partition_media(entries, media_segment_size) if component == "media" else [entries]
    results: list[ArchiveResult] = []
    for index, group in enumerate(groups, 1):
        stem = f"{component}-{backup_id}"
        if component == "media":
            stem += f"-{index:04d}"
        relative = PurePosixPath(component) / f"{stem}.tar.{compression.extension}"
        validate_relative_path(relative.as_posix())
        final_path = destination / Path(relative.as_posix())
        final_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        partial_path = final_path.with_name(final_path.name + ".part")
        uncompressed_size = 0
        member_count = 0
        try:
            with open_compressed_writer(partial_path, compression) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w|",
                    format=tarfile.PAX_FORMAT,
                ) as archive:
                    for entry in group:
                        info = _tar_info(entry)
                        if entry.kind == "file":
                            staged, stable_size = _stable_copy(
                                entry.source_path,
                                temporary_root=temporary_root,
                                relative=entry.relative_path,
                            )
                            try:
                                if component == "media" and stable_size != entry.size_bytes:
                                    raise UnstableFileError(
                                        "Media file size changed after segment planning: "
                                        f"{entry.relative_path}"
                                    )
                                info.size = stable_size
                                with staged.open("rb") as stream:
                                    archive.addfile(info, stream)
                            finally:
                                staged.unlink(missing_ok=True)
                            uncompressed_size += stable_size
                        else:
                            archive.addfile(info)
                        member_count += 1
            _fsync_file(partial_path)
            os.replace(partial_path, final_path)
        except Exception:
            partial_path.unlink(missing_ok=True)
            raise
        digest, size = sha256_file(final_path)
        results.append(
            ArchiveResult(
                file=BackupFile(
                    path=relative.as_posix(),
                    size_bytes=size,
                    sha256=digest,
                    archive_format=f"tar-pax+{compression.backend}",
                    uncompressed_size_bytes=uncompressed_size,
                    segment=index if component == "media" else None,
                    members=member_count,
                    member_paths=tuple(entry.relative_path.as_posix() for entry in group),
                ),
                archive_path=final_path,
            )
        )
    return results


def _partition_media(entries: list[ArchiveEntry], target: int) -> list[list[ArchiveEntry]]:
    if not entries:
        return [[]]
    groups: list[list[ArchiveEntry]] = []
    current: list[ArchiveEntry] = []
    current_size = 0
    for entry in entries:
        if entry.kind == "file" and entry.size_bytes > target:
            if current:
                groups.append(current)
                current, current_size = [], 0
            groups.append([entry])
            continue
        if entry.kind == "file" and current and current_size + entry.size_bytes > target:
            groups.append(current)
            current, current_size = [], 0
        current.append(entry)
        if entry.kind == "file":
            current_size += entry.size_bytes
    if current:
        groups.append(current)
    return groups or [[]]


def _tar_info(entry: ArchiveEntry) -> tarfile.TarInfo:
    name = validate_relative_path(entry.relative_path.as_posix())
    info = tarfile.TarInfo(name)
    info.mode = entry.mode
    info.mtime = entry.mtime
    # Restore never gets host ownership from an archive.
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if entry.kind == "directory":
        info.type = tarfile.DIRTYPE
        info.size = 0
    elif entry.kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = entry.symlink_target or ""
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.size = entry.size_bytes
    return info


def _stat_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_copy(
    source: Path,
    *,
    temporary_root: Path,
    relative: PurePosixPath,
) -> tuple[Path, int]:
    """Stage a stable regular file so a changed source can be retried safely."""
    temporary_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    last_error: OSError | None = None
    for attempt in range(1, STABLE_READ_ATTEMPTS + 1):
        staged_path: Path | None = None
        try:
            before = source.lstat()
            if not stat.S_ISREG(before.st_mode):
                raise UnstableFileError(f"Source stopped being a regular file: {relative}")
            descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(descriptor)
                if _stat_signature(opened) != _stat_signature(before):
                    raise UnstableFileError(f"Source changed before it could be read: {relative}")
                handle = tempfile.NamedTemporaryFile(
                    prefix="backup-file-",
                    suffix=".stage",
                    dir=temporary_root,
                    delete=False,
                )
                staged_path = Path(handle.name)
                with handle, os.fdopen(os.dup(descriptor), "rb") as source_stream:
                    while chunk := source_stream.read(COPY_CHUNK_SIZE):
                        handle.write(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
                after_open = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after_path = source.lstat()
            signature = _stat_signature(before)
            if signature != _stat_signature(after_open) or signature != _stat_signature(after_path):
                raise UnstableFileError(f"Source changed while being read: {relative}")
            return staged_path, after_open.st_size
        except OSError as exc:
            last_error = exc
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            if attempt == STABLE_READ_ATTEMPTS:
                break
    raise UnstableFileError(
        f"Could not read stable backup file {relative} after {STABLE_READ_ATTEMPTS} attempts"
    ) from last_error


def _fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())
