from __future__ import annotations

import bz2
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from arborpress.backups.archive import UnsafeArchiveEntryError
from arborpress.backups.compression import CompressionSettings
from arborpress.backups.manifest import BackupManifest
from arborpress.backups.service import (
    BackupLockError,
    _available_backup_id,
    backup_lock,
    create_backup,
    inspect_backup,
    list_backups,
)
from arborpress.backups.verify import verify_backup_set
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


def test_backup_ids_resolve_same_second_collisions_without_overwriting(tmp_path: Path) -> None:
    (tmp_path / "20261018-120000").mkdir()
    (tmp_path / "20261018-120000-01").mkdir()

    assert _available_backup_id(tmp_path, "20261018-120000") == "20261018-120000-02"


def test_backup_lock_is_instance_scoped_and_reports_parallel_operation(tmp_path: Path) -> None:
    paths_a = ArborPressPaths.from_prefix(tmp_path / "a")
    paths_b = ArborPressPaths.from_prefix(tmp_path / "b")
    ensure_instance_layout(paths_a)
    ensure_instance_layout(paths_b)

    with backup_lock(paths_a):
        with pytest.raises(BackupLockError, match="Another backup is running"):
            with backup_lock(paths_a):
                pass
        with backup_lock(paths_b):
            pass


@pytest.mark.asyncio
async def test_create_backup_publishes_atomic_set_and_omits_bootstrap_secrets(
    tmp_path: Path,
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    bootstrap_content = 'secret_key = "must-not-be-in-backup"\n'
    (paths.config / "config.toml").write_text(bootstrap_content, encoding="utf-8")
    (paths.config / "secrets.toml").write_text('api_key = "also-secret"\n', encoding="utf-8")
    (paths.config / ".installed").write_text("installed\n", encoding="utf-8")
    (paths.config / "install.token").write_text("token-value\n", encoding="utf-8")
    revisions = paths.data / "theme-revisions"
    revisions.mkdir()
    (revisions / "revision.json").write_text('{"revision": 1}\n', encoding="utf-8")
    (paths.media / "a.bin").write_bytes(b"0123456789")
    (paths.media / "b.bin").write_bytes(b"abc")
    database_path = paths.data / "arborpress.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    try:
        import arborpress.models  # noqa: F401
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(engine)
        summary = await create_backup(
            paths=paths,
            engine=engine,
            components=("database", "config", "data", "themes", "plugins", "media"),
            compression=CompressionSettings(),
            media_segment_size=5,
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
    finally:
        await engine.dispose()

    assert summary.backup_id == "20261018-120000"
    assert summary.verification_ok
    assert not list(paths.backups.glob(".incomplete-*"))
    assert (summary.directory / "manifest.toml").is_file()
    assert (summary.directory / "checksums.sha256").is_file()
    manifest = BackupManifest.from_toml((summary.directory / "manifest.toml").read_bytes())
    assert set(manifest.omitted_sensitive) == {
        "config/.installed",
        "config/config.toml",
        "config/install.token",
        "config/secrets.toml",
    }
    assert manifest.database_system == "sqlite"
    assert manifest.alembic_revisions
    assert [
        item.segment for item in next(c for c in manifest.components if c.name == "media").files
    ] == [
        1,
        2,
    ]
    assert [
        item.path for item in next(c for c in manifest.components if c.name == "database").files
    ] == ["database/database-20261018-120000.ndjson.bz2"]
    media_files = next(c for c in manifest.components if c.name == "media").files
    assert [item.member_paths for item in media_files] == [("a.bin",), ("b.bin",)]
    data_archive = next(
        item.path for item in next(c for c in manifest.components if c.name == "data").files
    )
    with bz2.open(summary.directory / data_archive, "rb") as compressed:
        with tarfile.open(fileobj=compressed, mode="r|") as archive:
            data_members = [member.name for member in archive]
    assert "theme-revisions/revision.json" in data_members
    assert "arborpress.db" not in data_members
    assert "arborpress.db-wal" not in data_members
    assert "arborpress.db-shm" not in data_members
    assert "arborpress.db-journal" not in data_members
    assert verify_backup_set(summary.directory).checked_files >= 6
    assert [item.backup_id for item in list_backups(paths)] == [summary.backup_id]
    inspected = inspect_backup(summary.backup_id, paths)
    assert inspected.verification_ok


@pytest.mark.asyncio
async def test_backup_sets_are_isolated_between_prefixes_and_ignore_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths_a = ArborPressPaths.from_prefix(tmp_path / "a")
    paths_b = ArborPressPaths.from_prefix(tmp_path / "b")
    ensure_instance_layout(paths_a)
    ensure_instance_layout(paths_b)
    (paths_a.media / "a.txt").write_text("only A", encoding="utf-8")
    (paths_b.media / "b.txt").write_text("only B", encoding="utf-8")
    foreign_cwd = tmp_path / "foreign-cwd"
    foreign_cwd.mkdir()
    (foreign_cwd / "media").mkdir()
    (foreign_cwd / "media" / "foreign.txt").write_text("ignore", encoding="utf-8")
    monkeypatch.chdir(foreign_cwd)
    timestamp = datetime(2026, 10, 18, 12, tzinfo=UTC)

    backup_a = await create_backup(paths=paths_a, components=("media",), created_at=timestamp)
    backup_b = await create_backup(paths=paths_b, components=("media",), created_at=timestamp)

    assert backup_a.backup_id == backup_b.backup_id
    assert [entry.backup_id for entry in list_backups(paths_a)] == [backup_a.backup_id]
    assert [entry.backup_id for entry in list_backups(paths_b)] == [backup_b.backup_id]
    assert "a.txt" in backup_a.manifest.components[0].files[0].member_paths
    assert "b.txt" in backup_b.manifest.components[0].files[0].member_paths
    assert "foreign.txt" not in backup_a.manifest.components[0].files[0].member_paths


@pytest.mark.asyncio
async def test_verify_rejects_corrupt_and_missing_component_files(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.data / "document.txt").write_text("restore state", encoding="utf-8")

    first = await create_backup(
        paths=paths,
        components=("data",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    first_file = first.directory / first.manifest.components[0].files[0].path
    first_file.write_bytes(first_file.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="Size mismatch|SHA-256 mismatch"):
        verify_backup_set(first.directory)

    second = await create_backup(
        paths=paths,
        components=("data",),
        created_at=datetime(2026, 10, 18, 12, 1, tzinfo=UTC),
    )
    second_file = second.directory / second.manifest.components[0].files[0].path
    second_file.unlink()
    with pytest.raises(ValueError, match="missing"):
        verify_backup_set(second.directory)


@pytest.mark.asyncio
async def test_failed_backup_removes_only_its_incomplete_directory(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("do not archive", encoding="utf-8")
    (paths.plugins / "escape").symlink_to(outside, target_is_directory=True)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        with pytest.raises(UnsafeArchiveEntryError):
            await create_backup(
                paths=paths,
                engine=engine,
                components=("plugins",),
                created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
            )
    finally:
        await engine.dispose()
    assert not list(paths.backups.glob(".incomplete-*"))
    assert not (paths.backups / "20261018-120000").exists()
