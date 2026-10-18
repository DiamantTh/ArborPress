from __future__ import annotations

import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import create_async_engine

from arborpress.backups.manifest import BackupFile, BackupVerificationError
from arborpress.backups.restore import (
    RestoreError,
    RestoreRecoveryRequired,
    _extract_archive,
    _validate_member_path,
    _write_restore_history,
    apply_restore,
    plan_restore,
    recover_restore,
    restore_journal_path,
    restore_maintenance_path,
)
from arborpress.backups.service import BackupLockError, backup_lock, create_backup
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


@pytest.mark.asyncio
async def test_plan_is_read_only_and_apply_restores_selected_file_root(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.media / "image.txt").write_text("backup version", encoding="utf-8")
    backup = await create_backup(
        paths=paths,
        components=("media",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    (paths.media / "image.txt").write_text("live mutation", encoding="utf-8")

    plan = await plan_restore(backup.backup_id, paths=paths, components=("media",))

    assert plan.compatible
    assert plan.config_coverage == "not-selected"
    assert (paths.media / "image.txt").read_text(encoding="utf-8") == "live mutation"
    report = await apply_restore(
        backup.backup_id,
        paths=paths,
        components=("media",),
        offline=True,
    )

    assert report["result"] == "success"
    assert (paths.media / "image.txt").read_text(encoding="utf-8") == "backup version"
    assert not restore_maintenance_path(paths).exists()
    assert not restore_journal_path(paths).exists()
    history = paths.data / "restore-history" / f"{report['restore_id']}.json"
    assert json.loads(history.read_text(encoding="utf-8"))["result"] == "success"


@pytest.mark.asyncio
async def test_restore_is_prefix_isolated_and_reassembles_media_segments(
    tmp_path: Path, monkeypatch
) -> None:
    prefix_a = ArborPressPaths.from_prefix(tmp_path / "prefix-a")
    prefix_b = ArborPressPaths.from_prefix(tmp_path / "prefix-b")
    ensure_instance_layout(prefix_a)
    ensure_instance_layout(prefix_b)
    (prefix_a.media / "large.bin").write_bytes(b"larger than each segment")
    (prefix_a.media / "small.bin").write_bytes(b"x")
    (prefix_b.media / "foreign.bin").write_text("prefix b", encoding="utf-8")
    backup = await create_backup(
        paths=prefix_a,
        components=("media",),
        media_segment_size=4,
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    media_component = backup.manifest.components[0]
    assert len(media_component.files) >= 2
    (prefix_a.media / "large.bin").write_bytes(b"changed")
    foreign = tmp_path / "foreign-working-directory"
    fake_backup = foreign / "instance" / "backups" / backup.backup_id
    fake_backup.mkdir(parents=True)
    (fake_backup / "manifest.toml").write_text("not a backup", encoding="utf-8")
    monkeypatch.chdir(foreign)

    report = await apply_restore(
        backup.backup_id,
        paths=prefix_a,
        components=("media",),
        offline=True,
    )

    assert report["result"] == "success"
    assert (prefix_a.media / "large.bin").read_bytes() == b"larger than each segment"
    assert (prefix_a.media / "small.bin").read_bytes() == b"x"
    assert (prefix_b.media / "foreign.bin").read_text(encoding="utf-8") == "prefix b"


@pytest.mark.asyncio
async def test_restore_and_backup_share_the_instance_lock(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    backup = await create_backup(
        paths=paths,
        components=("media",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )

    with backup_lock(paths), pytest.raises(BackupLockError):
        await apply_restore(
            backup.backup_id,
            paths=paths,
            components=("media",),
            offline=True,
        )

    assert not restore_maintenance_path(paths).exists()


@pytest.mark.asyncio
async def test_dangling_maintenance_marker_fails_closed(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.media / "image.txt").write_text("live", encoding="utf-8")
    backup = await create_backup(
        paths=paths,
        components=("media",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    restore_maintenance_path(paths).symlink_to(paths.run / "missing-marker-target")

    plan = await plan_restore(backup.backup_id, paths=paths, components=("media",))
    assert not plan.compatible
    assert any("maintenance mode" in item for item in plan.blockers)
    with pytest.raises(RestoreRecoveryRequired, match="incomplete restore"):
        await apply_restore(
            backup.backup_id,
            paths=paths,
            components=("media",),
            offline=True,
        )
    assert (paths.media / "image.txt").read_text(encoding="utf-8") == "live"


@pytest.mark.asyncio
async def test_partial_config_restore_preserves_omitted_secrets(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.config / "config.toml").write_text('secret_key = "live-secret"\n', encoding="utf-8")
    (paths.config / "notice.txt").write_text("old notice", encoding="utf-8")
    backup = await create_backup(
        paths=paths,
        components=("config",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    (paths.config / "notice.txt").write_text("changed notice", encoding="utf-8")

    plan = await plan_restore(backup.backup_id, paths=paths, components=("config",))
    assert plan.config_coverage == "partial"
    assert plan.omitted_sensitive == ("config/config.toml", "config/notice.txt")
    report = await apply_restore(
        backup.backup_id,
        paths=paths,
        components=("config",),
        offline=True,
    )

    assert report["result"] == "success"
    assert (paths.config / "config.toml").read_text(
        encoding="utf-8"
    ) == 'secret_key = "live-secret"\n'
    assert (paths.config / "notice.txt").read_text(encoding="utf-8") == "changed notice"


@pytest.mark.asyncio
async def test_corrupt_backup_is_rejected_before_any_live_mutation(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.media / "image.txt").write_text("must remain", encoding="utf-8")
    backup = await create_backup(
        paths=paths,
        components=("media",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    component_file = next((backup.directory / "media").iterdir())
    with component_file.open("ab") as stream:
        stream.write(b"corrupt")

    with pytest.raises((RestoreError, BackupVerificationError), match="failed verification"):
        await apply_restore(
            backup.backup_id,
            paths=paths,
            components=("media",),
            offline=True,
        )

    assert (paths.media / "image.txt").read_text(encoding="utf-8") == "must remain"
    assert not restore_maintenance_path(paths).exists()
    history_files = list((paths.data / "restore-history").glob("*.json"))
    assert len(history_files) == 1
    failed_report = json.loads(history_files[0].read_text(encoding="utf-8"))
    assert failed_report["result"] == "failed"
    assert failed_report["verify"]["ok"] is False


@pytest.mark.asyncio
async def test_sqlite_backup_restore_replaces_rows_and_keeps_autoincrement_working(
    tmp_path: Path,
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    engine = create_async_engine(f"sqlite+aiosqlite:///{paths.data / 'arborpress.db'}")
    try:
        import arborpress.models  # noqa: F401
        from arborpress.backups.archive import DEFAULT_MEDIA_SEGMENT_SIZE
        from arborpress.backups.compression import CompressionSettings
        from arborpress.core.db import Base
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(engine)
        tags = Base.metadata.tables["tags"]
        categories = Base.metadata.tables["categories"]
        async with engine.begin() as connection:
            await connection.execute(insert(tags).values(id=20, slug="saved", label="Saved"))
            await connection.execute(
                insert(categories),
                [
                    {"id": 1, "slug": "first", "label": "First", "parent_id": None},
                    {"id": 2, "slug": "second", "label": "Second", "parent_id": 1},
                ],
            )
            await connection.execute(
                categories.update().where(categories.c.id == 1).values(parent_id=2)
            )
        backup = await create_backup(
            paths=paths,
            engine=engine,
            components=("database",),
            compression=CompressionSettings(),
            media_segment_size=DEFAULT_MEDIA_SEGMENT_SIZE,
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
        async with engine.begin() as connection:
            await connection.execute(tags.delete())
            await connection.execute(insert(tags).values(id=99, slug="mutated", label="Mutated"))
            await connection.execute(categories.delete())

        report = await apply_restore(
            backup.backup_id,
            paths=paths,
            engine=engine,
            components=("database",),
            offline=True,
        )

        assert report["result"] == "success"
        assert report["end_checks"]["row_counts"]["tags"] == 1
        assert report["end_checks"]["foreign_key_check"] == "passed"
        async with engine.connect() as connection:
            rows = (await connection.execute(select(tags.c.id, tags.c.slug))).all()
            assert rows == [(20, "saved")]
            parents = (
                await connection.execute(
                    select(categories.c.id, categories.c.parent_id).order_by(categories.c.id)
                )
            ).all()
            assert parents == [(1, 2), (2, 1)]
            result = await connection.execute(
                insert(tags).values(slug="after-restore", label="After restore")
            )
            assert result.inserted_primary_key[0] > 20
            integrity = await connection.exec_driver_sql("PRAGMA integrity_check")
            assert integrity.scalar_one() == "ok"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_empty_sqlite_target_is_migrated_in_staging_before_import(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    source_path = paths.data / "source.db"
    target_path = paths.instance / "empty-target.db"
    source_engine = create_async_engine(f"sqlite+aiosqlite:///{source_path}")
    target_engine = create_async_engine(f"sqlite+aiosqlite:///{target_path}")
    try:
        import arborpress.models  # noqa: F401
        from arborpress.backups.compression import CompressionSettings
        from arborpress.core.db import Base
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(source_engine)
        tags = Base.metadata.tables["tags"]
        async with source_engine.begin() as connection:
            await connection.execute(insert(tags).values(id=71, slug="restored", label="Restored"))
        backup = await create_backup(
            paths=paths,
            engine=source_engine,
            components=("database",),
            compression=CompressionSettings(),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )

        plan = await plan_restore(
            backup.backup_id,
            paths=paths,
            engine=target_engine,
            components=("database",),
        )
        assert plan.compatible
        assert plan.target_schema_state == "empty"
        assert any("migrated to this release's Alembic head" in item for item in plan.warnings)
        assert not target_path.exists(), "restore planning must not create the target database"
        report = await apply_restore(
            backup.backup_id,
            paths=paths,
            engine=target_engine,
            components=("database",),
            offline=True,
        )

        assert report["result"] == "success"
        assert report["database"]["revision_after"]
        async with target_engine.connect() as connection:
            restored = (
                await connection.execute(select(tags.c.id, tags.c.slug))
            ).one()
            assert restored == (71, "restored")
            integrity = await connection.exec_driver_sql("PRAGMA integrity_check")
            assert integrity.scalar_one() == "ok"
    finally:
        await source_engine.dispose()
        await target_engine.dispose()


@pytest.mark.asyncio
async def test_sqlite_database_symlink_is_preserved_and_restore_plan_blocks_it(
    tmp_path: Path,
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    source_path = paths.data / "source.db"
    symlink_path = paths.instance / "database-link.db"
    source_engine = create_async_engine(f"sqlite+aiosqlite:///{source_path}")
    try:
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(source_engine)
        backup = await create_backup(
            paths=paths,
            engine=source_engine,
            components=("database",),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
        symlink_path.symlink_to(source_path)
        target_engine = create_async_engine(f"sqlite+aiosqlite:///{symlink_path}")
        try:
            plan = await plan_restore(
                backup.backup_id,
                paths=paths,
                engine=target_engine,
                components=("database",),
            )
            assert not plan.compatible
            assert any("must not contain symlinks" in item for item in plan.blockers)
            assert symlink_path.is_symlink()
            assert source_path.is_file()
        finally:
            await target_engine.dispose()
    finally:
        await source_engine.dispose()


@pytest.mark.asyncio
async def test_sqlite_import_failure_before_commit_keeps_live_database(
    tmp_path: Path, monkeypatch
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    database_path = paths.data / "arborpress.db"
    paths.config_file.write_text(
        f'[db]\nurl = "sqlite+aiosqlite:///{database_path}"\n', encoding="utf-8"
    )
    from arborpress.core.config import reset_settings
    from arborpress.runtime.paths import reset_runtime_for_tests

    reset_runtime_for_tests(paths.prefix)
    reset_settings()
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    try:
        import arborpress.models  # noqa: F401
        from arborpress.core.db import Base
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(engine)
        tags = Base.metadata.tables["tags"]
        async with engine.begin() as connection:
            await connection.execute(insert(tags).values(id=31, slug="live", label="Live"))
        backup = await create_backup(
            paths=paths,
            engine=engine,
            components=("database",),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
        async with engine.begin() as connection:
            await connection.execute(tags.update().values(slug="must-remain"))

        import arborpress.backups.restore as restore_module

        async def fail_import(*args, **kwargs):
            raise RuntimeError("injected pre-commit failure")

        monkeypatch.setattr(restore_module, "_import_database_stream", fail_import)
        with pytest.raises(RestoreError, match="Restore failed in phase verified"):
            await apply_restore(
                backup.backup_id,
                paths=paths,
                engine=engine,
                components=("database",),
                offline=True,
            )

        async with engine.connect() as connection:
            assert (await connection.execute(select(tags.c.slug))).scalar_one() == "must-remain"
        assert not restore_maintenance_path(paths).exists()
        history = list((paths.data / "restore-history").glob("*.json"))
        assert json.loads(history[0].read_text(encoding="utf-8"))["result"] == "failed"
    finally:
        await engine.dispose()
        reset_settings()


@pytest.mark.asyncio
async def test_sqlite_crash_after_database_swap_is_cleanup_recoverable(
    tmp_path: Path, monkeypatch
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    database_path = paths.data / "arborpress.db"
    paths.config_file.write_text(
        f'[db]\nurl = "sqlite+aiosqlite:///{database_path}"\n', encoding="utf-8"
    )
    from arborpress.core.config import reset_settings
    from arborpress.runtime.paths import reset_runtime_for_tests

    reset_runtime_for_tests(paths.prefix)
    reset_settings()
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    try:
        import arborpress.models  # noqa: F401
        from arborpress.core.db import Base
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(engine)
        tags = Base.metadata.tables["tags"]
        async with engine.begin() as connection:
            await connection.execute(insert(tags).values(id=41, slug="saved", label="Saved"))
        backup = await create_backup(
            paths=paths,
            engine=engine,
            components=("database",),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
        async with engine.begin() as connection:
            await connection.execute(tags.update().values(slug="mutated"))

        import arborpress.backups.restore as restore_module

        original_cleanup = restore_module._cleanup_restore_swaps

        def fail_cleanup(_journal):
            raise OSError("injected post-commit cleanup failure")

        with monkeypatch.context() as patch:
            patch.setattr(restore_module, "_cleanup_restore_swaps", fail_cleanup)
            with pytest.raises(restore_module.RestoreRecoveryRequired):
                await apply_restore(
                    backup.backup_id,
                    paths=paths,
                    engine=engine,
                    components=("database",),
                    offline=True,
                )

        monkeypatch.setattr(restore_module, "_cleanup_restore_swaps", original_cleanup)
        assert restore_maintenance_path(paths).exists()
        async with engine.connect() as connection:
            assert (await connection.execute(select(tags.c.slug))).scalar_one() == "saved"
        recovery = recover_restore(paths)
        assert recovery["result"] == "completed-cleanup"
        assert not restore_maintenance_path(paths).exists()
        async with engine.connect() as connection:
            assert (await connection.execute(select(tags.c.slug))).scalar_one() == "saved"
    finally:
        await engine.dispose()
        reset_settings()


@pytest.mark.asyncio
async def test_data_only_restore_preserves_unselected_sqlite_database(
    tmp_path: Path,
) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    database_path = paths.data / "arborpress.db"
    paths.config_file.write_text(
        f'[db]\nurl = "sqlite+aiosqlite:///{database_path}"\n', encoding="utf-8"
    )
    from arborpress.core.config import reset_settings

    reset_settings()
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    try:
        import arborpress.models  # noqa: F401
        from arborpress.core.db import Base
        from arborpress.core.migrations import upgrade_database

        await upgrade_database(engine)
        tags = Base.metadata.tables["tags"]
        async with engine.begin() as connection:
            await connection.execute(insert(tags).values(id=10, slug="kept", label="Kept"))
        (paths.data / "state.txt").write_text("saved state", encoding="utf-8")
        backup = await create_backup(
            paths=paths,
            engine=engine,
            components=("data",),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
        async with engine.begin() as connection:
            await connection.execute(insert(tags).values(id=90, slug="live", label="Live"))
        (paths.data / "state.txt").write_text("mutated state", encoding="utf-8")

        report = await apply_restore(
            backup.backup_id,
            paths=paths,
            engine=engine,
            components=("data",),
            offline=True,
        )

        assert report["result"] == "success"
        assert (paths.data / "state.txt").read_text(encoding="utf-8") == "saved state"
        async with engine.connect() as connection:
            slugs = (await connection.execute(select(tags.c.slug))).scalars().all()
            assert slugs == ["kept", "live"]
    finally:
        await engine.dispose()
        reset_settings()


@pytest.mark.asyncio
async def test_file_swap_failure_rolls_back_prior_roots(tmp_path: Path, monkeypatch) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    (paths.media / "saved.txt").write_text("saved media", encoding="utf-8")
    (paths.plugins / "saved.txt").write_text("saved plugin", encoding="utf-8")
    backup = await create_backup(
        paths=paths,
        components=("media", "plugins"),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    (paths.media / "saved.txt").write_text("mutated media", encoding="utf-8")
    (paths.plugins / "saved.txt").write_text("mutated plugin", encoding="utf-8")

    import arborpress.backups.restore as restore_module

    original_switch = restore_module._switch_path
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected failure")
        return original_switch(*args, **kwargs)

    monkeypatch.setattr(restore_module, "_switch_path", fail_second)
    with pytest.raises(RestoreError, match="Restore failed"):
        await apply_restore(
            backup.backup_id,
            paths=paths,
            components=("media", "plugins"),
            offline=True,
        )

    assert (paths.media / "saved.txt").read_text(encoding="utf-8") == "mutated media"
    assert (paths.plugins / "saved.txt").read_text(encoding="utf-8") == "mutated plugin"
    assert not restore_maintenance_path(paths).exists()
    assert not restore_journal_path(paths).exists()
    assert not list(paths.instance.glob(".restore-rollback-*"))


@pytest.mark.asyncio
async def test_recovery_rolls_back_interrupted_directory_swap(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    restore_id = "a" * 32
    rollback = paths.instance / f".restore-rollback-{restore_id}-media"
    os_media = paths.media
    os_media.rename(rollback)
    os_media.mkdir()
    (os_media / "new.txt").write_text("new", encoding="utf-8")
    journal = {
        "format_version": 1,
        "restore_id": restore_id,
        "backup_id": "20261018-120000",
        "started_at": "2026-10-18T12:00:00Z",
        "staging_root": str(paths.tmp / f"restore-20261018-120000-{restore_id[:12]}-test"),
        "phase": "applying-files",
        "selected_components": ["media"],
        "database_backend": None,
        "database_committed": False,
        "database_commit_started": False,
        "swaps": [
            {
                "component": "media",
                "target": str(paths.media),
                "rollback": str(rollback),
                "staged": str(
                    paths.tmp / f"restore-20261018-120000-{restore_id[:12]}-test" / "media"
                ),
                "kind": "directory",
                "had_original": True,
                "old_moved": True,
                "new_moved": False,
            }
        ],
    }
    restore_journal_path(paths).write_text(json.dumps(journal), encoding="utf-8")
    restore_maintenance_path(paths).write_text("{}", encoding="utf-8")

    report = recover_restore(paths)

    assert report["result"] == "rolled-back"
    assert not (paths.media / "new.txt").exists()
    assert paths.media.is_dir()
    assert not restore_journal_path(paths).exists()
    assert not restore_maintenance_path(paths).exists()


@pytest.mark.parametrize("path", ["../escape", "/absolute", "C:/drive", "a\\b", "a/./b"])
def test_restore_rejects_unsafe_archive_paths(path: str) -> None:
    with pytest.raises((ValueError, RestoreError)):
        _validate_member_path(path)


def _tar_link(name: str, target: str, kind: bytes) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.type = kind
    member.linkname = target
    return member, b""


def _tar_special(name: str, kind: bytes) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.type = kind
    return member, b""


def _write_restore_test_archive(path: Path, entries: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, "w:bz2", format=tarfile.PAX_FORMAT) as archive:
        for member, body in entries:
            if member.isreg():
                member.size = len(body)
            archive.addfile(member, io.BytesIO(body) if member.isreg() else None)


@pytest.mark.parametrize(
    "entries",
    [
        [(tarfile.TarInfo("../escape"), b"x")],
        [(tarfile.TarInfo("/absolute"), b"x")],
        [(tarfile.TarInfo("C:/drive"), b"x")],
        [_tar_link("link", "../escape", tarfile.SYMTYPE)],
        [_tar_link("link", "target", tarfile.LNKTYPE)],
        [_tar_special("device", tarfile.CHRTYPE)],
        [_tar_special("pipe", tarfile.FIFOTYPE)],
        [
            (tarfile.TarInfo("duplicate"), b"first"),
            (tarfile.TarInfo("duplicate"), b"second"),
        ],
    ],
)
def test_restore_extractor_rejects_unsafe_or_conflicting_tar_members(
    tmp_path: Path, entries: list[tuple[tarfile.TarInfo, bytes]]
) -> None:
    archive_path = tmp_path / "unsafe.tar.bz2"
    _write_restore_test_archive(archive_path, entries)
    destination = tmp_path / "staging"
    destination.mkdir()
    metadata = BackupFile(
        path="media/unsafe.tar.bz2",
        size_bytes=archive_path.stat().st_size,
        sha256="0" * 64,
        archive_format="test",
        uncompressed_size_bytes=0,
        members=len(entries),
    )

    with pytest.raises((RestoreError, ValueError)):
        _extract_archive(archive_path, destination, metadata, "bz2", set())

    assert not (tmp_path / "escape").exists()


def test_restore_extractor_preserves_safe_relative_symlink(tmp_path: Path) -> None:
    archive_path = tmp_path / "safe.tar.bz2"
    entries = [
        (tarfile.TarInfo("assets/logo.txt"), b"logo"),
        _tar_link("logo.txt", "assets/logo.txt", tarfile.SYMTYPE),
    ]
    _write_restore_test_archive(archive_path, entries)
    destination = tmp_path / "staging"
    destination.mkdir()
    metadata = BackupFile(
        path="media/safe.tar.bz2",
        size_bytes=archive_path.stat().st_size,
        sha256="0" * 64,
        archive_format="test",
        uncompressed_size_bytes=4,
        members=len(entries),
    )

    _extract_archive(archive_path, destination, metadata, "bz2", set())

    assert (destination / "logo.txt").is_symlink()
    assert (destination / "logo.txt").read_text(encoding="utf-8") == "logo"


def test_restore_history_refuses_a_symlinked_storage_directory(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    outside = tmp_path / "outside"
    outside.mkdir()
    (paths.data / "restore-history").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RestoreError, match="must not be a symlink"):
        _write_restore_history(paths, {"restore_id": "a" * 32})

    assert list(outside.iterdir()) == []


@pytest.mark.asyncio
async def test_apply_requires_explicit_offline_attestation(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    backup = await create_backup(
        paths=paths,
        components=("media",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )

    with pytest.raises(RestoreError, match="--offline"):
        await apply_restore(backup.backup_id, paths=paths, components=("media",))


@pytest.mark.asyncio
async def test_restore_maintenance_marker_blocks_web_requests(client, runtime_prefix) -> None:
    from arborpress.runtime.paths import ArborPressPaths

    paths = ArborPressPaths.from_prefix(runtime_prefix)
    marker = restore_maintenance_path(paths)
    marker.parent.mkdir(parents=True, exist_ok=True)
    try:
        marker.write_text('{"restore_id":"test"}\n', encoding="utf-8")
        response = await client.get("/_health")
        assert response.status_code == 503
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Retry-After"] == "60"
    finally:
        marker.unlink(missing_ok=True)
