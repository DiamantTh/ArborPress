from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from arborpress.backups.retention import cleanup_incomplete, pin_backup, prune_backups
from arborpress.backups.service import BackupLockError, backup_lock, create_backup
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


@pytest.mark.asyncio
async def test_pin_and_combined_prune_policies_are_local_and_keep_last(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    other = ArborPressPaths.from_prefix(tmp_path / "other-prefix")
    ensure_instance_layout(paths)
    ensure_instance_layout(other)
    ids: list[str] = []
    for minute in (0, 1, 2):
        backup = await create_backup(
            paths=paths,
            components=("media",),
            created_at=datetime(2026, 10, 18, 12, minute, tzinfo=UTC),
        )
        ids.append(backup.backup_id)
    await create_backup(
        paths=other,
        components=("media",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )

    state_path = pin_backup(ids[0], paths=paths)
    assert state_path.is_file()
    plan = prune_backups(keep_last=1, paths=paths)
    assert plan.backup_ids == (ids[1],)
    assert set(plan.kept_ids) == {ids[0], ids[2]}
    assert plan.pinned_ids == (ids[0],)
    assert plan.dry_run
    assert (paths.backups / ids[1]).is_dir()
    assert (other.backups / ids[0]).is_dir()

    applied = prune_backups(keep_last=1, paths=paths, dry_run=False)
    assert applied.backup_ids == (ids[1],)
    assert not (paths.backups / ids[1]).exists()
    assert (paths.backups / ids[0]).is_dir()
    assert (paths.backups / ids[2]).is_dir()

    pin_backup(ids[0], paths=paths, pinned=False)
    unpinned = prune_backups(
        keep_days=0,
        paths=paths,
        now=datetime(2026, 10, 19, tzinfo=UTC),
    )
    assert ids[0] in unpinned.backup_ids
    assert ids[2] not in unpinned.backup_ids  # the newest valid set is always retained


def test_incomplete_cleanup_is_age_gated_and_shares_instance_lock(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    incomplete = paths.backups / ".incomplete-20261018-120000-0123456789abcdef0123456789abcdef"
    incomplete.mkdir()
    old_time = datetime(2026, 10, 1, tzinfo=UTC).timestamp()
    os.utime(incomplete, (old_time, old_time))
    unknown = paths.backups / ".incomplete-user-data"
    unknown.mkdir()
    os.utime(unknown, (old_time, old_time))

    listed = cleanup_incomplete(paths=paths, dry_run=True)
    assert listed == (incomplete.name,)
    assert incomplete.exists()
    with backup_lock(paths), pytest.raises(BackupLockError):
        cleanup_incomplete(paths=paths)
    removed = cleanup_incomplete(paths=paths, dry_run=False)
    assert removed == (incomplete.name,)
    assert not incomplete.exists()
    assert unknown.exists()


@pytest.mark.asyncio
async def test_prune_ignores_symlink_and_unknown_directories(tmp_path: Path) -> None:
    paths = ArborPressPaths.from_prefix(tmp_path / "prefix")
    ensure_instance_layout(paths)
    backup = await create_backup(
        paths=paths,
        components=("media",),
        created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
    )
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep").write_text("outside", encoding="utf-8")
    (paths.backups / "linked-backup").symlink_to(external, target_is_directory=True)
    unknown = paths.backups / "operator-notes"
    unknown.mkdir()

    plan = prune_backups(keep_last=0, paths=paths)

    assert plan.backup_ids == ()
    assert (paths.backups / backup.backup_id).is_dir()
    assert (external / "keep").is_file()
    assert unknown.is_dir()
