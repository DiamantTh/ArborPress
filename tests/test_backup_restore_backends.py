"""Optional live same-backend restore tests for PostgreSQL and MariaDB."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import create_async_engine

from arborpress.backups.restore import (
    RestoreRecoveryRequired,
    apply_restore,
    recover_restore,
    restore_journal_path,
    restore_maintenance_path,
)
from arborpress.backups.service import create_backup
from arborpress.core.db import Base
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


@pytest.mark.asyncio
async def test_live_server_database_backup_restore_and_sequence_reset(tmp_path: Path) -> None:
    """Run against an explicitly supplied disposable PostgreSQL or MariaDB database."""
    database_url = os.environ.get("ARBORPRESS_TEST_RESTORE_URL")
    if not database_url:
        pytest.skip("set ARBORPRESS_TEST_RESTORE_URL to a disposable server database")

    import arborpress.models  # noqa: F401 - register all application tables
    from arborpress.core.migrations import upgrade_database

    paths = ArborPressPaths.from_prefix(tmp_path / "restore-prefix")
    ensure_instance_layout(paths)
    engine = create_async_engine(database_url)
    try:
        await upgrade_database(engine)
        tags = Base.metadata.tables["tags"]
        async with engine.begin() as connection:
            await connection.execute(insert(tags).values(id=1_000_000, slug="saved", label="Saved"))

        backup = await create_backup(
            paths=paths,
            engine=engine,
            components=("database",),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
        async with engine.begin() as connection:
            await connection.execute(tags.delete())
            await connection.execute(insert(tags).values(id=1, slug="changed", label="Changed"))

        report = await apply_restore(
            backup.backup_id,
            paths=paths,
            engine=engine,
            components=("database",),
            offline=True,
        )

        assert report["result"] == "success"
        async with engine.begin() as connection:
            saved = (
                await connection.execute(
                    select(tags.c.id, tags.c.slug).where(tags.c.slug == "saved")
                )
            ).one()
            assert saved == (1_000_000, "saved")
            result = await connection.execute(
                insert(tags).values(slug="after-restore", label="After restore")
            )
            assert result.inserted_primary_key[0] > 1_000_000
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_uncertain_server_commit_keeps_maintenance_and_refuses_automatic_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A lost response after commit intent must not trigger a guessed file rollback."""
    database_url = os.environ.get("ARBORPRESS_TEST_RESTORE_URL")
    if not database_url:
        pytest.skip("set ARBORPRESS_TEST_RESTORE_URL to a disposable server database")

    import arborpress.backups.restore as restore_module
    import arborpress.models  # noqa: F401 - register all application tables
    from arborpress.core.migrations import upgrade_database

    paths = ArborPressPaths.from_prefix(tmp_path / "uncertain-prefix")
    ensure_instance_layout(paths)
    engine = create_async_engine(database_url)
    try:
        await upgrade_database(engine)
        backup = await create_backup(
            paths=paths,
            engine=engine,
            components=("database",),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )

        async def fail_after_commit_intent(*args, before_commit=None, **kwargs):
            assert before_commit is not None
            before_commit()
            raise OSError("simulated lost commit response")

        monkeypatch.setattr(restore_module, "import_database_stream", fail_after_commit_intent)
        with pytest.raises(RestoreRecoveryRequired):
            await apply_restore(
                backup.backup_id,
                paths=paths,
                engine=engine,
                components=("database",),
                offline=True,
            )

        journal = json.loads(restore_journal_path(paths).read_text(encoding="utf-8"))
        assert journal["database_commit_started"] is True
        assert journal["database_committed"] is False
        assert restore_maintenance_path(paths).exists()
        with pytest.raises(RestoreRecoveryRequired, match="outcome is uncertain"):
            recover_restore(paths)
        assert restore_maintenance_path(paths).exists()
    finally:
        await engine.dispose()
