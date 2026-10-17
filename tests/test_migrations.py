"""Alembic fresh-install, downgrade and supported legacy-adoption tests."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from arborpress.core.migrations import (
    BASELINE_REVISION,
    MigrationError,
    MigrationLockError,
    adopt_legacy_database,
    downgrade_database,
    schema_status,
    upgrade_database,
)

FIXTURE = Path(__file__).parent / "fixtures" / "pre_alembic_phase1_schema.sql"


def _sqlite_engine(path: Path) -> AsyncEngine:
    return create_async_engine(
        f"sqlite+aiosqlite:///{path}",
        connect_args={"check_same_thread": False},
    )


def _load_legacy_fixture(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(FIXTURE.read_text(encoding="utf-8"))
        connection.execute(
            """
            INSERT INTO users (
                id, username, display_name, account_type, role, is_active,
                legacy_password_enabled, require_uv, require_stepup,
                sso_disabled, federation_opt_out
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-user",
                "phase1-admin",
                "Legacy Administrator",
                "OPERATIONAL",
                "ADMIN",
                1,
                0,
                1,
                1,
                0,
                0,
            ),
        )
        connection.execute(
            """
            INSERT INTO user_sessions (
                id, user_id, expires_at, is_tls, is_cli, is_valid,
                auth_method, assurance_level
            ) VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
            """,
            ("legacy-session", "legacy-user", 1, 0, 1, "webauthn", "aal2"),
        )
        connection.execute(
            """
            INSERT INTO webauthn_credentials (
                id, user_id, label, credential_id, public_key, sign_count,
                transport, uv_capable, transports, verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-credential",
                "legacy-user",
                "Legacy security key",
                b"synthetic-credential-id",
                b"synthetic-public-key",
                4,
                "usb",
                1,
                None,
                "verified",
            ),
        )
        connection.execute(
            """
            INSERT INTO mfa_devices (
                id, user_id, device_type, label, secret_enc, is_active,
                verification_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-mfa",
                "legacy-user",
                "totp",
                "Legacy TOTP",
                b"synthetic-encrypted-secret",
                1,
                "verified",
            ),
        )
        connection.execute(
            """
            INSERT INTO auth_stepup_grants (
                id, user_id, session_id, action, target, auth_method,
                assurance_level, confirming_credential_id, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                "legacy-stepup",
                "legacy-user",
                "legacy-session",
                "remove_totp_credential",
                "legacy-mfa",
                "webauthn",
                "aal2",
                "legacy-credential",
            ),
        )
        connection.commit()


async def _schema_snapshot(engine: AsyncEngine) -> dict[str, tuple[str, ...]]:
    async with engine.connect() as connection:

        def inspect(sync_connection: Connection) -> dict[str, tuple[str, ...]]:
            inspector = sa.inspect(sync_connection)
            return {
                table: tuple(column["name"] for column in inspector.get_columns(table))
                for table in sorted(inspector.get_table_names())
                if table != "alembic_version"
            }

        return await connection.run_sync(inspect)


@pytest.mark.asyncio
async def test_empty_database_upgrade_noop_and_repeated_install(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "fresh.db")
    try:
        assert (await schema_status(engine)).state == "empty"
        status = await upgrade_database(engine)
        assert status.is_current
        assert status.current_revisions == (BASELINE_REVISION,)
        before = await _schema_snapshot(engine)
        assert len(before) == 25
        assert "webauthn_credentials" in before

        async with engine.connect() as connection:
            version = await connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            assert version == BASELINE_REVISION
            credential_columns = await connection.run_sync(
                lambda sync_connection: {
                    column["name"]
                    for column in sa.inspect(sync_connection).get_columns("webauthn_credentials")
                }
            )
            assert {
                "aaguid",
                "transports",
                "authenticator_attachment",
                "backup_eligible",
                "backup_state",
                "verification_status",
            } <= credential_columns
            assert (
                await connection.scalar(
                    sa.text(
                        "SELECT COUNT(*) FROM sqlite_master "
                        "WHERE type='index' AND name='ix_audit_events_target_id'"
                    )
                )
                == 1
            )

        assert (await upgrade_database(engine)).is_current
        assert await _schema_snapshot(engine) == before
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_baseline_downgrade_removes_application_objects_and_can_reinstall(
    tmp_path: Path,
) -> None:
    engine = _sqlite_engine(tmp_path / "downgrade.db")
    try:
        await upgrade_database(engine)
        await downgrade_database("base", engine)
        assert (await schema_status(engine)).state == "empty"
        async with engine.connect() as connection:
            app_tables = await connection.run_sync(
                lambda sync_connection: (
                    set(sa.inspect(sync_connection).get_table_names()) - {"alembic_version"}
                )
            )
            assert not app_tables
            assert await connection.scalar(sa.text("SELECT COUNT(*) FROM alembic_version")) == 0
        assert (await upgrade_database(engine)).is_current
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_independent_phase1_legacy_fixture_is_adopted_without_data_loss(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "legacy.db"
    _load_legacy_fixture(database_path)
    engine = _sqlite_engine(database_path)
    try:
        assert (await schema_status(engine)).state == "legacy"
        before = await _schema_snapshot(engine)
        await adopt_legacy_database(engine)
        status = await schema_status(engine)
        assert status.is_current
        assert status.current_revisions == (BASELINE_REVISION,)
        assert await _schema_snapshot(engine) == before

        async with engine.connect() as connection:
            user = (
                await connection.execute(
                    sa.text("SELECT id, username FROM users WHERE id='legacy-user'")
                )
            ).one()
            assert user == ("legacy-user", "phase1-admin")
            assert (
                await connection.scalar(
                    sa.text("SELECT id FROM user_sessions WHERE id='legacy-session'")
                )
                == "legacy-session"
            )
            assert (
                await connection.scalar(sa.text("SELECT id FROM mfa_devices WHERE id='legacy-mfa'"))
                == "legacy-mfa"
            )
            transports = await connection.scalar(
                sa.text("SELECT transports FROM webauthn_credentials WHERE id='legacy-credential'")
            )
            assert json.loads(transports) == ["usb"]
            assert (
                await connection.scalar(
                    sa.text(
                        "SELECT confirming_credential_id FROM auth_stepup_grants "
                        "WHERE id='legacy-stepup'"
                    )
                )
                == "legacy-credential"
            )

        assert (await upgrade_database(engine)).is_current
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_unknown_and_incomplete_legacy_schemas_are_not_stamped(tmp_path: Path) -> None:
    unknown_engine = _sqlite_engine(tmp_path / "unknown.db")
    try:
        async with unknown_engine.begin() as connection:
            await connection.execute(sa.text("CREATE TABLE users (id TEXT PRIMARY KEY)"))
        assert (await schema_status(unknown_engine)).state == "unknown_legacy"
        with pytest.raises(MigrationError, match="Legacy adoption refused"):
            await adopt_legacy_database(unknown_engine)
        async with unknown_engine.connect() as connection:
            assert "alembic_version" not in await connection.run_sync(
                lambda sync_connection: sa.inspect(sync_connection).get_table_names()
            )
    finally:
        await unknown_engine.dispose()

    incomplete_path = tmp_path / "incomplete.db"
    _load_legacy_fixture(incomplete_path)
    with sqlite3.connect(incomplete_path) as connection:
        connection.execute("DROP TABLE webauthn_credentials")
        connection.commit()
    incomplete_engine = _sqlite_engine(incomplete_path)
    try:
        assert (await schema_status(incomplete_engine)).state == "unknown_legacy"
        with pytest.raises(MigrationError, match="Legacy adoption refused"):
            await adopt_legacy_database(incomplete_engine)
    finally:
        await incomplete_engine.dispose()

    extended_path = tmp_path / "extended-legacy.db"
    _load_legacy_fixture(extended_path)
    with sqlite3.connect(extended_path) as connection:
        connection.execute("CREATE TABLE unrecognized_extension (id TEXT PRIMARY KEY)")
        connection.commit()
    extended_engine = _sqlite_engine(extended_path)
    try:
        status = await schema_status(extended_engine)
        assert status.state == "unknown_legacy"
        assert "unexpected table unrecognized_extension" in status.detail
        with pytest.raises(MigrationError, match="Legacy adoption refused"):
            await adopt_legacy_database(extended_engine)
        async with extended_engine.connect() as connection:
            tables = await connection.run_sync(
                lambda sync_connection: set(sa.inspect(sync_connection).get_table_names())
            )
            assert "unrecognized_extension" in tables
            assert "alembic_version" not in tables
    finally:
        await extended_engine.dispose()


@pytest.mark.asyncio
async def test_unknown_revision_and_migration_lock_timeout_fail_closed(
    tmp_path: Path,
) -> None:
    unknown_engine = _sqlite_engine(tmp_path / "unknown-revision.db")
    try:
        await upgrade_database(unknown_engine)
        async with unknown_engine.begin() as connection:
            await connection.execute(
                sa.text("UPDATE alembic_version SET version_num='future_revision'")
            )
        assert (await schema_status(unknown_engine)).state == "unknown_revision"
        with pytest.raises(MigrationError, match="Cannot upgrade database"):
            await upgrade_database(unknown_engine)
    finally:
        await unknown_engine.dispose()

    locked_path = tmp_path / "locked.db"
    with sqlite3.connect(locked_path, timeout=0) as lock_connection:
        lock_connection.execute("BEGIN EXCLUSIVE")
        locked_engine = _sqlite_engine(locked_path)
        try:
            from arborpress.core.migrations import _migration_lock

            async with locked_engine.connect() as connection:
                with pytest.raises(MigrationLockError, match="migration lock"):
                    async with _migration_lock(connection, timeout=0.05):
                        pytest.fail("lock should not be acquired")
        finally:
            await locked_engine.dispose()
            lock_connection.rollback()


@pytest.mark.asyncio
async def test_known_older_revision_is_reported_as_behind_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from alembic.config import Config

    import arborpress.core.migrations as migration_module

    engine = _sqlite_engine(tmp_path / "behind.db")
    versions = tmp_path / "extra_versions"
    versions.mkdir()
    (versions / "0002_test_next.py").write_text(
        "revision = '0002_test_next'\n"
        "down_revision = '0001_pre_alembic_baseline'\n"
        "branch_labels = None\n"
        "depends_on = None\n"
        "def upgrade(): pass\n"
        "def downgrade(): pass\n",
        encoding="utf-8",
    )
    try:
        await upgrade_database(engine)
        config = Config(migration_module._config().config_file_name)
        config.set_main_option(
            "version_locations",
            f"{Path(__file__).parents[1] / 'arborpress/migrations/versions'}{os.pathsep}{versions}",
        )
        monkeypatch.setattr(migration_module, "_config", lambda: config)
        status = await schema_status(engine)
        assert status.state == "behind"
        assert status.current_revisions == (BASELINE_REVISION,)
        assert status.head_revision == "0002_test_next"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_failed_migration_propagates_without_stamping_or_false_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from alembic import command as alembic_command

    engine = _sqlite_engine(tmp_path / "failed-upgrade.db")

    def fail_upgrade(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic migration failure")

    monkeypatch.setattr(alembic_command, "upgrade", fail_upgrade)
    try:
        with pytest.raises(RuntimeError, match="synthetic migration failure"):
            await upgrade_database(engine)
        assert (await schema_status(engine)).state == "empty"
    finally:
        await engine.dispose()


def test_alembic_ini_does_not_contain_a_database_dsn_or_password() -> None:
    ini_text = (Path(__file__).parents[1] / "arborpress/migrations/alembic.ini").read_text(
        encoding="utf-8"
    )
    assert "sqlalchemy.url" not in ini_text
    assert "password" not in ini_text.lower()
