"""Alembic fresh-install, downgrade and supported legacy-adoption tests."""

from __future__ import annotations

import hashlib
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
CURRENT_HEAD = "0009_activitypub_foundation"


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
        assert status.current_revisions == (CURRENT_HEAD,)
        before = await _schema_snapshot(engine)
        assert len(before) == 48
        assert "webauthn_credentials" in before

        async with engine.connect() as connection:
            version = await connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            assert version == CURRENT_HEAD
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
async def test_mail_outbox_migration_preserves_legacy_failed_rows(tmp_path: Path) -> None:
    engine = _sqlite_engine(tmp_path / "mail-outbox-upgrade.db")
    try:
        await upgrade_database(engine)
        await downgrade_database("0005_plugin_capabilities_storage_jobs", engine)
        async with engine.begin() as connection:
            await connection.execute(
                sa.text(
                    "INSERT INTO mail_queue (id, idempotency_key, recipient, subject, body_text, "
                    "body_html, pgp_encrypted, status, attempts, next_attempt_at, last_error, "
                    "created_at, sent_at) VALUES (:id, :key, :recipient, :subject, :body, NULL, "
                    "0, 'FAILED', 2, NULL, 'legacy failure', CURRENT_TIMESTAMP, NULL)"
                ),
                {
                    "id": "legacy-mail-id",
                    "key": "legacy-mail-key",
                    "recipient": "legacy@example.test",
                    "subject": "Legacy subject",
                    "body": "Legacy body",
                },
            )
        await upgrade_database(engine)
        async with engine.connect() as connection:
            row = (
                await connection.execute(
                    sa.text(
                        "SELECT status, attempts, message_id, profile_id, updated_at "
                        "FROM mail_queue WHERE id = 'legacy-mail-id'"
                    )
                )
            ).one()
            assert row.status == "dead"
            assert row.attempts == 2
            assert row.message_id == "<legacy-mail-id@arborpress.invalid>"
            assert row.profile_id == "transactional"
            assert row.updated_at is not None
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
        initial_status = await schema_status(engine)
        assert initial_status.state == "legacy", initial_status.detail
        before = await _schema_snapshot(engine)
        await adopt_legacy_database(engine)
        status = await schema_status(engine)
        assert status.is_current
        assert status.current_revisions == (CURRENT_HEAD,)
        after = await _schema_snapshot(engine)
        assert after != before
        assert "comment_revisions" in after

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
async def test_comment_core_migration_maps_legacy_states_and_hashes_pending_tokens(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "legacy-comments.db"
    _load_legacy_fixture(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO posts (id, short_id, author_id, slug, title, body_md, body_html, status, "
            "visibility, is_pinned, is_featured, noindex, reading_time_min) "
            "VALUES ('post', 'short', 'legacy-user', 'post', 'Title', '', '', 'PUBLISHED', "
            "'PUBLIC', 0, 0, 0, 1)"
        )
        connection.execute(
            "INSERT INTO posts (id, short_id, author_id, slug, title, body_md, body_html, status, "
            "visibility, is_pinned, is_featured, noindex, reading_time_min) "
            "VALUES ('unassigned-post', 'short-null', NULL, 'unassigned', 'Unassigned', '', '', "
            "'DRAFT', 'PUBLIC', 0, 0, 0, 1)"
        )
        connection.executemany(
            "INSERT INTO comments (id, post_id, author_name, author_email, body, status, "
            "confirmation_token) VALUES (?, 'post', 'Visitor', ?, 'body', ?, ?)",
            [
                ("pending", "pending@example.test", "PENDING", "old-pending-token"),
                ("confirmed", "confirmed@example.test", "CONFIRMED", "old-confirmed-token"),
                ("approved", "approved@example.test", "APPROVED", "old-approved-token"),
                ("rejected", "rejected@example.test", "REJECTED", "old-rejected-token"),
                ("spam", "spam@example.test", "SPAM", "old-spam-token"),
            ],
        )
        connection.commit()
    engine = _sqlite_engine(database_path)
    try:
        await upgrade_database(engine)
        async with engine.connect() as connection:
            rows = (
                (
                    await connection.execute(
                        sa.text(
                            "SELECT id, status, confirmation_token_hash, confirmation_expires_at, "
                            "published_at "
                            "FROM comments ORDER BY id"
                        )
                    )
                )
                .mappings()
                .all()
            )
        by_id = {row["id"]: row for row in rows}
        assert by_id["pending"]["status"] == "pending_confirmation"
        assert (
            by_id["pending"]["confirmation_token_hash"]
            == hashlib.sha256(b"old-pending-token").hexdigest()
        )
        assert by_id["pending"]["confirmation_expires_at"] is not None
        assert by_id["confirmed"]["status"] == "pending_moderation"
        assert by_id["confirmed"]["confirmation_token_hash"] is None
        assert by_id["approved"]["status"] == "approved"
        assert by_id["approved"]["published_at"] is not None
        assert by_id["rejected"]["status"] == "rejected"
        assert by_id["spam"]["status"] == "spam"
        async with engine.connect() as connection:
            author_row = (
                await connection.execute(
                    sa.text(
                        "SELECT user_id, role, position FROM post_author_relations "
                        "WHERE post_id='post'"
                    )
                )
            ).one()
            unassigned_count = await connection.scalar(
                sa.text(
                    "SELECT COUNT(*) FROM post_author_relations WHERE post_id='unassigned-post'"
                )
            )
        assert author_row == ("legacy-user", "primary", 0)
        assert unassigned_count == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_authorship_revision_downgrade_preserves_legacy_primary_projection(
    tmp_path: Path,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.content.authors import replace_post_authors
    from arborpress.models.authorization import ObjectRelation, ObjectRelationName
    from arborpress.models.content import Post
    from arborpress.models.user import AccountType, User, UserRole

    engine = _sqlite_engine(tmp_path / "authors-downgrade.db")
    try:
        await upgrade_database(engine)
        factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with factory() as db:
            author = User(
                username="migration-author",
                display_name="Migration Author",
                account_type=AccountType.PUBLIC,
                role=UserRole.AUTHOR,
                is_active=True,
            )
            post = Post(
                short_id="migration1",
                slug="migration-author-post",
                title="Migration post",
                body_md="",
                body_html="",
            )
            db.add_all([author, post])
            await db.flush()
            await replace_post_authors(
                db,
                post_id=str(post.id),
                primary_user_id=str(author.id),
                coauthor_user_ids=[],
                actor_user_id=str(author.id),
            )
            db.add(
                ObjectRelation(
                    subject_user_id=str(author.id),
                    object_type="content",
                    object_id=str(post.id),
                    relation=ObjectRelationName.EDITOR,
                )
            )
            await db.commit()
            post_id, author_id = str(post.id), str(author.id)

        await downgrade_database("0003_comment_moderation_appeals", engine)
        async with engine.connect() as connection:
            restored_legacy_author = await connection.scalar(
                sa.text("SELECT author_id FROM posts WHERE id=:post_id"),
                {"post_id": post_id},
            )
            remaining_tables = await connection.run_sync(
                lambda sync_connection: set(sa.inspect(sync_connection).get_table_names())
            )
        assert restored_legacy_author == author_id
        assert "post_author_relations" not in remaining_tables
        assert "object_relations" not in remaining_tables

        await upgrade_database(engine)
        async with engine.connect() as connection:
            migrated_author = (
                await connection.execute(
                    sa.text(
                        "SELECT user_id, role, position FROM post_author_relations "
                        "WHERE post_id=:post_id"
                    ),
                    {"post_id": post_id},
                )
            ).one()
        assert migrated_author == (author_id, "primary", 0)
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
        "revision = '9999_test_next'\n"
        "down_revision = '0009_activitypub_foundation'\n"
        "branch_labels = None\n"
        "depends_on = None\n"
        "def upgrade(): pass\n"
        "def downgrade(): pass\n",
        encoding="utf-8",
    )
    try:
        await upgrade_database(engine)
        await downgrade_database(BASELINE_REVISION, engine)
        config = Config(migration_module._config().config_file_name)
        config.set_main_option(
            "version_locations",
            f"{Path(__file__).parents[1] / 'arborpress/migrations/versions'}{os.pathsep}{versions}",
        )
        monkeypatch.setattr(migration_module, "_config", lambda: config)
        status = await schema_status(engine)
        assert status.state == "behind"
        assert status.current_revisions == (BASELINE_REVISION,)
        assert status.head_revision == "9999_test_next"
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
