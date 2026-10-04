"""DB session factory (SQLAlchemy async).

Supported backends:
  postgresql+asyncpg://...     PostgreSQL (production, recommended)
  mysql+aiomysql://...         MariaDB ≥ 11 / MySQL ≥ 8
  sqlite+aiosqlite:///...      SQLite (development / tests; dep: aiosqlite)
  sqlite+aiosqlite:///:memory: In-memory SQLite (unit tests only)

SQLite notes:
  - pool_size is ignored (StaticPool for :memory:, NullPool for file SQLite)
  - WAL mode and foreign keys are enabled automatically
  - Not suitable for production use with multiple worker processes
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from arborpress.core.config import get_settings

log = logging.getLogger("arborpress.db")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


class Base(DeclarativeBase):
    """Base class for all ORM models."""


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        cfg = get_settings()
        url = cfg.db.url
        echo = cfg.db.echo

        if cfg.db.is_sqlite:
            # SQLite: no connection pool, WAL + FK via connect_args/event
            from sqlalchemy import event as sa_event
            from sqlalchemy.pool import NullPool, StaticPool

            is_memory = ":memory:" in url
            pool_cls = StaticPool if is_memory else NullPool

            connect_args: dict = {}
            if is_memory:
                connect_args = {"check_same_thread": False}

            _engine = create_async_engine(
                url,
                echo=echo,
                connect_args=connect_args,
                poolclass=pool_cls,
            )

            # Enable WAL mode and foreign key enforcement for SQLite

            @sa_event.listens_for(_engine.sync_engine, "connect")
            def _sqlite_pragmas(dbapi_conn: object, _: object) -> None:
                cursor = dbapi_conn.cursor()  # type: ignore[union-attr]
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

            log.info("SQLite backend: %s (WAL + FK enabled)", url)
        else:
            _engine = create_async_engine(
                url,
                pool_size=cfg.db.pool_size,
                echo=echo,
            )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _session_factory


async def get_db_session() -> AsyncGenerator[AsyncSession]:
    """Dependency-injection helper for routes / CLI."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


async def create_all_tables() -> None:
    """Create tables and apply the repository's additive DB migrations.

    ``arborpress db migrate`` and the production container entrypoint call
    this idempotent migration path. Existing auth rows are retained and the
    legacy transport column is copied into its new list representation.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Idempotent column additions for existing databases
        await _add_column_if_missing(conn, "comments", "country_code", "VARCHAR(2)")
        await _add_column_if_missing(conn, "comments", "rdap_json", "TEXT")
        # Auth schema evolution is additive: legacy credentials, MFA devices,
        # users, and sessions remain intact during upgrades.
        for column, col_type in (
            ("aaguid", "VARCHAR(64)"),
            ("transports", "TEXT"),
            ("authenticator_attachment", "VARCHAR(32)"),
            ("backup_eligible", "BOOLEAN"),
            ("backup_state", "BOOLEAN"),
            ("verification_status", "VARCHAR(32) NOT NULL DEFAULT 'unknown'"),
        ):
            await _add_column_if_missing(conn, "webauthn_credentials", column, col_type)
        await _add_column_if_missing(
            conn, "user_sessions", "auth_method", "VARCHAR(64) NOT NULL DEFAULT 'unknown'"
        )
        await _add_column_if_missing(
            conn, "user_sessions", "assurance_level", "VARCHAR(32) NOT NULL DEFAULT 'unknown'"
        )
        await _add_column_if_missing(
            conn, "auth_stepup_grants", "auth_method", "VARCHAR(32) NOT NULL DEFAULT 'unknown'"
        )
        await _add_column_if_missing(
            conn, "auth_stepup_grants", "assurance_level", "VARCHAR(32) NOT NULL DEFAULT 'unknown'"
        )
        await _add_column_if_missing(
            conn, "auth_stepup_grants", "confirming_credential_id", "VARCHAR(36)"
        )
        await _add_column_if_missing(
            conn, "auth_stepup_grants", "confirming_mfa_device_id", "VARCHAR(36)"
        )
        await _add_column_if_missing(
            conn, "mfa_devices", "verification_status", "VARCHAR(32) NOT NULL DEFAULT 'unknown'"
        )
        await _add_column_if_missing(conn, "audit_events", "target_id", "VARCHAR(36)")
        await _backfill_legacy_transports(conn)


async def _add_column_if_missing(
    conn,
    table: str,
    column: str,
    col_type: str,
) -> None:
    """Add *column* to *table* when it does not exist yet (no-op otherwise)."""
    import sqlalchemy as sa

    dialect = conn.dialect.name
    try:
        if dialect == "sqlite":
            # PRAGMA table_info returns one row per column
            result = await conn.execute(sa.text(f"PRAGMA table_info({table})"))
            existing = {row[1] for row in result.fetchall()}
            if column not in existing:
                await conn.execute(
                    sa.text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                )
        elif dialect == "postgresql":
            # Scope to the current schema to avoid false positives from other
            # schemas that may contain a same-named table (e.g. public vs. app).
            result = await conn.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = current_schema() "
                    "AND table_name = :t AND column_name = :c"
                ),
                {"t": table, "c": column},
            )
            if result.fetchone() is None:
                await conn.execute(
                    sa.text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                )
        else:
            # MariaDB / MySQL: scope to current database()
            result = await conn.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = database() "
                    "AND table_name = :t AND column_name = :c"
                ),
                {"t": table, "c": column},
            )
            if result.fetchone() is None:
                await conn.execute(
                    sa.text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                )
    except Exception as exc:  # noqa: BLE001
        # Do not hide production schema failures. A deployment must not start
        # with a half-applied security migration.
        log.exception("Column migration failed for %s.%s", table, column)
        raise RuntimeError(f"Failed to migrate {table}.{column}") from exc


async def _backfill_legacy_transports(conn) -> None:
    """Copy the old single `transport` value into the new JSON list field."""
    import json

    import sqlalchemy as sa

    result = await conn.execute(sa.text(
        "SELECT id, transport FROM webauthn_credentials "
        "WHERE transports IS NULL AND transport IS NOT NULL"
    ))
    for credential_id, transport in result.fetchall():
        value = str(transport).strip()
        if value:
            await conn.execute(
                sa.text(
                    "UPDATE webauthn_credentials SET transports = :transports WHERE id = :id"
                ),
                {"transports": json.dumps([value]), "id": credential_id},
            )
