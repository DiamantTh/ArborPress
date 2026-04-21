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


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency-injection helper for routes / CLI."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


async def create_all_tables() -> None:
    """Create all tables (dev/test – production: Alembic).

    Also runs lightweight column migrations for tables that already exist,
    so that an existing installation is upgraded without data loss.
    """
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Idempotent column additions for existing databases
        await _add_column_if_missing(conn, "comments", "country_code", "VARCHAR(2)")
        await _add_column_if_missing(conn, "comments", "rdap_json", "TEXT")


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
        else:
            # PostgreSQL / MariaDB / MySQL: information_schema
            result = await conn.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = :t AND column_name = :c"
                ),
                {"t": table, "c": column},
            )
            if result.fetchone() is None:
                await conn.execute(
                    sa.text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                )
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger("arborpress.db").debug(
            "Column migration skipped for %s.%s (may already exist)", table, column
        )
