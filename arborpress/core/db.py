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
    """Create all tables (dev/test – production: Alembic)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
