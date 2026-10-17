"""Alembic environment using ArborPress configuration and async SQLAlchemy."""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

import arborpress.models  # noqa: F401
from arborpress.core.config import get_settings
from arborpress.core.db import Base

# Importing arborpress.models above registers every mapped table before the
# metadata is handed to Alembic.
config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Render migration SQL without opening a database connection."""
    context.configure(
        url=get_settings().db.url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    settings = get_settings()
    connectable = create_async_engine(
        settings.db.url,
        echo=settings.db.echo,
        poolclass=NullPool,
    )
    try:
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        await connectable.dispose()


def run_migrations_online() -> None:
    """Use an injected connection for ArborPress API calls, otherwise async DB."""
    connection = config.attributes.get("connection")
    if connection is not None:
        do_run_migrations(connection)
    else:
        asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
