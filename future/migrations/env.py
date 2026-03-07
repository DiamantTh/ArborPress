"""Alembic Environment-Skript für ArborPress (§12 async DB).

Unterstützt sowohl Online-Mode (direkter DB-Zugriff) als auch
Offline-Mode (SQL-Skript-Generierung).

Konfiguration wird aus config.toml geladen; ALEMBIC_URL-Umgebungsvariable
überschreibt die URL (für CI/CD).
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# ArborPress-Paket im sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Modelle importieren damit metadata vollständig ist
import arborpress.models  # noqa: F401 E402
from arborpress.core.db import Base  # noqa: E402

# Alembic-Config
config = context.config

# Logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    """URL aus Umgebungsvariable oder config.toml (§12)."""
    env_url = os.environ.get("ALEMBIC_URL") or os.environ.get("ARBORPRESS_DB__URL")
    if env_url:
        return env_url

    config_toml = Path("config.toml")
    if config_toml.exists():
        from arborpress.core.config import Settings
        settings = Settings.from_file(config_toml)
        return settings.db.url

    return config.get_main_option("sqlalchemy.url", "")


def run_migrations_offline() -> None:
    """SQL-Skript ohne DB-Verbindung generieren."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Async-Engine für PostgreSQL / MariaDB (§12)."""
    url = _get_url()
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
