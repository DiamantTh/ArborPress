"""Pytest-Fixtures für ArborPress-Tests (§12 async SQLAlchemy, §2 Auth)."""

from __future__ import annotations

import asyncio
import pytest
from quart import Quart
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# asyncio-mode ist in pyproject.toml auf "auto" gesetzt


@pytest.fixture(scope="session")
def event_loop_policy():
    """asyncio-Eventloop-Policy für die gesamte Test-Session."""
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="session")
async def test_engine():
    """In-Memory-SQLite-Engine für Tests (kein PostgreSQL nötig)."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    # Alle Tabellen erstellen
    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture()
async def db_session(test_engine):
    """Async-DB-Session – jeder Test bekommt eine frische Transaction."""
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as session:
        async with session.begin():
            yield session
            await session.rollback()


@pytest.fixture(scope="session")
def app(test_engine):
    """Quart-Test-App mit In-Memory-SQLite."""
    import arborpress.core.db as db_mod

    # Test-Engine injizieren
    db_mod._engine = test_engine

    from arborpress.web.app import create_app
    quart_app = create_app()
    quart_app.config["TESTING"] = True
    return quart_app


@pytest.fixture()
async def client(app: Quart):
    """Async-HTTP-Test-Client."""
    async with app.test_client() as c:
        yield c


@pytest.fixture()
def settings():
    """Lädt die (Default-)Settings ohne config.toml."""
    from arborpress.core.config import Settings
    return Settings()

