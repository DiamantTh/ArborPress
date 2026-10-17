"""Pytest-Fixtures für ArborPress-Tests (§12 async SQLAlchemy, §2 Auth)."""

from __future__ import annotations

import os
import tempfile

import pytest
from quart import Quart
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


@pytest.fixture(scope="session", autouse=True)
def runtime_prefix(tmp_path_factory: pytest.TempPathFactory):
    """Give tests one explicit instance identity without relying on cwd."""
    from arborpress.runtime.paths import reset_runtime_for_tests

    prefix = tmp_path_factory.mktemp("arborpress-test-prefix")
    reset_runtime_for_tests(prefix)
    yield prefix
    reset_runtime_for_tests()


@pytest.fixture(autouse=True)
def reset_runtime_settings(runtime_prefix):
    """Isolate prefix-sensitive settings and service singletons per test."""
    from arborpress.core.config import reset_settings
    from arborpress.plugins.registry import reset_registry_for_tests
    from arborpress.runtime.paths import reset_runtime_for_tests
    from arborpress.themes.manifest import reset_theme_registry_for_tests
    from arborpress.web import ratelimit

    reset_settings()
    ratelimit._limiter = None
    reset_registry_for_tests()
    reset_theme_registry_for_tests()
    yield
    reset_settings()
    ratelimit._limiter = None
    reset_registry_for_tests()
    reset_theme_registry_for_tests()
    reset_runtime_for_tests(runtime_prefix)


@pytest.fixture(scope="session")
async def test_engine(runtime_prefix):
    """Datei-SQLite-Engine für Tests (kein PostgreSQL nötig).

    Eine temporäre Datei statt :memory: wird verwendet, damit Verbindungs-
    invalidierungen (CancelledError beim aiosqlite-Rollback) keine leere
    In-Memory-Datenbank erzeugen – alle Tabellen bleiben über Verbindungsresets
    erhalten.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db_path = tmp.name

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    # Test databases use the same packaged migration path as fresh installs.
    import arborpress.models  # noqa: F401
    from arborpress.core.migrations import upgrade_database

    await upgrade_database(engine)

    yield engine

    await engine.dispose()
    os.unlink(db_path)


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

    # Test-Engine injizieren; _session_factory zurücksetzen damit
    # get_session_factory() die neue Engine aufgreift statt eine alte zu cachen.
    db_mod._engine = test_engine
    db_mod._session_factory = None

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
