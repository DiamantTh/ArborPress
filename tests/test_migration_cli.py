"""End-to-end CLI contract for the packaged migration commands."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from quart.testing.app import LifespanError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from typer.testing import CliRunner

import arborpress.core.config as config_module
import arborpress.core.db as db_module
from arborpress.core.config import DatabaseSettings, Settings


def test_database_cli_upgrade_current_check_history_and_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from arborpress.cli.main import app

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}",
        poolclass=NullPool,
    )
    monkeypatch.setattr(
        config_module,
        "_settings",
        Settings(db=DatabaseSettings(url=f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}")),
    )
    monkeypatch.setattr(db_module, "_engine", engine)
    monkeypatch.setattr(db_module, "_session_factory", None)
    runner = CliRunner()
    try:
        initial_check = runner.invoke(app, ["db", "check"])
        assert initial_check.exit_code == 1
        assert "empty" in initial_check.output

        history = runner.invoke(app, ["db", "history"])
        assert history.exit_code == 0
        assert "0001_pre_alembic_baseline" in history.output

        upgrade = runner.invoke(app, ["db", "upgrade"])
        assert upgrade.exit_code == 0, upgrade.output
        assert "current" in upgrade.output

        current = runner.invoke(app, ["db", "current"])
        assert current.exit_code == 0
        assert "Status:           current" in current.output

        check = runner.invoke(app, ["db", "check"])
        assert check.exit_code == 0, check.output

        downgrade = runner.invoke(app, ["db", "downgrade", "base", "--yes"])
        assert downgrade.exit_code == 0, downgrade.output
        assert runner.invoke(app, ["db", "check"]).exit_code == 1
    finally:
        asyncio.run(engine.dispose())


def test_database_cli_upgrade_failure_has_a_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import arborpress.core.migrations as migration_module
    from arborpress.cli.main import app

    async def fail_upgrade() -> None:
        raise RuntimeError("synthetic migration failure")

    monkeypatch.setattr(migration_module, "upgrade_database", fail_upgrade)
    result = CliRunner().invoke(app, ["db", "upgrade"])
    assert result.exit_code == 1
    assert "synthetic migration failure" in result.output


@pytest.mark.asyncio
async def test_installed_web_startup_refuses_an_empty_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'startup.db'}",
        poolclass=NullPool,
    )
    monkeypatch.setattr(
        config_module,
        "_settings",
        Settings(db=DatabaseSettings(url=f"sqlite+aiosqlite:///{tmp_path / 'startup.db'}")),
    )
    monkeypatch.setattr(config_module, "is_installed", lambda: True)
    monkeypatch.setattr(db_module, "_engine", engine)
    monkeypatch.setattr(db_module, "_session_factory", None)

    from arborpress.web.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    try:
        with pytest.raises(LifespanError, match="arborpress db upgrade"):
            async with app.test_app():
                pass
    finally:
        await engine.dispose()
