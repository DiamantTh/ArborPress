"""End-to-end CLI contract for the packaged migration commands."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from quart.testing.app import LifespanError
from sqlalchemy.ext.asyncio import create_async_engine
from typer.testing import CliRunner

import arborpress.core.config as config_module
import arborpress.core.db as db_module
from arborpress.runtime.paths import ensure_instance_layout, initialize_runtime


def test_database_cli_upgrade_current_check_history_and_downgrade(
    tmp_path: Path,
) -> None:
    from arborpress.cli.main import app

    paths = initialize_runtime(tmp_path / "cli-prefix", override=True)
    ensure_instance_layout(paths)
    paths.config_file.write_text(
        '[db]\nurl = "sqlite+aiosqlite:///cli.db"\n', encoding="utf-8"
    )
    old_engine = db_module._engine
    old_factory = db_module._session_factory
    db_module._engine = None
    db_module._session_factory = None
    runner = CliRunner()
    prefix_args = ["--prefix", str(paths.prefix)]
    try:
        initial_check = runner.invoke(app, [*prefix_args, "db", "check"])
        assert initial_check.exit_code == 1
        assert "empty" in initial_check.output

        history = runner.invoke(app, [*prefix_args, "db", "history"])
        assert history.exit_code == 0
        assert "0001_pre_alembic_baseline" in history.output

        upgrade = runner.invoke(app, [*prefix_args, "db", "upgrade"])
        assert upgrade.exit_code == 0, upgrade.output
        assert "current" in upgrade.output

        current = runner.invoke(app, [*prefix_args, "db", "current"])
        assert current.exit_code == 0
        assert "Status:           current" in current.output

        check = runner.invoke(app, [*prefix_args, "db", "check"])
        assert check.exit_code == 0, check.output

        downgrade = runner.invoke(app, [*prefix_args, "db", "downgrade", "base", "--yes"])
        assert downgrade.exit_code == 0, downgrade.output
        assert runner.invoke(app, [*prefix_args, "db", "check"]).exit_code == 1
    finally:
        if db_module._engine is not None:
            asyncio.run(db_module._engine.dispose())
        db_module._engine = old_engine
        db_module._session_factory = old_factory


def test_database_cli_upgrade_failure_has_a_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import arborpress.core.migrations as migration_module
    from arborpress.cli.main import app

    async def fail_upgrade() -> None:
        raise RuntimeError("synthetic migration failure")

    monkeypatch.setattr(migration_module, "upgrade_database", fail_upgrade)
    prefix = tmp_path / "failure-prefix"
    result = CliRunner().invoke(app, ["--prefix", str(prefix), "db", "upgrade"])
    assert result.exit_code == 1
    assert "synthetic migration failure" in result.output


@pytest.mark.asyncio
async def test_installed_web_startup_refuses_an_empty_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = initialize_runtime(tmp_path / "startup-prefix", override=True)
    ensure_instance_layout(paths)
    startup_db = tmp_path / "startup.db"
    paths.config_file.write_text(
        f'[db]\nurl = "sqlite+aiosqlite:///{startup_db}"\n', encoding="utf-8"
    )
    engine = create_async_engine(f"sqlite+aiosqlite:///{startup_db}")
    config_module.reset_settings()
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
