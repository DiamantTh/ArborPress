from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url
from typer.testing import CliRunner

from arborpress.core.config import (
    get_config_dir,
    get_settings,
    install_token_path,
    installed_marker_path,
    is_installed,
    reset_settings,
)
from arborpress.runtime.paths import ensure_instance_layout, initialize_runtime


def _activate_prefix(prefix: Path) -> None:
    paths = initialize_runtime(prefix, override=True)
    ensure_instance_layout(paths)
    reset_settings()


def test_default_config_ignores_working_directory_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = initialize_runtime(tmp_path / "prefix", override=True)
    ensure_instance_layout(paths)
    paths.config_file.write_text("[web]\nport = 8123\n", encoding="utf-8")
    foreign_cwd = tmp_path / "foreign"
    (foreign_cwd / "config").mkdir(parents=True)
    (foreign_cwd / "config" / "config.toml").write_text(
        "[web]\nport = 8999\n", encoding="utf-8"
    )
    monkeypatch.chdir(foreign_cwd)
    reset_settings()

    settings = get_settings()

    assert settings.web.port == 8123
    assert settings._config_file == paths.config_file
    assert get_config_dir() == paths.config


def test_explicit_config_override_does_not_change_prefix_sidecars(tmp_path: Path) -> None:
    paths = initialize_runtime(tmp_path / "prefix", override=True)
    ensure_instance_layout(paths)
    override = tmp_path / "secure" / "config.toml"
    override.parent.mkdir()
    override.write_text("[web]\nport = 9123\n", encoding="utf-8")
    reset_settings()

    settings = get_settings(override)

    assert settings.web.port == 9123
    assert settings._config_file == override.resolve()
    assert get_config_dir() == paths.config
    assert install_token_path() == paths.config / "install.token"
    assert installed_marker_path() == paths.config / ".installed"


def test_install_marker_and_token_are_prefix_scoped_not_cwd_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = initialize_runtime(tmp_path / "prefix", override=True)
    ensure_instance_layout(paths)
    foreign_cwd = tmp_path / "foreign"
    (foreign_cwd / "config").mkdir(parents=True)
    (foreign_cwd / "config" / ".installed").write_text("foreign\n", encoding="utf-8")
    (foreign_cwd / ".installed").write_text("foreign\n", encoding="utf-8")
    monkeypatch.chdir(foreign_cwd)
    reset_settings()

    assert install_token_path() == paths.config / "install.token"
    assert installed_marker_path() == paths.config / ".installed"
    assert not is_installed()

    installed_marker_path().write_text("installed\n", encoding="utf-8")
    assert is_installed()


def test_relative_sqlite_database_is_resolved_under_instance_data(tmp_path: Path) -> None:
    paths = initialize_runtime(tmp_path / "prefix", override=True)
    ensure_instance_layout(paths)
    paths.config_file.write_text(
        '[db]\nurl = "sqlite+aiosqlite:///nested/arborpress.db"\n', encoding="utf-8"
    )
    reset_settings()

    database_url = make_url(get_settings().db.url)

    assert database_url.database == str(paths.data / "nested" / "arborpress.db")


def test_absolute_sqlite_and_server_database_urls_are_not_rewritten(
    tmp_path: Path,
) -> None:
    paths = initialize_runtime(tmp_path / "prefix", override=True)
    ensure_instance_layout(paths)
    absolute_sqlite = tmp_path / "explicit.db"
    paths.config_file.write_text(
        f'[db]\nurl = "sqlite+aiosqlite:///{absolute_sqlite}"\n', encoding="utf-8"
    )
    reset_settings()
    assert make_url(get_settings().db.url).database == str(absolute_sqlite)

    reset_settings()
    postgres_url = "postgresql+asyncpg://user:pass@example.invalid/db"
    paths.config_file.write_text(
        f'[db]\nurl = "{postgres_url}"\n', encoding="utf-8"
    )
    assert get_settings().db.url == postgres_url


def test_relative_sqlite_path_cannot_escape_instance_data(tmp_path: Path) -> None:
    paths = initialize_runtime(tmp_path / "prefix", override=True)
    ensure_instance_layout(paths)
    paths.config_file.write_text(
        '[db]\nurl = "sqlite+aiosqlite:///../escape.db"\n', encoding="utf-8"
    )
    reset_settings()

    with pytest.raises(ValueError, match="inside instance/data"):
        get_settings()


def test_paths_cli_accepts_explicit_and_environment_prefixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.cli.main import app

    cli_prefix = tmp_path / "cli-prefix"
    env_prefix = tmp_path / "env-prefix"
    monkeypatch.setenv("ARBORPRESS_PREFIX", str(env_prefix))
    runner = CliRunner()

    explicit = runner.invoke(app, ["--prefix", str(cli_prefix), "paths", "--json"])
    assert explicit.exit_code == 0, explicit.output
    cli_values = json.loads(explicit.output)
    assert cli_values["prefix"] == str(cli_prefix.resolve())
    assert cli_values["config_file"] == str(
        cli_prefix.resolve() / "instance" / "config" / "config.toml"
    )

    environment = runner.invoke(app, ["paths", "--json"])
    assert environment.exit_code == 0, environment.output
    env_values = json.loads(environment.output)
    assert env_values["prefix"] == str(env_prefix.resolve())


def test_cli_config_override_does_not_change_prefix_identity(tmp_path: Path) -> None:
    from arborpress.cli.main import app

    prefix = tmp_path / "prefix"
    override = tmp_path / "external" / "config.toml"
    override.parent.mkdir()
    override.write_text("[web]\nport = 9222\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["--prefix", str(prefix), "--config", str(override), "paths", "--json"],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["prefix"] == str(prefix.resolve())


def test_runtime_context_can_be_initialized_without_cli_for_library_use(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "embedded"
    _activate_prefix(prefix)

    assert get_config_dir() == prefix.resolve() / "instance" / "config"
