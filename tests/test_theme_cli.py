"""Read-only CLI diagnostics for the theme registry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arborpress.themes.manifest import ThemeRegistry


def _write_theme(root: Path, theme_id: str) -> None:
    theme_dir = root / theme_id
    theme_dir.mkdir(parents=True)
    (theme_dir / "theme.toml").write_text(
        f'name = "{theme_id}"\nversion = "1.0.0"\ntype = "public"\n',
        encoding="utf-8",
    )


def test_themes_cli_lists_and_inspects_registry_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = tmp_path / "instance-themes"
    _write_theme(instance, "cli-theme")
    registry = ThemeRegistry(extra_dirs=[instance])
    registry.load()
    monkeypatch.setattr("arborpress.themes.manifest.get_theme_registry", lambda: registry)
    monkeypatch.setattr(
        "arborpress.cli.main._read_theme_selection",
        lambda: {"active": "default", "admin_active": "arbor-admin"},
    )
    from arborpress.cli.main import app

    runner = CliRunner()
    result = runner.invoke(
        app, ["--prefix", str(tmp_path / "cli-prefix"), "themes", "list", "--json"]
    )
    assert result.exit_code == 0, result.output
    entries = json.loads(result.output)
    assert any(entry["id"] == "cli-theme" for entry in entries)
    assert next(entry for entry in entries if entry["id"] == "arbor-admin")["active_admin"]

    inspected = runner.invoke(
        app,
        [
            "--prefix",
            str(tmp_path / "cli-prefix"),
            "themes",
            "inspect",
            "cli-theme",
            "--json",
        ],
    )
    assert inspected.exit_code == 0, inspected.output
    assert json.loads(inspected.output)["status"] == "valid"


def test_theme_cli_does_not_mark_duplicate_instance_id_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = tmp_path / "instance-themes"
    _write_theme(instance, "default")
    registry = ThemeRegistry(extra_dirs=[instance])
    registry.load()
    monkeypatch.setattr("arborpress.themes.manifest.get_theme_registry", lambda: registry)
    monkeypatch.setattr(
        "arborpress.cli.main._read_theme_selection",
        lambda: {"active": "default", "admin_active": "arbor-admin"},
    )
    from arborpress.cli.main import app

    result = CliRunner().invoke(
        app, ["--prefix", str(tmp_path / "cli-prefix"), "themes", "list", "--json"]
    )
    assert result.exit_code == 0, result.output
    entries = json.loads(result.output)
    builtin = next(
        item for item in entries if item["id"] == "default" and item["source"] == "builtin"
    )
    duplicate = next(
        item for item in entries if item["id"] == "default" and item["source"] == "instance"
    )
    assert builtin["active_public"] is True
    assert duplicate["status"] == "duplicate_id"
    assert duplicate["active_public"] is False


def test_fresh_prefix_theme_listing_does_not_open_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import arborpress.core.config as config_module
    import arborpress.core.db as db_module
    from arborpress.cli.main import _read_theme_selection

    monkeypatch.setattr(config_module, "is_installed", lambda: False)
    monkeypatch.setattr(
        db_module,
        "get_db_session",
        lambda: pytest.fail("fresh-prefix theme listing must not open a database"),
    )
    assert _read_theme_selection() == {
        "active": "default",
        "admin_active": "arbor-admin",
    }
