from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from arborpress.cli.main import app
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


def test_backup_list_json_and_rejects_unknown_inspect_id(tmp_path: Path) -> None:
    prefix = tmp_path / "prefix"
    paths = ArborPressPaths.from_prefix(prefix)
    ensure_instance_layout(paths)
    runner = CliRunner()

    listed = runner.invoke(app, ["--prefix", str(prefix), "backup", "list", "--json"])
    inspected = runner.invoke(
        app,
        ["--prefix", str(prefix), "backup", "inspect", "../elsewhere"],
    )

    assert listed.exit_code == 0
    assert listed.stdout.strip() == "[]"
    assert inspected.exit_code == 2
    assert "Invalid backup ID" in inspected.stderr


def test_backup_create_command_can_create_and_verify_a_selected_component(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "prefix"
    paths = ArborPressPaths.from_prefix(prefix)
    ensure_instance_layout(paths)
    (paths.media / "cover.txt").write_text("public media", encoding="utf-8")
    runner = CliRunner()

    created = runner.invoke(
        app,
        [
            "--prefix",
            str(prefix),
            "backup",
            "create",
            "--component",
            "media",
            "--media-segment-size",
            "5",
        ],
    )

    assert created.exit_code == 0, created.output
    assert "Backup created and verified" in created.stdout
    assert "unencrypted" in created.stderr
    assert len(list(paths.backups.glob("20*/manifest.toml"))) == 1
