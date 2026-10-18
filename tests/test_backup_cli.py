from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from arborpress.backups.service import create_backup
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


def test_restore_plan_dry_run_and_apply_cli(tmp_path: Path) -> None:
    prefix = tmp_path / "restore-prefix"
    paths = ArborPressPaths.from_prefix(prefix)
    ensure_instance_layout(paths)
    (paths.media / "cover.txt").write_text("saved", encoding="utf-8")
    backup = asyncio.run(
        create_backup(
            paths=paths,
            components=("media",),
            created_at=datetime(2026, 10, 18, 12, tzinfo=UTC),
        )
    )
    (paths.media / "cover.txt").write_text("changed", encoding="utf-8")
    runner = CliRunner()
    prefix_args = ["--prefix", str(prefix)]

    planned = runner.invoke(
        app,
        [*prefix_args, "restore", "plan", backup.backup_id, "--component", "media", "--json"],
    )
    assert planned.exit_code == 0, planned.output
    assert json.loads(planned.stdout)["verification_ok"] is True
    assert (paths.media / "cover.txt").read_text(encoding="utf-8") == "changed"

    dry_run = runner.invoke(
        app,
        [
            *prefix_args,
            "restore",
            "apply",
            backup.backup_id,
            "--component",
            "media",
            "--dry-run",
            "--json",
        ],
    )
    assert dry_run.exit_code == 0, dry_run.output
    assert json.loads(dry_run.stdout)["staging_validated"] is True
    assert (paths.media / "cover.txt").read_text(encoding="utf-8") == "changed"

    applied = runner.invoke(
        app,
        [
            *prefix_args,
            "restore",
            "apply",
            backup.backup_id,
            "--component",
            "media",
            "--offline",
            "--yes",
            "--json",
        ],
    )
    assert applied.exit_code == 0, applied.output
    assert json.loads(applied.stdout)["result"] == "success"
    assert (paths.media / "cover.txt").read_text(encoding="utf-8") == "saved"
