"""ArborPress CLI – Admin Focus (§14, WP-CLI/occ-style).

Rules (§14 / CLI design rules):
- Commands use the same core services as the web app
- Plugins can register additional CLI commands via declared capabilities

Usage:  arborpress --help
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import venv
from collections.abc import Awaitable, Callable
from dataclasses import asdict, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import typer

from arborpress.backups.archive import DEFAULT_MEDIA_SEGMENT_SIZE
from arborpress.core.config import get_settings
from arborpress.core.i18n import cli_gettext as __
from arborpress.runtime.paths import (
    ensure_instance_layout,
    get_runtime_paths,
    initialize_runtime,
    resolve_prefix,
)

if TYPE_CHECKING:
    from cryptography.fernet import Fernet

    from arborpress.backups.encryption import BackupKey
    from arborpress.themes.manifest import ThemeRecord, ThemeRegistry

# ---------------------------------------------------------------------------
# App-Instanz + Sub-Apps
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="arborpress",
    help="Arbor Press – security-focused blogging platform/mini CMS",
    no_args_is_help=True,
)

db_app = typer.Typer(help="Database operations (§12)", no_args_is_help=True)
user_app = typer.Typer(help="User management (§14)", no_args_is_help=True)
mfa_app = typer.Typer(help="MFA device management (§3)", no_args_is_help=True)
key_app = typer.Typer(help="Key management (§13 OpenPGP, §14)", no_args_is_help=True)
search_app = typer.Typer(help="Search index (§12 FTS)", no_args_is_help=True)
cache_app = typer.Typer(help="Cache management", no_args_is_help=True)
federation_app = typer.Typer(help="Federation / ActivityPub (§5, §14)", no_args_is_help=True)
federation_actor_app = typer.Typer(help="Explicit local federation actors", no_args_is_help=True)
federation_inbox_app = typer.Typer(help="Persisted federation inbox intake", no_args_is_help=True)
federation_domain_app = typer.Typer(help="Federation domain policy", no_args_is_help=True)
mail_app = typer.Typer(help="Mail queue (§13)", no_args_is_help=True)
mail_profiles_app = typer.Typer(help="Named SMTP profiles", no_args_is_help=True)
mail_queue_app = typer.Typer(help="Durable mail outbox diagnostics", no_args_is_help=True)
notifications_app = typer.Typer(help="User notification delivery", no_args_is_help=True)
plugin_app = typer.Typer(help="Third-party plugin diagnostics and enablement", no_args_is_help=True)
plugin_runtime_app = typer.Typer(help="Plugin-local isolated interpreters", no_args_is_help=True)
webauthn_app = typer.Typer(help="WebAuthn / Passkey recovery (§17)", no_args_is_help=True)
themes_app = typer.Typer(help="Theme diagnostics (read-only)", no_args_is_help=True)
backup_app = typer.Typer(help="Local backup set operations", no_args_is_help=True)
backup_key_app = typer.Typer(help="Backup encryption keyfiles", no_args_is_help=True)
restore_app = typer.Typer(help="Offline local restore operations", no_args_is_help=True)

app.add_typer(db_app, name="db")
app.add_typer(user_app, name="user")
user_app.add_typer(mfa_app, name="mfa")
app.add_typer(key_app, name="key")
app.add_typer(search_app, name="search")
app.add_typer(cache_app, name="cache")
app.add_typer(federation_app, name="federation")
federation_app.add_typer(federation_actor_app, name="actors")
federation_app.add_typer(federation_inbox_app, name="inbox")
federation_app.add_typer(federation_domain_app, name="domains")
app.add_typer(mail_app, name="mail")
app.add_typer(notifications_app, name="notifications")
mail_app.add_typer(mail_profiles_app, name="profiles")
mail_app.add_typer(mail_queue_app, name="queue")
app.add_typer(plugin_app, name="plugins")
# Keep the pre-8A singular CLI namespace as a compatibility alias; both names
# execute only Core-owned discovery/control code.
app.add_typer(plugin_app, name="plugin")
plugin_app.add_typer(plugin_runtime_app, name="runtime")
app.add_typer(webauthn_app, name="webauthn")
app.add_typer(themes_app, name="themes")
app.add_typer(backup_app, name="backup")
backup_app.add_typer(backup_key_app, name="key")
app.add_typer(restore_app, name="restore")


# ---------------------------------------------------------------------------
# Callback – globale Optionen
# ---------------------------------------------------------------------------


@app.callback()
def main_callback(
    prefix: Path | None = typer.Option(  # noqa: B008
        None, "--prefix", help="ArborPress installation prefix"
    ),
    config: Path | None = typer.Option(  # noqa: B008
        None,
        "--config",
        "-c",
        help="Path to config.toml or a config/ directory",
    ),
) -> None:
    """Initialize prefix identity before any command loads configuration."""
    selected_prefix = resolve_prefix(prefix)
    initialize_runtime(selected_prefix, override=True)
    import arborpress.core.config as config_mod

    config_mod.reset_settings()
    from arborpress.core.site_settings import invalidate_cache
    from arborpress.themes.manifest import reset_theme_registry

    invalidate_cache()
    reset_theme_registry()
    if config is not None:
        config_mod.get_settings(config)


@app.command("paths")
def show_paths(
    as_json: bool = typer.Option(False, "--json", help="Print stable JSON fields"),
) -> None:
    """Show the active prefix layout without starting services or opening the DB."""
    paths = get_runtime_paths()
    values = {field.name: str(getattr(paths, field.name)) for field in fields(paths)}
    if as_json:
        typer.echo(json.dumps(values, indent=2, sort_keys=True))
        return
    for name, value in values.items():
        typer.echo(f"{name.replace('_', ' ')}: {value}")


def _theme_payload(record: ThemeRecord, active: dict[str, str]) -> dict[str, Any]:
    return {
        "id": record.id,
        "name": record.name,
        "version": record.version,
        "type": record.type,
        "source": record.source,
        "parent": record.manifest.parent if record.manifest else None,
        "status": record.status,
        "diagnostics": record.diagnostics,
        "active_public": (
            record.status == "valid"
            and record.type == "public"
            and record.id == active.get("active", "default")
        ),
        "active_admin": (
            record.status == "valid"
            and record.type == "admin"
            and record.id == active.get("admin_active", "arbor-admin")
        ),
    }


def _effective_theme_selection(
    registry: ThemeRegistry, configured: dict[str, str]
) -> dict[str, str]:
    return {
        "active": registry.get_or_default(configured.get("active", "default"), "public").id,
        "admin_active": registry.get_or_default(
            configured.get("admin_active", "arbor-admin"), "admin"
        ).id,
    }


def _read_theme_selection() -> dict[str, str]:
    """Read current persisted selections, falling back safely to defaults."""
    from arborpress.core.config import is_installed
    from arborpress.core.db import get_db_session
    from arborpress.core.site_settings import get_defaults, get_section

    defaults = get_defaults("theme")
    default_selection = {
        "active": str(defaults.get("active", "default")),
        "admin_active": str(defaults.get("admin_active", "arbor-admin")),
    }
    # Avoid creating an empty SQLite database simply to list package themes on
    # a fresh, not-yet-installed prefix.
    if not is_installed():
        return default_selection

    async def _read() -> dict[str, str]:
        try:
            async for db in get_db_session():
                settings = await get_section("theme", db)
                return {
                    "active": str(settings.get("active", "default")),
                    "admin_active": str(settings.get("admin_active", "arbor-admin")),
                }
        except Exception:
            return default_selection
        return default_selection

    return asyncio.run(_read())


@themes_app.command("list")
def themes_list(
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """List built-in and instance themes with validation diagnostics."""
    from arborpress.themes.manifest import get_theme_registry

    registry = get_theme_registry()
    active = _effective_theme_selection(registry, _read_theme_selection())
    payload = [_theme_payload(record, active) for record in registry.records()]
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    for item in payload:
        marker = " [active]" if item["active_public"] or item["active_admin"] else ""
        typer.echo(
            f"{item['id']}\t{item['type'] or '-'}\t{item['source']}\t"
            f"{item['status']}{marker}\t{item['name']}"
        )
        for diagnostic in item["diagnostics"]:
            typer.echo(f"  ! {diagnostic}")


@themes_app.command("inspect")
def themes_inspect(
    theme_id: str,
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Show manifest status and compatibility details for one theme."""
    from arborpress.themes.manifest import get_theme_registry

    record = get_theme_registry().record(theme_id)
    if record is None:
        typer.echo(f"Theme {theme_id!r} was not found.", err=True)
        raise typer.Exit(code=2)
    item = _theme_payload(
        record,
        _effective_theme_selection(get_theme_registry(), _read_theme_selection()),
    )
    if as_json:
        typer.echo(json.dumps(item, indent=2, sort_keys=True))
        return
    for key, value in item.items():
        typer.echo(f"{key}: {value}")


# ---------------------------------------------------------------------------
# Local backup sets
# ---------------------------------------------------------------------------


def _backup_json(summary: Any) -> dict[str, Any]:
    return {
        "backup_id": summary.backup_id,
        "path": str(summary.directory),
        "verified": summary.verification_ok,
        "verification_error": summary.verification_error,
        "verification_level": summary.verification_level,
        "sensitive_data_warning": (
            "This unencrypted set contains sensitive application data."
            if summary.manifest.encryption == "none"
            and any(component.name == "database" for component in summary.manifest.components)
            else None
        ),
        "manifest": asdict(summary.manifest),
    }


def _backup_key_from_options(
    *, backup_id: str | None = None, keyfile: Path | None = None, confirm: bool = False
) -> BackupKey | None:
    from getpass import getpass

    from arborpress.backups.encryption import BackupKey, load_keyfile

    if keyfile is not None:
        return load_keyfile(keyfile)
    if backup_id is not None:
        from arborpress.backups.service import inspect_backup

        manifest = inspect_backup(backup_id).manifest
        if manifest.encryption == "none":
            return None
        if not sys.stdin.isatty():
            return None
    elif not sys.stdin.isatty():
        raise ValueError("Encryption requires an interactive passphrase or --keyfile")
    passphrase = getpass("Backup passphrase: ").encode("utf-8")
    if confirm:
        repeated = getpass("Repeat backup passphrase: ").encode("utf-8")
        if not passphrase or passphrase != repeated:
            raise ValueError("Backup passphrases are empty or do not match")
    return BackupKey("passphrase", passphrase)


@backup_key_app.command("generate")
def backup_key_generate(
    path: Path,
    force: bool = typer.Option(False, "--force", help="Replace an existing keyfile"),
) -> None:
    """Generate a random ArborPress 256-bit backup keyfile."""
    from arborpress.backups.encryption import generate_keyfile

    try:
        generate_keyfile(path, overwrite=force)
    except (OSError, ValueError) as exc:
        typer.echo(f"Backup key generation failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Backup keyfile generated: {path}")


def _parse_backup_threads(value: str) -> int | None:
    if value.lower() == "auto":
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError("--threads must be 'auto' or a positive integer") from exc
    if parsed < 1 or parsed > 64:
        raise ValueError("--threads must be between 1 and 64")
    return parsed


@backup_app.command("create")
def backup_create(
    compression: str = typer.Option("bz2", "--compression", help="bz2 or optional bz3"),
    profile: str = typer.Option("medium", "--profile", help="fast, medium, strong or custom"),
    level: int | None = typer.Option(None, "--level", min=1, max=9),
    threads: str = typer.Option("auto", "--threads", help="BZip3: auto or 1..64"),
    component: list[str] | None = typer.Option(  # noqa: B008
        None, "--component", help="Select a component; repeatable"
    ),
    media_segment_size: int = typer.Option(
        DEFAULT_MEDIA_SEGMENT_SIZE,
        "--media-segment-size",
        min=1,
        help="Maximum uncompressed media payload per archive, in bytes",
    ),
    keep_incomplete: bool = typer.Option(
        False,
        "--keep-incomplete",
        help="Developer diagnostic: retain a failed .incomplete set",
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
    encrypt: bool = typer.Option(
        False, "--encrypt", help="Encrypt each component with AES-256-GCM"
    ),
    include_secrets: bool = typer.Option(
        False, "--include-secrets", help="Include secret-bearing config (requires encryption)"
    ),
    keyfile: Path | None = typer.Option(  # noqa: B008
        None, "--keyfile", help="Use a protected ArborPress keyfile"
    ),
) -> None:
    """Create and internally verify a local backup set."""
    from arborpress.backups.compression import (
        CompressionSettings,
        CompressionUnavailableError,
    )
    from arborpress.backups.service import BackupError, create_backup

    if not encrypt:
        typer.echo(
            "WARNING: this backup set is unencrypted and contains sensitive database "
            "and user data.",
            err=True,
        )
    try:
        if include_secrets and not encrypt:
            raise ValueError("--include-secrets requires --encrypt")
        key = _backup_key_from_options(keyfile=keyfile, confirm=encrypt) if encrypt else None
        backend = compression.lower()
        selected_profile = profile.lower()
        thread_count = _parse_backup_threads(threads)
        if backend == "bz2":
            if threads.lower() != "auto" and thread_count != 1:
                raise ValueError("BZip2 uses one process thread; --threads applies only to BZip3")
            thread_count = None
        if backend not in {"bz2", "bz3"}:
            raise ValueError("--compression must be bz2 or bz3")
        if selected_profile not in {"fast", "medium", "strong", "custom"}:
            raise ValueError("--profile must be fast, medium, strong or custom")
        settings = CompressionSettings(
            backend=cast(Literal["bz2", "bz3"], backend),
            profile=cast(Literal["fast", "medium", "strong", "custom"], selected_profile),
            level=level,
            threads=thread_count,
        )

        async def _create() -> Any:
            from arborpress.core.db import get_engine

            selected = component or (
                "database",
                "config",
                "data",
                "themes",
                "plugins",
                "media",
            )
            engine = get_engine() if "database" in selected else None
            try:
                return await create_backup(
                    components=selected,
                    engine=engine,
                    compression=settings,
                    media_segment_size=media_segment_size,
                    keep_incomplete=keep_incomplete,
                    key=key,
                    include_secrets=include_secrets,
                    keyfile_path=keyfile,
                )
            finally:
                if engine is not None:
                    await engine.dispose()

        summary = asyncio.run(_create())
    except (BackupError, CompressionUnavailableError, ValueError, OSError) as exc:
        typer.echo(f"Backup failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception as exc:
        # Unexpected database/library exceptions can include credentials in
        # their diagnostic text, so only expose the exception class here.
        typer.echo(f"Backup failed due to {type(exc).__name__}; no set was published.", err=True)
        raise typer.Exit(code=1) from None
    if as_json:
        typer.echo(json.dumps(_backup_json(summary), indent=2, sort_keys=True))
    else:
        typer.echo(f"Backup created and verified: {summary.backup_id}")
        typer.echo(f"Path: {summary.directory}")


@backup_app.command("list")
def backup_list(
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """List completed sets with valid manifests."""
    from arborpress.backups.service import BackupError, list_backups

    try:
        values = list_backups()
    except (BackupError, OSError, ValueError) as exc:
        typer.echo(f"Backup listing failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    if as_json:
        payload = [_backup_json(value) for value in values]
        for item in payload:
            item["verified"] = None
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    for summary in values:
        total = sum(item.size_bytes for comp in summary.manifest.components for item in comp.files)
        typer.echo(
            f"{summary.backup_id}\t{summary.manifest.created_at}\t{total} bytes\t"
            f"{summary.manifest.compression_backend}/{summary.manifest.compression_profile}"
        )


@backup_app.command("inspect")
def backup_inspect(
    backup_id: str,
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
    keyfile: Path | None = typer.Option(  # noqa: B008
        None, "--keyfile", help="Use a protected ArborPress keyfile"
    ),
) -> None:
    """Display backup metadata and a read-only verification result."""
    from arborpress.backups.compression import CompressionUnavailableError
    from arborpress.backups.service import BackupError, inspect_backup

    try:
        key = _backup_key_from_options(backup_id=backup_id, keyfile=keyfile)
        summary = inspect_backup(backup_id, key=key)
    except (BackupError, OSError, ValueError, CompressionUnavailableError) as exc:
        typer.echo(f"Backup inspection failed: {exc}", err=True)
        raise typer.Exit(code=2) from None
    if as_json:
        typer.echo(json.dumps(_backup_json(summary), indent=2, sort_keys=True))
        return
    typer.echo(f"ID: {summary.backup_id}")
    typer.echo(f"Created: {summary.manifest.created_at}")
    typer.echo(f"ArborPress: {summary.manifest.arborpress_version}")
    typer.echo(f"Database: {summary.manifest.database_system or 'not included'}")
    typer.echo(f"Alembic revisions: {', '.join(summary.manifest.alembic_revisions) or 'none'}")
    typer.echo(
        "Compression: "
        f"{summary.manifest.compression_backend}/{summary.manifest.compression_profile}"
    )
    typer.echo(f"Encryption: {summary.manifest.encryption}")
    if summary.manifest.encryption == "none" and any(
        component.name == "database" for component in summary.manifest.components
    ):
        typer.echo("Security warning: this unencrypted set contains sensitive application data.")
    typer.echo(f"Components: {', '.join(comp.name for comp in summary.manifest.components)}")
    typer.echo(f"Verification: {'passed' if summary.verification_ok else 'FAILED'}")
    if summary.verification_level:
        typer.echo(f"Verification level: {summary.verification_level}")
    if summary.verification_error:
        typer.echo(f"Reason: {summary.verification_error}")
    for item in summary.manifest.omitted_sensitive:
        typer.echo(f"Omitted sensitive config: {item}")


@backup_app.command("verify")
def backup_verify(
    backup_id: str,
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
    keyfile: Path | None = typer.Option(  # noqa: B008
        None, "--keyfile", help="Use a protected ArborPress keyfile"
    ),
) -> None:
    """Verify checksums and archive structure without extracting."""
    from arborpress.backups.compression import CompressionUnavailableError
    from arborpress.backups.service import BackupError, verify_backup

    try:
        key = _backup_key_from_options(backup_id=backup_id, keyfile=keyfile)
        report = verify_backup(backup_id, key=key)
    except (BackupError, OSError, ValueError, CompressionUnavailableError) as exc:
        typer.echo(f"Backup verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    payload = asdict(report)
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(
            f"Verified {report.backup_id}: {report.checked_files} files, "
            f"{report.checked_bytes} bytes, {report.database_rows} database rows "
            f"({report.verification_level})"
        )


@backup_app.command("pin")
def backup_pin(
    backup_id: str,
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Protect a local backup set from prune operations."""
    from arborpress.backups.retention import pin_backup
    from arborpress.backups.service import BackupError

    try:
        pin_backup(backup_id)
    except (BackupError, OSError, ValueError) as exc:
        typer.echo(f"Backup pin failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(
        json.dumps({"backup_id": backup_id, "pinned": True}) if as_json else f"Pinned {backup_id}"
    )


@backup_app.command("unpin")
def backup_unpin(
    backup_id: str,
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Remove a local pin from a backup set."""
    from arborpress.backups.retention import pin_backup
    from arborpress.backups.service import BackupError

    try:
        pin_backup(backup_id, pinned=False)
    except (BackupError, OSError, ValueError) as exc:
        typer.echo(f"Backup unpin failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(
        json.dumps({"backup_id": backup_id, "pinned": False})
        if as_json
        else f"Unpinned {backup_id}"
    )


@backup_app.command("prune")
def backup_prune(
    keep_last: int | None = typer.Option(None, "--keep-last", min=0),
    keep_days: int | None = typer.Option(None, "--keep-days", min=0),
    apply: bool = typer.Option(False, "--apply", help="Delete the listed unpinned sets"),
    yes: bool = typer.Option(False, "--yes", help="Do not prompt before deletion"),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Plan or apply local backup retention; the default is read-only."""
    from arborpress.backups.retention import prune_backups
    from arborpress.backups.service import BackupError

    try:
        plan = prune_backups(keep_last=keep_last, keep_days=keep_days, dry_run=True)
    except (BackupError, OSError, ValueError) as exc:
        typer.echo(f"Backup prune failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    if apply and plan.backup_ids:
        if not yes:
            typer.confirm(
                f"Delete {len(plan.backup_ids)} unpinned backup set(s)?",
                abort=True,
            )
        try:
            plan = prune_backups(keep_last=keep_last, keep_days=keep_days, dry_run=False)
        except (BackupError, OSError, ValueError) as exc:
            typer.echo(f"Backup prune failed: {exc}", err=True)
            raise typer.Exit(code=1) from None
    elif apply:
        plan = plan.__class__(plan.backup_ids, plan.kept_ids, plan.pinned_ids, False)
    payload = asdict(plan)
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo("Dry run; no backup sets deleted." if plan.dry_run else "Prune complete.")
        typer.echo(f"Delete: {', '.join(plan.backup_ids) or 'none'}")
        typer.echo(f"Keep: {', '.join(plan.kept_ids) or 'none'}")
        if plan.pinned_ids:
            typer.echo(f"Pinned: {', '.join(plan.pinned_ids)}")


@backup_app.command("cleanup-incomplete")
def backup_cleanup_incomplete(
    older_than_hours: int = typer.Option(24, "--older-than-hours", min=24),
    apply: bool = typer.Option(False, "--apply", help="Delete the listed incomplete sets"),
    yes: bool = typer.Option(False, "--yes", help="Do not prompt before deletion"),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Find or remove old ArborPress-owned incomplete backup staging sets."""
    from datetime import timedelta

    from arborpress.backups.retention import cleanup_incomplete
    from arborpress.backups.service import BackupError

    try:
        values = cleanup_incomplete(older_than=timedelta(hours=older_than_hours), dry_run=True)
        if apply and values:
            if not yes:
                typer.confirm(f"Delete {len(values)} incomplete backup staging set(s)?", abort=True)
            values = cleanup_incomplete(older_than=timedelta(hours=older_than_hours), dry_run=False)
    except (BackupError, OSError, ValueError) as exc:
        typer.echo(f"Incomplete backup cleanup failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    if as_json:
        typer.echo(json.dumps({"removed_or_listed": list(values), "dry_run": not apply}, indent=2))
    else:
        typer.echo("Dry run; no incomplete sets deleted." if not apply else "Cleanup complete.")
        for value in values:
            typer.echo(value)


@restore_app.command("plan")
def restore_plan_command(
    backup_id: str,
    component: list[str] | None = typer.Option(  # noqa: B008
        None, "--component", help="Select a component; repeatable"
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
    keyfile: Path | None = typer.Option(  # noqa: B008
        None, "--keyfile", help="Use a protected ArborPress keyfile"
    ),
) -> None:
    """Verify a backup and print a read-only compatibility/apply plan."""
    from arborpress.backups.restore import RestoreError, plan_restore
    from arborpress.backups.service import BackupError

    try:
        key = _backup_key_from_options(backup_id=backup_id, keyfile=keyfile)
        plan = asyncio.run(
            plan_restore(backup_id, components=tuple(component) if component else None, key=key)
        )
    except (BackupError, RestoreError, OSError, ValueError) as exc:
        typer.echo(f"Restore planning failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    if as_json:
        typer.echo(json.dumps(plan.as_json(), indent=2, sort_keys=True))
        return
    typer.echo(f"Backup: {plan.backup_id} ({plan.created_at})")
    typer.echo(f"Format: {plan.format_version}; ArborPress: {plan.arborpress_version}")
    typer.echo(
        "Database: "
        f"{plan.backup_database_system or 'not selected'} → "
        f"{plan.target_database_system or 'not selected'}"
    )
    typer.echo(
        "Alembic revisions: backup="
        f"{', '.join(plan.backup_alembic_revisions) or 'none'}; "
        f"target={', '.join(plan.target_alembic_revisions) or 'none'}"
    )
    typer.echo(f"Components: {', '.join(plan.selected_components)}")
    typer.echo(f"Configuration coverage: {plan.config_coverage}")
    if plan.omitted_sensitive:
        typer.echo(f"Omitted sensitive configuration entries: {', '.join(plan.omitted_sensitive)}")
    typer.echo(f"Estimated staging space: {plan.estimated_uncompressed_bytes} bytes")
    for name, path in sorted(plan.target_paths.items()):
        typer.echo(f"Target {name}: {path}")
    typer.echo(f"Compatibility: {'ready' if plan.compatible else 'BLOCKED'}")
    for item in plan.warnings:
        typer.echo(f"Warning: {item}")
    for item in plan.blockers:
        typer.echo(f"Blocker: {item}")


@restore_app.command("apply")
def restore_apply_command(
    backup_id: str,
    all_components: bool = typer.Option(False, "--all", help="Restore all available components"),
    component: list[str] | None = typer.Option(  # noqa: B008
        None, "--component", help="Select a component; repeatable"
    ),
    offline: bool = typer.Option(False, "--offline", help="Confirm all web workers are stopped"),
    yes: bool = typer.Option(False, "--yes", help="Do not prompt for confirmation"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Verify and print the plan without mutation"
    ),
    safety_backup: bool = typer.Option(
        False, "--safety-backup", help="Create a complete backup of the current instance first"
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
    keyfile: Path | None = typer.Option(  # noqa: B008
        None, "--keyfile", help="Use a protected ArborPress keyfile"
    ),
) -> None:
    """Apply a verified restore while ArborPress is offline."""
    from arborpress.backups.restore import (
        RestoreError,
        apply_restore,
        plan_restore,
        validate_restore_staging,
    )
    from arborpress.backups.service import BackupError

    if all_components and component:
        typer.echo("Use either --all or --component, not both.", err=True)
        raise typer.Exit(code=2)
    if not all_components and not component and not dry_run:
        typer.echo("Choose --all or at least one --component before applying.", err=True)
        raise typer.Exit(code=2)
    selected = tuple(component) if component else None
    try:
        key = _backup_key_from_options(backup_id=backup_id, keyfile=keyfile)
        if dry_run:
            plan = asyncio.run(plan_restore(backup_id, components=selected, key=key))
            staging_warnings: tuple[str, ...] = ()
            if plan.compatible:
                staging_warnings = asyncio.run(validate_restore_staging(plan, key=key))
            if as_json:
                typer.echo(
                    json.dumps(
                        {
                            "plan": plan.as_json(),
                            "staging_validated": plan.compatible,
                            "staging_warnings": list(staging_warnings),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                typer.echo("Dry run only; no files or database were changed.")
                typer.echo(f"Compatibility: {'ready' if plan.compatible else 'BLOCKED'}")
                typer.echo(f"Components: {', '.join(plan.selected_components)}")
                typer.echo(
                    "Staging validation: "
                    f"{'passed' if plan.compatible else 'not run (plan is blocked)'}"
                )
                for item in (*plan.warnings, *staging_warnings, *plan.blockers):
                    typer.echo(item)
            if not plan.compatible:
                raise typer.Exit(code=1)
            return
        if not offline:
            typer.echo(
                "Apply requires --offline after stopping every ArborPress web worker.", err=True
            )
            raise typer.Exit(code=2)
        if not yes:
            typer.confirm(
                f"Apply backup {backup_id}; selected live roots and/or database rows "
                "will be replaced?",
                abort=True,
            )
        report = asyncio.run(
            apply_restore(
                backup_id,
                components=selected,
                offline=offline,
                safety_backup=safety_backup,
                key=key,
            )
        )
    except typer.Exit:
        raise
    except (BackupError, RestoreError, OSError, ValueError) as exc:
        typer.echo(f"Restore failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    except Exception as exc:
        typer.echo(
            f"Restore failed due to {type(exc).__name__}; inspect the restore history.", err=True
        )
        raise typer.Exit(code=1) from None
    if as_json:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(f"Restore {report['restore_id']}: {report['result']}")
        typer.echo(f"Backup: {report['backup_id']}; report: {report['restore_id']}.json")


@restore_app.command("recover")
def restore_recover_command(
    offline: bool = typer.Option(False, "--offline", help="Confirm all web workers remain stopped"),
    yes: bool = typer.Option(False, "--yes", help="Do not prompt for confirmation"),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON"),
) -> None:
    """Roll back an interrupted, pre-database-commit restore."""
    from arborpress.backups.restore import RestoreError, recover_restore
    from arborpress.backups.service import BackupError

    if not offline:
        typer.echo(
            "Recovery requires --offline after stopping every ArborPress web worker.", err=True
        )
        raise typer.Exit(code=2)
    if not yes:
        typer.confirm("Attempt rollback-first recovery of the incomplete restore?", abort=True)
    try:
        report = recover_restore()
    except (BackupError, RestoreError, OSError, ValueError) as exc:
        typer.echo(f"Restore recovery failed: {exc}", err=True)
        raise typer.Exit(code=1) from None
    if as_json:
        typer.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        typer.echo(f"Restore recovery {report['restore_id']}: {report['result']}")


# ---------------------------------------------------------------------------
# §14 install / init
# ---------------------------------------------------------------------------


@app.command("init")
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite an already initialised instance"),
    seed: bool = typer.Option(
        True,
        "--seed/--no-seed",
        help="Insert sample content (posts, pages, imprint, privacy policy)",
    ),
) -> None:
    """Initialises a new ArborPress instance (§14 install/init).

    Sample content is inserted by default (use --no-seed to disable).
    """
    ensure_instance_layout(get_runtime_paths())
    typer.echo(__("Applying database migrations …"))
    asyncio.run(_db_upgrade())
    if seed:
        typer.echo(__("Inserting sample content …"))
        asyncio.run(_seed(force=force))
    typer.echo("\n" + __("✓ ArborPress initialised."))
    typer.echo("  " + __("Next step: arborpress user add"))
    typer.echo("  " + __("Start server: arborpress serve --dev"))


# ---------------------------------------------------------------------------
# §14 serve
# ---------------------------------------------------------------------------


@app.command()
def serve(
    host: str = typer.Option(None, "--host", "-H"),
    port: int = typer.Option(None, "--port", "-p"),
    dev: bool = typer.Option(False, "--dev", help="Entwicklungsmodus (Reload)"),
    workers: int = typer.Option(1, "--workers", "-w"),
) -> None:
    """Starts the ArborPress server (Hypercorn/ASGI)."""
    import hypercorn.asyncio
    import hypercorn.config

    cfg = get_settings()
    hcfg = hypercorn.config.Config()
    hcfg.bind = [f"{host or cfg.web.host}:{port or cfg.web.port}"]
    hcfg.workers = workers
    if dev:
        hcfg.use_reloader = True

    from arborpress.web.app import create_app

    quart_app = create_app()
    typer.echo(__("Starting ArborPress on {bind}").format(bind=hcfg.bind[0]))
    asyncio.run(hypercorn.asyncio.serve(quart_app, hcfg))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §14 healthcheck
# ---------------------------------------------------------------------------


@app.command("healthcheck")
def healthcheck() -> None:
    """Checks DB connection and configuration (§14)."""
    import asyncio

    async def _check() -> None:
        from arborpress.core.db import get_engine
        from arborpress.core.db_capabilities import detect_capabilities

        engine = get_engine()
        try:
            caps = await detect_capabilities(engine)
            typer.echo(
                __("DB: {engine} {version}").format(
                    engine=caps.engine_name, version=caps.version_string
                )
            )
            typer.echo(__("FTS: {provider}").format(provider=caps.fts_provider))
            typer.echo(__("Status: OK"))
        except Exception as exc:
            typer.echo(__("DB error: {exc}").format(exc=exc), err=True)
            raise typer.Exit(1) from exc

    asyncio.run(_check())


# ---------------------------------------------------------------------------
# Database migration commands
# ---------------------------------------------------------------------------


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Adopt a validated legacy schema if needed and upgrade to Alembic head."""
    from arborpress.core.migrations import upgrade_database

    try:
        ensure_instance_layout(get_runtime_paths())
        status = asyncio.run(_run_db_migration_operation(upgrade_database))
    except Exception as exc:
        typer.echo(f"Database upgrade failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"Database schema is current at {status.head_revision}.")


@db_app.command("migrate", hidden=True)
def db_migrate() -> None:
    """Deprecated compatibility alias for db upgrade."""
    typer.echo("'arborpress db migrate' is deprecated; use 'arborpress db upgrade'.", err=True)
    db_upgrade()


@db_app.command("current")
def db_current() -> None:
    """Show the installed revision and its relation to this release's head."""
    from arborpress.core.migrations import schema_status

    try:
        status = asyncio.run(_run_db_migration_operation(schema_status))
    except Exception as exc:
        typer.echo(f"Database status unavailable: {exc}", err=True)
        raise typer.Exit(1) from exc
    current = ", ".join(status.current_revisions) if status.current_revisions else "none"
    typer.echo(f"Current revision: {current}")
    typer.echo(f"Head revision:    {status.head_revision or 'unavailable'}")
    typer.echo(f"Status:           {status.state}")
    if status.detail:
        typer.echo(f"Detail:           {status.detail}")


@db_app.command("check")
def db_check() -> None:
    """Return success only when the database is compatible and at current head."""
    from arborpress.core.migrations import schema_status

    try:
        status = asyncio.run(_run_db_migration_operation(schema_status))
    except Exception as exc:
        typer.echo(f"Database schema check failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    if not status.is_current:
        typer.echo(f"Database schema is not ready ({status.state}): {status.detail}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Database schema is current at {status.head_revision}.")


@db_app.command("history")
def db_history() -> None:
    """List migration revisions packaged with this ArborPress release."""
    from arborpress.core.migrations import migration_history

    for revision, message, parent in migration_history():
        typer.echo(f"{revision} <- {parent or 'base'}  {message}")


@db_app.command("adopt-legacy")
def db_adopt_legacy() -> None:
    """Validate and mark the supported pre-Alembic schema as adopted."""
    from arborpress.core.migrations import adopt_legacy_database

    try:
        asyncio.run(_run_db_migration_operation(adopt_legacy_database))
    except Exception as exc:
        typer.echo(f"Legacy database adoption refused: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo("Validated pre-Alembic database adopted successfully.")


@db_app.command("downgrade")
def db_downgrade(
    revision: str = typer.Argument(..., help="Target revision or base"),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Confirm the potentially destructive downgrade"
    ),
) -> None:
    """Run an explicit downgrade (may destroy data; never run automatically)."""
    if not yes and not typer.confirm(f"Downgrade database to {revision!r}? This may destroy data."):
        raise typer.Exit(0)
    from arborpress.core.migrations import downgrade_database

    try:
        asyncio.run(_run_db_migration_operation(downgrade_database, revision))
    except Exception as exc:
        typer.echo(f"Database downgrade failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"Database downgrade to {revision} completed.")


@db_app.command("seed")
def db_seed(
    force: bool = typer.Option(False, "--force", help="Overwrite existing seed data"),
) -> None:
    """Inserts sample content, imprint and privacy policy (§14)."""
    typer.echo(__("Inserting seed data …"))
    result = asyncio.run(_seed(force=force))
    typer.echo("  " + __("Posts inserted:  {n}").format(n=result.get("posts", 0)))
    typer.echo("  " + __("Pages inserted:  {n}").format(n=result.get("pages", 0)))
    typer.echo("  " + __("Tags inserted:   {n}").format(n=result.get("tags", 0)))
    typer.echo(__("Done."))


@db_app.command("capabilities")
def db_capabilities() -> None:
    """Shows detected DB capabilities (§12)."""

    async def _show() -> None:
        from arborpress.core.db import get_engine
        from arborpress.core.db_capabilities import detect_capabilities

        caps = await detect_capabilities(get_engine())
        typer.echo(f"Engine:  {caps.engine_name}")
        typer.echo(f"Version: {caps.version_string}")
        typer.echo(f"FTS:     {caps.fts_available} ({caps.fts_provider})")
        typer.echo(f"JSON:    {caps.json_ops}")

    asyncio.run(_show())


# ---------------------------------------------------------------------------
# §14 user: add / disable / roles
# ---------------------------------------------------------------------------


@user_app.command("add")
def user_add(
    username: str = typer.Argument(..., help="Username"),
    role: str = typer.Option(
        "viewer", "--role", "-r", help="Rolle (admin/editor/author/moderator/viewer)"
    ),
    operational: bool = typer.Option(False, "--operational", help="Operationales Admin-Konto (§4)"),
    email: str | None = typer.Option(None, "--email", "-e"),
    display_name: str | None = typer.Option(None, "--display-name", "-n"),
) -> None:
    """Creates a new user (§14 user management)."""
    from arborpress.models.user import AccountType, User, UserRole

    try:
        role_enum = UserRole(role)
    except ValueError:
        typer.echo(
            __("Invalid role: {role}. Allowed: {allowed}").format(
                role=role, allowed=[r.value for r in UserRole]
            ),
            err=True,
        )
        raise typer.Exit(1) from None

    account_type = AccountType.OPERATIONAL if operational else AccountType.PUBLIC

    async def _create() -> None:
        from arborpress.core.db import get_db_session

        async for db in get_db_session():
            user = User(
                username=username,
                display_name=display_name or username,
                email=email,
                account_type=account_type,
                role=role_enum,
            )
            db.add(user)
            await db.commit()
            typer.echo(
                __("User created: {username!r} [{type}/{role}]").format(
                    username=username, type=account_type.value, role=role_enum.value
                )
            )
            typer.echo("  " + __("ID: {id}").format(id=user.id))
            typer.echo(
                "  " + __("Next step: arborpress user mfa add {username}").format(username=username)
            )

    asyncio.run(_create())


@user_app.command("disable")
def user_disable(
    username: str = typer.Argument(..., help="Username"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Disables a user (§14 user management)."""
    if not yes:
        confirmed = typer.confirm(__("Really disable user {username!r}?").format(username=username))
        if not confirmed:
            raise typer.Exit(0)

    async def _disable() -> None:
        from sqlalchemy import func, select

        from arborpress.core.audit import write_audit_event
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(__("User {username!r} not found.").format(username=username), err=True)
                raise typer.Exit(1)
            if user.role.value == "admin" and user.is_active:
                from arborpress.auth.policy import is_last_active_admin

                if await is_last_active_admin(db, user):
                    await write_audit_event(
                        event_type="auth_lockout_prevention",
                        outcome="blocked",
                        actor_id="cli",
                        target_id=str(user.id),
                        detail="last_active_admin_disable",
                        db=db,
                    )
                    await db.commit()
                    typer.echo("ERROR: Cannot disable the last active administrator.", err=True)
                    raise typer.Exit(1)
            user.is_active = False
            db.add(user)
            await write_audit_event(
                event_type="user_disabled",
                outcome="success",
                actor_id="cli",
                target_id=str(user.id),
                db=db,
            )
            await db.commit()
            typer.echo(__("User {username!r} disabled.").format(username=username))

    asyncio.run(_disable())


@user_app.command("unlock")
def user_unlock(
    username: str = typer.Argument(..., help="Username"),
) -> None:
    """Hebt eine temporäre Anmelde-Sperre auf (§2 Account Lockout)."""

    async def _unlock() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            was_locked = bool(user.locked_until)
            user.failed_login_count = 0
            user.locked_until = None
            db.add(user)
            await db.commit()
            if was_locked:
                typer.echo(
                    __(
                        "User {username!r} unlocked (lock removed, failed_login_count reset)."
                    ).format(username=username)
                )
            else:
                typer.echo(
                    __("User {username!r}: no active lock, failed_login_count reset to 0.").format(
                        username=username
                    )
                )

    asyncio.run(_unlock())


@user_app.command("roles")
def user_roles(
    username: str = typer.Argument(..., help="Username"),
    role: str = typer.Argument(..., help="New role"),
) -> None:
    """Changes a user's role from the trusted local CLI and audits the change."""
    from arborpress.models.user import UserRole

    try:
        role_enum = UserRole(role)
    except ValueError:
        typer.echo(f"Invalid role: {role}. Allowed: {[r.value for r in UserRole]}", err=True)
        raise typer.Exit(1) from None

    typer.echo("Role changes are audited; the last active administrator is protected.")

    async def _set_role() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(__("User {username!r} not found.").format(username=username), err=True)
                raise typer.Exit(1)
            old_role = user.role.value
            if old_role == "admin" and role_enum.value != "admin" and user.is_active:
                from arborpress.auth.policy import is_last_active_admin
                from arborpress.core.audit import write_audit_event

                if await is_last_active_admin(db, user):
                    await write_audit_event(
                        event_type="auth_lockout_prevention",
                        outcome="blocked",
                        actor_id="cli",
                        target_id=str(user.id),
                        detail="last_active_admin_demotion",
                        db=db,
                    )
                    await db.commit()
                    typer.echo("ERROR: Cannot demote the last active administrator.", err=True)
                    raise typer.Exit(1)
            user.role = role_enum
            db.add(user)
            from arborpress.core.audit import write_audit_event

            await write_audit_event(
                event_type="role_changed",
                outcome="success",
                actor_id="cli",
                target_id=str(user.id),
                detail=f"old={old_role};new={role_enum.value}",
                db=db,
            )
            await db.commit()
            typer.echo(
                __("Role: {old} → {new} for {username!r}").format(
                    old=old_role, new=role_enum.value, username=username
                )
            )

    asyncio.run(_set_role())


@user_app.command("list")
def user_list(
    inactive: bool = typer.Option(False, "--inactive", help="Also show inactive accounts"),
) -> None:
    """Lists all users."""

    async def _list() -> None:
        from sqlalchemy import select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            stmt = select(User)
            if not inactive:
                stmt = stmt.where(User.is_active.is_(True))
            result = await db.execute(stmt)
            users = result.scalars().all()
            if not users:
                typer.echo(__("No users found."))
                return
            header = (
                f"{__('Username'):<20} {__('Role'):<14} "
                f"{__('Type'):<14} {__('Active'):<6} {__('Email')}"
            )
            typer.echo(header)
            typer.echo("-" * 80)
            for u in users:
                pw_warn = " ⚠ PW active" if u.legacy_password_enabled else ""
                typer.echo(
                    f"{u.username:<20} {u.role.value:<14} {u.account_type.value:<14} "
                    f"{'yes' if u.is_active else 'no':<6} {u.email or ''}{pw_warn}"
                )

    asyncio.run(_list())


def _prompt_password_twice() -> str:
    first = typer.prompt(__("New break-glass password"), hide_input=True)
    second = typer.prompt(__("Confirm break-glass password"), hide_input=True)
    if first != second:
        typer.echo(__("Passwords do not match."), err=True)
        raise typer.Exit(2)
    return first


def _build_breakglass_password(
    *,
    generator: str,
    words: int,
    delimiter: str,
    length: int,
) -> str:
    from arborpress.auth.password_tools import (
        generate_diceware_passphrase,
        generate_random_password,
    )

    normalized = generator.strip().lower()
    if normalized in {"diceware", "xkcd"}:
        return generate_diceware_passphrase(word_count=words, delimiter=delimiter)
    if normalized == "random":
        return generate_random_password(length=length)
    raise typer.BadParameter("generator must be one of: diceware, random")


def _print_password_assessment(assessment) -> None:
    typer.echo(__("zxcvbn score:            {score}/4").format(score=assessment.score))
    if assessment.warning:
        typer.echo(__("Warning:                 {warning}").format(warning=assessment.warning))
    if assessment.suggestions:
        typer.echo(
            __("Suggestions:             {suggestions}").format(
                suggestions=" | ".join(assessment.suggestions)
            )
        )
    offline = assessment.crack_times_display.get("offline_slow_hashing_1e4_per_second")
    if offline:
        typer.echo(__("Crack time (offline):    {time}").format(time=offline))


@user_app.command("password-status")
def user_password_status(
    username: str = typer.Argument(..., help="Username"),
) -> None:
    """Shows password status of an account (warning if active)."""

    async def _check() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            if user.legacy_password_enabled:
                typer.echo(
                    f"WARNING: Account {username!r} has an active password"
                    " (legacy_password_enabled=True).\n"
                    f"  The password is a fallback (Break-Glass §2)"
                    " and should be disabled,\n"
                    f"  once WebAuthn/MFA has been set up.\n"
                    f"  Disable: arborpress user password-disable {username}"
                )
            else:
                typer.echo(f"Account {username!r}: password disabled (recommended).")

    asyncio.run(_check())


@user_app.command("password-set")
def user_password_set(
    username: str = typer.Argument(..., help="Username"),
    password: str | None = typer.Option(
        None,
        "--password",
        "-p",
        help="Set a specific break-glass password",
        hide_input=True,
    ),
    generate: bool = typer.Option(False, "--generate", help="Generate the password automatically"),
    generator: str = typer.Option("random", "--generator", help="Generator mode: diceware|random"),
    words: int = typer.Option(
        6, "--words", min=4, max=10, help="Word count for Diceware passphrases"
    ),
    delimiter: str = typer.Option("-", "--delimiter", help="Separator for Diceware passphrases"),
    length: int = typer.Option(24, "--length", min=16, max=256, help="Length for random passwords"),
) -> None:
    """Sets or changes the break-glass password of an account."""
    if password and generate:
        typer.echo(__("Use either --password or --generate, not both."), err=True)
        raise typer.Exit(2)
    if generate:
        password = _build_breakglass_password(
            generator=generator,
            words=words,
            delimiter=delimiter,
            length=length,
        )
    elif password is None:
        password = _prompt_password_twice()

    async def _load_security() -> dict:
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_security_settings

        async for db in get_db_session():
            return await get_security_settings(db)
        return {}

    sec = asyncio.run(_load_security())

    try:
        from arborpress.auth.breakglass import validate_password_policy

        assessment = validate_password_policy(
            password,
            min_length=sec["legacy_password_min_length"],
            max_length=sec["legacy_password_max_length"],
            min_score=sec["legacy_password_min_score"],
            user_inputs=[username, "arborpress", "admin"],
            # HIBP only on manually entered passwords; skip for --generate
            check_hibp=sec["hibp_enabled"] and not generate,
            hibp_max_count=sec["hibp_max_count"],
            hibp_timeout=sec["hibp_timeout"],
            hibp_fail_open=sec["hibp_fail_open"],
        )
    except ValueError as exc:
        typer.echo(__("Invalid break-glass password: {exc}").format(exc=exc), err=True)
        raise typer.Exit(2) from exc

    async def _set_pw() -> None:
        from sqlalchemy import func, select

        from arborpress.auth.breakglass import hash_password
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            was_enabled = bool(user.legacy_password_enabled and user.legacy_password_hash)
            user.legacy_password_hash = hash_password(password)
            user.legacy_password_enabled = True
            db.add(user)
            from arborpress.core.audit import write_audit_event

            await write_audit_event(
                event_type="password_changed" if was_enabled else "password_enabled",
                outcome="success",
                actor_id="cli",
                target_id=str(user.id),
                detail="cli_password_set",
                db=db,
            )
            await write_audit_event(
                event_type="breakglass_password_set",
                outcome="success",
                actor_id="cli",
                target_id=str(user.id),
                detail="cli_password_set",
                db=db,
            )
            await db.commit()
            typer.echo(__("Password for {username!r} set and activated.").format(username=username))
            _print_password_assessment(assessment)
            if generate:
                typer.echo(__("Generated password:      {password}").format(password=password))

    asyncio.run(_set_pw())


@user_app.command("password-generate")
def user_password_generate(
    generator: str = typer.Option("random", "--generator", help="Generator mode: diceware|random"),
    words: int = typer.Option(
        6, "--words", min=4, max=10, help="Word count for Diceware passphrases"
    ),
    delimiter: str = typer.Option("-", "--delimiter", help="Separator for Diceware passphrases"),
    length: int = typer.Option(24, "--length", min=16, max=256, help="Length for random passwords"),
    username: str | None = typer.Option(
        None, "--username", help="Optional username for zxcvbn context"
    ),
    as_json: bool = typer.Option(False, "--json", help="Print machine-readable JSON output"),
) -> None:
    """Generates a break-glass password and prints the quality assessment."""
    from arborpress.auth.breakglass import validate_password_policy

    async def _load_security() -> dict:
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_security_settings

        async for db in get_db_session():
            return await get_security_settings(db)
        return {}

    sec = asyncio.run(_load_security())

    password = _build_breakglass_password(
        generator=generator,
        words=words,
        delimiter=delimiter,
        length=length,
    )
    assessment = validate_password_policy(
        password,
        min_length=sec["legacy_password_min_length"],
        max_length=sec["legacy_password_max_length"],
        min_score=sec["legacy_password_min_score"],
        user_inputs=[item for item in [username, "arborpress", "admin"] if item],
    )
    if as_json:
        typer.echo(json.dumps({"password": password, "assessment": assessment.to_dict()}))
        return
    typer.echo(__("Generated password:      {password}").format(password=password))
    _print_password_assessment(assessment)


@user_app.command("password-disable")
def user_password_disable(
    username: str = typer.Argument(..., help="Username"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Disables the password of an account (§2 Break-Glass).

    Ensures that at least one MFA device or WebAuthn credential
    exists before disabling the password.
    """
    if not yes:
        confirmed = typer.confirm(
            f"Really disable password for {username!r}? Make sure WebAuthn/MFA is set up."
        )
        if not confirmed:
            raise typer.Exit(0)

    async def _disable_pw() -> None:
        from sqlalchemy import func, select

        from arborpress.core.audit import write_audit_event
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            if not user.legacy_password_enabled:
                typer.echo(f"Password for {username!r} is already disabled.")
                return
            from arborpress.auth.policy import assert_auth_path_remains

            try:
                await assert_auth_path_remains(db, user, exclude_password=True)
            except ValueError:
                await write_audit_event(
                    event_type="auth_lockout_prevention",
                    outcome="blocked",
                    actor_id="cli",
                    target_id=str(user.id),
                    detail="last_auth_path_password_disable",
                    db=db,
                )
                await db.commit()
                typer.echo(
                    "ERROR: No usable alternate authentication path found.\n"
                    "  Set up WebAuthn or TOTP first before disabling the password.",
                    err=True,
                )
                raise typer.Exit(1)
            user.legacy_password_enabled = False
            user.legacy_password_hash = None
            db.add(user)
            await write_audit_event(
                event_type="password_disabled",
                outcome="success",
                actor_id="cli",
                target_id=str(user.id),
                db=db,
            )
            await db.commit()
            typer.echo(f"Password for {username!r} disabled and hash deleted.")

    asyncio.run(_disable_pw())


@user_app.command("federation-status")
def user_federation_status(
    username: str = typer.Argument(..., help="Username"),
) -> None:
    """Shows federation status of an account (opt-out, key pair)."""

    async def _show() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import ActorKeypair, User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            typer.echo(f"Account type:       {user.account_type.value}")
            typer.echo(f"Federation opt-out: {user.federation_opt_out}")
            if user.account_type.value == "operational":
                typer.echo("  OPERATIONAL account: no WebFinger / ActivityPub endpoint")
                return
            key_result = await db.execute(
                select(ActorKeypair).where(ActorKeypair.user_id == str(user.id))
            )
            keypair = key_result.scalar_one_or_none()
            if keypair:
                typer.echo(f"Actor key:          present ({keypair.algorithm})")
                typer.echo(f"  Key-ID:           {keypair.key_id_url}")
                typer.echo(f"  Created:          {keypair.created_at}")
                if keypair.rotated_at:
                    typer.echo(f"  Last rotated:     {keypair.rotated_at}")
            else:
                typer.echo("Actor key:          NOT PRESENT – run: arborpress federation keygen")

    asyncio.run(_show())


@user_app.command("auth-policy")
def auth_policy_status(
    username: str | None = typer.Argument(None, help="User (empty = global)"),
) -> None:
    """Shows auth policy status (§2, §14 auth policy status)."""
    cfg = get_settings()
    typer.echo(f"UV global:              {cfg.auth.require_uv}")
    typer.echo(f"Legacy-PW global:       {cfg.auth.legacy_password_enabled}")
    typer.echo(
        "Legacy-PW length:       "
        f"{cfg.auth.legacy_password_min_length}-{cfg.auth.legacy_password_max_length} chars"
    )
    typer.echo(f"Legacy-PW zxcvbn:       >= {cfg.auth.legacy_password_min_score}/4")
    typer.echo(f"Step-up TTL (effective): {min(300, max(0, cfg.auth.stepup_ttl))}s")
    typer.echo(f"Admin session TTL:      {cfg.auth.admin_session_ttl}s")
    typer.echo(f"Auth rate limit:        {cfg.auth.auth_rate_limit}")


# ---------------------------------------------------------------------------
# §14 user mfa: list / add / remove / rename
# ---------------------------------------------------------------------------


@mfa_app.command("list")
def mfa_list(
    username: str = typer.Argument(..., help="Username"),
) -> None:
    """Lists all MFA devices of a user."""

    async def _list() -> None:
        from sqlalchemy import func, select

        from arborpress.auth.mfa import get_device_limit
        from arborpress.core.db import get_db_session
        from arborpress.models.user import MFADevice, MFADeviceType, User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            dev_result = await db.execute(
                select(MFADevice).where(MFADevice.user_id == str(user.id))
            )
            devices = dev_result.scalars().all()
            if not devices:
                typer.echo(f"No MFA devices for {username!r}.")
                return
            limits = {
                dtype.value: await get_device_limit(db, dtype)
                for dtype in (MFADeviceType.TOTP, MFADeviceType.HOTP, MFADeviceType.PLUGIN)
            }
            typer.echo(f"MFA devices ({len(devices)} total; limits: {limits}):")
            typer.echo(f"  {'Label':<30} {'Type':<8} {'Active':<6} {'Status':<12} {'Last used'}")
            typer.echo("  " + "-" * 86)
            for d in devices:
                typer.echo(
                    f"  {d.label:<30} {d.device_type.value:<8} "
                    f"{'yes' if d.is_active else 'no':<6} {d.verification_status:<12} "
                    f"{str(d.last_used_at or 'Never')}"
                )

    asyncio.run(_list())


@mfa_app.command("add")
def mfa_add(
    username: str = typer.Argument(..., help="Username"),
    label: str = typer.Option(..., "--label", "-l", help="Device name (e.g. 'Personal', 'Work')"),
    device_type: str = typer.Option("totp", "--type", "-t", help="Device type: totp|hotp"),
) -> None:
    """Adds a new TOTP/HOTP device and outputs the provisioning URI."""
    from arborpress.auth.mfa import HOTPService, TOTPService, encrypt_secret, get_device_limit
    from arborpress.models.user import MFADeviceType

    try:
        dtype = MFADeviceType(device_type.lower())
    except ValueError:
        typer.echo(f"Invalid type {device_type!r}. Allowed: totp, hotp", err=True)
        raise typer.Exit(1) from None

    async def _add() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import MFADevice, User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            # Check limit
            count_result = await db.execute(
                select(func.count())
                .select_from(MFADevice)
                .where(
                    MFADevice.user_id == str(user.id),
                    MFADevice.device_type == dtype,
                    MFADevice.is_active.is_(True),
                )
            )
            count = count_result.scalar_one()
            limit = await get_device_limit(db, dtype)
            if count >= limit:
                from arborpress.core.audit import write_audit_event

                await write_audit_event(
                    event_type="auth_lockout_prevention",
                    outcome="blocked",
                    actor_id="cli",
                    target_id=str(user.id),
                    detail=f"{dtype.value}_credential_limit",
                    db=db,
                )
                await db.commit()
                typer.echo(f"ERROR: Maximum of {limit} {dtype.value} devices reached.", err=True)
                raise typer.Exit(1)

            if dtype == MFADeviceType.TOTP:
                svc = TOTPService()
                secret = svc.generate_secret()
                uri = svc.provisioning_uri(secret, account_name=f"{username}:{label}")
            else:
                svc = HOTPService()  # type: ignore[assignment]
                secret = svc.generate_secret()
                uri = svc.provisioning_uri(secret, account_name=f"{username}:{label}")

            if dtype == MFADeviceType.TOTP:
                typer.echo("Scan this provisioning URI, then enter the current 8-digit code:")
                typer.echo(f"  {uri}")
                code = typer.prompt("TOTP confirmation code", hide_input=False).strip()
                if not TOTPService().verify(secret, code, user_id=str(user.id)):
                    typer.echo("Invalid TOTP code; no active device was stored.", err=True)
                    raise typer.Exit(1)
            secret_enc = encrypt_secret(secret)

            device = MFADevice(
                user_id=str(user.id),
                device_type=dtype,
                label=label,
                secret_enc=secret_enc,
                verification_status="verified" if dtype == MFADeviceType.TOTP else "unknown",
                last_used_at=(
                    datetime.now(UTC).replace(tzinfo=None) if dtype == MFADeviceType.TOTP else None
                ),
            )
            db.add(device)
            from arborpress.core.audit import write_audit_event

            await write_audit_event(
                event_type=("totp_added" if dtype == MFADeviceType.TOTP else "mfa_device_added"),
                outcome="success",
                actor_id="cli",
                target_id=str(user.id),
                detail=f"type={dtype.value};label={label}",
                db=db,
            )
            await db.commit()

            typer.echo(f"MFA device {label!r} ({dtype.value}) created.")
            if dtype != MFADeviceType.TOTP:
                typer.echo(f"Provisioning-URI:\n  {uri}")

    asyncio.run(_add())


@mfa_app.command("remove")
def mfa_remove(
    username: str = typer.Argument(..., help="Username"),
    label: str = typer.Argument(..., help="Device name"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Removes an MFA device."""
    if not yes:
        confirmed = typer.confirm(f"Really remove MFA device {label!r} from {username!r}?")
        if not confirmed:
            raise typer.Exit(0)

    async def _remove() -> None:
        from sqlalchemy import func, select

        from arborpress.core.audit import write_audit_event
        from arborpress.core.db import get_db_session
        from arborpress.models.user import MFADevice, MFADeviceType, User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            dev_result = await db.execute(
                select(MFADevice).where(
                    MFADevice.user_id == str(user.id),
                    MFADevice.label == label,
                )
            )
            device = dev_result.scalar_one_or_none()
            if not device:
                typer.echo(f"Device {label!r} not found.", err=True)
                raise typer.Exit(1)
            if device.device_type == MFADeviceType.TOTP:
                from arborpress.auth.policy import assert_auth_path_remains

                try:
                    await assert_auth_path_remains(db, user, exclude_mfa_id=str(device.id))
                except ValueError:
                    await write_audit_event(
                        event_type="auth_lockout_prevention",
                        outcome="blocked",
                        actor_id="cli",
                        target_id=str(user.id),
                        detail="last_totp_removed",
                        db=db,
                    )
                    await db.commit()
                    typer.echo("ERROR: This is the last usable authentication path.", err=True)
                    raise typer.Exit(1)
            await db.delete(device)
            if device.device_type == MFADeviceType.TOTP:
                await write_audit_event(
                    event_type="totp_removed",
                    outcome="success",
                    actor_id="cli",
                    target_id=str(user.id),
                    detail=f"label={label}",
                    db=db,
                )
            await db.commit()
            typer.echo(f"MFA device {label!r} removed.")

    asyncio.run(_remove())


@mfa_app.command("rename")
def mfa_rename(
    username: str = typer.Argument(..., help="Username"),
    old_label: str = typer.Argument(..., help="Current device name"),
    new_label: str = typer.Argument(..., help="New device name"),
) -> None:
    """Renames an MFA device."""

    async def _rename() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import MFADevice, User

        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            dev_result = await db.execute(
                select(MFADevice).where(
                    MFADevice.user_id == str(user.id),
                    MFADevice.label == old_label,
                )
            )
            device = dev_result.scalar_one_or_none()
            if not device:
                typer.echo(f"Device {old_label!r} not found.", err=True)
                raise typer.Exit(1)
            device.label = new_label
            db.add(device)
            await db.commit()
            typer.echo(f"MFA device renamed: {old_label!r} → {new_label!r}")

    asyncio.run(_rename())


# ---------------------------------------------------------------------------
# §14 key: generate / import / rotate / status
# ---------------------------------------------------------------------------


@key_app.command("generate")
def key_generate(
    name: str = typer.Argument(..., help="Key ID / name"),
) -> None:
    """Generates a new ECC/Ed25519 key pair (§13, §14)."""
    typer.echo(f"Generating Ed25519 key for {name!r} (TODO).")
    typer.echo("NOTE: Private keys are stored encrypted (§13).")


@key_app.command("import")
def key_import(
    file: Path = typer.Argument(..., help="Path to key file (RSA >= 4096 or ECC)"),  # noqa: B008
) -> None:
    """Imports an existing key (§13 RSA import)."""
    typer.echo(f"Importing key from {file} (TODO).")


@key_app.command("rotate")
def key_rotate(
    name: str = typer.Argument(..., help="Key ID / name"),
) -> None:
    """Rotates a key – step-up operation (§2, §14 key rotation)."""
    typer.echo("NOTE: 'rotate_key' requires step-up (via web admin).")
    typer.echo(f"Rotating {name!r} (TODO).")


@key_app.command("status")
def key_status(
    username: str | None = typer.Argument(None, help="Username (empty = instance key pair)"),
) -> None:
    """Shows key status (§13, §14).

    Without argument: instance key pair (HTTP signatures) + all actor keys.
    With username: OpenPGP keys + actor key of that account.
    """

    async def _show() -> None:
        from datetime import UTC, datetime

        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import ActorKeypair, InstanceKeypair, User, UserPGPKey

        now = datetime.now(UTC).replace(tzinfo=None)

        async for db in get_db_session():
            if username is None:
                # ---- Instance key pair ----
                inst = (await db.execute(select(InstanceKeypair))).scalar_one_or_none()
                if inst:
                    age_days = (now - inst.created_at).days
                    typer.echo("Instance key pair:")
                    typer.echo(f"  Algorithm: {inst.algorithm}")
                    typer.echo(f"  Key-ID:    {inst.key_id_url}")
                    typer.echo(f"  Created:   {inst.created_at.date()} ({age_days} days old)")
                    if inst.rotated_at:
                        typer.echo(f"  Rotated:   {inst.rotated_at.date()}")
                else:
                    typer.echo("Instance key pair: NOT PRESENT – run: arborpress federation keygen")

                # ---- Actor keys (all accounts) ----
                rows = (
                    await db.execute(
                        select(ActorKeypair, User.username)
                        .join(User, User.id == ActorKeypair.user_id)
                        .order_by(User.username)
                    )
                ).all()
                typer.echo(f"\nActor keys ({len(rows)}):")
                if rows:
                    typer.echo(f"  {'User':<20} {'Algo':<10} {'Created':<12} Rotated")
                    typer.echo("  " + "-" * 62)
                    for kp, uname in rows:
                        rotated = str(kp.rotated_at.date()) if kp.rotated_at else "–"
                        typer.echo(
                            f"  {uname:<20} {kp.algorithm:<10}"
                            f" {str(kp.created_at.date()):<12} {rotated}"
                        )

                # ---- OpenPGP keys (overall overview) ----
                pgp_count = (
                    await db.execute(select(func.count()).select_from(UserPGPKey))
                ).scalar_one()
                typer.echo(f"\nOpenPGP keys total: {pgp_count}")
                return

            # ---- User-specific ----
            user_row = (
                await db.execute(select(User).where(func.lower(User.username) == username.lower()))
            ).scalar_one_or_none()
            if not user_row:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)

            typer.echo(f"Key status for {username!r}:")

            # Actor key
            kp = (
                await db.execute(
                    select(ActorKeypair).where(ActorKeypair.user_id == str(user_row.id))
                )
            ).scalar_one_or_none()
            typer.echo("\nActor key (HTTP signatures):")
            if kp:
                typer.echo(f"  Algorithm: {kp.algorithm}")
                typer.echo(f"  Key-ID:    {kp.key_id_url}")
                typer.echo(
                    f"  Created:   {kp.created_at.date()} ({(now - kp.created_at).days} days old)"
                )
                if kp.rotated_at:
                    typer.echo(f"  Rotated:   {kp.rotated_at.date()}")
            else:
                typer.echo("  NOT PRESENT")

            # OpenPGP keys
            pgp_rows = (
                (
                    await db.execute(
                        select(UserPGPKey)
                        .where(UserPGPKey.user_id == str(user_row.id))
                        .order_by(UserPGPKey.is_primary_signing.desc(), UserPGPKey.created_at)
                    )
                )
                .scalars()
                .all()
            )
            typer.echo(f"\nOpenPGP keys ({len(pgp_rows)}):")
            if pgp_rows:
                typer.echo(
                    f"  {'Label':<20} {'Fingerprint':<42} {'Sign':<5} {'Enc':<5} {'Prim':<5} Expiry"
                )
                typer.echo("  " + "-" * 90)
                for pk in pgp_rows:
                    expired = ""
                    if pk.expires_at and pk.expires_at < now:
                        expired = " [EXPIRED]"
                    elif pk.expires_at:
                        expired = f" (until {pk.expires_at.date()})"
                    typer.echo(
                        f"  {pk.label:<20} {pk.fingerprint:<42}"
                        f" {'✓' if pk.use_for_signing else '–':<5}"
                        f" {'✓' if pk.use_for_encryption else '–':<5}"
                        f" {'★' if pk.is_primary_signing else ' ':<5}"
                        f"{expired}"
                    )
            else:
                typer.echo("  none")

    asyncio.run(_show())


# ---------------------------------------------------------------------------
# §14 search: reindex
# ---------------------------------------------------------------------------


@search_app.command("reindex")
def search_reindex(
    provider: str | None = typer.Option(
        None,
        "--provider",
        help=(
            "Explicit: pg_fts/mariadb_fulltext/sqlite_fts5"
            "/meilisearch/typesense/elasticsearch/fallback"
        ),
    ),
) -> None:
    """Rebuilds the search index (§12 FTS, §14 search reindex)."""
    from arborpress.core.site_settings import get_defaults

    effective = provider or get_defaults("search").get("provider", "fallback")
    typer.echo(f"Reindex with provider {effective!r} (TODO: provider-specific actions).")

    async def _show_caps() -> None:
        from arborpress.core.db import get_engine
        from arborpress.core.db_capabilities import detect_capabilities

        caps = await detect_capabilities(get_engine())
        typer.echo(f"DB-FTS:     {caps.fts_provider}")
        if caps.external_fts:
            typer.echo(f"Externe FTS: {caps.external_fts}")

    asyncio.run(_show_caps())


# ---------------------------------------------------------------------------
# §14 cache: purge / warm / status
# ---------------------------------------------------------------------------


@cache_app.command("status")
def cache_status() -> None:
    """Shows cache backend status (§14 cache status)."""
    from arborpress.core.cache import cache_backend_info

    info = cache_backend_info()
    typer.echo(f"Cache backend: {info}")
    typer.echo(f"Default TTL:   {get_settings().cache.ttl}s")


@cache_app.command("purge")
def cache_purge() -> None:
    """Clears the entire cache (§14 cache purge)."""
    from arborpress.core.cache import cache_backend_info, cache_flush

    asyncio.run(cache_flush())
    typer.echo(f"Cache cleared. Backend: {cache_backend_info()}")
    # Also clear site settings cache
    from arborpress.core.site_settings import invalidate_cache

    invalidate_cache()
    typer.echo("Site settings cache cleared.")


@cache_app.command("warm")
def cache_warm() -> None:
    """Pre-warms important cache entries (§14 cache warm)."""

    async def _warm() -> None:
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section

        sections = ["general", "theme", "mail", "comments", "captcha", "federation", "search"]
        async for db in get_db_session():
            for sec in sections:
                await get_section(sec, db)
                typer.echo(f"  Warm: site_settings[{sec!r}]")
        typer.echo("Cache warmed up.")

    asyncio.run(_warm())


# ---------------------------------------------------------------------------
# §14 federation: inbox-process
# ---------------------------------------------------------------------------


@federation_app.command("inbox-process")
def federation_inbox_process(
    batch: int = typer.Option(50, "--batch", "-n", help="Number of items per run"),
) -> None:
    """Process a bounded batch of authenticated, persisted inbox activities."""

    async def _process() -> None:
        from arborpress.core.db import get_session_factory
        from arborpress.federation.inbox import process_inbox_batch

        count = await process_inbox_batch(get_session_factory(), batch_size=batch)
        typer.echo(f"Processed inbox activities: {count}")

    asyncio.run(_process())


@federation_app.command("worker")
def federation_worker() -> None:
    """Run the persistent inbox and outbound-delivery workers."""

    async def _run() -> None:
        from arborpress.core.db import get_session_factory
        from arborpress.federation.inbox import run_worker as run_inbox_worker
        from arborpress.federation.services import run_worker as run_delivery_worker

        stop = asyncio.Event()
        tasks = [
            asyncio.create_task(run_inbox_worker(get_session_factory(), stop_event=stop)),
            asyncio.create_task(run_delivery_worker(get_session_factory(), stop_event=stop)),
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            stop.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        typer.echo("Federation worker stopped.")


@federation_app.command("status")
def federation_status() -> None:
    """Shows federation configuration and instance key status from the DB (§5)."""

    async def _show() -> None:
        from sqlalchemy import select

        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        from arborpress.models.federation import FederationInstanceIdentity
        from arborpress.models.user import InstanceKeypair

        async for db in get_db_session():
            fed = await get_section("federation", db)
            ikp_result = await db.execute(select(InstanceKeypair).where(InstanceKeypair.id == 1))
            ikp = ikp_result.scalar_one_or_none()
            identity = await db.get(FederationInstanceIdentity, 1)
        from arborpress.federation.policy import federation_is_enabled

        typer.echo(f"Enabled:                    {federation_is_enabled(fed)}")
        typer.echo(f"Mode:                       {fed.get('mode', 'disabled')}")
        typer.echo(f"Configured origin:          {get_settings().web.base_url}")
        typer.echo(
            "Pinned actor origin:         "
            f"{identity.canonical_origin if identity else 'not pinned'}"
        )
        typer.echo(f"Instance:                   {fed.get('instance_name', '')}")
        typer.echo(f"Description:                {fed.get('instance_description', '') or '—'}")
        typer.echo(f"Contact e-mail:             {fed.get('contact_email', '') or '—'}")
        typer.echo(f"HTTP signature required:    {fed.get('require_http_signature', True)}")
        typer.echo(f"Authorized fetch:           {fed.get('authorized_fetch', False)}")
        typer.echo(f"Follow approval required:   {fed.get('require_approval_to_follow', False)}")
        typer.echo(f"Follower list public:       {fed.get('followers_visible', True)}")
        typer.echo(f"Following list public:      {fed.get('following_visible', True)}")
        typer.echo(f"Federate tags:              {fed.get('federate_tags', True)}")
        typer.echo(f"Federate media:             {fed.get('federate_media', False)}")
        typer.echo(f"Max note length:            {fed.get('max_note_length', 500)}")
        blocked = fed.get("inbox_blocklist_domains", [])
        typer.echo(f"Blocklisted domains:        {len(blocked)} entries")
        typer.echo("")
        if ikp:
            typer.echo(f"Instance key:               {ikp.algorithm}  {ikp.key_id_url}")
            typer.echo(f"  created:                  {ikp.created_at}")
            typer.echo(f"  rotated:                  {ikp.rotated_at or '—'}")
        else:
            typer.echo("Instance key:               NONE  → arborpress federation keygen")
        cfg = get_settings()
        kek_ok = cfg.auth.actor_key_enc_key is not None
        kek_hint = "yes ✓" if kek_ok else "NO ✗  → arborpress federation kek-init"
        typer.echo(f"Actor KEK configured:       {kek_hint}")

    asyncio.run(_show())


@federation_app.command("kek-init")
def federation_kek_init() -> None:
    """Generates a new actor key encryption key (KEK) and prints it.

    Add the value in config.toml under [auth] actor_key_enc_key.
    Afterwards re-encrypt existing key pairs with --force.
    """
    import base64
    import os

    kek = base64.urlsafe_b64encode(os.urandom(32)).decode()
    typer.echo("New actor KEK generated:")
    typer.echo(f"\n  {kek}\n")
    typer.echo("Add to config.toml:")
    typer.echo("  [auth]")
    typer.echo(f'  actor_key_enc_key = "{kek}"')
    typer.echo("\nStore the key securely – losing it makes all actor key pairs unusable.")


def _get_actor_fernet() -> Fernet:  # type: ignore[name-defined]
    """Returns the Fernet object with the actor KEK.

    Aborts if no KEK is configured.
    """
    from cryptography.fernet import Fernet

    cfg = get_settings()
    kek = cfg.auth.actor_key_enc_key
    if kek is None:
        typer.echo(
            "ERROR: auth.actor_key_enc_key is not set.\n"
            "  Generate: arborpress federation kek-init\n"
            '  Then add in config.toml [auth] actor_key_enc_key = "..."',
            err=True,
        )
        raise typer.Exit(1)
    return Fernet(kek.get_secret_value().encode())


@federation_app.command("keygen")
def federation_keygen(
    algorithm: str = typer.Option(
        "ed25519", "--algo", help="ed25519 (default) | rsa-sha256 (legacy)"
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite existing key pair (rotation)"),
) -> None:
    """Generates the instance key pair for HTTP signatures (§5).

    The instance itself is the primary ActivityPub actor.
    Default: Ed25519. RSA-SHA256 only needed for very old software.
    Prerequisite: auth.actor_key_enc_key in config.toml (arborpress federation kek-init).
    Per-account keys: arborpress federation user-keygen <user>
    """
    if algorithm not in ("rsa-sha256", "ed25519"):
        typer.echo("Invalid algorithm. Allowed: ed25519, rsa-sha256", err=True)
        raise typer.Exit(1)

    fernet = _get_actor_fernet()

    async def _gen() -> None:
        from datetime import datetime

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
        from sqlalchemy import select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import InstanceKeypair

        async for db in get_db_session():
            existing = await db.execute(select(InstanceKeypair).where(InstanceKeypair.id == 1))
            ikp = existing.scalar_one_or_none()
            if ikp and not force:
                typer.echo(
                    f"Instance key already present (algo={ikp.algorithm}).\n"
                    "  Use --force to rotate."
                )
                return

            cfg = get_settings()
            base = cfg.web.base_url.rstrip("/")
            key_id_url = f"{base}/ap/actor#main-key"

            if algorithm == "rsa-sha256":
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                public_pem = (
                    private_key.public_key()
                    .public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    .decode()
                )
                private_raw = private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            else:  # ed25519
                priv = ed25519.Ed25519PrivateKey.generate()
                public_pem = (
                    priv.public_key()
                    .public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    .decode()
                )
                private_raw = priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )

            enc = fernet.encrypt(private_raw)

            if ikp:
                ikp.algorithm = algorithm
                ikp.key_id_url = key_id_url
                ikp.public_key_pem = public_pem
                ikp.private_key_enc = enc
                ikp.rotated_at = datetime.now(UTC).replace(tzinfo=None)
                db.add(ikp)
                action = "rotated"
            else:
                db.add(
                    InstanceKeypair(
                        id=1,
                        key_id_url=key_id_url,
                        public_key_pem=public_pem,
                        private_key_enc=enc,
                        algorithm=algorithm,
                    )
                )
                action = "created"
            await db.commit()
            typer.echo(f"Instance key {action}: {key_id_url} ({algorithm})")

    asyncio.run(_gen())


@federation_app.command("follower-list")
def federation_follower_list(
    username: str = typer.Argument(..., help="Username"),
    direction: str = typer.Option("inbound", "--direction", "-d", help="inbound|outbound"),
) -> None:
    """Lists followers (inbound) or following (outbound) of an account."""

    async def _list() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import Follower, FollowerDirection, User

        try:
            dir_enum = FollowerDirection(direction)
        except ValueError:
            typer.echo("Invalid direction. Allowed: inbound, outbound", err=True)
            raise typer.Exit(1) from None
        async for db in get_db_session():
            result = await db.execute(
                select(User).where(func.lower(User.username) == username.lower())
            )
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            foll_result = await db.execute(
                select(Follower).where(
                    Follower.local_user_id == str(user.id),
                    Follower.direction == dir_enum,
                )
            )
            followers = foll_result.scalars().all()
            label = "Follower" if dir_enum == FollowerDirection.INBOUND else "Following"
            typer.echo(f"{label} of {username!r}: {len(followers)}")
            if not followers:
                return
            typer.echo(f"  {'Status':<12} {'Display name':<30} URI")
            typer.echo("  " + "-" * 80)
            for fol in followers:
                typer.echo(
                    f"  {fol.state.value:<12}"
                    f" {(fol.remote_display_name or ''):<30}"
                    f" {fol.remote_actor_uri}"
                )


@federation_actor_app.command("list")
def federation_actor_list() -> None:
    """List explicit local ActivityPub actors without exposing key material."""

    async def _run() -> None:
        from sqlalchemy import select

        from arborpress.core.db import get_db_session
        from arborpress.models.federation import LocalFederationActor

        async for db in get_db_session():
            rows = (
                (
                    await db.execute(
                        select(LocalFederationActor).order_by(
                            LocalFederationActor.preferred_username
                        )
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                typer.echo(
                    f"{row.preferred_username}\t"
                    f"{'enabled' if row.enabled else 'disabled'}\t{row.actor_uri}"
                )

    asyncio.run(_run())


@federation_actor_app.command("inspect")
def federation_actor_inspect(username: str) -> None:
    async def _run() -> None:
        from sqlalchemy import select

        from arborpress.core.db import get_db_session
        from arborpress.models.federation import LocalFederationActor

        async for db in get_db_session():
            row = (
                await db.execute(
                    select(LocalFederationActor).where(
                        LocalFederationActor.preferred_username == username
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                typer.echo("Actor not found", err=True)
                raise typer.Exit(1)
            typer.echo(
                f"id: {row.id}\nenabled: {row.enabled}\nactor_uri: {row.actor_uri}\n"
                f"key_configured: {bool(row.current_keypair_id)}"
            )

    asyncio.run(_run())


@federation_actor_app.command("enable")
def federation_actor_enable(username: str) -> None:
    """Explicitly publish an eligible public account as an ActivityPub actor."""

    async def _run() -> None:
        from sqlalchemy import func, select

        from arborpress.core.audit import write_audit_event
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        from arborpress.federation.actors import enable_local_actor
        from arborpress.federation.policy import federation_is_enabled
        from arborpress.models.user import ActorKeypair, User

        async for db in get_db_session():
            settings = await get_section("federation", db)
            if not federation_is_enabled(settings):
                typer.echo("Federation master switch and mode must be enabled first", err=True)
                raise typer.Exit(1)
            user = (
                await db.execute(select(User).where(func.lower(User.username) == username.lower()))
            ).scalar_one_or_none()
            if user is None:
                typer.echo("User not found", err=True)
                raise typer.Exit(1)
            previous_key = (
                await db.execute(select(ActorKeypair).where(ActorKeypair.user_id == str(user.id)))
            ).scalar_one_or_none()
            key_created = previous_key is None or previous_key.algorithm != "rsa-sha256"
            actor = await enable_local_actor(db, user)
            if key_created:
                await write_audit_event(
                    event_type="federation.actor_key.created",
                    outcome="success",
                    actor_id="cli",
                    target_id=actor.id,
                    detail="RSA-SHA256 actor signing key provisioned",
                    db=db,
                )
            await write_audit_event(
                event_type="federation.actor.enabled",
                outcome="success",
                actor_id="cli",
                target_id=actor.id,
                detail="explicit local actor opt-in",
                db=db,
            )
            await db.commit()
            typer.echo(f"Enabled {actor.preferred_username}: {actor.actor_uri}")

    asyncio.run(_run())


@federation_actor_app.command("disable")
def federation_actor_disable(username: str) -> None:
    async def _run() -> None:
        from sqlalchemy import select

        from arborpress.core.audit import write_audit_event
        from arborpress.core.db import get_db_session
        from arborpress.models.federation import LocalFederationActor

        async for db in get_db_session():
            actor = (
                await db.execute(
                    select(LocalFederationActor).where(
                        LocalFederationActor.preferred_username == username
                    )
                )
            ).scalar_one_or_none()
            if actor is None:
                typer.echo("Actor not found", err=True)
                raise typer.Exit(1)
            actor.enabled = False
            await write_audit_event(
                event_type="federation.actor.disabled",
                outcome="success",
                actor_id="cli",
                target_id=actor.id,
                detail="explicit local actor opt-out",
                db=db,
            )
            await db.commit()
            typer.echo(f"Disabled {username}")

    asyncio.run(_run())


@federation_app.command("fetch-actor")
def federation_fetch_actor(actor_uri: str) -> None:
    """Fetch and cache one actor using the same SSRF and domain checks as runtime."""

    async def _run() -> None:
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        from arborpress.federation.policy import federation_is_enabled
        from arborpress.federation.remote import fetch_remote_actor

        async for db in get_db_session():
            settings = await get_section("federation", db)
            if not federation_is_enabled(settings):
                typer.echo("Federation is disabled", err=True)
                raise typer.Exit(1)
            actor = await fetch_remote_actor(db, actor_uri, settings, force=True)
            await db.commit()
            typer.echo(
                f"Fetched {actor.actor_uri} ({actor.actor_type}) from {actor.domain}; "
                f"expiry {actor.expires_at}"
            )

    try:
        asyncio.run(_run())
    except (ValueError, OSError) as exc:
        typer.echo(f"Fetch failed: {type(exc).__name__}", err=True)
        raise typer.Exit(1) from None


@federation_inbox_app.command("inspect")
def federation_inbox_inspect(activity_id: str) -> None:
    async def _run() -> None:
        from arborpress.core.db import get_db_session
        from arborpress.models.federation import FederationInboxActivity

        async for db in get_db_session():
            row = await db.get(FederationInboxActivity, activity_id)
            if row is None:
                typer.echo("Inbox item not found", err=True)
                raise typer.Exit(1)
            typer.echo(
                f"id: {row.id}\nactivity_id: {row.activity_uri}\n"
                f"type: {row.activity_type}\nactor: {row.actor_uri}\n"
                f"state: {row.processing_state}\nattempts: {row.attempt_count}\n"
                f"sha256: {row.body_sha256}\nerror: {row.last_error or '—'}"
            )

    asyncio.run(_run())


@federation_domain_app.command("list")
def federation_domains_list() -> None:
    async def _run() -> None:
        from sqlalchemy import select

        from arborpress.core.db import get_db_session
        from arborpress.models.federation import FederationDomainRule

        async for db in get_db_session():
            rows = (
                (
                    await db.execute(
                        select(FederationDomainRule).order_by(FederationDomainRule.domain)
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                typer.echo(f"{row.domain}\t{row.rule}")

    asyncio.run(_run())


@federation_domain_app.command("allow")
def federation_domain_allow(domain: str) -> None:
    _change_federation_domain_rule(domain, "allow")


@federation_domain_app.command("block")
def federation_domain_block(domain: str) -> None:
    _change_federation_domain_rule(domain, "block")


@federation_domain_app.command("remove")
def federation_domain_remove(domain: str) -> None:
    _change_federation_domain_rule(domain, None)


def _change_federation_domain_rule(domain: str, rule: str | None) -> None:
    """Create, replace or remove a normalized operator domain rule."""

    async def _run() -> None:
        from sqlalchemy import select

        from arborpress.core.audit import write_audit_event
        from arborpress.core.db import get_db_session
        from arborpress.federation.security import normalize_domain
        from arborpress.models.federation import FederationDomainRule

        try:
            normalized = normalize_domain(domain)
        except ValueError as exc:
            typer.echo("Invalid domain", err=True)
            raise typer.Exit(1) from exc
        async for db in get_db_session():
            result = await db.execute(
                select(FederationDomainRule).where(FederationDomainRule.domain == normalized)
            )
            existing = result.scalar_one_or_none()
            if rule is None:
                if existing is not None:
                    await db.delete(existing)
            elif existing is None:
                db.add(FederationDomainRule(domain=normalized, rule=rule))
            else:
                existing.rule = rule
            await write_audit_event(
                event_type="federation.domain_rule.changed",
                outcome="success",
                actor_id="cli",
                target_id=hashlib.sha256(normalized.encode()).hexdigest()[:36],
                detail=f"rule={rule or 'removed'}",
                db=db,
            )
            await db.commit()
            typer.echo(f"{normalized}: {rule or 'removed'}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# §13 mail: queue
# ---------------------------------------------------------------------------


@mail_app.command("process")
def mail_process(
    once: bool = typer.Option(False, "--once", help="Process only once"),
    interval: int = typer.Option(30, "--interval", "-i", help="Worker interval in seconds"),
) -> None:
    """Processes the mail queue (§13)."""
    from arborpress.mail.queue import process_queue, run_queue_worker

    if once:
        sent = asyncio.run(process_queue())
        typer.echo(f"Sent: {sent}")
    else:
        typer.echo(f"Starting mail queue worker (interval: {interval}s) …")
        asyncio.run(run_queue_worker(interval=interval))


@mail_app.command("status")
def mail_status() -> None:
    """Shows mail configuration and queue status (§13)."""
    from arborpress.core.site_settings import get_defaults

    mail = get_defaults("mail")
    typer.echo(f"Backend:  {mail.get('backend', 'none')}")
    if mail.get("backend", "none") == "smtp":
        typer.echo(f"SMTP:     {mail.get('smtp_host', 'localhost')}:{mail.get('smtp_port', 587)}")
    typer.echo(f"PGP-Sign: {mail.get('pgp_sign_enabled', False)}")


@mail_profiles_app.command("list")
def mail_profiles_list(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON diagnostics"),
) -> None:
    """List SMTP profile metadata without revealing credentials."""
    from sqlalchemy import select

    from arborpress.core.db import get_session_factory
    from arborpress.mail.profiles import safe_profile_data
    from arborpress.models.mail import SMTPProfile

    async def _list() -> list[dict[str, Any]]:
        async with get_session_factory()() as db:
            rows = (await db.execute(select(SMTPProfile).order_by(SMTPProfile.id))).scalars().all()
            return [safe_profile_data(row) for row in rows]

    values = asyncio.run(_list())
    if json_output:
        typer.echo(json.dumps(values, indent=2))
    else:
        for item in values:
            typer.echo(
                f"{item['id']}: {item['host']}:{item['port']} {item['transport']} "
                f"enabled={item['enabled']} auth={'yes' if item['auth_configured'] else 'no'}"
            )


@mail_profiles_app.command("inspect")
def mail_profiles_inspect(
    profile_id: str,
    json_output: bool = typer.Option(False, "--json", help="Emit JSON diagnostics"),
) -> None:
    """Inspect a profile with secret values omitted."""
    from arborpress.core.db import get_session_factory
    from arborpress.mail.profiles import safe_profile_data
    from arborpress.models.mail import SMTPProfile

    async def _read() -> dict[str, Any] | None:
        async with get_session_factory()() as db:
            row = await db.get(SMTPProfile, profile_id)
            return safe_profile_data(row) if row else None

    value = asyncio.run(_read())
    if value is None:
        raise typer.BadParameter("SMTP profile not found")
    if json_output:
        typer.echo(json.dumps(value, indent=2))
    else:
        for key, item in value.items():
            typer.echo(f"{key}: {item}")


@mail_profiles_app.command("configure")
def mail_profiles_configure(
    profile_id: str,
    host: str = typer.Option(..., prompt=True),
    port: int = typer.Option(465, prompt=True),
    transport: str = typer.Option("implicit_tls", prompt=True),
    from_address: str = typer.Option(..., prompt=True),
    from_name: str = typer.Option("ArborPress", prompt=True),
    username: str = typer.Option("", prompt=True),
    envelope_domain: str = typer.Option("", prompt=True),
    enabled: bool = typer.Option(True, "--enabled/--disabled"),
) -> None:
    """Create/update a named profile; an SMTP secret is prompted privately."""
    from arborpress.core.db import get_session_factory
    from arborpress.mail.profiles import save_profile

    secret = typer.prompt("SMTP secret (empty for anonymous SMTP)", hide_input=True, default="")

    async def _save() -> None:
        async with get_session_factory()() as db:
            await save_profile(
                db,
                {
                    "id": profile_id,
                    "display_name": profile_id,
                    "host": host,
                    "port": port,
                    "transport": transport,
                    "username": username,
                    "secret": secret or None,
                    "from_address": from_address,
                    "from_name": from_name,
                    "envelope_domain": envelope_domain or None,
                    "enabled": enabled,
                },
            )
            from arborpress.core.audit import write_audit_event

            await write_audit_event(
                event_type="smtp_profile_changed",
                outcome="success",
                target_id=profile_id,
                detail=f"transport={transport} enabled={str(enabled).lower()}",
                db=db,
            )
            if profile_id == "transactional":
                from arborpress.core.site_settings import get_section, save_section

                mail_settings = await get_section("mail", db)
                mail_settings.pop("smtp_password", None)
                mail_settings["backend"] = "smtp"
                mail_settings["transactional_profile"] = profile_id
                await save_section("mail", mail_settings, db, updated_by="cli")
            else:
                await db.commit()

    asyncio.run(_save())
    typer.echo(f"SMTP profile {profile_id!r} saved; secret omitted.")


@mail_profiles_app.command("test")
def mail_profiles_test(profile_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    """Probe DNS/TLS/EHLO/AUTH without sending mail."""
    from arborpress.core.audit import write_audit_event
    from arborpress.core.db import get_session_factory
    from arborpress.mail.dns import SMTPDNSResolver
    from arborpress.mail.profiles import profile_transport_data
    from arborpress.mail.smtp import test_profile
    from arborpress.models.mail import SMTPProfile

    async def _probe() -> dict[str, Any]:
        async with get_session_factory()() as db:
            row = await db.get(SMTPProfile, profile_id)
            if row is None:
                raise typer.BadParameter("SMTP profile not found")
            profile = profile_transport_data(row)
        transport = await test_profile(profile)
        dns = await SMTPDNSResolver().smtp_diagnostics(profile["host"], profile["port"])
        return {"transport": transport, "dns": dns}

    async def _run() -> dict[str, Any]:
        result = await _probe()
        await write_audit_event(
            event_type="smtp_profile_tested",
            outcome="success" if result["transport"]["ok"] else "failure",
            target_id=profile_id,
            detail=(
                f"dnssec={result['dns']['tlsa']['dnssec']} "
                f"dane_records={result['dns']['dane_authenticated_records']}"
            ),
        )
        return result

    result = asyncio.run(_run())
    if json_output:
        typer.echo(json.dumps(result, indent=2))
    else:
        typer.echo(f"Transport: {'OK' if result['transport']['ok'] else 'FAILED'}")
        typer.echo(
            f"DNSSEC/TLSA: {result['dns']['tlsa']['dnssec']} / "
            f"authenticated TLSA records={result['dns']['dane_authenticated_records']} "
            "(certificate match not checked)"
        )
        typer.echo(f"CAA: {result['dns']['caa']['values'] or 'no record'} (informational)")


@mail_profiles_app.command("set-default")
def mail_profiles_set_default(
    profile_id: str,
    purpose: str = typer.Option("transactional", "--purpose", help="transactional or bulk"),
) -> None:
    """Route a producer class to an explicitly named enabled profile."""
    from arborpress.core.audit import write_audit_event
    from arborpress.core.db import get_session_factory
    from arborpress.core.site_settings import get_section, save_section
    from arborpress.models.mail import SMTPProfile

    if purpose not in {"transactional", "bulk"}:
        raise typer.BadParameter("purpose must be transactional or bulk")

    async def _set() -> None:
        async with get_session_factory()() as db:
            row = await db.get(SMTPProfile, profile_id)
            if row is None or not row.enabled:
                raise typer.BadParameter("SMTP profile must exist and be enabled")
            settings = await get_section("mail", db)
            settings[f"{purpose}_profile"] = profile_id
            if purpose == "transactional":
                settings["backend"] = "smtp"
            await write_audit_event(
                event_type="smtp_profile_default_changed",
                outcome="success",
                target_id=profile_id,
                detail=f"purpose={purpose}",
                db=db,
            )
            await save_section("mail", settings, db, updated_by="cli")

    asyncio.run(_set())
    typer.echo(f"Default {purpose} profile set to {profile_id!r}.")


@mail_queue_app.command("list")
def mail_queue_list(
    status: str | None = typer.Option(None, "--status"),
    profile_id: str | None = typer.Option(None, "--profile"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Show queue metadata only; message bodies are never exposed."""
    from sqlalchemy import select

    from arborpress.core.db import get_session_factory
    from arborpress.models.mail import MailQueue

    async def _list() -> list[dict[str, Any]]:
        async with get_session_factory()() as db:
            stmt = select(MailQueue).order_by(MailQueue.created_at.desc()).limit(100)
            if status:
                stmt = stmt.where(MailQueue.status == status)
            if profile_id:
                stmt = stmt.where(MailQueue.profile_id == profile_id)
            rows = (await db.execute(stmt)).scalars().all()
            return [
                {
                    "id": row.id,
                    "profile_id": row.profile_id,
                    "recipient_domain": row.recipient.rpartition("@")[2],
                    "status": row.status,
                    "attempts": row.attempts,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                    "sent_at": row.sent_at.isoformat() if row.sent_at else None,
                    "last_error": row.last_error,
                }
                for row in rows
            ]

    rows = asyncio.run(_list())
    if json_output:
        typer.echo(json.dumps(rows, indent=2))
    else:
        for row in rows:
            typer.echo(f"{row['id']} {row['status']} {row['profile_id']} {row['recipient_domain']}")


@mail_queue_app.command("inspect")
def mail_queue_inspect(job_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    """Inspect delivery state without showing recipient local-part or body."""
    from arborpress.core.db import get_session_factory
    from arborpress.models.mail import MailQueue

    async def _read() -> dict[str, Any] | None:
        async with get_session_factory()() as db:
            row = await db.get(MailQueue, job_id)
            if not row:
                return None
            return {
                "id": row.id,
                "profile_id": row.profile_id,
                "recipient_domain": row.recipient.rpartition("@")[2],
                "status": row.status,
                "attempts": row.attempts,
                "max_attempts": row.max_attempts,
                "next_attempt_at": row.next_attempt_at.isoformat() if row.next_attempt_at else None,
                "lease_until": row.lease_until.isoformat() if row.lease_until else None,
                "message_id": row.message_id,
                "dsn_status": row.dsn_status,
                "dsn_enhanced_code": row.dsn_enhanced_code,
                "last_error": row.last_error,
            }

    value = asyncio.run(_read())
    if value is None:
        raise typer.BadParameter("Mail job not found")
    output = (
        json.dumps(value, indent=2)
        if json_output
        else "\n".join(f"{key}: {item}" for key, item in value.items())
    )
    typer.echo(output)


@mail_queue_app.command("retry")
def mail_queue_retry(job_id: str) -> None:
    from arborpress.core.audit import write_audit_event
    from arborpress.mail.queue import retry_mail

    async def _retry() -> bool:
        changed = await retry_mail(job_id)
        if changed:
            await write_audit_event(
                event_type="mail_manual_retry",
                outcome="success",
                target_id=job_id,
                detail="dead or retry delivery manually queued",
            )
        return changed

    if not asyncio.run(_retry()):
        raise typer.BadParameter("Mail job is not retryable")
    typer.echo("Mail job queued for manual retry.")


@mail_queue_app.command("cancel")
def mail_queue_cancel(job_id: str) -> None:
    from arborpress.core.audit import write_audit_event
    from arborpress.mail.queue import cancel_mail

    async def _cancel() -> bool:
        changed = await cancel_mail(job_id)
        if changed:
            await write_audit_event(
                event_type="mail_cancelled",
                outcome="success",
                target_id=job_id,
                detail="outbox delivery cancelled",
            )
        return changed

    if not asyncio.run(_cancel()):
        raise typer.BadParameter("Mail job is not cancellable")
    typer.echo("Mail job cancelled.")


@mail_app.command("worker")
def mail_worker(interval: int = typer.Option(5, "--interval", min=1)) -> None:
    """Run the same durable worker used by the embedded app lifecycle."""
    from arborpress.mail.queue import run_queue_worker

    asyncio.run(run_queue_worker(interval=interval))


@notifications_app.command("worker")
def notifications_worker(
    interval: int | None = typer.Option(None, "--interval", min=1, max=60),
) -> None:
    """Run the durable Web Push delivery worker used by embedded instances."""
    from arborpress.notifications.push import run_notification_worker

    asyncio.run(run_notification_worker(interval=interval))


# ---------------------------------------------------------------------------
# Third-party plugin discovery (metadata only; never imports plugin code)
# ---------------------------------------------------------------------------


@plugin_app.command("list")
def plugin_list(
    json_output: bool = typer.Option(False, "--json", help="Emit JSON diagnostics"),
) -> None:
    """List discovered built-in and third-party plugin metadata."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry

    plugins = get_registry().all()
    if json_output:
        typer.echo(json.dumps([_plugin_diagnostic(plugin) for plugin in plugins], indent=2))
        return
    if not plugins:
        typer.echo("No third-party plugins discovered.")
        return
    for p in plugins:
        manifest_version = p.manifest.version if p.manifest else "?"
        caps = ", ".join(p.capabilities) or "none"
        typer.echo(
            f"{p.id:24s} v{manifest_version:12s} {p.status.value:14s} "
            f"enabled={str(p.enabled).lower()} source={p.source} requested=[{caps}]"
        )


@plugin_app.command("inspect")
def plugin_inspect(plugin_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    """Show one discovered plugin without executing it."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry

    plugin = get_registry().get(plugin_id)
    if plugin is None:
        typer.echo(f"Plugin {plugin_id!r} was not found", err=True)
        raise typer.Exit(1)
    info = _plugin_diagnostic(plugin)
    if json_output:
        typer.echo(json.dumps(info, indent=2))
    else:
        for key, value in info.items():
            typer.echo(f"{key}: {value}")


@plugin_app.command("check")
def plugin_check(plugin_id: str) -> None:
    """Validate a discovered plugin manifest and compatibility."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry

    plugin = get_registry().get(plugin_id)
    if plugin is None:
        typer.echo(f"Plugin {plugin_id!r} was not found", err=True)
        raise typer.Exit(1)
    if plugin.error:
        typer.echo(plugin.error)
    elif plugin.manifest is not None:
        typer.echo(f"OK: {plugin.id} v{plugin.manifest.version}")
    if not plugin.compatible:
        raise typer.Exit(1)


@plugin_app.command("enable")
def plugin_enable(plugin_id: str) -> None:
    """Enable a compatible plugin for the next ArborPress server startup."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry
    from arborpress.plugins.state import PluginStateStore

    plugin = get_registry().get(plugin_id)
    if plugin is None or plugin.manifest is None or not plugin.compatible:
        typer.echo("Plugin is missing, invalid, or incompatible", err=True)
        raise typer.Exit(1)
    store = PluginStateStore(get_runtime_paths().data / "plugin-state.toml")
    store.set_enabled(plugin_id, True)
    _audit_plugin_admin("plugin_enabled", plugin_id)
    typer.echo(f"Enabled {plugin_id}; CLI activation applies on next server start.")


@plugin_app.command("disable")
def plugin_disable(plugin_id: str) -> None:
    """Disable a plugin for the next server startup."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry
    from arborpress.plugins.state import PluginStateStore

    if get_registry().get(plugin_id) is None:
        typer.echo(f"Plugin {plugin_id!r} was not found", err=True)
        raise typer.Exit(1)
    PluginStateStore(get_runtime_paths().data / "plugin-state.toml").set_enabled(plugin_id, False)
    _audit_plugin_admin("plugin_disabled", plugin_id)
    typer.echo(f"Disabled {plugin_id}; CLI shutdown applies on next server start.")


@plugin_app.command("validate")
def plugin_validate(path: Path = typer.Argument(..., help="Path to plugin directory")) -> None:  # noqa: B008
    """Validate a plugin.toml without importing plugin code."""
    from arborpress.plugins.manifest import PluginManifest

    try:
        manifest = PluginManifest.from_file(path / "plugin.toml")
        if manifest.id != path.name:
            raise ValueError("manifest id must match directory basename")
        typer.echo(
            f"OK: {manifest.id} v{manifest.version}; requested={manifest.requested_capabilities}"
        )
    except Exception as exc:
        typer.echo(f"Invalid plugin manifest: {type(exc).__name__}", err=True)
        raise typer.Exit(1) from exc


@plugin_app.command("install")
def plugin_install(bundle: Path = typer.Argument(..., help="Local plugin ZIP bundle")) -> None:  # noqa: B008
    """Install a validated local bundle; installation stays disabled."""
    from arborpress.plugins.lifecycle import PluginLifecycle, PluginLifecycleError

    try:
        installed = PluginLifecycle().install(bundle)
    except PluginLifecycleError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    _audit_plugin_admin(
        "plugin_installed", installed.manifest.id, detail="local bundle installed disabled"
    )
    typer.echo(
        f"Installed {installed.manifest.id} v{installed.manifest.version}; disabled by default."
    )
    typer.echo(f"Requested capabilities: {', '.join(installed.manifest.requested_capabilities)}")


@plugin_app.command("update")
def plugin_update(
    plugin_id: str,
    bundle: Path = typer.Argument(..., help="Local plugin ZIP bundle"),  # noqa: B008
) -> None:
    """Stage and atomically update a plugin from a local ZIP bundle."""
    from arborpress.plugins.lifecycle import PluginLifecycle, PluginLifecycleError

    try:
        updated = PluginLifecycle().update(plugin_id, bundle)
    except PluginLifecycleError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    _audit_plugin_admin(
        "plugin_updated",
        plugin_id,
        detail=(
            "local bundle updated; added="
            + ",".join(updated.added_capabilities)
            + "; removed="
            + ",".join(updated.removed_capabilities)
        ),
    )
    typer.echo(f"Updated {plugin_id} to v{updated.manifest.version}.")
    if updated.added_capabilities:
        typer.echo(
            "New requested capabilities remain ungranted: " + ", ".join(updated.added_capabilities)
        )
    if updated.removed_capabilities:
        typer.echo("No longer requested: " + ", ".join(updated.removed_capabilities))


@plugin_app.command("uninstall")
def plugin_uninstall(plugin_id: str) -> None:
    """Remove the package/runtime while preserving plugin data."""
    from arborpress.plugins.lifecycle import PluginLifecycle, PluginLifecycleError

    try:
        PluginLifecycle().uninstall(plugin_id)
    except PluginLifecycleError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    _audit_plugin_admin(
        "plugin_uninstalled", plugin_id, detail="package/runtime removed; data kept"
    )
    typer.echo(f"Uninstalled {plugin_id}; persistent plugin data was preserved.")


@plugin_app.command("purge")
def plugin_purge(
    plugin_id: str,
    yes: bool = typer.Option(False, "--yes", help="Confirm permanent plugin data deletion"),  # noqa: B008
) -> None:
    """Uninstall and permanently remove this plugin's persistent data."""
    if not yes and not typer.confirm(f"Permanently delete all data for {plugin_id!r}?"):
        raise typer.Abort()
    from arborpress.plugins.lifecycle import PluginLifecycle, PluginLifecycleError

    try:
        PluginLifecycle().uninstall(plugin_id, purge=True)
    except PluginLifecycleError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    _audit_plugin_admin("plugin_purged", plugin_id, detail="package/runtime/data purged")
    typer.echo(f"Uninstalled and purged plugin {plugin_id}.")


@plugin_runtime_app.command("create")
def plugin_runtime_create(plugin_id: str) -> None:
    """Create an empty isolated interpreter without installing dependencies."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry

    plugin = get_registry().get(plugin_id)
    if plugin is None or plugin.manifest is None or not plugin.compatible:
        typer.echo("Plugin is missing, invalid, or incompatible", err=True)
        raise typer.Exit(1)
    runtime_root = get_runtime_paths().plugin_runtime
    plugin_runtime = runtime_root / plugin_id
    plugin_runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    if plugin_runtime.resolve().parent != runtime_root.resolve():
        typer.echo("Plugin runtime path escapes the instance runtime root", err=True)
        raise typer.Exit(1)
    target = plugin_runtime / "venv"
    if target.exists() or target.is_symlink():
        typer.echo(f"Plugin runtime already exists: {target}", err=True)
        raise typer.Exit(1)
    venv.EnvBuilder(with_pip=False, clear=False).create(target)
    typer.echo(
        f"Created isolated interpreter at {target}; no dependencies were downloaded or installed."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _db_upgrade() -> None:
    from arborpress.core.migrations import upgrade_database

    await _run_db_migration_operation(upgrade_database)


async def _run_db_migration_operation[T](
    operation: Callable[..., Awaitable[T]], *args: object
) -> T:
    """Run a one-shot DB CLI operation and close its async engine cleanly."""
    from arborpress.core.db import create_engine_for_cli

    engine = create_engine_for_cli()
    try:
        return await operation(*args, engine=engine)
    finally:
        await engine.dispose()


async def _seed(*, force: bool = False) -> dict[str, int]:
    from arborpress.core.db import get_db_session
    from arborpress.core.seed import seed_database

    async for session in get_db_session():
        return await seed_database(session, force=force)
    return {}


def _bootstrap_plugins() -> None:
    from arborpress.plugins.registry import discover_instance_plugins

    discover_instance_plugins(get_settings().plugin_dirs())


def _plugin_diagnostic(plugin: Any) -> dict[str, Any]:
    manifest = plugin.manifest
    from arborpress.plugins.capabilities import CapabilityGrantStore
    from arborpress.runtime.paths import get_runtime_paths

    grants = CapabilityGrantStore(get_runtime_paths().data / "plugin-grants.toml")
    granted = sorted(grants.grants_for(plugin.id))
    return {
        "id": plugin.id,
        "name": plugin.name,
        "version": manifest.version if manifest else None,
        "source": plugin.source,
        "status": plugin.status.value,
        "error": plugin.error,
        "enabled": plugin.enabled,
        "managed_install": plugin.managed_install,
        "package_integrity": plugin.package_integrity,
        "runtime_status": plugin.runtime_status.value,
        "pid": plugin.pid,
        "restart_count": plugin.restart_count,
        "hardening": list(plugin.hardening),
        "pending_jobs": plugin.pending_jobs,
        "dead_jobs": plugin.dead_jobs,
        "exit_status": plugin.exit_status,
        "last_error": plugin.last_error,
        "interpreter": plugin.interpreter,
        "requested_capabilities": list(plugin.capabilities),
        "granted_capabilities": granted,
        "missing_required_capabilities": list(plugin.missing_required_capabilities),
    }


def _audit_plugin_admin(
    event_type: str, plugin_id: str, *, detail: str = "plugin state changed"
) -> None:
    from arborpress.core.audit import write_audit_event
    from arborpress.logging.config import setup_logging

    setup_logging(get_settings().logging)
    asyncio.run(
        write_audit_event(
            event_type=event_type,
            outcome="success",
            actor_id="cli",
            actor_name="cli",
            target_id=plugin_id,
            detail=detail,
        )
    )


# ---------------------------------------------------------------------------
# WebAuthn recovery (RP-ID lock)
# ---------------------------------------------------------------------------


@webauthn_app.command("status")
def webauthn_status() -> None:
    """Show resolved RP ID, locked value, and credential count."""
    import asyncio

    from arborpress.auth.webauthn import (
        resolve_origin,
        resolve_rp_id,
        resolve_rp_name,
    )
    from arborpress.core.config import get_settings as _gs
    from arborpress.core.db import get_db_session as _gds
    from arborpress.core.site_settings import get_webauthn_settings

    cfg = _gs()
    rp_id = resolve_rp_id(cfg.web.base_url)
    origin = resolve_origin(cfg.web.base_url)

    async def _run():
        from sqlalchemy import func, select

        from arborpress.models.user import WebAuthnCredential

        async for db in _gds():
            wa = await get_webauthn_settings(db)
            count = (
                await db.execute(select(func.count()).select_from(WebAuthnCredential))
            ).scalar_one() or 0
            rp_name = await resolve_rp_name(db)
            return wa, count, rp_name

    wa, count, rp_name = asyncio.run(_run())
    typer.echo(f"resolved rp.id   : {rp_id}")
    typer.echo(f"resolved origin  : {origin}")
    typer.echo(f"resolved rp.name : {rp_name}")
    typer.echo(f"locked rp.id     : {wa.get('rp_id_last_known') or '-'}")
    typer.echo(f"rp_id_locked     : {wa.get('rp_id_locked')}")
    typer.echo(f"credentials in DB: {count}")


@webauthn_app.command("unlock-rp-id")
def webauthn_cli_unlock(
    confirm: str = typer.Option(..., "--confirm", help="Must equal the new resolved rp.id."),
) -> None:
    """Operator escape hatch: confirm an RP-ID change from the shell.

    Use when no admin can log in because their passkeys were invalidated
    by a domain change (W3C WebAuthn L3 §5.3).
    """
    import asyncio

    from arborpress.auth.webauthn import resolve_rp_id
    from arborpress.core.config import get_settings as _gs
    from arborpress.core.db import get_db_session as _gds
    from arborpress.core.site_settings import (
        get_webauthn_settings,
        save_section,
    )

    cfg = _gs()
    resolved = resolve_rp_id(cfg.web.base_url)

    if confirm != resolved:
        typer.echo(
            f"ERROR: --confirm {confirm!r} does not match the current resolved rp.id {resolved!r}.",
            err=True,
        )
        raise typer.Exit(1)

    async def _run():
        async for db in _gds():
            wa = await get_webauthn_settings(db)
            old = wa.get("rp_id_last_known", "")
            wa["rp_id_last_known"] = resolved
            wa["rp_id_locked"] = True
            await save_section("webauthn", wa, db, updated_by="cli:webauthn-unlock")
            return old

    old = asyncio.run(_run())
    typer.echo(f"OK - rp.id unlocked: {old or '(unset)'} -> {resolved}")
    typer.echo(
        "Existing WebAuthn credentials are no longer valid for this rp.id "
        "and should be removed manually."
    )


if __name__ == "__main__":
    app()
