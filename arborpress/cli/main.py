"""ArborPress CLI – Admin Focus (§14, WP-CLI/occ-style).

Rules (§14 / CLI design rules):
- Commands use the same core services as the web app
- Plugins can register additional CLI commands via declared capabilities

Usage:  arborpress --help
"""

from __future__ import annotations

import asyncio
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from arborpress.core.config import Settings, get_settings

if TYPE_CHECKING:
    from cryptography.fernet import Fernet

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
mail_app = typer.Typer(help="Mail queue (§13)", no_args_is_help=True)
plugin_app = typer.Typer(help="Plugin management (§15)", no_args_is_help=True)

app.add_typer(db_app, name="db")
app.add_typer(user_app, name="user")
user_app.add_typer(mfa_app, name="mfa")
app.add_typer(key_app, name="key")
app.add_typer(search_app, name="search")
app.add_typer(cache_app, name="cache")
app.add_typer(federation_app, name="federation")
app.add_typer(mail_app, name="mail")
app.add_typer(plugin_app, name="plugin")


# ---------------------------------------------------------------------------
# Callback – globale Optionen
# ---------------------------------------------------------------------------


@app.callback()
def main_callback(
    config: Path | None = typer.Option(  # noqa: B008
        None, "--config", "-c",
        help="Path to config.toml or a config/ directory",
    ),
) -> None:
    """Shared entry point. Loads configuration."""
    if config:
        import arborpress.core.config as config_mod
        config_mod._settings = Settings.from_path(config)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# §14 install / init
# ---------------------------------------------------------------------------


@app.command("init")
def init(
    force: bool = typer.Option(
        False, "--force", help="Overwrite an already initialised instance"
    ),
    seed: bool = typer.Option(
        True, "--seed/--no-seed",
        help="Insert sample content (posts, pages, imprint, privacy policy)",
    ),
) -> None:
    """Initialises a new ArborPress instance (§14 install/init).

    Sample content is inserted by default (use --no-seed to disable).
    """
    typer.echo("Creating DB schema …")
    asyncio.run(_db_create_all())
    if seed:
        typer.echo("Inserting sample content …")
        asyncio.run(_seed(force=force))
    typer.echo("\n✓ ArborPress initialised.")
    typer.echo("  Next step: arborpress user add")
    typer.echo("  Server starten:   arborpress serve --dev")


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
    typer.echo(f"Starting ArborPress on {hcfg.bind[0]}")
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
            typer.echo(f"DB: {caps.engine_name} {caps.version_string}")
            typer.echo(f"FTS: {caps.fts_provider}")
            typer.echo("Status: OK")
        except Exception as exc:
            typer.echo(f"DB error: {exc}", err=True)
            raise typer.Exit(1) from exc

    asyncio.run(_check())


# ---------------------------------------------------------------------------
# §14 db: migrate
# ---------------------------------------------------------------------------


@db_app.command("migrate")
def db_migrate() -> None:
    """Creates / updates the database schema (§14 migrate)."""
    import arborpress.models  # noqa: F401 – register models
    typer.echo("Creating tables …")
    asyncio.run(_db_create_all())
    typer.echo("Done.")


@db_app.command("seed")
def db_seed(
    force: bool = typer.Option(False, "--force", help="Overwrite existing seed data"),
) -> None:
    """Inserts sample content, imprint and privacy policy (§14)."""
    typer.echo("Inserting seed data …")
    result = asyncio.run(_seed(force=force))
    typer.echo(f"  Posts inserted:  {result.get('posts', 0)}")
    typer.echo(f"  Pages inserted:  {result.get('pages', 0)}")
    typer.echo(f"  Tags inserted:   {result.get('tags', 0)}")
    typer.echo("Done.")


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
        typer.echo(f"Invalid role: {role}. Allowed: {[r.value for r in UserRole]}", err=True)
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
            typer.echo(f"User created: {username!r} [{account_type.value}/{role_enum.value}]")
            typer.echo(f"  ID: {user.id}")
            typer.echo("  Next step: arborpress user mfa add" + " " + username)

    asyncio.run(_create())


@user_app.command("disable")
def user_disable(
    username: str = typer.Argument(..., help="Username"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Disables a user (§14 user management)."""
    if not yes:
        confirmed = typer.confirm(f"Really disable user {username!r}?")
        if not confirmed:
            raise typer.Exit(0)

    async def _disable() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import User
        async for db in get_db_session():
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            user.is_active = False
            db.add(user)
            await db.commit()
            typer.echo(f"User {username!r} disabled.")

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
                typer.echo(f"User {username!r} unlocked (lock removed, failed_login_count reset).")
            else:
                typer.echo(f"User {username!r}: no active lock, failed_login_count reset to 0.")

    asyncio.run(_unlock())


@user_app.command("roles")
def user_roles(
    username: str = typer.Argument(..., help="Username"),
    role: str = typer.Argument(..., help="New role"),
) -> None:
    """Changes a user's role – requires step-up (§2, §14)."""
    from arborpress.auth.stepup import STEPUP_REQUIRED_OPERATIONS
    from arborpress.models.user import UserRole

    try:
        role_enum = UserRole(role)
    except ValueError:
        typer.echo(f"Invalid role: {role}. Allowed: {[r.value for r in UserRole]}", err=True)
        raise typer.Exit(1) from None

    typer.echo(
        f"NOTE: 'change_roles' is a step-up operation ({STEPUP_REQUIRED_OPERATIONS})."
    )

    async def _set_role() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import User
        async for db in get_db_session():
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            old_role = user.role.value
            user.role = role_enum
            db.add(user)
            await db.commit()
            typer.echo(f"Role: {old_role} → {role_enum.value} for {username!r}")

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
                typer.echo("No users found.")
                return
            typer.echo(f"{'Username':<20} {'Role':<14} {'Type':<14} {'Active':<6} {'Email'}")
            typer.echo("-" * 80)
            for u in users:
                pw_warn = " ⚠ PW active" if u.legacy_password_enabled else ""
                typer.echo(
                    f"{u.username:<20} {u.role.value:<14} {u.account_type.value:<14} "
                    f"{'yes' if u.is_active else 'no':<6} {u.email or ''}{pw_warn}"
                )

    asyncio.run(_list())


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
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
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
    password: str = typer.Option(
        ..., prompt=True, hide_input=True, confirmation_prompt=True,
        help="New break-glass password",
    ),
) -> None:
    """Sets or changes the break-glass password of an account."""
    async def _set_pw() -> None:
        from sqlalchemy import func, select

        from arborpress.auth.breakglass import hash_password
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User

        async for db in get_db_session():
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            user.legacy_password_hash = hash_password(password)
            user.legacy_password_enabled = True
            db.add(user)
            await db.commit()
            typer.echo(f"Password for {username!r} set and activated.")

    asyncio.run(_set_pw())


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
            f"Really disable password for {username!r}? "
            "Make sure WebAuthn/MFA is set up."
        )
        if not confirmed:
            raise typer.Exit(0)

    async def _disable_pw() -> None:
        from sqlalchemy import func, select

        from arborpress.core.db import get_db_session
        from arborpress.models.user import User
        async for db in get_db_session():
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            if not user.legacy_password_enabled:
                typer.echo(f"Password for {username!r} is already disabled.")
                return
            # Check for at least 1 credential/MFA
            await db.refresh(user, ["credentials", "mfa_devices"])
            if not user.credentials and not user.mfa_devices:
                typer.echo(
                    "ERROR: No WebAuthn credential and no MFA device found.\n"
                    "  Set up WebAuthn or TOTP first before disabling the password.",
                    err=True,
                )
                raise typer.Exit(1)
            user.legacy_password_enabled = False
            user.legacy_password_hash = None
            db.add(user)
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
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
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
                typer.echo(
                    "Actor key:          NOT PRESENT"
                    " – run: arborpress federation keygen"
                )

    asyncio.run(_show())


@user_app.command("auth-policy")
def auth_policy_status(
    username: str | None = typer.Argument(None, help="User (empty = global)"),
) -> None:
    """Shows auth policy status (§2, §14 auth policy status)."""
    cfg = get_settings()
    typer.echo(f"UV global:              {cfg.auth.require_uv}")
    typer.echo(f"Legacy-PW global:       {cfg.auth.legacy_password_enabled}")
    typer.echo(f"Step-up TTL:            {cfg.auth.stepup_ttl}s")
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

        from arborpress.auth.mfa import MFA_MAX_DEVICES
        from arborpress.core.db import get_db_session
        from arborpress.models.user import MFADevice, User
        async for db in get_db_session():
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
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
            typer.echo(f"MFA devices ({len(devices)}/{MFA_MAX_DEVICES}):")
            typer.echo(f"  {'Label':<30} {'Type':<8} {'Active':<6} {'Last used'}")
            typer.echo("  " + "-" * 70)
            for d in devices:
                typer.echo(
                    f"  {d.label:<30} {d.device_type.value:<8} "
                    f"{'yes' if d.is_active else 'no':<6} "
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
    from arborpress.auth.mfa import MFA_MAX_DEVICES, HOTPService, TOTPService
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
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"User {username!r} not found.", err=True)
                raise typer.Exit(1)
            # Check limit
            count_result = await db.execute(
                select(func.count()).select_from(MFADevice).where(MFADevice.user_id == str(user.id))
            )
            count = count_result.scalar_one()
            if count >= MFA_MAX_DEVICES:
                typer.echo(
                    f"ERROR: Maximum of {MFA_MAX_DEVICES} MFA devices reached.", err=True
                )
                raise typer.Exit(1)

            if dtype == MFADeviceType.TOTP:
                svc = TOTPService()
                secret = svc.generate_secret()
                uri = svc.provisioning_uri(secret, account_name=f"{username}:{label}")
            else:
                svc = HOTPService()  # type: ignore[assignment]
                secret = svc.generate_secret()
                uri = svc.provisioning_uri(secret, account_name=f"{username}:{label}")

            cfg = get_settings()
            # Simple encryption via Fernet (secret key from config)
            import base64
            import hashlib

            from cryptography.fernet import Fernet
            key = base64.urlsafe_b64encode(
                hashlib.sha256(cfg.web.secret_key.get_secret_value().encode()).digest()
            )
            f = Fernet(key)
            secret_enc = f.encrypt(secret)

            device = MFADevice(
                user_id=str(user.id),
                device_type=dtype,
                label=label,
                secret_enc=secret_enc,
            )
            db.add(device)
            await db.commit()

            typer.echo(f"MFA device {label!r} ({dtype.value}) created.")
            typer.echo(f"Provisioning-URI:\n  {uri}")
            typer.echo("Scan the QR code with your authenticator app.")

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

        from arborpress.core.db import get_db_session
        from arborpress.models.user import MFADevice, User
        async for db in get_db_session():
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
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
            await db.delete(device)
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
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
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
                    typer.echo(
                        "Instance key pair: NOT PRESENT"
                        " – run: arborpress federation keygen"
                    )

                # ---- Actor keys (all accounts) ----
                rows = (await db.execute(
                    select(ActorKeypair, User.username)
                    .join(User, User.id == ActorKeypair.user_id)
                    .order_by(User.username)
                )).all()
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
                pgp_count = (await db.execute(
                    select(func.count()).select_from(UserPGPKey)
                )).scalar_one()
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
            kp = (await db.execute(
                select(ActorKeypair).where(ActorKeypair.user_id == str(user_row.id))
            )).scalar_one_or_none()
            typer.echo("\nActor key (HTTP signatures):")
            if kp:
                typer.echo(f"  Algorithm: {kp.algorithm}")
                typer.echo(f"  Key-ID:    {kp.key_id_url}")
                typer.echo(f"  Created:   {kp.created_at.date()}"
                           f" ({(now - kp.created_at).days} days old)")
                if kp.rotated_at:
                    typer.echo(f"  Rotated:   {kp.rotated_at.date()}")
            else:
                typer.echo("  NOT PRESENT")

            # OpenPGP keys
            pgp_rows = (await db.execute(
                select(UserPGPKey)
                .where(UserPGPKey.user_id == str(user_row.id))
                .order_by(UserPGPKey.is_primary_signing.desc(), UserPGPKey.created_at)
            )).scalars().all()
            typer.echo(f"\nOpenPGP keys ({len(pgp_rows)}):")
            if pgp_rows:
                typer.echo(
                    f"  {'Label':<20} {'Fingerprint':<42}"
                    f" {'Sign':<5} {'Enc':<5} {'Prim':<5} Expiry"
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
    """Processes ActivityPub inbox items (§5, §14 federation inbox processing)."""
    async def _process() -> None:
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        async for db in get_db_session():
            fed = await get_section("federation", db)
        if fed.get("mode", "disabled") in ("disabled", "outgoing_only"):
            mode = fed.get("mode", "disabled")
            typer.echo(f"Federation mode is {mode!r} – no inbox.", err=True)
            raise typer.Exit(1)
        typer.echo(f"Processing {batch} inbox items (TODO).")

    asyncio.run(_process())


@federation_app.command("status")
def federation_status() -> None:
    """Shows federation configuration and instance key status from the DB (§5)."""
    async def _show() -> None:
        from sqlalchemy import select

        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        from arborpress.models.user import InstanceKeypair
        async for db in get_db_session():
            fed = await get_section("federation", db)
            ikp_result = await db.execute(select(InstanceKeypair).where(InstanceKeypair.id == 1))
            ikp = ikp_result.scalar_one_or_none()
        typer.echo(f"Mode:                       {fed.get('mode', 'disabled')}")
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
    force: bool = typer.Option(
        False, "--force", help="Overwrite existing key pair (rotation)"
    ),
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
                public_pem = private_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
                private_raw = private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            else:  # ed25519
                priv = ed25519.Ed25519PrivateKey.generate()
                public_pem = priv.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
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
                db.add(InstanceKeypair(
                    id=1,
                    key_id_url=key_id_url,
                    public_key_pem=public_pem,
                    private_key_enc=enc,
                    algorithm=algorithm,
                ))
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
            result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
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


# ---------------------------------------------------------------------------
# §15 plugin: list / validate
# ---------------------------------------------------------------------------


@plugin_app.command("list")
def plugin_list() -> None:
    """Shows all loaded plugins (§15)."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry

    plugins = get_registry().all()
    if not plugins:
        typer.echo("No plugins loaded.")
        return
    for p in plugins:
        caps = ", ".join(c.value for c in p.capabilities)
        typer.echo(f"  {p.id:30s} v{p.manifest.plugin.version:10s} [{caps}]")


@plugin_app.command("validate")
def plugin_validate(
    path: Path = typer.Argument(..., help="Path to plugin directory"),  # noqa: B008
) -> None:
    """Validates the manifest of a plugin (§15)."""
    from arborpress.plugins.manifest import PluginManifest

    manifest_path = path / "manifest.toml"
    if not manifest_path.exists():
        typer.echo(f"No manifest.toml in {path}", err=True)
        raise typer.Exit(1)

    try:
        m = PluginManifest.from_file(manifest_path)
        missing = m.validate_entry_points()
        if missing:
            typer.echo(f"Missing entry points: {missing}", err=True)
            raise typer.Exit(1)
        typer.echo(
            f"OK – Plugin {m.plugin.id!r} v{m.plugin.version}"
            f" | Capabilities: {[c.value for c in m.plugin.capabilities]}"
        )
    except Exception as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _db_create_all() -> None:
    import arborpress.models  # noqa: F401
    from arborpress.core.db import create_all_tables
    await create_all_tables()


async def _seed(*, force: bool = False) -> dict[str, int]:
    from arborpress.core.db import get_db_session
    from arborpress.core.seed import seed_database
    async for session in get_db_session():
        return await seed_database(session, force=force)
    return {}


def _bootstrap_plugins() -> None:
    cfg = get_settings()
    from arborpress.plugins.registry import get_registry
    reg = get_registry()
    for d in cfg.plugin_dirs():
        reg.load_directory(d)
    _load_plugin_cli_extensions()


def _load_plugin_cli_extensions() -> None:
    """§15 – Plugins can register Typer sub-apps."""
    import importlib

    from arborpress.plugins.registry import get_registry

    for plugin in get_registry().all():
        cli_ep = plugin.manifest.entry_points.cli
        if not cli_ep:
            continue
        try:
            module_path, _, attr = cli_ep.rpartition(":")
            mod = importlib.import_module(module_path)
            plugin_app_obj = getattr(mod, attr)
            app.add_typer(plugin_app_obj, name=plugin.id)
        except Exception as exc:
            typer.echo(
                f"Warning: CLI extension from plugin {plugin.id!r} failed: {exc}",
                err=True,
            )


if __name__ == "__main__":
    app()
