"""ArborPress CLI – Admin Focus (§14, WP-CLI/occ-style).

Regeln (§14 / CLI design rules):
- Kommandos nutzen dieselben Core-Services wie die Web-App
- Plugins können via deklarierter Capabilities zusätzliche CLI-Kommandos registrieren

Aufruf:  arborpress --help
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer

from arborpress.core.config import get_settings, Settings

# ---------------------------------------------------------------------------
# App-Instanz + Sub-Apps
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="arborpress",
    help="Arbor Press – security-focused blogging platform/mini CMS",
    no_args_is_help=True,
)

db_app = typer.Typer(help="Datenbankoperationen (§12)")
user_app = typer.Typer(help="Benutzerverwaltung (§14)")
mfa_app = typer.Typer(help="MFA-Geräteverwaltung (§3)")
key_app = typer.Typer(help="Schlüsselverwaltung (§13 OpenPGP, §14)")
search_app = typer.Typer(help="Suchindex (§12 FTS)")
cache_app = typer.Typer(help="Cache-Verwaltung")
federation_app = typer.Typer(help="Federation / ActivityPub (§5, §14)")
mail_app = typer.Typer(help="Mail-Queue (§13)")
plugin_app = typer.Typer(help="Plugin-Verwaltung (§15)")

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
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Pfad zur config.toml"
    ),
) -> None:
    """Gemeinsamer Einstiegspunkt. Lädt Konfiguration."""
    if config:
        import arborpress.core.config as config_mod
        config_mod._settings = Settings.from_file(config)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# §14 install / init
# ---------------------------------------------------------------------------


@app.command("init")
def init(
    force: bool = typer.Option(False, "--force", help="Bereits initialisierte Instanz überschreiben"),
    seed:  bool = typer.Option(True,  "--seed/--no-seed", help="Beispielinhalte (Posts, Seiten, Impressum, Datenschutz) einfügen"),
) -> None:
    """Initialisiert eine neue ArborPress-Instanz (§14 install/init).

    Standardmäßig werden Beispielinhalte eingefügt (--no-seed zum Deaktivieren).
    """
    typer.echo("Erstelle DB-Schema …")
    asyncio.run(_db_create_all())
    if seed:
        typer.echo("Füge Beispielinhalte ein …")
        asyncio.run(_seed(force=force))
    typer.echo("\n✓ ArborPress initialisiert.")
    typer.echo("  Nächster Schritt: arborpress user add")
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
    """Startet den ArborPress-Server (Hypercorn/ASGI)."""
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
    typer.echo(f"Starte ArborPress auf {hcfg.bind[0]}")
    asyncio.run(hypercorn.asyncio.serve(quart_app, hcfg))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §14 healthcheck
# ---------------------------------------------------------------------------


@app.command("healthcheck")
def healthcheck() -> None:
    """Prüft DB-Verbindung und Konfiguration (§14)."""
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
            typer.echo(f"DB-Fehler: {exc}", err=True)
            raise typer.Exit(1)

    asyncio.run(_check())


# ---------------------------------------------------------------------------
# §14 db: migrate
# ---------------------------------------------------------------------------


@db_app.command("migrate")
def db_migrate() -> None:
    """Erstellt / aktualisiert das Datenbankschema (§14 migrate)."""
    import arborpress.models  # noqa: F401 – Modelle registrieren
    typer.echo("Erstelle Tabellen …")
    asyncio.run(_db_create_all())
    typer.echo("Fertig.")


@db_app.command("seed")
def db_seed(
    force: bool = typer.Option(False, "--force", help="Vorhandene Seed-Daten überschreiben"),
) -> None:
    """Fügt Beispielinhalte, Impressum und Datenschutz ein (§14)."""
    typer.echo("Füge Seed-Daten ein …")
    result = asyncio.run(_seed(force=force))
    typer.echo(f"  Posts eingefügt:  {result.get('posts', 0)}")
    typer.echo(f"  Seiten eingefügt: {result.get('pages', 0)}")
    typer.echo(f"  Tags eingefügt:   {result.get('tags', 0)}")
    typer.echo("Fertig.")


@db_app.command("capabilities")
def db_capabilities() -> None:
    """Zeigt erkannte DB-Capabilities (§12)."""
    async def _show() -> None:
        from arborpress.core.db import get_engine
        from arborpress.core.db_capabilities import detect_capabilities
        caps = await detect_capabilities(get_engine())
        typer.echo(f"Motor:   {caps.engine_name}")
        typer.echo(f"Version: {caps.version_string}")
        typer.echo(f"FTS:     {caps.fts_available} ({caps.fts_provider})")
        typer.echo(f"JSON:    {caps.json_ops}")
    asyncio.run(_show())


# ---------------------------------------------------------------------------
# §14 user: add / disable / roles
# ---------------------------------------------------------------------------


@user_app.command("add")
def user_add(
    username: str = typer.Argument(..., help="Benutzername"),
    role: str = typer.Option("viewer", "--role", "-r", help="Rolle (admin/editor/author/moderator/viewer)"),
    operational: bool = typer.Option(False, "--operational", help="Operationales Admin-Konto (§4)"),
    email: Optional[str] = typer.Option(None, "--email", "-e"),
    display_name: Optional[str] = typer.Option(None, "--display-name", "-n"),
) -> None:
    """Legt einen neuen Benutzer an (§14 user management)."""
    from arborpress.models.user import AccountType, User, UserRole

    try:
        role_enum = UserRole(role)
    except ValueError:
        typer.echo(f"Ungültige Rolle: {role}. Erlaubt: {[r.value for r in UserRole]}", err=True)
        raise typer.Exit(1)

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
            typer.echo(f"Benutzer angelegt: {username!r} [{account_type.value}/{role_enum.value}]")
            typer.echo(f"  ID: {user.id}")
            typer.echo("  Nächster Schritt: arborpress user mfa add" + " " + username)

    asyncio.run(_create())


@user_app.command("disable")
def user_disable(
    username: str = typer.Argument(..., help="Benutzername"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Bestätigungs-Prompt"),
) -> None:
    """Deaktiviert einen Benutzer (§14 user management)."""
    if not yes:
        confirmed = typer.confirm(f"Benutzer {username!r} wirklich deaktivieren?")
        if not confirmed:
            raise typer.Exit(0)

    async def _disable() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            user.is_active = False
            db.add(user)
            await db.commit()
            typer.echo(f"Benutzer {username!r} deaktiviert.")

    asyncio.run(_disable())


@user_app.command("roles")
def user_roles(
    username: str = typer.Argument(..., help="Benutzername"),
    role: str = typer.Argument(..., help="Neue Rolle"),
) -> None:
    """Ändert die Rolle eines Benutzers – erfordert Step-up (§2, §14)."""
    from arborpress.auth.stepup import STEPUP_REQUIRED_OPERATIONS
    from arborpress.models.user import UserRole

    try:
        role_enum = UserRole(role)
    except ValueError:
        typer.echo(f"Ungültige Rolle: {role}. Erlaubt: {[r.value for r in UserRole]}", err=True)
        raise typer.Exit(1)

    typer.echo(f"HINWEIS: 'change_roles' ist eine Step-up-Operation ({STEPUP_REQUIRED_OPERATIONS}).")

    async def _set_role() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            old_role = user.role.value
            user.role = role_enum
            db.add(user)
            await db.commit()
            typer.echo(f"Rolle: {old_role} → {role_enum.value} für {username!r}")

    asyncio.run(_set_role())


@user_app.command("list")
def user_list(
    inactive: bool = typer.Option(False, "--inactive", help="Auch inaktive Konten anzeigen"),
) -> None:
    """Listet alle Benutzer auf."""
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
                typer.echo("Keine Benutzer gefunden.")
                return
            typer.echo(f"{'Username':<20} {'Rolle':<14} {'Typ':<14} {'Aktiv':<6} {'Email'}")
            typer.echo("-" * 80)
            for u in users:
                pw_warn = " ⚠ PW aktiv" if u.legacy_password_enabled else ""
                typer.echo(
                    f"{u.username:<20} {u.role.value:<14} {u.account_type.value:<14} "
                    f"{'ja' if u.is_active else 'nein':<6} {u.email or ''}{pw_warn}"
                )

    asyncio.run(_list())


@user_app.command("password-status")
def user_password_status(
    username: str = typer.Argument(..., help="Benutzername"),
) -> None:
    """Zeigt Passwort-Status eines Accounts (Warnung wenn aktiv)."""
    async def _check() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            if user.legacy_password_enabled:
                typer.echo(
                    f"WARNUNG: Account {username!r} hat ein aktives Passwort (legacy_password_enabled=True).\n"
                    f"  Das Passwort ist ein Fallback (Break-Glass §2) und sollte deaktiviert werden,\n"
                    f"  sobald WebAuthn/MFA eingerichtet ist.\n"
                    f"  Deaktivieren: arborpress user password-disable {username}"
                )
            else:
                typer.echo(f"Account {username!r}: Passwort deaktiviert (empfohlen).")

    asyncio.run(_check())


@user_app.command("password-disable")
def user_password_disable(
    username: str = typer.Argument(..., help="Benutzername"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Bestätigungs-Prompt"),
) -> None:
    """Deaktiviert das Passwort eines Accounts (§2 Break-Glass).

    Stellt sicher, dass mindestens ein MFA-Gerät oder WebAuthn-Credential
    vorhanden ist, bevor das Passwort deaktiviert wird.
    """
    if not yes:
        confirmed = typer.confirm(
            f"Passwort für {username!r} wirklich deaktivieren? "
            "Stelle sicher, dass WebAuthn/MFA eingerichtet ist."
        )
        if not confirmed:
            raise typer.Exit(0)

    async def _disable_pw() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            if not user.legacy_password_enabled:
                typer.echo(f"Passwort für {username!r} ist bereits deaktiviert.")
                return
            # Mindestens 1 Credential/MFA prüfen
            await db.refresh(user, ["credentials", "mfa_devices"])
            if not user.credentials and not user.mfa_devices:
                typer.echo(
                    "FEHLER: Kein WebAuthn-Credential und kein MFA-Gerät gefunden.\n"
                    "  Richte zuerst WebAuthn oder TOTP ein, bevor das Passwort deaktiviert wird.",
                    err=True,
                )
                raise typer.Exit(1)
            user.legacy_password_enabled = False
            user.legacy_password_hash = None
            db.add(user)
            await db.commit()
            typer.echo(f"Passwort für {username!r} deaktiviert und Hash gelöscht.")

    asyncio.run(_disable_pw())


@user_app.command("federation-status")
def user_federation_status(
    username: str = typer.Argument(..., help="Benutzername"),
) -> None:
    """Zeigt Federation-Status eines Accounts (Opt-out, Schlüsselpaar)."""
    async def _show() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, ActorKeypair
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            typer.echo(f"Account-Typ:      {user.account_type.value}")
            typer.echo(f"Federation Opt-out: {user.federation_opt_out}")
            if user.account_type.value == "operational":
                typer.echo("  OPERATIONAL-Account: kein WebFinger / ActivityPub-Endpunkt")
                return
            key_result = await db.execute(
                select(ActorKeypair).where(ActorKeypair.user_id == str(user.id))
            )
            keypair = key_result.scalar_one_or_none()
            if keypair:
                typer.echo(f"Actor-Schlüssel:  vorhanden ({keypair.algorithm})")
                typer.echo(f"  Key-ID:          {keypair.key_id_url}")
                typer.echo(f"  Erstellt:        {keypair.created_at}")
                if keypair.rotated_at:
                    typer.echo(f"  Zuletzt rotiert: {keypair.rotated_at}")
            else:
                typer.echo("Actor-Schlüssel:  NICHT VORHANDEN – arborpress federation keygen ausführen")

    asyncio.run(_show())


@user_app.command("auth-policy")
def auth_policy_status(
    username: Optional[str] = typer.Argument(None, help="Benutzer (leer = global)"),
) -> None:
    """Zeigt Auth-Policy-Status (§2, §14 auth policy status)."""
    cfg = get_settings()
    typer.echo(f"UV global:              {cfg.auth.require_uv}")
    typer.echo(f"Legacy-PW global:       {cfg.auth.legacy_password_enabled}")
    typer.echo(f"Step-up TTL:            {cfg.auth.stepup_ttl}s")
    typer.echo(f"Admin-Session TTL:      {cfg.auth.admin_session_ttl}s")
    typer.echo(f"Auth Rate-Limit:        {cfg.auth.auth_rate_limit}")


# ---------------------------------------------------------------------------
# §14 user mfa: list / add / remove / rename
# ---------------------------------------------------------------------------


@mfa_app.command("list")
def mfa_list(
    username: str = typer.Argument(..., help="Benutzername"),
) -> None:
    """Listet alle MFA-Geräte eines Benutzers auf."""
    async def _list() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, MFADevice
        from arborpress.auth.mfa import MFA_MAX_DEVICES
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            dev_result = await db.execute(
                select(MFADevice).where(MFADevice.user_id == str(user.id))
            )
            devices = dev_result.scalars().all()
            if not devices:
                typer.echo(f"Keine MFA-Geräte für {username!r}.")
                return
            typer.echo(f"MFA-Geräte ({len(devices)}/{MFA_MAX_DEVICES}):")
            typer.echo(f"  {'Label':<30} {'Typ':<8} {'Aktiv':<6} {'Zuletzt genutzt'}")
            typer.echo("  " + "-" * 70)
            for d in devices:
                typer.echo(
                    f"  {d.label:<30} {d.device_type.value:<8} "
                    f"{'ja' if d.is_active else 'nein':<6} "
                    f"{str(d.last_used_at or 'Nie')}"
                )

    asyncio.run(_list())


@mfa_app.command("add")
def mfa_add(
    username: str = typer.Argument(..., help="Benutzername"),
    label: str = typer.Option(..., "--label", "-l", help="Gerätename (z. B. 'Privat', 'Arbeit')"),
    device_type: str = typer.Option("totp", "--type", "-t", help="Gerätetyp: totp|hotp"),
) -> None:
    """Fügt ein neues TOTP/HOTP-Gerät hinzu und gibt den QR-URI aus."""
    from arborpress.auth.mfa import TOTPService, HOTPService, MFA_MAX_DEVICES
    from arborpress.models.user import MFADeviceType

    try:
        dtype = MFADeviceType(device_type.lower())
    except ValueError:
        typer.echo(f"Ungültiger Typ {device_type!r}. Erlaubt: totp, hotp", err=True)
        raise typer.Exit(1)

    async def _add() -> None:
        from sqlalchemy import select, func
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, MFADevice
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            # Limit prüfen
            count_result = await db.execute(
                select(func.count()).select_from(MFADevice).where(MFADevice.user_id == str(user.id))
            )
            count = count_result.scalar_one()
            if count >= MFA_MAX_DEVICES:
                typer.echo(
                    f"FEHLER: Maximum von {MFA_MAX_DEVICES} MFA-Geräten erreicht.", err=True
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
            # Einfache Verschlüsselung via Fernet (Secret-Key aus config)
            from cryptography.fernet import Fernet
            import base64, hashlib
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

            typer.echo(f"MFA-Gerät {label!r} ({dtype.value}) angelegt.")
            typer.echo(f"Provisioning-URI:\n  {uri}")
            typer.echo("Scanne den QR-Code mit deiner Authenticator-App.")

    asyncio.run(_add())


@mfa_app.command("remove")
def mfa_remove(
    username: str = typer.Argument(..., help="Benutzername"),
    label: str = typer.Argument(..., help="Gerätename"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Entfernt ein MFA-Gerät."""
    if not yes:
        confirmed = typer.confirm(f"MFA-Gerät {label!r} von {username!r} wirklich entfernen?")
        if not confirmed:
            raise typer.Exit(0)

    async def _remove() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, MFADevice
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            dev_result = await db.execute(
                select(MFADevice).where(
                    MFADevice.user_id == str(user.id),
                    MFADevice.label == label,
                )
            )
            device = dev_result.scalar_one_or_none()
            if not device:
                typer.echo(f"Gerät {label!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            await db.delete(device)
            await db.commit()
            typer.echo(f"MFA-Gerät {label!r} entfernt.")

    asyncio.run(_remove())


@mfa_app.command("rename")
def mfa_rename(
    username: str = typer.Argument(..., help="Benutzername"),
    old_label: str = typer.Argument(..., help="Aktueller Gerätename"),
    new_label: str = typer.Argument(..., help="Neuer Gerätename"),
) -> None:
    """Benennt ein MFA-Gerät um."""
    async def _rename() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, MFADevice
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            dev_result = await db.execute(
                select(MFADevice).where(
                    MFADevice.user_id == str(user.id),
                    MFADevice.label == old_label,
                )
            )
            device = dev_result.scalar_one_or_none()
            if not device:
                typer.echo(f"Gerät {old_label!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            device.label = new_label
            db.add(device)
            await db.commit()
            typer.echo(f"MFA-Gerät umbenannt: {old_label!r} → {new_label!r}")

    asyncio.run(_rename())


# ---------------------------------------------------------------------------
# §14 key: generate / import / rotate / status
# ---------------------------------------------------------------------------


@key_app.command("generate")
def key_generate(
    name: str = typer.Argument(..., help="Schlüssel-ID / Name"),
) -> None:
    """Generiert ein neues ECC/Ed25519-Schlüsselpaar (§13, §14)."""
    typer.echo(f"Generiere Ed25519-Schlüssel für {name!r} (TODO).")
    typer.echo("HINWEIS: Private Keys werden verschlüsselt gespeichert (§13).")


@key_app.command("import")
def key_import(
    file: Path = typer.Argument(..., help="Pfad zum Schlüssel (RSA >= 4096 oder ECC)"),
) -> None:
    """Importiert einen bestehenden Schlüssel (§13 RSA-Import)."""
    typer.echo(f"Importiere Schlüssel aus {file} (TODO).")


@key_app.command("rotate")
def key_rotate(
    name: str = typer.Argument(..., help="Schlüssel-ID / Name"),
) -> None:
    """Rotiert einen Schlüssel – Step-up-Operation (§2, §14 key rotation)."""
    from arborpress.auth.stepup import STEPUP_REQUIRED_OPERATIONS
    typer.echo(f"HINWEIS: 'rotate_key' erfordert Step-up (via Web-Admin).")
    typer.echo(f"Rotiere {name!r} (TODO).")


@key_app.command("status")
def key_status() -> None:
    """Zeigt Schlüssel-Status (§13, §14)."""
    typer.echo("Schlüssel-Status (TODO).")


# ---------------------------------------------------------------------------
# §14 search: reindex
# ---------------------------------------------------------------------------


@search_app.command("reindex")
def search_reindex(
    provider: Optional[str] = typer.Option(None, "--provider", help="Explizit: pg_fts/mariadb_fulltext/sqlite_fts5/meilisearch/typesense/elasticsearch/fallback"),
) -> None:
    """Baut den Suchindex neu auf (§12 FTS, §14 search reindex)."""
    from arborpress.core.site_settings import get_defaults
    effective = provider or get_defaults("search").get("provider", "fallback")
    typer.echo(f"Reindex mit Provider {effective!r} (TODO: Provider-spezifische Aktionen).")
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
    """Zeigt Cache-Backend-Status (§14 cache status)."""
    from arborpress.core.cache import cache_backend_info
    info = cache_backend_info()
    typer.echo(f"Cache-Backend: {info}")
    typer.echo(f"Standard-TTL:  {get_settings().cache.ttl}s")


@cache_app.command("purge")
def cache_purge() -> None:
    """Leert den gesamten Cache (§14 cache purge)."""
    from arborpress.core.cache import cache_flush, cache_backend_info
    asyncio.run(cache_flush())
    typer.echo(f"Cache geleert. Backend: {cache_backend_info()}")
    # Auch Site-Settings-Cache leeren
    from arborpress.core.site_settings import invalidate_cache
    invalidate_cache()
    typer.echo("Site-Settings-Cache geleert.")


@cache_app.command("warm")
def cache_warm() -> None:
    """Wärmt wichtige Cache-Einträge vor (§14 cache warm)."""
    async def _warm() -> None:
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        sections = ["general", "theme", "mail", "comments", "captcha", "federation", "search"]
        async for db in get_db_session():
            for sec in sections:
                await get_section(sec, db)
                typer.echo(f"  Warm: site_settings[{sec!r}]")
        typer.echo("Cache aufgewärmt.")

    asyncio.run(_warm())


# ---------------------------------------------------------------------------
# §14 federation: inbox-process
# ---------------------------------------------------------------------------


@federation_app.command("inbox-process")
def federation_inbox_process(
    batch: int = typer.Option(50, "--batch", "-n", help="Anzahl Items pro Lauf"),
) -> None:
    """Verarbeitet ActivityPub-Inbox-Items (§5, §14 federation inbox processing)."""
    async def _process() -> None:
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        async for db in get_db_session():
            fed = await get_section("federation", db)
        if fed.get("mode", "disabled") in ("disabled", "outgoing_only"):
            mode = fed.get("mode", "disabled")
            typer.echo(f"Federation-Modus ist {mode!r} – kein Inbox.", err=True)
            raise typer.Exit(1)
        typer.echo(f"Verarbeite {batch} Inbox-Items (TODO).")

    asyncio.run(_process())


@federation_app.command("status")
def federation_status() -> None:
    """Zeigt Federation-Konfiguration und Instanzschlüssel-Status aus der DB (§5)."""
    async def _show() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        from arborpress.models.user import InstanceKeypair
        async for db in get_db_session():
            fed = await get_section("federation", db)
            ikp_result = await db.execute(select(InstanceKeypair).where(InstanceKeypair.id == 1))
            ikp = ikp_result.scalar_one_or_none()
        typer.echo(f"Modus:                      {fed.get('mode', 'disabled')}")
        typer.echo(f"Instanz:                    {fed.get('instance_name', '')}")
        typer.echo(f"Beschreibung:               {fed.get('instance_description', '') or '—'}")
        typer.echo(f"Kontakt-E-Mail:             {fed.get('contact_email', '') or '—'}")
        typer.echo(f"HTTP-Signatur required:     {fed.get('require_http_signature', True)}")
        typer.echo(f"Authorized Fetch:           {fed.get('authorized_fetch', False)}")
        typer.echo(f"Follow-Bestätigung:         {fed.get('require_approval_to_follow', False)}")
        typer.echo(f"Follower-Liste öffentlich:  {fed.get('followers_visible', True)}")
        typer.echo(f"Following-Liste öffentlich: {fed.get('following_visible', True)}")
        typer.echo(f"Tags federieren:            {fed.get('federate_tags', True)}")
        typer.echo(f"Medien federieren:          {fed.get('federate_media', False)}")
        typer.echo(f"Max Notiz-Länge:            {fed.get('max_note_length', 500)}")
        blocked = fed.get("inbox_blocklist_domains", [])
        typer.echo(f"Blocklisted Domains:        {len(blocked)} Einträge")
        typer.echo("")
        if ikp:
            typer.echo(f"Instanzschlüssel:           {ikp.algorithm}  {ikp.key_id_url}")
            typer.echo(f"  erstellt:                 {ikp.created_at}")
            typer.echo(f"  rotiert:                  {ikp.rotated_at or '—'}")
        else:
            typer.echo("Instanzschlüssel:           KEINER  → arborpress federation keygen")
        cfg = get_settings()
        kek_ok = cfg.auth.actor_key_enc_key is not None
        typer.echo(f"Actor-KEK konfiguriert:     {'ja ✓' if kek_ok else 'NEIN ✗  → arborpress federation kek-init'}")

    asyncio.run(_show())


@federation_app.command("kek-init")
def federation_kek_init() -> None:
    """Generiert einen neuen Actor-Key-Encryption-Key (KEK) und gibt ihn aus.

    Den Wert in config.toml unter [auth] actor_key_enc_key eintragen.
    Danach vorhandene Schlüsselpaare mit --force neu verschlüsseln.
    """
    import base64, os
    kek = base64.urlsafe_b64encode(os.urandom(32)).decode()
    typer.echo("Neuer Actor-KEK generiert:")
    typer.echo(f"\n  {kek}\n")
    typer.echo("In config.toml eintragen:")
    typer.echo(f"  [auth]")
    typer.echo(f'  actor_key_enc_key = "{kek}"')
    typer.echo("\nDen Key sicher aufbewahren – Verlust macht alle Actor-Keypairs unbrauchbar.")


def _get_actor_fernet() -> "Fernet":  # type: ignore[name-defined]
    """Gibt das Fernet-Objekt mit dem Actor-KEK zurück.

    Bricht ab, wenn kein KEK konfiguriert ist.
    """
    from cryptography.fernet import Fernet
    cfg = get_settings()
    kek = cfg.auth.actor_key_enc_key
    if kek is None:
        typer.echo(
            "FEHLER: auth.actor_key_enc_key ist nicht gesetzt.\n"
            "  Generieren: arborpress federation kek-init\n"
            "  Dann in config.toml [auth] actor_key_enc_key = \"...\" eintragen.",
            err=True,
        )
        raise typer.Exit(1)
    return Fernet(kek.get_secret_value().encode())


@federation_app.command("keygen")
def federation_keygen(
    algorithm: str = typer.Option("ed25519", "--algo", help="ed25519 (Standard) | rsa-sha256 (Legacy)"),
    force: bool = typer.Option(False, "--force", help="Bestehendes Schlüsselpaar überschreiben (Rotation)"),
) -> None:
    """Generiert das Instanz-Schlüsselpaar für HTTP-Signatures (§5).

    Die Instanz selbst ist der primäre ActivityPub-Actor.
    Standard: Ed25519. RSA-SHA256 nur für sehr alte Software nötig.
    Prerequisite: auth.actor_key_enc_key in config.toml (arborpress federation kek-init).
    Per-Account-Schlüssel: arborpress federation user-keygen <user>
    """
    if algorithm not in ("rsa-sha256", "ed25519"):
        typer.echo("Ungültiger Algorithmus. Erlaubt: ed25519, rsa-sha256", err=True)
        raise typer.Exit(1)

    fernet = _get_actor_fernet()

    async def _gen() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import InstanceKeypair
        from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
        from cryptography.hazmat.primitives import serialization
        from datetime import datetime, timezone

        async for db in get_db_session():
            existing = await db.execute(select(InstanceKeypair).where(InstanceKeypair.id == 1))
            ikp = existing.scalar_one_or_none()
            if ikp and not force:
                typer.echo(
                    f"Instanzschlüssel bereits vorhanden (algo={ikp.algorithm}).\n"
                    "  Nutze --force zur Rotation."
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
                ikp.rotated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.add(ikp)
                action = "rotiert"
            else:
                db.add(InstanceKeypair(
                    id=1,
                    key_id_url=key_id_url,
                    public_key_pem=public_pem,
                    private_key_enc=enc,
                    algorithm=algorithm,
                ))
                action = "erstellt"
            await db.commit()
            typer.echo(f"Instanzschlüssel {action}: {key_id_url} ({algorithm})")
            typer.echo("Backup: arborpress federation key-export")

    asyncio.run(_gen())


@federation_app.command("user-keygen")
def federation_user_keygen(
    username: str = typer.Argument(..., help="Benutzername"),
    algorithm: str = typer.Option("ed25519", "--algo", help="ed25519 (Standard) | rsa-sha256 (Legacy)"),
    force: bool = typer.Option(False, "--force", help="Bestehendes Schlüsselpaar überschreiben (Rotation)"),
) -> None:
    """Generiert ein per-Account-Schlüsselpaar (nur wenn allow_per_account_federation aktiv).

    Für die meisten ArborPress-Installationen reicht arborpress federation keygen.
    """
    if algorithm not in ("rsa-sha256", "ed25519"):
        typer.echo("Ungültiger Algorithmus. Erlaubt: ed25519, rsa-sha256", err=True)
        raise typer.Exit(1)

    fernet = _get_actor_fernet()

    async def _gen() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.core.site_settings import get_section
        from arborpress.models.user import User, ActorKeypair, AccountType
        from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
        from cryptography.hazmat.primitives import serialization
        from datetime import datetime, timezone

        async for db in get_db_session():
            fed = await get_section("federation", db)
            if not fed.get("allow_per_account_federation", True):
                typer.echo(
                    "FEHLER: allow_per_account_federation ist deaktiviert.\n"
                    "  Admin-UI → Einstellungen → Federation → 'Per-Account-Federation erlauben'.",
                    err=True,
                )
                raise typer.Exit(1)

            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            if user.account_type == AccountType.OPERATIONAL:
                typer.echo(
                    "FEHLER: OPERATIONAL-Accounts erhalten kein Actor-Schlüsselpaar (§4).",
                    err=True,
                )
                raise typer.Exit(1)

            existing = await db.execute(
                select(ActorKeypair).where(ActorKeypair.user_id == str(user.id))
            )
            kp = existing.scalar_one_or_none()
            if kp and not force:
                typer.echo(
                    f"Schlüsselpaar bereits vorhanden (algo={kp.algorithm}).\n"
                    "  Nutze --force zur Rotation."
                )
                return

            cfg = get_settings()
            base = cfg.web.base_url.rstrip("/")
            key_id_url = f"{base}/ap/actor/{username}#main-key"

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
            else:
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

            if kp:
                kp.algorithm = algorithm
                kp.key_id_url = key_id_url
                kp.public_key_pem = public_pem
                kp.private_key_enc = enc
                kp.rotated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                db.add(kp)
                action = "rotiert"
            else:
                db.add(ActorKeypair(
                    user_id=str(user.id),
                    key_id_url=key_id_url,
                    public_key_pem=public_pem,
                    private_key_enc=enc,
                    algorithm=algorithm,
                ))
                action = "erstellt"
            await db.commit()
            typer.echo(f"User-Actor-Schlüsselpaar {action}: {key_id_url} ({algorithm})")
            typer.echo("Backup: arborpress federation key-export --user " + username)

    asyncio.run(_gen())


@federation_app.command("key-export")
def federation_key_export(
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Benutzername für per-Account-Schlüssel (Standard: Instanzschlüssel)"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Zieldatei (Standard: stdout)"),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Optionales Passwort für zusätzliche PEM-Verschlüsselung der Exportdatei",
    ),
) -> None:
    """Exportiert das Instanz- oder Account-Keypair als PEM für Backups.

    Ohne --user: Instanzschlüssel (Normalfall).
    Mit --user <name>: per-Account-Schlüssel (allow_per_account_federation).
    Mit --password: privater Schlüssel zusätzlich AES-256-verschlüsselt.
    """
    fernet = _get_actor_fernet()

    async def _export() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, ActorKeypair, InstanceKeypair
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        async for db in get_db_session():
            if user:
                result = await db.execute(select(User).where(User.username == user))
                u = result.scalar_one_or_none()
                if not u:
                    typer.echo(f"Benutzer {user!r} nicht gefunden.", err=True)
                    raise typer.Exit(1)
                kp_result = await db.execute(
                    select(ActorKeypair).where(ActorKeypair.user_id == str(u.id))
                )
                kp = kp_result.scalar_one_or_none()
                if not kp:
                    typer.echo(f"Kein per-Account-Keypair für {user!r}. Erstellen: arborpress federation user-keygen {user}", err=True)
                    raise typer.Exit(1)
                label = f"User: {user}"
                algorithm = kp.algorithm
                key_id_url = kp.key_id_url
                created_at = kp.created_at
                rotated_at = kp.rotated_at
                private_key_enc = kp.private_key_enc
                public_key_pem = kp.public_key_pem
            else:
                ikp_result = await db.execute(select(InstanceKeypair).where(InstanceKeypair.id == 1))
                ikp = ikp_result.scalar_one_or_none()
                if not ikp:
                    typer.echo("Kein Instanzschlüssel vorhanden. Erstellen: arborpress federation keygen", err=True)
                    raise typer.Exit(1)
                label = "Instanz"
                algorithm = ikp.algorithm
                key_id_url = ikp.key_id_url
                created_at = ikp.created_at
                rotated_at = ikp.rotated_at
                private_key_enc = ikp.private_key_enc
                public_key_pem = ikp.public_key_pem

            try:
                private_pem = fernet.decrypt(private_key_enc)
            except Exception:
                typer.echo(
                    "FEHLER: Privater Schlüssel konnte nicht entschlüsselt werden.\n"
                    "  Ist actor_key_enc_key korrekt?",
                    err=True,
                )
                raise typer.Exit(1)

            if password:
                priv_key = serialization.load_pem_private_key(
                    private_pem, password=None, backend=default_backend()
                )
                private_pem = priv_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(password.encode()),
                )

            export_lines = [
                "# ArborPress Actor-Keypair Export",
                f"# {label}",
                f"# Algorithm: {algorithm}",
                f"# Key-ID:    {key_id_url}",
                f"# Created:   {created_at}",
                f"# Rotated:   {rotated_at or '—'}",
                f"# Password-protected: {'yes' if password else 'no'}",
                "",
                "# PUBLIC KEY",
                public_key_pem.strip(),
                "",
                "# PRIVATE KEY",
                private_pem.decode() if isinstance(private_pem, bytes) else private_pem,
            ]
            content = "\n".join(export_lines) + "\n"

            if out:
                out.write_text(content, encoding="utf-8")
                typer.echo(f"Keypair exportiert nach: {out}")
            else:
                typer.echo(content)

    asyncio.run(_export())


@federation_app.command("key-import")
def federation_key_import(
    file: Path = typer.Argument(..., help="Exportdatei (aus key-export)"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Benutzername für per-Account-Import (Standard: Instanzschlüssel)"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Passwort falls exportiert mit --password"),
    force: bool = typer.Option(False, "--force", help="Bestehendes Keypair überschreiben"),
) -> None:
    """Importiert ein exportiertes Keypair (Restore aus Backup).

    Ohne --user: Instanzschlüssel (Normalfall).
    Mit --user <name>: per-Account-Schlüssel (allow_per_account_federation).
    """
    if not file.exists():
        typer.echo(f"Datei nicht gefunden: {file}", err=True)
        raise typer.Exit(1)

    fernet = _get_actor_fernet()

    async def _import() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, ActorKeypair, InstanceKeypair
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from datetime import datetime, timezone
        import re

        content = file.read_text(encoding="utf-8")

        pub_match = re.search(
            r"(-----BEGIN (?:PUBLIC KEY|RSA PUBLIC KEY).+?-----END (?:PUBLIC KEY|RSA PUBLIC KEY)-----)",
            content, re.DOTALL,
        )
        priv_match = re.search(
            r"(-----BEGIN (?:ENCRYPTED |)PRIVATE KEY.+?-----END (?:ENCRYPTED |)PRIVATE KEY-----)",
            content, re.DOTALL,
        )
        if not pub_match or not priv_match:
            typer.echo("FEHLER: Datei enthält keinen gültigen PEM-Public- oder Private-Key.", err=True)
            raise typer.Exit(1)

        public_pem = pub_match.group(1).strip()
        private_pem_raw = priv_match.group(1).strip().encode()

        pw_bytes = password.encode() if password else None
        try:
            priv_key = serialization.load_pem_private_key(
                private_pem_raw, password=pw_bytes, backend=default_backend()
            )
            private_pem_clear = priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        except Exception as exc:
            typer.echo(f"FEHLER beim Laden des privaten Schlüssels: {exc}", err=True)
            raise typer.Exit(1)

        from cryptography.hazmat.primitives.asymmetric import ed25519 as ed_mod
        algo = "ed25519" if isinstance(priv_key, ed_mod.Ed25519PrivateKey) else "rsa-sha256"
        enc = fernet.encrypt(private_pem_clear)

        cfg = get_settings()
        base = cfg.web.base_url.rstrip("/")

        async for db in get_db_session():
            if user:
                result = await db.execute(select(User).where(User.username == user))
                u = result.scalar_one_or_none()
                if not u:
                    typer.echo(f"Benutzer {user!r} nicht gefunden.", err=True)
                    raise typer.Exit(1)
                kp_result = await db.execute(
                    select(ActorKeypair).where(ActorKeypair.user_id == str(u.id))
                )
                kp = kp_result.scalar_one_or_none()
                if kp and not force:
                    typer.echo("Bestehendes per-Account-Keypair vorhanden. Nutze --force.", err=True)
                    raise typer.Exit(1)
                key_id_url = f"{base}/ap/actor/{user}#main-key"
                if kp:
                    kp.public_key_pem = public_pem
                    kp.private_key_enc = enc
                    kp.algorithm = algo
                    kp.key_id_url = key_id_url
                    kp.rotated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                    db.add(kp)
                else:
                    db.add(ActorKeypair(
                        user_id=str(u.id),
                        key_id_url=key_id_url,
                        public_key_pem=public_pem,
                        private_key_enc=enc,
                        algorithm=algo,
                    ))
                await db.commit()
                typer.echo(f"per-Account-Keypair importiert: {user} ({algo})")
            else:
                ikp_result = await db.execute(select(InstanceKeypair).where(InstanceKeypair.id == 1))
                ikp = ikp_result.scalar_one_or_none()
                if ikp and not force:
                    typer.echo("Bestehendes Instanzschlüssel vorhanden. Nutze --force.", err=True)
                    raise typer.Exit(1)
                key_id_url = f"{base}/ap/actor#main-key"
                if ikp:
                    ikp.public_key_pem = public_pem
                    ikp.private_key_enc = enc
                    ikp.algorithm = algo
                    ikp.key_id_url = key_id_url
                    ikp.rotated_at = datetime.now(timezone.utc).replace(tzinfo=None)
                    db.add(ikp)
                else:
                    db.add(InstanceKeypair(
                        id=1,
                        key_id_url=key_id_url,
                        public_key_pem=public_pem,
                        private_key_enc=enc,
                        algorithm=algo,
                    ))
                await db.commit()
                typer.echo(f"Instanzschlüssel importiert ({algo})")

    asyncio.run(_import())


@federation_app.command("follower-list")
def federation_follower_list(
    username: str = typer.Argument(..., help="Benutzername"),
    direction: str = typer.Option("inbound", "--direction", "-d", help="inbound|outbound"),
) -> None:
    """Listet Follower (inbound) oder Following (outbound) eines Accounts."""
    async def _list() -> None:
        from sqlalchemy import select
        from arborpress.core.db import get_db_session
        from arborpress.models.user import User, Follower, FollowerDirection
        try:
            dir_enum = FollowerDirection(direction)
        except ValueError:
            typer.echo("Ungültige Richtung. Erlaubt: inbound, outbound", err=True)
            raise typer.Exit(1)
        async for db in get_db_session():
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            if not user:
                typer.echo(f"Benutzer {username!r} nicht gefunden.", err=True)
                raise typer.Exit(1)
            foll_result = await db.execute(
                select(Follower).where(
                    Follower.local_user_id == str(user.id),
                    Follower.direction == dir_enum,
                )
            )
            followers = foll_result.scalars().all()
            label = "Follower" if dir_enum == FollowerDirection.INBOUND else "Following"
            typer.echo(f"{label} von {username!r}: {len(followers)}")
            if not followers:
                return
            typer.echo(f"  {'Status':<12} {'Anzeigename':<30} URI")
            typer.echo("  " + "-" * 80)
            for fol in followers:
                typer.echo(
                    f"  {fol.state.value:<12} {(fol.remote_display_name or ''):<30} {fol.remote_actor_uri}"
                )


# ---------------------------------------------------------------------------
# §13 mail: queue
# ---------------------------------------------------------------------------


@mail_app.command("process")
def mail_process(
    once: bool = typer.Option(False, "--once", help="Nur einmalig verarbeiten"),
    interval: int = typer.Option(30, "--interval", "-i", help="Worker-Intervall in Sekunden"),
) -> None:
    """Verarbeitet die Mail-Warteschlange (§13)."""
    from arborpress.mail.queue import process_queue, run_queue_worker

    if once:
        sent = asyncio.run(process_queue())
        typer.echo(f"Gesendet: {sent}")
    else:
        typer.echo(f"Starte Mail-Queue-Worker (Intervall: {interval}s) …")
        asyncio.run(run_queue_worker(interval=interval))


@mail_app.command("status")
def mail_status() -> None:
    """Zeigt Mail-Konfiguration und Queue-Status (§13)."""
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
    """Zeigt alle geladenen Plugins (§15)."""
    _bootstrap_plugins()
    from arborpress.plugins.registry import get_registry

    plugins = get_registry().all()
    if not plugins:
        typer.echo("Keine Plugins geladen.")
        return
    for p in plugins:
        caps = ", ".join(c.value for c in p.capabilities)
        typer.echo(f"  {p.id:30s} v{p.manifest.plugin.version:10s} [{caps}]")


@plugin_app.command("validate")
def plugin_validate(
    path: Path = typer.Argument(..., help="Pfad zum Plugin-Verzeichnis"),
) -> None:
    """Validiert das Manifest eines Plugins (§15)."""
    from arborpress.plugins.manifest import PluginManifest

    manifest_path = path / "manifest.toml"
    if not manifest_path.exists():
        typer.echo(f"Kein manifest.toml in {path}", err=True)
        raise typer.Exit(1)

    try:
        m = PluginManifest.from_file(manifest_path)
        missing = m.validate_entry_points()
        if missing:
            typer.echo(f"Fehlende Entry-Points: {missing}", err=True)
            raise typer.Exit(1)
        typer.echo(
            f"OK – Plugin {m.plugin.id!r} v{m.plugin.version}"
            f" | Capabilities: {[c.value for c in m.plugin.capabilities]}"
        )
    except Exception as exc:
        typer.echo(f"Fehler: {exc}", err=True)
        raise typer.Exit(1)


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
    for d in cfg.plugins.dirs:
        reg.load_directory(d)
    _load_plugin_cli_extensions()


def _load_plugin_cli_extensions() -> None:
    """§15 – Plugins können Typer-Sub-Apps registrieren."""
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
                f"Warnung: CLI-Erweiterung von Plugin {plugin.id!r} fehlgeschlagen: {exc}",
                err=True,
            )


if __name__ == "__main__":
    app()
