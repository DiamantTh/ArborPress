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
key_app = typer.Typer(help="Schlüsselverwaltung (§13 OpenPGP, §14)")
search_app = typer.Typer(help="Suchindex (§12 FTS)")
cache_app = typer.Typer(help="Cache-Verwaltung")
federation_app = typer.Typer(help="Federation / ActivityPub (§5, §14)")
mail_app = typer.Typer(help="Mail-Queue (§13)")
plugin_app = typer.Typer(help="Plugin-Verwaltung (§15)")

app.add_typer(db_app, name="db")
app.add_typer(user_app, name="user")
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
) -> None:
    """Legt einen neuen Benutzer an (§14 user management)."""
    from arborpress.models.user import AccountType, UserRole

    try:
        role_enum = UserRole(role)
    except ValueError:
        typer.echo(f"Ungültige Rolle: {role}. Erlaubt: {[r.value for r in UserRole]}", err=True)
        raise typer.Exit(1)

    account_type = AccountType.OPERATIONAL if operational else AccountType.PUBLIC
    typer.echo(f"Erstelle Benutzer {username!r} [{account_type.value}/{role_enum.value}] …")
    # TODO: DB-Insert
    typer.echo("Benutzer angelegt (DB-Persistenz TODO).")


@user_app.command("disable")
def user_disable(
    username: str = typer.Argument(..., help="Benutzername"),
) -> None:
    """Deaktiviert einen Benutzer (§14 user management)."""
    typer.echo(f"Deaktiviere {username!r} (TODO).")


@user_app.command("roles")
def user_roles(
    username: str = typer.Argument(..., help="Benutzername"),
    role: str = typer.Argument(..., help="Neue Rolle"),
) -> None:
    """Ändert die Rolle eines Benutzers – erfordert Step-up (§2, §14)."""
    from arborpress.auth.stepup import STEPUP_REQUIRED_OPERATIONS
    typer.echo(
        f"HINWEIS: 'change_roles' ist eine Step-up-Operation ({STEPUP_REQUIRED_OPERATIONS})."
    )
    typer.echo(f"Setze Rolle {role!r} für {username!r} (TODO).")


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
    provider: Optional[str] = typer.Option(None, "--provider", help="Explizit: pg_fts/mariadb_fulltext/fallback"),
) -> None:
    """Baut den Suchindex neu auf (§12 FTS, §14 search reindex)."""
    from arborpress.core.site_settings import get_defaults
    effective = provider or get_defaults("search").get("provider", "fallback")
    typer.echo(f"Reindex mit Provider {effective!r} (TODO).")


# ---------------------------------------------------------------------------
# §14 cache: purge / warm
# ---------------------------------------------------------------------------


@cache_app.command("purge")
def cache_purge() -> None:
    """Leert den Cache (§14 cache purge)."""
    typer.echo("Cache geleert (TODO).")


@cache_app.command("warm")
def cache_warm() -> None:
    """Wärmt den Cache (§14 cache warm)."""
    typer.echo("Cache aufgewärmt (TODO).")


# ---------------------------------------------------------------------------
# §14 federation: inbox-process
# ---------------------------------------------------------------------------


@federation_app.command("inbox-process")
def federation_inbox_process(
    batch: int = typer.Option(50, "--batch", "-n", help="Anzahl Items pro Lauf"),
) -> None:
    """Verarbeitet ActivityPub-Inbox-Items (§5, §14 federation inbox processing)."""
    from arborpress.core.site_settings import get_defaults
    fed = get_defaults("federation")
    if fed.get("mode", "disabled") in ("disabled", "outgoing_only"):
        mode = fed.get("mode", "disabled")
        typer.echo(f"Federation-Modus ist {mode!r} – kein Inbox.", err=True)
        raise typer.Exit(1)
    typer.echo(f"Verarbeite {batch} Inbox-Items (TODO).")


@federation_app.command("status")
def federation_status() -> None:
    """Zeigt Federation-Konfiguration (§5)."""
    from arborpress.core.site_settings import get_defaults
    fed = get_defaults("federation")
    typer.echo(f"Modus:        {fed.get('mode', 'disabled')}")
    typer.echo(f"Instanz:      {fed.get('instance_name', '')}")
    typer.echo(f"Beschreibung: {fed.get('instance_description', '')}")


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
