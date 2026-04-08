# ArborPress

Sicherheitsfokussierte Blogging-Plattform und Mini-CMS.

## Kern-Prinzipien (§17 Design Summary)

- **WebAuthn/FIDO2-first** – Legacy-Passwort nur als Break-Glass-Option (§2)
- **Saubere Identitätstrennung** – PUBLIC-Konten (föderiert) vs. OPERATIONAL-Konten (Admin, nie föderiert) (§4)
- **Stabiles URL-Schema** – Slugs kanonisiert, Medienpfade unveränderlich, Kurz-IDs für ActivityPub (§6)
- **Minimaler Core, Erweiterungen über Plugins** – deklarierte Capabilities, kein Auto-Update (§15)
- **Keine externen Abhängigkeiten zur Laufzeit** – kein CDN, keine Remote-HTML-Includes (§10)
- **ActivityPub-Optional** – Federation per Konfiguration ein-/ausschaltbar (§5)
- **PostgreSQL ≥ 16 oder MariaDB ≥ 11** – Runtime-Capability-Detection für FTS (§12)

## Schnellstart (Entwicklung)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Konfiguration
cp config/config.example.toml config/config.toml
# Datenbankverbindung + Geheimnisse in config/config.toml eintragen

# DB-Schema anlegen
arborpress db migrate

# Dev-Server starten
arborpress serve --dev

# Vollständige CLI-Hilfe
arborpress --help
```

## Verzeichnisstruktur

```
arborpress/               Python-Paket (Backend)
  core/                   Konfiguration, Events, DB-Session, Capability-Detection
  auth/                   WebAuthn, Session, Break-Glass, MFA (TOTP/Backup), Step-up
  models/                 SQLAlchemy-ORM: User, Content, Mail
  plugins/                Plugin-Registry und Manifest-Validierung
  mail/                   SMTP-Backend + Async-Queue (§13)
  themes/                 Theme-Manifest-Schema (§9)
  logging/                Logging-Konfiguration (stdout/file)
  web/                    Quart-App, Routen, Middleware
    routes/               public, auth, admin, federation, sso, api
    security.py           CSP + Security-Headers Middleware
    app.py                App-Factory (create_app)
  cli/                    Typer-CLI (§14 alle Admin-Befehle)
content/                  Betreiber-Inhalte  (≡ wp-content)
  plugins/                Manuell installierte Plugins
  themes/                 Eigene Themes
config/                   Konfigurationsverzeichnis
  config.example.toml     Beispielkonfiguration (→ config/config.toml kopieren)
container/                Container-Dateien (OCI – Docker/Podman)
  Containerfile.ubuntu    Produktions-Image auf Ubuntu 24.04 LTS
  entrypoint.sh           Container-Entrypoint
  compose.postgresql.yml  Compose: UBI9 + PostgreSQL (RHEL9-Images)
  compose.postgresql.ubuntu.yml  Compose: Ubuntu + PostgreSQL
  compose.mariadb.yml     Compose: UBI9 + MariaDB (RHEL9-Images)
  compose.mariadb.ubuntu.yml     Compose: Ubuntu + MariaDB
docs/                     Proxy-Konfigurationen + Spezifikation (§0–§17)
frontend/                 SvelteKit-Frontend (Build-Zeit, §9)
tests/                    Automatisierte Tests
```

## CLI-Referenz (§14)

```
arborpress init                      Ersteinrichtung / DB-Schema

arborpress serve                     Produktionsserver (Hypercorn)
arborpress serve --dev               Dev-Server mit Reload

arborpress healthcheck               DB-Verbindung + Capabilities prüfen

arborpress db migrate                DB-Schema erstellen / aktualisieren
arborpress db capabilities           Erkannte DB-Features anzeigen

arborpress user add <name>           Benutzer anlegen
arborpress user disable <name>       Benutzer deaktivieren
arborpress user roles <name> <role>  Rolle ändern (Step-up)
arborpress user auth-policy          Auth-Policy anzeigen

arborpress key generate <id>         Ed25519-Schlüsselpaar erstellen
arborpress key import <file>         Schlüssel importieren (RSA ≥ 4096)
arborpress key rotate <id>           Schlüssel rotieren (Step-up)
arborpress key status                Schlüsselstatus anzeigen

arborpress search reindex            FTS-Index neu aufbauen (§12)

arborpress cache purge               Cache leeren
arborpress cache warm                Cache aufwärmen

arborpress federation inbox-process  ActivityPub-Inbox verarbeiten (§5)
arborpress federation status         Federation-Konfiguration anzeigen

arborpress mail process              Mail-Queue einmalig verarbeiten
arborpress mail process --interval 30  Mail-Queue-Worker (Daemon)
arborpress mail status               Mail-Konfiguration anzeigen

arborpress plugin list               Geladene Plugins anzeigen
arborpress plugin validate <pfad>    Plugin-Manifest prüfen
```

## API-Übersicht (§8)

| Methode | Pfad                          | Beschreibung                 |
|---------|-------------------------------|------------------------------|
| GET     | `/api/v1/posts`               | Post-Liste (paginiert)        |
| GET     | `/api/v1/posts/<slug>`        | Einzelner Post               |
| GET     | `/api/v1/pages/<slug>`        | Statische Seite              |
| GET     | `/api/v1/tags`                | Tag-Liste                    |
| GET     | `/api/v1/users/<handle>`      | Öffentliches Profil          |
| GET     | `/api/v1/search?q=`           | Volltext-Suche               |
| —       | —                             | —                            |
| GET     | `/api/v1/admin/posts`         | Admin: alle Posts            |
| POST    | `/api/v1/admin/posts`         | Admin: Post erstellen        |
| PUT     | `/api/v1/admin/posts/<slug>`  | Admin: Post bearbeiten       |
| DELETE  | `/api/v1/admin/posts/<slug>`  | Admin: Post löschen          |
| POST    | `/api/v1/admin/users/<n>/roles` | Admin: Rolle setzen (Step-up) |

## Plugin-Installation (§15)

Plugins werden ausschließlich manuell installiert – kein automatisches Update:

```bash
# 1. Plugin-Verzeichnis in config/config.toml eintragen:
[plugins]
dirs = ["content/plugins/mein-plugin"]

# 2. Manifest prüfen
arborpress plugin validate /pfad/zum/plugin

# 3. Aktive Plugins anzeigen
arborpress plugin list
```

## Authentifizierung (§2 / §3)

| Methode              | Beschreibung                          |
|----------------------|---------------------------------------|
| WebAuthn/FIDO2       | Primär; UV global konfigurierbar      |
| Passkey              | Cloud-Sync-Keys (optional)            |
| TOTP (SHA-256, 8 Zif.) | 2FA-Zusatz (§3)                    |
| Backup-Codes         | Einmalige Notfall-Codes (§3)          |
| Break-Glass Passwort | Argon2id, explizit aktiviert (§2)     |
| Step-up / Sudo-Mode  | Für Admin-Aktionen re-auth (§2)       |
| SSO/OIDC             | Optional, konfigurierbar (§11)        |

## Logging (§16)

Standard: stdout/stderr (Container- und systemd-kompatibel).

```toml
[logging]
level      = "INFO"
# file     = "/var/log/arborpress/app.log"
access_log = false
audit_log  = true
# audit_file = "/var/log/arborpress/audit.log"
```

Audit-Log: Nur relevante Ereignisse, minimale sensitive Daten (§16 no sensitive data in logs).

## Stack (Anhang A)

| Komponente     | Technologie                                      |
|----------------|--------------------------------------------------|
| Backend        | Python 3.10+, Quart (ASGI), Hypercorn            |
| Datenbank      | PostgreSQL ≥ 16 / MariaDB ≥ 11                   |
| ORM            | SQLAlchemy 2.0 async + asyncpg / aiomysql        |
| Auth           | webauthn ≥ 2, argon2-cffi, pyotp                 |
| Federation     | httpx (ActivityPub-HTTP-Sig), bleach             |
| Mail           | aiosmtplib, cryptography (OpenPGP)               |
| CLI            | Typer ≥ 0.12                                     |
| Frontend       | SvelteKit + @simplewebauthn/browser              |
| Config         | pydantic-settings v2, TOML                       |
