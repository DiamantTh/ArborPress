# ArborPress

Security-focused blogging platform and mini-CMS.

> German documentation: [README.de.md](README.de.md)

## Core Principles (§17 Design Summary)

- **WebAuthn/FIDO2-first** – Legacy password only as break-glass option (§2)
- **Clean identity separation** – PUBLIC accounts (federated) vs. OPERATIONAL accounts (admin, never federated) (§4)
- **Stable URL scheme** – Slugs canonicalized, media paths immutable, short IDs for ActivityPub (§6)
- **Minimal core, extensions via plugins** – declared capabilities, no auto-update (§15)
- **No external runtime dependencies** – no CDN, no remote HTML includes (§10)
- **ActivityPub-optional** – federation toggled per configuration (§5)
- **PostgreSQL ≥ 16 or MariaDB ≥ 11** – runtime capability detection for FTS (§12)

## Quick Start (Development)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Configuration
cp config/config.example.toml config/config.toml
# Fill in database connection + secrets in config/config.toml

# Create DB schema
arborpress db migrate

# Start dev server
arborpress serve --dev

# Full CLI help
arborpress --help
```

## Directory Structure

```
arborpress/               Python package (backend)
  core/                   Configuration, events, DB session, capability detection
  auth/                   WebAuthn, session, break-glass, MFA (TOTP/backup), step-up
  models/                 SQLAlchemy ORM: User, Content, Mail
  plugins/                Plugin registry and manifest validation
  mail/                   SMTP backend + async queue (§13)
  themes/                 Theme manifest schema (§9)
  logging/                Logging configuration (stdout/file)
  web/                    Quart app, routes, middleware
    routes/               public, auth, admin, federation, sso, api
    security.py           CSP + security headers middleware
    app.py                App factory (create_app)
  cli/                    Typer CLI (§14 all admin commands)
content/                  Operator content (≡ wp-content)
  plugins/                Manually installed plugins
  themes/                 Custom themes
config/                   Configuration directory
  config.example.toml     Example configuration (→ copy to config/config.toml)
container/                Container files (OCI – Docker/Podman)
  Containerfile.ubuntu    Production image on Ubuntu 24.04 LTS
  entrypoint.sh           Container entrypoint
  compose.postgresql.yml  Compose: UBI9 + PostgreSQL (RHEL9 images)
  compose.postgresql.ubuntu.yml  Compose: Ubuntu + PostgreSQL
  compose.mariadb.yml     Compose: UBI9 + MariaDB (RHEL9 images)
  compose.mariadb.ubuntu.yml     Compose: Ubuntu + MariaDB
docs/                     Proxy configurations + specification (§0–§17)
frontend/                 SvelteKit frontend (build-time, §9)
tests/                    Automated tests
```

## CLI Reference (§14)

```
arborpress init                      Initial setup / DB schema

arborpress serve                     Production server (Hypercorn)
arborpress serve --dev               Dev server with reload

arborpress healthcheck               Check DB connection + capabilities

arborpress db migrate                Create / update DB schema
arborpress db capabilities           Show detected DB features

arborpress user add <name>           Create user
arborpress user disable <name>       Disable user
arborpress user roles <name> <role>  Change role (step-up)
arborpress user auth-policy          Show auth policy

arborpress key generate <id>         Create Ed25519 key pair
arborpress key import <file>         Import key (RSA ≥ 4096)
arborpress key rotate <id>           Rotate key (step-up)
arborpress key status                Show key status

arborpress search reindex            Rebuild FTS index (§12)

arborpress cache purge               Clear cache
arborpress cache warm                Warm cache

arborpress federation inbox-process  Process ActivityPub inbox (§5)
arborpress federation status         Show federation configuration

arborpress mail process              Process mail queue once
arborpress mail process --interval 30  Mail queue worker (daemon)
arborpress mail status               Show mail configuration

arborpress plugin list               Show loaded plugins
arborpress plugin validate <path>    Validate plugin manifest
```

## API Overview (§8)

| Method | Path                          | Description                    |
|--------|-------------------------------|--------------------------------|
| GET    | `/api/v1/posts`               | Post list (paginated)          |
| GET    | `/api/v1/posts/<slug>`        | Single post                    |
| GET    | `/api/v1/pages/<slug>`        | Static page                    |
| GET    | `/api/v1/tags`                | Tag list                       |
| GET    | `/api/v1/users/<handle>`      | Public profile                 |
| GET    | `/api/v1/search?q=`           | Full-text search               |
| —      | —                             | —                              |
| GET    | `/api/v1/admin/posts`         | Admin: all posts               |
| POST   | `/api/v1/admin/posts`         | Admin: create post             |
| PUT    | `/api/v1/admin/posts/<slug>`  | Admin: edit post               |
| DELETE | `/api/v1/admin/posts/<slug>`  | Admin: delete post             |
| POST   | `/api/v1/admin/users/<n>/roles` | Admin: set role (step-up)    |

## Plugin Installation (§15)

Plugins are installed manually only – no automatic updates:

```bash
# 1. Add plugin directory in config/config.toml:
[plugins]
dirs = ["content/plugins/my-plugin"]

# 2. Validate manifest
arborpress plugin validate /path/to/plugin

# 3. Show active plugins
arborpress plugin list
```

## Authentication (§2 / §3)

| Method               | Description                            |
|----------------------|----------------------------------------|
| WebAuthn/FIDO2       | Primary; UV globally configurable      |
| Passkey              | Cloud-sync keys (optional)             |
| TOTP (SHA-256, 8 dig.) | 2FA add-on (§3)                      |
| Backup codes         | Single-use emergency codes (§3)        |
| Break-glass password | Argon2id, explicitly enabled (§2)      |
| Step-up / sudo mode  | Re-auth for admin actions (§2)         |
| SSO/OIDC             | Optional, configurable (§11)           |

## Logging (§16)

Default: stdout/stderr (container- and systemd-compatible).

```toml
[logging]
level      = "INFO"
# file     = "/var/log/arborpress/app.log"
access_log = false
audit_log  = true
# audit_file = "/var/log/arborpress/audit.log"
```

Audit log: only relevant events, minimal sensitive data (§16 no sensitive data in logs).

## Stack (Appendix A)

| Component      | Technology                                       |
|----------------|--------------------------------------------------|
| Backend        | Python 3.10+, Quart (ASGI), Hypercorn            |
| Database       | PostgreSQL ≥ 16 / MariaDB ≥ 11                   |
| ORM            | SQLAlchemy 2.0 async + asyncpg / aiomysql        |
| Auth           | webauthn ≥ 2, argon2-cffi, pyotp                 |
| Federation     | httpx (ActivityPub HTTP-Sig), bleach             |
| Mail           | aiosmtplib, cryptography (OpenPGP)               |
| CLI            | Typer ≥ 0.12                                     |
| Frontend       | SvelteKit + @simplewebauthn/browser              |
| Config         | pydantic-settings v2, TOML                       |
