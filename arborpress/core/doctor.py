"""Read-only operational diagnostics for operators and the admin status page.

The doctor reports bounded, non-secret facts. It deliberately does not probe
or repair state by changing it; migrations, backup verification and restore
remain explicit operator actions.
"""

from __future__ import annotations

import asyncio
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from sqlalchemy import func, select

from arborpress import BUILD_SHA
from arborpress.core.config import get_settings
from arborpress.runtime.paths import get_runtime_paths

DoctorLevel = Literal["ok", "warning", "blocker"]
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    key: str
    level: DoctorLevel
    status: str
    message: str


def _check(
    checks: list[DoctorCheck],
    key: str,
    condition: bool,
    message: str,
    *,
    production: bool = False,
    production_blocker: bool = False,
    warning: bool = False,
) -> None:
    if condition:
        level: DoctorLevel = "ok"
    elif production_blocker:
        level = "blocker" if production else "warning"
    else:
        level = "warning" if warning else "blocker"
    checks.append(DoctorCheck(key, level, "ok" if condition else "failed", message))


def _safe_origin(value: str) -> tuple[bool, str]:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        safe = (
            parsed.scheme in {"http", "https"}
            and bool(host)
            and parsed.username is None
            and parsed.password is None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )
        return safe, parsed.scheme
    except ValueError:
        return False, "invalid"


def _directory_state(path: Path) -> tuple[bool, bool]:
    """Return (exists-and-writable, group-or-world-accessible)."""
    if path.is_symlink():
        return False, True
    try:
        info = path.stat()
    except OSError:
        return False, False
    return (
        stat.S_ISDIR(info.st_mode) and os.access(path, os.W_OK),
        bool(info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)),
    )


async def collect_doctor_report(*, production: bool = False) -> dict[str, object]:
    """Return a JSON-safe report without URLs, secret values, or user data."""
    checks: list[DoctorCheck] = []
    settings = get_settings()
    paths = get_runtime_paths()
    is_sha = bool(_SHA_RE.fullmatch(BUILD_SHA))
    _check(
        checks,
        "build_sha",
        is_sha,
        "Build is identified by a 40-character source commit SHA."
        if is_sha
        else "Build SHA is unavailable; rebuild from a Git checkout for traceable deployment.",
        production=production,
        production_blocker=True,
    )

    parsed_url_ok, scheme = _safe_origin(settings.web.base_url)
    https_origin = parsed_url_ok and scheme == "https"
    _check(
        checks,
        "canonical_origin",
        https_origin if production else parsed_url_ok,
        "Canonical origin is a valid HTTPS origin."
        if https_origin
        else "Production base URL must be a canonical HTTPS origin."
        if production
        else "Base URL is syntactically valid; HTTPS is required before production.",
        production=production,
        production_blocker=True,
    )

    secret = settings.web.secret_key.get_secret_value()
    secret_safe = len(secret) >= 32 and secret not in {
        "CHANGE_ME_IN_PRODUCTION",
        "change-me",
        "secret",
    }
    _check(
        checks,
        "web_secret_key",
        secret_safe,
        "Application secret is configured with sufficient length."
        if secret_safe
        else "Application secret is a development default or is too short.",
        production=production,
        production_blocker=True,
    )

    database_kind = "unknown"
    try:
        from sqlalchemy.engine import make_url

        database_kind = make_url(settings.db.url).get_backend_name()
    except Exception:
        database_kind = "unknown"
    supported_production_db = database_kind in {"postgresql", "mysql"}
    _check(
        checks,
        "database_backend",
        supported_production_db if production else database_kind != "unknown",
        "Supported production database backend is configured."
        if supported_production_db
        else (
            "SQLite is supported for tests, demos, and local development; "
            "production uses PostgreSQL or MariaDB."
        )
        if database_kind == "sqlite"
        else "Database backend could not be identified.",
        production=production,
        production_blocker=True,
    )

    from arborpress.core.migrations import migration_history

    schema_head: str | None = migration_history()[0][0]
    schema_state = "unavailable"
    engine = None
    database_version: str | None = None
    try:
        from arborpress.core.db import get_engine
        from arborpress.core.migrations import schema_status

        engine = get_engine()
        schema = await asyncio.wait_for(schema_status(engine), timeout=5.0)
        schema_state = schema.state
        schema_head = schema.head_revision
        current = schema.is_current
        message = (
            "Database schema matches the packaged Alembic head."
            if current
            else f"Database schema is not ready ({schema.state})."
        )
        _check(checks, "database_schema", current, message)
        if current:
            from sqlalchemy import text

            version_query = {
                "postgresql": "SELECT version()",
                "mysql": "SELECT VERSION()",
                "sqlite": "SELECT sqlite_version()",
            }.get(database_kind)
            if version_query:
                async with engine.connect() as connection:
                    database_version = str(
                        await asyncio.wait_for(
                            connection.scalar(text(version_query)), timeout=2.0
                        )
                    )
        db_version_supported = False
        if database_kind == "postgresql" and database_version:
            match = re.search(r"PostgreSQL\s+(\d+)", database_version)
            db_version_supported = bool(match and int(match.group(1)) >= 16)
        elif database_kind == "mysql" and database_version and "MariaDB" in database_version:
            match = re.search(r"(\d+)\.(\d+)\.\d+-MariaDB", database_version)
            db_version_supported = bool(
                match
                and tuple(map(int, match.groups())) >= (11, 4)
            )
        _check(
            checks,
            "database_version",
            db_version_supported if production else database_version is not None,
            "Database server meets the supported production baseline."
            if db_version_supported
            else "Production supports PostgreSQL 16+ and MariaDB 11.4+; MySQL is not supported."
            if production
            else (
                "Database server version could not be read or is below the production baseline."
                if production or database_kind in {"postgresql", "mysql"}
                else "SQLite version is available for development and test use."
            ),
            production=production,
            production_blocker=True,
        )
    except Exception as exc:
        _check(
            checks,
            "database_schema",
            False,
            f"Database/schema check failed ({type(exc).__name__}).",
        )

    marker_paths = (paths.run / "restore-maintenance.json", paths.run / "restore-journal.json")
    maintenance = any(path.exists() or path.is_symlink() for path in marker_paths)
    _check(
        checks,
        "restore_maintenance",
        not maintenance,
        "No interrupted restore or maintenance marker is present."
        if not maintenance
        else "Restore recovery is required before serving traffic.",
    )
    from arborpress.core.config import is_installed

    installed = is_installed()
    _check(
        checks,
        "installation",
        installed,
        "Initial installation is complete."
        if installed
        else "Initial installation has not been completed.",
        production=production,
        production_blocker=True,
    )

    required_dirs = {
        "instance": paths.instance,
        "config": paths.config,
        "data": paths.data,
        "run": paths.run,
        "temporary": paths.tmp,
        "backups": paths.backups,
    }
    unsafe_dirs: list[str] = []
    missing_dirs: list[str] = []
    for label, directory in required_dirs.items():
        usable, accessible = _directory_state(directory)
        if not usable:
            missing_dirs.append(label)
        if label in {"instance", "config", "data", "run", "backups"} and accessible:
            unsafe_dirs.append(label)
    paths_ok = not missing_dirs and not unsafe_dirs
    _check(
        checks,
        "runtime_paths",
        paths_ok,
        "Required runtime directories are writable and sensitive roots are private."
        if paths_ok
        else "Runtime directory permissions/existence need attention."
        + (f" Unavailable: {', '.join(missing_dirs)}." if missing_dirs else "")
        + (f" Too broadly accessible: {', '.join(unsafe_dirs)}." if unsafe_dirs else ""),
        production=production,
        production_blocker=True,
    )

    cache_required = bool(settings.cache.required)
    try:
        from arborpress.core.cache import cache_backend_info, cache_health

        cache_ok, _cache_detail = await asyncio.wait_for(cache_health(read_only=True), timeout=1.5)
        cache_name = cache_backend_info()
        _check(
            checks,
            "cache",
            cache_ok,
            f"Cache backend {cache_name} is reachable."
            if cache_ok
            else f"Cache backend {cache_name} is degraded; core reads must continue without it.",
            production=production,
            production_blocker=cache_required,
            warning=not cache_required,
        )
    except Exception as exc:
        _check(
            checks,
            "cache",
            False,
            f"Cache diagnostics unavailable ({type(exc).__name__}).",
            production=production,
            production_blocker=cache_required,
            warning=not cache_required,
        )

    site: dict[str, dict[str, object]] = {}
    try:
        if engine is not None and schema_state == "current":
            from sqlalchemy.ext.asyncio import async_sessionmaker

            from arborpress.core.site_settings import get_section_uncached

            factory = async_sessionmaker(engine, expire_on_commit=False)
            async with factory() as db:
                for section in ("search", "mail", "federation", "webauthn"):
                    site[section] = await get_section_uncached(section, db)
    except Exception as exc:
        checks.append(
            DoctorCheck(
                "site_settings",
                "warning",
                "unavailable",
                f"Optional settings diagnostics unavailable ({type(exc).__name__}).",
            )
        )

    search = site.get("search", {})
    try:
        from arborpress.core.search import search_health

        if engine is not None and schema_state == "current":
            search_status = await asyncio.wait_for(
                search_health(engine, str(search.get("provider", "auto"))), timeout=2.0
            )
            search_required = bool(search.get("required", False))
            _check(
                checks,
                "search",
                bool(search_status.get("healthy")),
                "Search is "
                f"{('healthy' if search_status.get('healthy') else 'degraded')}; "
                f"provider requirement is {'required' if search_required else 'optional'}.",
                production=production,
                production_blocker=search_required,
                warning=not search_required,
            )
    except Exception as exc:
        _check(
            checks,
            "search",
            False,
            f"Search diagnostics unavailable ({type(exc).__name__}).",
            production=production,
            production_blocker=bool(search.get("required", False)),
            warning=not bool(search.get("required", False)),
        )

    if engine is not None and schema_state == "current":
        from arborpress.models.federation import FederationInstanceIdentity, LocalFederationActor
        from arborpress.models.mail import SMTPProfile
        from arborpress.models.oidc import OIDCProvider, OIDCServerSettings, OIDCSigningKey
        from arborpress.models.user import WebAuthnCredential

        try:
            from sqlalchemy.ext.asyncio import async_sessionmaker

            factory = async_sessionmaker(engine, expire_on_commit=False)
            async with factory() as db:
                enabled_providers = int(
                    await db.scalar(
                        select(func.count()).select_from(OIDCProvider).where(OIDCProvider.enabled)
                    )
                    or 0
                )
                unhealthy_providers = int(
                    await db.scalar(
                        select(func.count())
                        .select_from(OIDCProvider)
                        .where(
                            OIDCProvider.enabled,
                            (OIDCProvider.discovery_status != "ok")
                            | (OIDCProvider.jwks_status != "ok"),
                        )
                    )
                    or 0
                )
                checks.append(
                    DoctorCheck(
                        "oidc_relying_party",
                        "warning" if unhealthy_providers else "ok",
                        "degraded" if unhealthy_providers else "ok",
                        f"{enabled_providers} enabled provider(s); "
                        f"{unhealthy_providers} need a discovery/JWKS check."
                        if unhealthy_providers
                        else f"{enabled_providers} enabled provider(s); "
                        "no stored provider health errors.",
                    )
                )

                oauth_state = await db.get(OIDCServerSettings, 1)
                current_key_count = int(
                    await db.scalar(
                        select(func.count())
                        .select_from(OIDCSigningKey)
                        .where(OIDCSigningKey.is_current)
                    )
                    or 0
                )
                oauth_enabled = bool(oauth_state and oauth_state.enabled)
                oauth_ok = not oauth_enabled or (
                    current_key_count == 1
                    and oauth_state is not None
                    and oauth_state.issuer == settings.web.base_url.rstrip("/")
                )
                if oauth_enabled and oauth_ok:
                    from cryptography.hazmat.primitives.serialization import load_pem_private_key

                    from arborpress.auth.oauth_server import private_key

                    signing_key = await db.scalar(
                        select(OIDCSigningKey).where(OIDCSigningKey.is_current)
                    )
                    if signing_key is not None:
                        load_pem_private_key(private_key(signing_key), password=None)
                _check(
                    checks,
                    "oauth_oidc_server",
                    oauth_ok,
                    "Authorization server is disabled."
                    if not oauth_enabled
                    else "OIDC server has exactly one current signing key."
                    if oauth_ok
                    else "Enabled OIDC server must have exactly one current signing key.",
                    production=production,
                    production_blocker=True,
                )

                federation_settings = site.get("federation", {})
                federation_enabled = bool(federation_settings.get("enabled", False))
                federation_identity = await db.get(FederationInstanceIdentity, 1)
                local_actors = int(
                    await db.scalar(
                        select(func.count())
                        .select_from(LocalFederationActor)
                        .where(LocalFederationActor.enabled)
                    )
                    or 0
                )
                federation_key = settings.auth.actor_key_enc_key
                federation_ready = not federation_enabled or (
                    bool(federation_key and federation_key.get_secret_value())
                    and federation_identity is not None
                    and federation_identity.canonical_origin == settings.web.base_url.rstrip("/")
                )
                _check(
                    checks,
                    "federation",
                    federation_ready,
                    "Federation is disabled."
                    if not federation_enabled
                    else f"Federation is enabled with {local_actors} active local actor(s)."
                    if federation_ready
                    else "Enabled federation is missing its pinned identity or "
                    "actor-key encryption secret.",
                    production=production,
                    production_blocker=True,
                )

                mail = site.get("mail", {})
                mail_enabled = str(mail.get("backend", "none")) not in {"none", "disabled", ""}
                enabled_mail_profiles = int(
                    await db.scalar(
                        select(func.count()).select_from(SMTPProfile).where(SMTPProfile.enabled)
                    )
                    or 0
                )
                mail_ready = not mail_enabled or enabled_mail_profiles > 0
                _check(
                    checks,
                    "mail",
                    mail_ready,
                    "Mail delivery is disabled."
                    if not mail_enabled
                    else f"Mail delivery has {enabled_mail_profiles} enabled SMTP profile(s)."
                    if mail_ready
                    else "Mail is enabled but no SMTP profile is active.",
                    production=production,
                    production_blocker=True,
                )

                webauthn = site.get("webauthn", {})
                credential_count = int(
                    await db.scalar(select(func.count()).select_from(WebAuthnCredential)) or 0
                )
                from arborpress.auth.webauthn import resolve_rp_id

                rp_id = resolve_rp_id(settings.web.base_url)
                pinned_rp = str(webauthn.get("rp_id_last_known", ""))
                rp_ok = credential_count == 0 or not pinned_rp or pinned_rp == rp_id
                _check(
                    checks,
                    "webauthn_rp_id",
                    rp_ok,
                    "WebAuthn RP-ID matches the pinned identity."
                    if rp_ok
                    else "Configured origin differs from the RP-ID pinned by existing credentials.",
                    production=production,
                    production_blocker=True,
                )
        except Exception as exc:
            _check(
                checks,
                "feature_configuration",
                False,
                f"Security-sensitive feature status could not be inspected ({type(exc).__name__}).",
                production=production,
                production_blocker=True,
            )

    manifests = list(paths.backups.glob("*/manifest.toml")) if paths.backups.is_dir() else []
    checks.append(
        DoctorCheck(
            "backup_evidence",
            "warning",
            "present_unverified" if manifests else "not_recorded",
            "A backup manifest exists, but the doctor does not cryptographically "
            "verify backup sets."
            if manifests
            else "No local backup manifest was found; verify encrypted off-host "
            "backup and restore evidence separately.",
        )
    )

    blockers = sum(item.level == "blocker" for item in checks)
    warnings = sum(item.level == "warning" for item in checks)
    return {
        "status": "blocked" if blockers else "ready",
        "production": production,
        "build_sha": BUILD_SHA if is_sha else None,
        "alembic_head": schema_head,
        "database_backend": database_kind,
        "checks": [asdict(item) for item in checks],
        "summary": {"blockers": blockers, "warnings": warnings},
    }
