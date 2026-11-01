"""Provider catalog, secret protection and low-PII OIDC diagnostics."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import _load_toml_file, get_settings
from arborpress.models.oidc import OIDCFailureDaily, OIDCProvider
from arborpress.models.settings import SiteSetting

_PROVIDER_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
_FAILURE_CLASSES = frozenset({
    "discovery", "issuer_mismatch", "state", "nonce", "pkce", "token_exchange",
    "token_signature", "audience", "expired", "jwks", "userinfo_subject",
    "identity_conflict", "provider_disabled", "local_account_disabled",
})


class OIDCProviderError(ValueError):
    """Invalid provider data or encrypted-secret state."""


def _fernet() -> Fernet:
    root = get_settings().web.secret_key.get_secret_value().encode()
    key = hashlib.sha256(b"arborpress:oidc-provider-secret:v1\0" + root).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _validate_provider(values: dict[str, Any]) -> dict[str, Any]:
    provider_id = str(values.get("id", "")).strip()
    if not _PROVIDER_ID.fullmatch(provider_id):
        raise OIDCProviderError("Invalid provider ID.")
    name = str(values.get("name", "")).strip()
    issuer = str(values.get("issuer", "")).strip()
    client_id = str(values.get("client_id", "")).strip()
    if (
        not name or len(name) > 128 or not issuer or len(issuer) > 512
        or not client_id or len(client_id) > 512
    ):
        raise OIDCProviderError("Provider name, issuer and client ID are required.")
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(issuer)
        port = parsed.port
    except ValueError as exc:
        raise OIDCProviderError("Issuer URL is invalid.") from exc
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or parsed.query or parsed.fragment or (port is not None and not 1 <= port <= 65535)
    ):
        raise OIDCProviderError("OIDC issuer must be a public HTTPS URL without credentials.")
    discovery_url = str(values.get("discovery_url") or "").strip() or None
    if discovery_url:
        try:
            parsed_discovery = urlsplit(discovery_url)
            discovery_port = parsed_discovery.port
        except ValueError as exc:
            raise OIDCProviderError("Discovery URL is invalid.") from exc
        if (
            parsed_discovery.scheme != "https" or not parsed_discovery.hostname
            or parsed_discovery.username or parsed_discovery.password
            or parsed_discovery.fragment
            or (discovery_port is not None and not 1 <= discovery_port <= 65535)
        ):
            raise OIDCProviderError("Discovery URL must be HTTPS without credentials.")
    raw_scopes = values.get("scopes", ["openid", "profile", "email"])
    if isinstance(raw_scopes, str):
        raw_scopes = raw_scopes.split()
    if not isinstance(raw_scopes, list):
        raise OIDCProviderError("Scopes must be a list.")
    scopes = list(dict.fromkeys(
        ["openid"] + [
            str(item) for item in raw_scopes
            if isinstance(item, str) and item and len(item) <= 128
        ]
    ))[:32]
    return {
        "id": provider_id,
        "name": name,
        "issuer": issuer,
        "discovery_url": discovery_url,
        "client_id": client_id,
        "scopes": json.dumps(scopes, separators=(",", ":")),
        "enabled": bool(values.get("enabled", True)),
        "auto_create": values.get("auto_create") is True,
    }


def provider_secret(row: OIDCProvider) -> str | None:
    if not row.client_secret_enc:
        return None
    try:
        return _fernet().decrypt(row.client_secret_enc).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise OIDCProviderError("Stored OIDC client secret cannot be decrypted.") from exc


def provider_config(row: OIDCProvider) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "issuer": row.issuer,
        "discovery_url": row.discovery_url,
        "client_id": row.client_id,
        "client_secret": provider_secret(row),
        "scopes": json.loads(row.scopes),
        "enabled": row.enabled,
        "auto_create": row.auto_create,
    }


def safe_provider(row: OIDCProvider, identity_count: int = 0) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "issuer": row.issuer,
        "discovery_url": row.discovery_url,
        "client_id": row.client_id,
        "has_secret": row.client_secret_enc is not None,
        "scopes": json.loads(row.scopes),
        "enabled": row.enabled,
        "auto_create": row.auto_create,
        "discovery_status": row.discovery_status,
        "jwks_status": row.jwks_status,
        "last_check_at": row.last_check_at,
        "last_success_at": row.last_success_at,
        "last_error_class": row.last_error_class,
        "identity_count": identity_count,
    }


async def _seed_from_config_once(db: AsyncSession) -> None:
    marker = await db.get(SiteSetting, "oidc_provider_catalog_initialized")
    if marker is not None:
        return
    settings = get_settings()
    config_file = settings._config_file
    config: dict[str, Any] = {}
    if config_file is not None and config_file.exists():
        try:
            loaded = _load_toml_file(config_file)
            section = loaded.get("sso", {})
            config = section if isinstance(section, dict) else {}
        except (OSError, ValueError):
            config = {}
    try:
        # Keep a competing first-request import from rolling back the caller's
        # transaction. The savepoint contains both provider rows and marker.
        async with db.begin_nested():
            providers = config.get("providers", {})
            if isinstance(providers, dict):
                for provider_id, raw in providers.items():
                    if not isinstance(raw, dict):
                        continue
                    legacy = {**raw, "id": provider_id}
                    try:
                        values = _validate_provider(legacy)
                    except OIDCProviderError:
                        continue
                    row = OIDCProvider(**values)
                    secret = raw.get("client_secret")
                    if isinstance(secret, str) and secret:
                        row.client_secret_enc = _fernet().encrypt(secret.encode())
                    db.add(row)
            db.add(SiteSetting(
                key="oidc_provider_catalog_initialized", value="true", updated_by="system"
            ))
            await db.flush()
    except IntegrityError:
        # Another worker performed the one-time migration concurrently.
        # Its commit will make the marker visible to subsequent requests.
        return


async def ensure_catalog(db: AsyncSession) -> None:
    await _seed_from_config_once(db)


async def get_provider(
    db: AsyncSession, provider_id: str, *, enabled_only: bool = False
) -> OIDCProvider | None:
    await ensure_catalog(db)
    stmt = select(OIDCProvider).where(OIDCProvider.id == provider_id)
    if enabled_only:
        stmt = stmt.where(OIDCProvider.enabled.is_(True))
    return (await db.execute(stmt)).scalar_one_or_none()


async def list_providers(db: AsyncSession) -> list[tuple[OIDCProvider, int]]:
    await ensure_catalog(db)
    rows = (await db.execute(select(OIDCProvider).order_by(OIDCProvider.id))).scalars().all()
    from arborpress.models.user import ExternalIdentity

    result = []
    for row in rows:
        count = (await db.execute(select(func.count()).select_from(ExternalIdentity).where(
            ExternalIdentity.provider_id == row.id
        ))).scalar_one()
        result.append((row, int(count or 0)))
    return result


async def save_provider(db: AsyncSession, data: dict[str, Any]) -> OIDCProvider:
    await ensure_catalog(db)
    values = _validate_provider(data)
    row = await db.get(OIDCProvider, values["id"])
    from arborpress.models.user import ExternalIdentity

    if row is not None and row.issuer != values["issuer"]:
        linked = (await db.execute(select(ExternalIdentity.id).where(
            ExternalIdentity.provider_id == row.id
        ).limit(1))).scalar_one_or_none()
        if linked is not None:
            raise OIDCProviderError("Issuer cannot change while identities are linked.")
    secret = data.get("client_secret")
    values.pop("client_secret", None)
    if row is None:
        row = OIDCProvider(**values)
        db.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
    if secret:
        if not isinstance(secret, str) or len(secret) > 4096:
            raise OIDCProviderError("Client secret is invalid or too large.")
        row.client_secret_enc = _fernet().encrypt(secret.encode())
    await db.flush()
    return row


async def set_provider_enabled(db: AsyncSession, provider_id: str, enabled: bool) -> OIDCProvider:
    row = await get_provider(db, provider_id)
    if row is None:
        raise OIDCProviderError("Provider not found.")
    row.enabled = enabled
    await db.flush()
    return row


async def rotate_provider_secret(db: AsyncSession, provider_id: str, secret: str) -> OIDCProvider:
    row = await get_provider(db, provider_id)
    if row is None:
        raise OIDCProviderError("Provider not found.")
    if not secret or len(secret) > 4096 or "\r" in secret or "\n" in secret:
        raise OIDCProviderError("Client secret is invalid or too large.")
    row.client_secret_enc = _fernet().encrypt(secret.encode("utf-8"))
    await db.flush()
    return row


async def record_failure(db: AsyncSession, provider_id: str | None, failure_class: str) -> None:
    """Increment a UTC-day aggregate; reject unbounded/free-form error labels."""
    if failure_class not in _FAILURE_CLASSES:
        failure_class = "token_exchange"
    provider = "unknown"
    if provider_id and _PROVIDER_ID.fullmatch(provider_id):
        known = (await db.execute(select(OIDCProvider.id).where(
            OIDCProvider.id == provider_id
        ))).scalar_one_or_none()
        if known is not None:
            provider = known
    today = datetime.now(UTC).date()
    stmt = select(OIDCFailureDaily).where(
        OIDCFailureDaily.day == today,
        OIDCFailureDaily.provider_id == provider,
        OIDCFailureDaily.failure_class == failure_class,
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = OIDCFailureDaily(
            day=today, provider_id=provider, failure_class=failure_class, count=1
        )
        try:
            async with db.begin_nested():
                db.add(row)
                await db.flush()
        except IntegrityError:
            await db.execute(update(OIDCFailureDaily).where(
                OIDCFailureDaily.day == today,
                OIDCFailureDaily.provider_id == provider,
                OIDCFailureDaily.failure_class == failure_class,
            ).values(
                count=OIDCFailureDaily.count + 1,
                updated_at=datetime.now(UTC).replace(tzinfo=None),
            ))
    else:
        await db.execute(update(OIDCFailureDaily).where(
            OIDCFailureDaily.id == row.id,
        ).values(
            count=OIDCFailureDaily.count + 1,
            updated_at=datetime.now(UTC).replace(tzinfo=None),
        ).execution_options(synchronize_session=False))
    # Enforce retention during normal writes as well as admin-page reads, so
    # diagnostics do not survive indefinitely when the overview is never opened.
    await prune_diagnostics(db, days=30)


async def prune_diagnostics(db: AsyncSession, *, days: int = 30) -> int:
    cutoff = datetime.now(UTC).date() - timedelta(days=max(1, min(days, 90)))
    result = await db.execute(delete(OIDCFailureDaily).where(OIDCFailureDaily.day < cutoff))
    return int(getattr(result, "rowcount", 0) or 0)


async def diagnostics(db: AsyncSession, *, days: int = 30) -> list[dict[str, Any]]:
    cutoff = datetime.now(UTC).date() - timedelta(days=max(1, min(days, 90)))
    rows = (await db.execute(select(
        OIDCFailureDaily.provider_id,
        OIDCFailureDaily.failure_class,
        func.sum(OIDCFailureDaily.count),
    ).where(OIDCFailureDaily.day >= cutoff).group_by(
        OIDCFailureDaily.provider_id, OIDCFailureDaily.failure_class
    ).order_by(OIDCFailureDaily.provider_id, OIDCFailureDaily.failure_class))).all()
    return [
        {"provider_id": provider, "failure_class": failure, "count": int(count)}
        for provider, failure, count in rows
    ]
