"""OAuth2/OIDC client (§11 – external login, optional only).

§11 constraints:
- Only visible when configured
- No automatic privilege escalation via SSO
- Operational accounts may have SSO disabled
- Separate button (not part of the WebAuthn flow)

Routes:
  /auth/sso/{provider}           – Redirect to IdP
  /auth/sso/{provider}/callback  – Callback processing
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import tomllib
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from quart import Blueprint, abort, redirect, request, session, url_for
from sqlalchemy import func, select

from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.core.validators import is_valid_username
from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.sso")
audit = get_audit_logger()

sso_bp = Blueprint("sso", __name__)

# ---------------------------------------------------------------------------
# SSO-Provider-Registry (aus config geladen)
# ---------------------------------------------------------------------------
# Beispiel-Provider-Konfiguration in config.toml:
#
# [sso.providers.github]
# client_id     = "..."
# client_secret = "..."
# authorize_url = "https://github.com/login/oauth/authorize"
# token_url     = "https://github.com/login/oauth/access_token"
# userinfo_url  = "https://api.github.com/user"
# scopes        = ["read:user", "user:email"]
# role_mapping  = { default = "viewer" }   # §11 – claims → internal roles


def _load_sso_config() -> dict:
    """Read SSO configuration from config.toml if available."""
    cfg = get_settings()
    config_file = getattr(cfg, "_config_file", None)
    candidates: list[Path] = []
    if config_file:
        candidates.append(Path(config_file))
    candidates.extend([Path("config/config.toml"), Path("config.toml")])

    for candidate in candidates:
        try:
            if candidate.exists():
                with open(candidate, "rb") as fh:
                    data = tomllib.load(fh)
                return data.get("sso", {}) if isinstance(data, dict) else {}
        except Exception as exc:  # noqa: BLE001
            log.warning("SSO config could not be read from %s: %s", candidate, exc)
    return {}


def _get_provider_config(provider: str) -> dict | None:
    """Loads provider configuration – returns None if not configured."""
    sso_cfg = _load_sso_config()
    providers = sso_cfg.get("providers", {})
    if not isinstance(providers, dict):
        return None
    provider_cfg = providers.get(provider)
    if not isinstance(provider_cfg, dict):
        return None

    normalized = dict(provider_cfg)
    normalized.setdefault("name", provider.replace("_", " ").title())
    normalized.setdefault("scopes", ["openid", "profile", "email"])
    normalized.setdefault("username_claim", "preferred_username")
    normalized.setdefault("email_claim", "email")
    normalized.setdefault("display_name_claim", "name")
    normalized.setdefault("role_mapping", {"default": "viewer"})
    normalized.setdefault("auto_create", True)
    normalized.setdefault("auto_link_by_email", True)
    normalized.setdefault("account_type", "operational")
    normalized.setdefault("use_pkce", True)
    return normalized


def get_configured_providers() -> list[dict[str, str]]:
    """Return visible configured SSO providers for the login page."""
    sso_cfg = _load_sso_config()
    providers = sso_cfg.get("providers", {})
    if not isinstance(providers, dict):
        return []
    return [
        {"id": key, "name": str(val.get("name") or key.replace("_", " ").title())}
        for key, val in providers.items()
        if isinstance(val, dict) and val.get("client_id")
    ]


async def _resolve_provider_endpoints(provider_cfg: dict) -> dict:
    """Resolve OIDC discovery metadata if configured."""
    resolved = dict(provider_cfg)
    discovery_url = resolved.get("discovery_url")
    if discovery_url and (
        not resolved.get("authorize_url")
        or not resolved.get("token_url")
        or not resolved.get("userinfo_url")
    ):
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(discovery_url, headers={"Accept": "application/json"})
            resp.raise_for_status()
            meta = resp.json()
        resolved.setdefault("authorize_url", meta.get("authorization_endpoint", ""))
        resolved.setdefault("token_url", meta.get("token_endpoint", ""))
        resolved.setdefault("userinfo_url", meta.get("userinfo_endpoint", ""))
    return resolved


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _normalize_username(candidate: str) -> str:
    candidate = re.sub(r"[^a-zA-Z0-9._-]+", "-", candidate.strip().lower()).strip("-._")
    candidate = candidate[:32] or "user"
    if not is_valid_username(candidate):
        return "user"
    return candidate


# ---------------------------------------------------------------------------
# §11 /auth/sso/{provider} – Redirect zu IdP
# ---------------------------------------------------------------------------


@sso_bp.get("/<provider>")
async def sso_begin(provider: str) -> tuple:
    provider_cfg = _get_provider_config(provider)
    if not provider_cfg:
        abort(404)

    provider_cfg = await _resolve_provider_endpoints(provider_cfg)
    if not provider_cfg.get("authorize_url"):
        abort(500, "SSO provider is missing authorize_url")

    state = secrets.token_urlsafe(32)
    session["sso_state"] = state
    session["sso_provider"] = provider

    cfg = get_settings()
    callback_url = f"{cfg.web.base_url.rstrip('/')}/auth/sso/{provider}/callback"

    params = {
        "client_id": provider_cfg["client_id"],
        "redirect_uri": callback_url,
        "scope": " ".join(provider_cfg.get("scopes", [])),
        "state": state,
        "response_type": "code",
    }
    if provider_cfg.get("use_pkce", True):
        verifier = secrets.token_urlsafe(48)
        session["sso_code_verifier"] = verifier
        params["code_challenge"] = _pkce_challenge(verifier)
        params["code_challenge_method"] = "S256"

    url = provider_cfg["authorize_url"] + "?" + urlencode(params)
    return redirect(url), 302


# ---------------------------------------------------------------------------
# §11 /auth/sso/{provider}/callback
# ---------------------------------------------------------------------------


@sso_bp.get("/<provider>/callback")
async def sso_callback(provider: str) -> tuple:
    provider_cfg = _get_provider_config(provider)
    if not provider_cfg:
        abort(404)
    provider_cfg = await _resolve_provider_endpoints(provider_cfg)

    state = request.args.get("state", "")
    if state != session.pop("sso_state", None):
        abort(400, "invalid state")

    code = request.args.get("code", "")
    if not code:
        abort(400, "no code")

    cfg = get_settings()
    callback_url = f"{cfg.web.base_url.rstrip('/')}/auth/sso/{provider}/callback"

    token_payload = {
        "client_id": provider_cfg["client_id"],
        "client_secret": provider_cfg.get("client_secret", ""),
        "code": code,
        "redirect_uri": callback_url,
        "grant_type": "authorization_code",
    }
    code_verifier = session.pop("sso_code_verifier", None)
    if code_verifier:
        token_payload["code_verifier"] = code_verifier

    async with httpx.AsyncClient(timeout=20.0) as client:
        token_resp = await client.post(
            provider_cfg["token_url"],
            data=token_payload,
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            abort(502, "SSO provider returned no access_token")

        userinfo_url = provider_cfg.get("userinfo_url")
        if not userinfo_url:
            abort(500, "SSO provider is missing userinfo_url")

        userinfo_resp = await client.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )
        userinfo_resp.raise_for_status()
        claims: dict = userinfo_resp.json()

    role_mapping: dict = provider_cfg.get("role_mapping", {})
    default_role = str(role_mapping.get("default", "viewer")).lower()
    allowed_roles = {"viewer", "author", "editor", "moderator", "admin"}
    internal_role = default_role if default_role in allowed_roles else "viewer"

    username_claim = str(provider_cfg.get("username_claim", "preferred_username"))
    email_claim = str(provider_cfg.get("email_claim", "email"))
    display_name_claim = str(provider_cfg.get("display_name_claim", "name"))

    email = str(claims.get(email_claim) or "").strip().lower() or None
    raw_username = str(
        claims.get(username_claim)
        or claims.get("preferred_username")
        or claims.get("nickname")
        or (email.split("@")[0] if email else "")
        or claims.get("sub")
        or "user"
    )
    desired_username = _normalize_username(raw_username)
    display_name = str(claims.get(display_name_claim) or raw_username or desired_username).strip()[:128]

    async for db in get_db_session():
        from datetime import UTC, datetime, timedelta

        from arborpress.models.user import AccountType, User, UserRole, UserSession

        user = None
        if email and provider_cfg.get("auto_link_by_email", True):
            result = await db.execute(select(User).where(func.lower(User.email) == email))
            user = result.scalar_one_or_none()

        if user is None:
            result = await db.execute(select(User).where(func.lower(User.username) == desired_username.lower()))
            user = result.scalar_one_or_none()

        if user is None:
            if not provider_cfg.get("auto_create", True):
                abort(403, "SSO account not linked")

            username = desired_username
            idx = 1
            while True:
                result = await db.execute(select(User).where(func.lower(User.username) == username.lower()))
                if result.scalar_one_or_none() is None:
                    break
                suffix = f"-{idx}"
                username = f"{desired_username[: max(1, 32 - len(suffix))]}{suffix}"
                idx += 1

            account_type_raw = str(provider_cfg.get("account_type", "operational")).lower()
            account_type = AccountType.OPERATIONAL if account_type_raw == "operational" else AccountType.PUBLIC
            user = User(
                username=username,
                display_name=display_name or username,
                email=email,
                account_type=account_type,
                role=UserRole(internal_role),
                is_active=True,
            )
            db.add(user)
            await db.flush()
        else:
            if not user.is_active or user.sso_disabled:
                audit.warning("SSO denied | provider=%s user=%s", provider, getattr(user, "username", "?"))
                abort(403, "SSO disabled for this account")

            if email and not user.email:
                user.email = email
            if display_name and not user.display_name:
                user.display_name = display_name

        session.clear()
        session["user_id"] = str(user.id)
        session["user_name"] = user.username
        session["user_role"] = user.role.value
        session["account_type"] = user.account_type.value
        session["auth_method"] = f"sso:{provider}"

        now = datetime.now(UTC)
        ttl = timedelta(seconds=cfg.auth.admin_session_ttl)
        proto = request.headers.get("X-Forwarded-Proto", "") or request.scheme
        is_tls = str(proto).lower() in ("https", "on") or request.url.startswith("https")
        raw_ua = request.headers.get("User-Agent", "")
        db_sess = UserSession(
            user_id=str(user.id),
            expires_at=now + ttl,
            last_seen_at=now,
            client_ip=request.remote_addr,
            user_agent=raw_ua[:512] if raw_ua else None,
            is_tls=is_tls,
            is_cli=False,
        )
        db.add(db_sess)
        await db.commit()
        session["session_id"] = db_sess.id

        audit.info(
            "SSO login successful | provider=%s user=%s role=%s",
            provider,
            user.username,
            user.role.value,
        )

        target = url_for("admin.dashboard") if user.role.value in {"author", "editor", "moderator", "admin"} else url_for("public.index")
        return redirect(target)

    abort(500, "SSO login failed")
