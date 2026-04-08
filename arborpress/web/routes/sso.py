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

import logging
import secrets

import httpx
from quart import Blueprint, abort, jsonify, redirect, request, session

from arborpress.core.config import get_settings
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


def _get_provider_config(provider: str) -> dict | None:
    """Loads provider configuration – returns None if not configured."""
    # TODO: Aus Settings laden
    # §11: Modul bleibt verborgen wenn nicht konfiguriert
    return None


# ---------------------------------------------------------------------------
# §11 /auth/sso/{provider} – Redirect zu IdP
# ---------------------------------------------------------------------------


@sso_bp.get("/<provider>")
async def sso_begin(provider: str) -> tuple:
    provider_cfg = _get_provider_config(provider)
    if not provider_cfg:
        # §11: nicht sichtbar wenn nicht konfiguriert
        abort(404)

    # PKCE / state
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
    from urllib.parse import urlencode

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

    # State-Check (CSRF)
    state = request.args.get("state", "")
    if state != session.pop("sso_state", None):
        abort(400, "invalid state")

    code = request.args.get("code", "")
    if not code:
        abort(400, "no code")

    cfg = get_settings()
    callback_url = f"{cfg.web.base_url.rstrip('/')}/auth/sso/{provider}/callback"

    # Token-Austausch
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            provider_cfg["token_url"],
            data={
                "client_id": provider_cfg["client_id"],
                "client_secret": provider_cfg["client_secret"],
                "code": code,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access_token = token_data.get("access_token")

        # UserInfo
        userinfo_resp = await client.get(
            provider_cfg["userinfo_url"],
            headers={"Authorization": f"Bearer {access_token}"},
        )
        userinfo_resp.raise_for_status()
        # TODO: §11 Claims from userinfo for role-based mapping
        _userinfo: dict = userinfo_resp.json()

    # §11: Claims → interne Rolle (kein automatischer Privileg-Eskalation)
    role_mapping: dict = provider_cfg.get("role_mapping", {})
    internal_role = role_mapping.get("default", "viewer")

    audit.info(
        "SSO login | provider=%s role=%s",
        provider,
        internal_role,
    )

    # TODO: Create/link user, set session
    # §11: Operational accounts never via SSO (check account.sso_disabled)
    return jsonify({"status": "not_fully_implemented", "role": internal_role}), 200
