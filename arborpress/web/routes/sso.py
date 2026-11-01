"""OIDC relying-party routes, extending ArborPress' existing SSO entry points."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
from typing import Any
from urllib.parse import urlencode

from quart import Blueprint, Response, abort, redirect, request, session, url_for
from sqlalchemy import func, select

from arborpress.auth.oidc import (
    OIDCError,
    discover,
    endpoint_url,
    mark_identity_login,
    merge_userinfo,
    request_json,
    verify_id_token_from_provider,
)
from arborpress.auth.pending import consume_pending, create_pending
from arborpress.core.audit import write_audit_event
from arborpress.core.config import _load_toml_file, get_settings
from arborpress.core.db import get_db_session
from arborpress.core.validators import is_valid_username
from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.sso")
audit = get_audit_logger()
sso_bp = Blueprint("sso", __name__)
_PROVIDER_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
_FLOW_TTL_SECONDS = 300
_FLOW_COOKIE = "arborpress_oidc_flow"


@sso_bp.after_request
async def _clear_oidc_flow_cookie(response: Response) -> Response:
    if request.path.startswith("/auth/sso/") and request.path.endswith("/callback"):
        response.delete_cookie(_FLOW_COOKIE, path="/auth/sso/")
    return response


def _load_sso_config() -> dict[str, Any]:
    """Load SSO configuration through ArborPress' include-aware config loader."""
    config_file = get_settings()._config_file
    if config_file is None or not config_file.exists():
        return {}
    try:
        data = _load_toml_file(config_file)
    except (OSError, ValueError) as exc:
        # Avoid logging exception text that may quote malformed secret-bearing TOML.
        log.warning("OIDC configuration could not be loaded (%s)", type(exc).__name__)
        return {}
    value = data.get("sso", {})
    return value if isinstance(value, dict) else {}


def _get_provider_config(provider: str) -> dict[str, Any] | None:
    if not _PROVIDER_ID.fullmatch(provider):
        return None
    providers = _load_sso_config().get("providers", {})
    if not isinstance(providers, dict):
        return None
    item = providers.get(provider)
    if not isinstance(item, dict) or item.get("enabled", True) is not True:
        return None
    issuer = item.get("issuer")
    client_id = item.get("client_id")
    if not isinstance(issuer, str) or not issuer or not isinstance(client_id, str) or not client_id:
        return None
    configured_scopes = item.get("scopes", ["profile", "email"])
    if not isinstance(configured_scopes, list):
        configured_scopes = ["profile", "email"]
    return {
        **{
            key: value for key, value in item.items()
            if key not in {"auto_link_by_email", "role_mapping"}
        },
        "id": provider,
        "name": str(item.get("name") or provider.replace("_", " ").title())[:128],
        "scopes": list(dict.fromkeys([
            "openid",
            *(
                scope for scope in configured_scopes
                if isinstance(scope, str) and scope and len(scope) <= 128
            ),
        ]))[:32],
        # Identity provisioning is opt-in; legacy auto_link_by_email is ignored.
        "auto_create": item.get("auto_create") is True,
    }


def get_configured_providers() -> list[dict[str, str]]:
    providers = _load_sso_config().get("providers", {})
    if not isinstance(providers, dict):
        return []
    configured = []
    for provider in providers:
        item = _get_provider_config(str(provider))
        if item is not None:
            configured.append({"id": str(provider), "name": item["name"]})
    return configured


async def _resolve_provider_endpoints(provider_cfg: dict[str, Any]) -> dict[str, Any]:
    """Resolve and validate endpoints exclusively from the configured issuer."""
    metadata = await discover(provider_cfg)
    return {**provider_cfg, **metadata, "_oidc_metadata": metadata}


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _normalize_username(candidate: str) -> str:
    candidate = re.sub(r"[^a-zA-Z0-9._-]+", "-", candidate.strip().lower()).strip("-._")
    candidate = candidate[:32] or "user"
    return candidate if is_valid_username(candidate) else "user"


def _callback_url(provider: str) -> str:
    base_url = get_settings().web.base_url.rstrip("/")
    return f"{base_url}/auth/sso/{provider}/callback"


@sso_bp.get("/<provider>")
async def sso_begin(provider: str) -> Any:
    provider_cfg = _get_provider_config(provider)
    if provider_cfg is None:
        abort(404)
    try:
        resolved = await _resolve_provider_endpoints(provider_cfg)
    except OIDCError:
        log.warning("OIDC discovery failed for configured provider %s", provider)
        abort(502, "SSO provider discovery failed")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    browser_binding = secrets.token_urlsafe(32)
    callback_url = _callback_url(provider)
    async for db in get_db_session():
        await create_pending(
            db,
            purpose="oidc_login",
            user_id=None,
            ttl_seconds=_FLOW_TTL_SECONDS,
            challenge=hashlib.sha256(state.encode()).digest(),
            context={
                "provider": provider,
                "issuer": provider_cfg.get("issuer", resolved.get("issuer", "")),
                "nonce": nonce,
                "verifier": verifier,
                "browser_binding_hash": hashlib.sha256(browser_binding.encode()).hexdigest(),
                "redirect_uri": callback_url,
                "metadata": resolved["_oidc_metadata"],
            },
        )
        await db.commit()
        params = {
            "client_id": provider_cfg["client_id"],
            "redirect_uri": callback_url,
            "scope": " ".join(provider_cfg["scopes"]),
            "state": state,
            "nonce": nonce,
            "response_type": "code",
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        response = redirect(str(resolved["authorization_endpoint"]) + "?" + urlencode(params))
        response.set_cookie(
            _FLOW_COOKIE,
            browser_binding,
            max_age=_FLOW_TTL_SECONDS,
            path="/auth/sso/",
            secure=get_settings().web.base_url.startswith("https://"),
            httponly=True,
            samesite="Lax",
        )
        return response
    abort(500, "SSO flow could not be created")


@sso_bp.get("/<provider>/callback")
async def sso_callback(provider: str) -> Any:
    provider_cfg = _get_provider_config(provider)
    if provider_cfg is None:
        abort(404)
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or len(state) > 256 or not code or len(code) > 4096:
        abort(400, "invalid OIDC response")
    browser_binding = request.cookies.get(_FLOW_COOKIE, "")
    if not browser_binding:
        abort(400, "OIDC browser flow binding missing")

    async for db in get_db_session():
        from arborpress.models.user import AuthPending

        state_hash = hashlib.sha256(state.encode()).digest()
        pending = (await db.execute(select(AuthPending).where(
            AuthPending.purpose == "oidc_login",
            AuthPending.challenge == state_hash,
        ))).scalar_one_or_none()
        if pending is None or pending.challenge is None:
            abort(400, "OIDC flow expired")
        try:
            flow = json.loads(pending.context or "{}")
        except (TypeError, ValueError):
            abort(400, "invalid OIDC flow")
        if (
            flow.get("provider") != provider
            or flow.get("issuer") != provider_cfg["issuer"]
            or flow.get("redirect_uri") != _callback_url(provider)
            or not hmac.compare_digest(
                str(flow.get("browser_binding_hash", "")),
                hashlib.sha256(browser_binding.encode()).hexdigest(),
            )
            or not isinstance(flow.get("nonce"), str)
            or not isinstance(flow.get("verifier"), str)
            or not isinstance(flow.get("metadata"), dict)
        ):
            abort(400, "OIDC provider mismatch")
        consumed = await consume_pending(
            db, pending_id=pending.id, purpose="oidc_login"
        )
        if consumed is None:
            abort(400, "OIDC flow already used")
        await db.commit()

        # The state is consumed before any network exchange: callbacks cannot replay.
        metadata = flow["metadata"]
        try:
            token_form = {
                "client_id": provider_cfg["client_id"],
                "code": code,
                "redirect_uri": flow["redirect_uri"],
                "grant_type": "authorization_code",
                "code_verifier": flow["verifier"],
            }
            token_auth: tuple[str, str] | None = None
            client_secret = provider_cfg.get("client_secret")
            if isinstance(client_secret, str) and client_secret:
                supported_auth = metadata.get("token_endpoint_auth_methods_supported") or [
                    "client_secret_basic"
                ]
                if "client_secret_basic" in supported_auth:
                    token_auth = (provider_cfg["client_id"], client_secret)
                elif "client_secret_post" in supported_auth:
                    token_form["client_secret"] = client_secret
                else:
                    raise OIDCError("client_auth_method_unsupported")
            token_data = await request_json(
                endpoint_url(metadata, "token_endpoint"),
                method="POST",
                data=token_form,
                auth=token_auth,
            )
            id_token = token_data.get("id_token")
            access_token = token_data.get("access_token")
            if not isinstance(id_token, str) or not isinstance(access_token, str):
                raise OIDCError("id_token_required")
            claims = await verify_id_token_from_provider(
                id_token,
                metadata=metadata,
                issuer=provider_cfg["issuer"],
                client_id=provider_cfg["client_id"],
                nonce=flow["nonce"],
            )
            if metadata.get("userinfo_endpoint"):
                userinfo = await request_json(
                    endpoint_url(metadata, "userinfo_endpoint"),
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                claims = merge_userinfo(claims, userinfo)
        except OIDCError as exc:
            log.warning("OIDC authentication rejected for provider %s (%s)", provider, str(exc))
            abort(401, "SSO authentication failed")
        except Exception as exc:
            # Do not include exception messages: HTTP libraries may embed endpoint details.
            log.warning(
                "OIDC authentication failed for provider %s (%s)", provider, type(exc).__name__
            )
            abort(502, "SSO provider request failed")

        from arborpress.models.user import (
            AccountType,
            ExternalIdentity,
            MFADevice,
            MFADeviceType,
            User,
            UserRole,
            WebAuthnCredential,
        )

        issuer = str(claims["iss"])
        subject = str(claims["sub"])
        identity = (await db.execute(
            select(ExternalIdentity).where(
                ExternalIdentity.issuer == issuer, ExternalIdentity.subject == subject
            )
        )).scalar_one_or_none()
        user = await db.get(User, identity.user_id) if identity else None
        raw_username = str(
            claims.get("preferred_username") or claims.get("nickname") or subject
        )[:255]
        username_base = _normalize_username(raw_username)
        email_value = claims.get("email")
        email = (
            str(email_value).strip().lower()
            if isinstance(email_value, str) and claims.get("email_verified") is True
            else None
        )
        if email:
            email = email[:254]
        display_value = claims.get("name")
        display_name = str(display_value).strip()[:128] if isinstance(display_value, str) else ""

        if user is None:
            if not provider_cfg.get("auto_create", False):
                abort(403, "SSO identity is not linked to an ArborPress account")
            if email:
                # A duplicate email is not a link signal; omit it from the new account.
                email_exists = (await db.execute(
                    select(User.id).where(func.lower(User.email) == email)
                )).scalar_one_or_none()
                if email_exists:
                    email = None
            username = username_base
            suffix = 0
            while (await db.execute(
                select(User.id).where(func.lower(User.username) == username.lower())
            )).scalar_one_or_none() is not None:
                suffix += 1
                ending = f"-{suffix}"
                username = f"{username_base[:32-len(ending)]}{ending}"
            user = User(
                username=username,
                display_name=display_name or username,
                email=email,
                account_type=AccountType.OPERATIONAL,
                role=UserRole.VIEWER,
                is_active=True,
            )
            db.add(user)
            await db.flush()
            identity = ExternalIdentity(
                user_id=str(user.id),
                provider_id=provider,
                issuer=issuer,
                subject=subject,
                profile=json.dumps(
                    {"name": display_name[:128], "preferred_username": raw_username[:128]},
                    separators=(",", ":"),
                ),
            )
            db.add(identity)
        elif not user.is_active or user.sso_disabled:
            audit.warning("OIDC login denied | provider=%s", provider)
            abort(403, "SSO disabled for this account")

        if not user.is_active or user.sso_disabled:
            abort(403, "SSO disabled for this account")
        if identity is None:
            abort(500, "OIDC identity could not be persisted")

        cfg = get_settings()
        from arborpress.auth.policy import requires_second_factor
        from arborpress.core.site_settings import get_webauthn_settings

        wa_settings = await get_webauthn_settings(db)
        webauthn_count = (await db.execute(select(func.count()).select_from(
            WebAuthnCredential
        ).where(
            WebAuthnCredential.user_id == str(user.id),
            WebAuthnCredential.uv_capable.is_not(False),
            WebAuthnCredential.verification_status != "recovery_pending",
        ))).scalar_one() or 0
        totp_count = (await db.execute(select(func.count()).select_from(MFADevice).where(
            MFADevice.user_id == str(user.id),
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
            MFADevice.verification_status.in_(("verified", "unknown")),
        ))).scalar_one() or 0
        factors = ({"webauthn"} if webauthn_count else set()) | ({"totp"} if totp_count else set())
        if requires_second_factor(
            user, "sso", factors, auth_settings=cfg.auth, webauthn_settings=wa_settings
        ):
            if not factors:
                abort(403, "This account requires an enrolled MFA factor before SSO login")
            from arborpress.auth.pending import create_pending as create_mfa_pending

            pending_mfa = await create_mfa_pending(
                db,
                purpose="sso_mfa",
                user_id=str(user.id),
                ttl_seconds=int(wa_settings.get("challenge_ttl_seconds", 300)),
                context={
                    "methods": [
                        *( ["webauthn"] if webauthn_count else []),
                        *( ["totp"] if totp_count else []),
                    ],
                    "auth_method": f"sso:{provider}",
                    "provider": provider,
                    "external_identity_id": identity.id,
                },
            )
            session.clear()
            session["sso_mfa_pending_id"] = pending_mfa.id
            await db.commit()
            return redirect(url_for("auth.mfa_page"))

        from arborpress.auth.sessions import create_user_session

        await mark_identity_login(db, str(identity.id), str(user.id))
        await create_user_session(db, user, auth_method=f"sso:{provider}", assurance_level="sso")
        await write_audit_event(
            event_type="login_success",
            outcome="success",
            actor_id=str(user.id),
            actor_name=user.username,
            target_id=str(user.id),
            detail=f"method=sso:{provider} assurance=sso",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            db=db,
        )
        await db.commit()
        audit.info("OIDC login successful | provider=%s user_id=%s", provider, user.id)
        target = (
            url_for("admin.dashboard")
            if user.role.value in {"author", "editor", "moderator", "admin"}
            else url_for("public.index")
        )
        return redirect(target)
    abort(500, "OIDC login failed")
