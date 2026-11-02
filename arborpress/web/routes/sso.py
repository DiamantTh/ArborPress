"""OIDC relying-party routes, extending ArborPress' existing SSO entry points."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode

from quart import Blueprint, Response, abort, redirect, render_template, request, session, url_for
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
from arborpress.auth.stepup import assert_stepup
from arborpress.core.audit import write_audit_event
from arborpress.core.config import get_settings
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


async def get_enabled_provider_choices(db: Any) -> list[dict[str, str]]:
    from arborpress.auth.oidc_providers import list_providers

    return [
        {"id": row.id, "name": row.name}
        for row, _count in await list_providers(db)
        if row.enabled
    ]


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


def _link_callback_url(provider: str) -> str:
    base_url = get_settings().web.base_url.rstrip("/")
    return f"{base_url}/auth/sso/{provider}/link/callback"


async def _provider_config(db: Any, provider: str) -> dict[str, Any] | None:
    if not _PROVIDER_ID.fullmatch(provider):
        return None
    from arborpress.auth.oidc_providers import get_provider, provider_config

    row = await get_provider(db, provider, enabled_only=True)
    return provider_config(row) if row is not None else None


@sso_bp.get("/<provider>")
async def sso_begin(provider: str) -> Any:
    return await _begin_flow(provider, operation="login")


@sso_bp.get("/<provider>/link")
async def sso_link_begin(provider: str) -> Any:
    return await _begin_flow(provider, operation="link")


async def _begin_flow(provider: str, *, operation: str) -> Any:
    if not _PROVIDER_ID.fullmatch(provider):
        abort(404)
    user_id = str(session.get("user_id") or "") if operation == "link" else ""
    if operation == "link" and (not user_id or session.get("recovery_only")):
        abort(401)
    async for db in get_db_session():
        provider_cfg = await _provider_config(db, provider)
        if provider_cfg is None:
            abort(404)
        if operation == "link":
            from arborpress.auth.sessions import refresh_session_identity

            active_user = await refresh_session_identity(db, session)
            if active_user is None or str(active_user.id) != user_id:
                abort(401)
            try:
                await assert_stepup(
                    cast(dict[str, Any], session), user_id,
                    "link_external_identity", target=provider,
                    consume=False, db=db,
                )
            except PermissionError:
                abort(403, "Step-up required")
        try:
            resolved = await _resolve_provider_endpoints(provider_cfg)
        except OIDCError:
            await _record_failure(db, provider, "discovery")
            await db.commit()
            log.warning("OIDC discovery failed for configured provider %s", provider)
            abort(502, "SSO provider discovery failed")

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        browser_binding = secrets.token_urlsafe(32)
        callback_url = (
            _link_callback_url(provider) if operation == "link" else _callback_url(provider)
        )
        purpose = "oidc_link" if operation == "link" else "oidc_login"
        await create_pending(
            db,
            purpose=purpose,
            user_id=user_id or None,
            ttl_seconds=_FLOW_TTL_SECONDS,
            challenge=hashlib.sha256(state.encode()).digest(),
            context={
                "operation": operation,
                "session_id": str(session.get("session_id") or "") if operation == "link" else None,
                "provider": provider,
                "issuer": provider_cfg["issuer"],
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
            _FLOW_COOKIE, browser_binding, max_age=_FLOW_TTL_SECONDS,
            path="/auth/sso/", secure=get_settings().web.base_url.startswith("https://"),
            httponly=True, samesite="Lax",
        )
        return response
    abort(500, "SSO flow could not be created")


async def _record_failure(db: Any, provider: str | None, failure_class: str) -> None:
    from arborpress.auth.oidc_providers import record_failure

    await record_failure(db, provider, failure_class)


async def _record_state_failure(provider: str) -> None:
    async for db in get_db_session():
        await _record_failure(db, provider, "state")
        await db.commit()
        return


async def _validate_sso_mutation() -> None:
    if request.is_json:
        from arborpress.auth.webauthn import resolve_origin
        from arborpress.web.routes.auth import _validate_json_origin

        _validate_json_origin(resolve_origin(get_settings().web.base_url))
        return
    from arborpress.web.security import validate_csrf

    await validate_csrf()


def _failure_class(error_code: str) -> str:
    code = error_code.lower()
    if "issuer" in code:
        return "issuer_mismatch"
    if "nonce" in code:
        return "nonce"
    if "pkce" in code:
        return "pkce"
    if any(token in code for token in ("audience", "authorized_party", "aud")):
        return "audience"
    if any(token in code for token in ("expired", "not_yet_valid", "time")):
        return "expired"
    if any(token in code for token in ("signature", "signing_key", "algorithm", "id_token")):
        return "token_signature"
    if "jwks" in code or "key" in code:
        return "jwks"
    if "userinfo_subject" in code:
        return "userinfo_subject"
    if any(token in code for token in ("redirect", "discovery", "provider_")):
        return "discovery"
    return "token_exchange"


@sso_bp.get("/<provider>/callback")
@sso_bp.get("/<provider>/link/callback")
async def sso_callback(provider: str) -> Any:
    is_link = request.path.endswith("/link/callback")
    purpose = "oidc_link" if is_link else "oidc_login"
    operation = "link" if is_link else "login"
    state = request.args.get("state", "")
    code = request.args.get("code", "")
    if not state or len(state) > 256 or not code or len(code) > 4096:
        await _record_state_failure(provider)
        abort(400, "invalid OIDC response")
    browser_binding = request.cookies.get(_FLOW_COOKIE, "")
    if not browser_binding:
        await _record_state_failure(provider)
        abort(400, "OIDC browser flow binding missing")

    async for db in get_db_session():
        from arborpress.models.user import AuthPending

        provider_cfg = await _provider_config(db, provider)
        if provider_cfg is None:
            await _record_failure(db, provider, "provider_disabled")
            await db.commit()
            abort(404)

        state_hash = hashlib.sha256(state.encode()).digest()
        pending = (await db.execute(select(AuthPending).where(
            AuthPending.purpose == purpose,
            AuthPending.challenge == state_hash,
        ))).scalar_one_or_none()
        if pending is None or pending.challenge is None:
            await _record_failure(db, provider, "state")
            await db.commit()
            abort(400, "OIDC flow expired")
        try:
            flow = json.loads(pending.context or "{}")
        except (TypeError, ValueError):
            await _record_failure(db, provider, "state")
            await db.commit()
            abort(400, "invalid OIDC flow")
        if (
            flow.get("operation") != operation
            or flow.get("provider") != provider
            or flow.get("issuer") != provider_cfg["issuer"]
            or flow.get("redirect_uri") != (
                _link_callback_url(provider) if is_link else _callback_url(provider)
            )
            or not hmac.compare_digest(
                str(flow.get("browser_binding_hash", "")),
                hashlib.sha256(browser_binding.encode()).hexdigest(),
            )
            or not isinstance(flow.get("nonce"), str)
            or not isinstance(flow.get("verifier"), str)
            or not isinstance(flow.get("metadata"), dict)
        ):
            await _record_failure(db, provider, "state")
            await db.commit()
            abort(400, "OIDC provider mismatch")
        consumed = await consume_pending(db, pending_id=pending.id, purpose=purpose)
        if consumed is None:
            await _record_failure(db, provider, "state")
            await db.commit()
            abort(400, "OIDC flow already used")
        if is_link:
            from arborpress.models.user import User, UserSession
            link_user = await db.get(User, str(pending.user_id))
            original_session_id = str(flow.get("session_id") or "")
            original_session = (await db.execute(select(UserSession).where(
                UserSession.id == original_session_id,
                UserSession.user_id == str(pending.user_id),
                UserSession.is_valid.is_(True),
                UserSession.expires_at > datetime.now(UTC).replace(tzinfo=None),
            ))).scalar_one_or_none()
            if link_user is None or not link_user.is_active or original_session is None:
                await _record_failure(db, provider, "local_account_disabled")
                await db.commit()
                abort(403, "Linking is unavailable")
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
            await _record_failure(db, provider, _failure_class(str(exc)))
            await db.commit()
            log.warning("OIDC authentication rejected for provider %s (%s)", provider, str(exc))
            abort(401, "SSO authentication failed")
        except Exception as exc:
            # Do not include exception messages: HTTP libraries may embed endpoint details.
            log.warning(
                "OIDC authentication failed for provider %s (%s)", provider, type(exc).__name__
            )
            await _record_failure(db, provider, "token_exchange")
            await db.commit()
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
        if is_link:
            from arborpress.models.user import AuthPending, ExternalIdentity, User

            link_user = await db.get(User, str(pending.user_id))
            if link_user is None or not link_user.is_active or link_user.sso_disabled:
                await _record_failure(db, provider, "local_account_disabled")
                await db.commit()
                abort(403, "Linking is unavailable")
            conflict = (await db.execute(select(ExternalIdentity.id).where(
                ExternalIdentity.issuer == issuer,
                ExternalIdentity.subject == subject,
            ).limit(1))).scalar_one_or_none()
            if conflict is not None:
                await _record_failure(db, provider, "identity_conflict")
                await write_audit_event(
                    event_type="oidc_identity_link_conflict", outcome="blocked",
                    actor_id=str(link_user.id),
                    detail=f"provider_id={provider}; external identity already linked",
                    db=db,
                )
                await db.commit()
                abort(409, "This external identity cannot be linked")
            confirm = await create_pending(
                db,
                purpose="oidc_link_confirm",
                user_id=str(link_user.id),
                ttl_seconds=_FLOW_TTL_SECONDS,
                context={
                    "provider": provider, "issuer": issuer, "subject": subject,
                    "session_id": str(flow.get("session_id") or ""),
                },
            )
            await db.commit()
            return await render_template(
                "auth/oidc_link_confirm.html", provider_name=provider_cfg["name"],
                pending_id=confirm.id, noindex=True,
            )

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
            await _record_failure(db, provider, "local_account_disabled")
            audit.warning("OIDC login denied | provider=%s", provider)
            await db.commit()
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
            oauth_resume = session.get("oauth_resume")
            session.clear()
            if (
                isinstance(oauth_resume, str)
                and oauth_resume.startswith("/oauth/authorize?")
                and len(oauth_resume) <= 2048
            ):
                session["oauth_resume"] = oauth_resume
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
        oauth_resume = session.pop("oauth_resume", None)
        if isinstance(oauth_resume, str) and oauth_resume.startswith("/oauth/authorize?"):
            return redirect(oauth_resume)
        target = (
            url_for("admin.dashboard")
            if user.role.value in {"author", "editor", "moderator", "admin"}
            else url_for("public.index")
        )
        return redirect(target)
    abort(500, "OIDC login failed")


@sso_bp.post("/link/confirm/<pending_id>")
async def sso_link_confirm(pending_id: str) -> Any:
    user_id = str(session.get("user_id") or "")
    if not user_id or session.get("recovery_only"):
        abort(401)
    await _validate_sso_mutation()
    async for db in get_db_session():
        from arborpress.models.oidc import OIDCProvider
        from arborpress.models.user import AuthPending, ExternalIdentity, User

        pending = await db.get(AuthPending, pending_id)
        if (
            pending is None or pending.purpose != "oidc_link_confirm"
            or str(pending.user_id) != user_id
        ):
            abort(404)
        try:
            context = json.loads(pending.context or "{}")
        except (TypeError, ValueError):
            abort(400)
        provider_id = str(context.get("provider", ""))
        issuer = str(context.get("issuer", ""))
        subject = str(context.get("subject", ""))
        provider = (await db.execute(select(OIDCProvider).where(
            OIDCProvider.id == provider_id,
            OIDCProvider.enabled.is_(True),
            OIDCProvider.issuer == issuer,
        ))).scalar_one_or_none()
        user = await db.get(User, user_id)
        if provider is None or user is None or not user.is_active or user.sso_disabled:
            abort(403, "Linking is unavailable")
        if str(context.get("session_id") or "") != str(session.get("session_id") or ""):
            abort(403, "Linking session changed")
        from arborpress.auth.sessions import refresh_session_identity

        refreshed = await refresh_session_identity(db, session)
        if refreshed is None or str(refreshed.id) != user_id:
            abort(401)
        try:
            await assert_stepup(
                cast(dict[str, Any], session), user_id,
                "link_external_identity", target=provider_id, db=db
            )
        except PermissionError:
            abort(403, "Step-up required")
        consumed = await consume_pending(db, pending_id=pending.id, purpose="oidc_link_confirm")
        if consumed is None:
            abort(400, "Link confirmation expired or already used")
        conflict = (await db.execute(select(ExternalIdentity.id).where(
            ExternalIdentity.issuer == issuer,
            ExternalIdentity.subject == subject,
        ).limit(1))).scalar_one_or_none()
        if conflict is not None:
            await _record_failure(db, provider_id, "identity_conflict")
            await db.commit()
            abort(409, "This external identity cannot be linked")
        db.add(ExternalIdentity(
            user_id=user_id, provider_id=provider_id, issuer=issuer, subject=subject,
        ))
        await write_audit_event(
            event_type="oidc_identity_linked", outcome="success",
            actor_id=user_id, actor_name=user.username,
            detail=(
                f"provider_id={provider_id}; linked after verified flow and explicit confirmation"
            ),
            db=db,
        )
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            abort(409, "This external identity cannot be linked")
        return redirect(url_for("auth.account_security_page"))
    abort(500)


@sso_bp.post("/identities/<identity_id>/unlink")
async def sso_identity_unlink(identity_id: str) -> Any:
    user_id = str(session.get("user_id") or "")
    if not user_id or session.get("recovery_only"):
        abort(401)
    await _validate_sso_mutation()
    async for db in get_db_session():
        from arborpress.auth.policy import lock_user_for_credential_change, usable_login_methods
        from arborpress.models.user import ExternalIdentity

        identity = (await db.execute(select(ExternalIdentity).where(
            ExternalIdentity.id == identity_id,
            ExternalIdentity.user_id == user_id,
        ))).scalar_one_or_none()
        if identity is None:
            abort(404)
        try:
            await assert_stepup(
                cast(dict[str, Any], session), user_id,
                "unlink_external_identity", target=identity_id, db=db
            )
        except PermissionError:
            abort(403, "Step-up required")
        user = await lock_user_for_credential_change(db, user_id)
        if user is None or not user.is_active:
            abort(403)
        methods = await usable_login_methods(
            db, user, exclude_external_identity_id=identity_id
        )
        if not methods:
            await db.rollback()
            abort(409, "This is the last usable login or recovery method")
        provider_id = identity.provider_id
        await db.delete(identity)
        await write_audit_event(
            event_type="oidc_identity_unlinked", outcome="success",
            actor_id=user_id, actor_name=user.username,
            detail=f"provider_id={provider_id}; external identity removed by its owner",
            db=db,
        )
        await db.commit()
        if request.is_json:
            from quart import jsonify

            return jsonify({"status": "unlinked"}), 200
        return redirect(url_for("auth.account_security_page"))
    abort(500)
