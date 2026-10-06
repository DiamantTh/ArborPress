"""Auth routes – WebAuthn registration and login (§2).

Endpoints:
  POST /auth/register/begin       – Challenge for credential registration
  POST /auth/register/complete    – Verification + DB persistence
  POST /auth/login/begin          – Challenge for login
  POST /auth/login/complete       – Verification + session creation
  POST /auth/logout               – End session
  POST /auth/stepup/begin         – Step-up challenge (§2 sudo-mode)
  POST /auth/stepup/complete      – Confirm step-up
  GET  /auth/login                – Login HTML page
  GET  /auth/register             – Registration HTML page
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import uuid
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from quart import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func, select, update

from arborpress.auth.stepup import (
    STEPUP_POLICIES,
    assert_stepup,
    grant_stepup,
    revoke_stepup,
)
from arborpress.auth.webauthn import WebAuthnService
from arborpress.core.audit import write_audit_event
from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.core.validators import is_valid_username
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.auth")
# Audit logger kept for direct use in non-DB paths (file-only, no DB write needed)
_audit = logging.getLogger("arborpress.audit")

auth_bp = Blueprint("auth", __name__, template_folder="../../templates")

# WebAuthn endpoints that *only* accept JSON bodies (§10 Content-Type enforcement)
_JSON_API_PATHS = frozenset({
    "/auth/register/begin",
    "/auth/register/complete",
    "/auth/login/begin",
    "/auth/login/complete",
    "/auth/stepup/begin",
    "/auth/stepup/complete",
    "/auth/stepup/totp/complete",
    "/auth/mfa/webauthn/begin",
    "/auth/mfa/webauthn/complete",
    "/auth/mfa/totp/complete",
    "/auth/totp/begin",
    "/auth/totp/complete",
    "/auth/recovery/complete",
})


def _origin_from_headers(origin: str | None, referer: str | None) -> str:
    """Return a canonical request origin from browser headers, if present."""
    if origin:
        return origin
    if referer:
        parsed = urlparse(referer)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def _validate_json_origin(expected_origin: str) -> None:
    origin = _origin_from_headers(
        request.headers.get("Origin"), request.headers.get("Referer")
    )
    if origin != expected_origin:
        abort(403, "A matching Origin or Referer is required")


@auth_bp.before_request
async def _auth_csrf_check() -> None:
    """CSRF + Content-Type protection for auth endpoints (§10).

    JSON API endpoints (WebAuthn): enforce ``Content-Type: application/json``
    and validate Origin/Referer instead of a CSRF token.
    HTML form endpoints: standard CSRF-token check via ``validate_csrf()``.
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    content_type = request.content_type or ""
    if request.path in _JSON_API_PATHS:
        # Enforce JSON body – prevents cross-origin form-encoded attacks
        if "application/json" not in content_type:
            abort(415, "Content-Type: application/json required")
        # Origin/Referer guard (replaces CSRF token for XHR/fetch)
        cfg = get_settings()
        from arborpress.auth.webauthn import resolve_origin
        expected_origin = resolve_origin(cfg.web.base_url)
        _validate_json_origin(expected_origin)
        return
    if "application/json" in content_type:
        # Non-enumerated JSON path – apply Origin check as sanity guard
        cfg = get_settings()
        from arborpress.auth.webauthn import resolve_origin
        expected_origin = resolve_origin(cfg.web.base_url)
        _validate_json_origin(expected_origin)
        return
    await validate_csrf()


# Auth-Endpunkte, die dem IP-basierten Rate-Limit unterliegen (§10)
_RATE_LIMITED_PATHS = frozenset({
    "/auth/breakglass",
    "/auth/login/begin",
    "/auth/login/complete",
    "/auth/register/begin",
    "/auth/register/complete",
    "/auth/stepup/begin",
    "/auth/stepup/complete",
    "/auth/stepup/totp/complete",
    "/auth/mfa/webauthn/begin",
    "/auth/mfa/totp/complete",
    "/auth/totp/begin",
    "/auth/totp/complete",
    "/auth/mfa/webauthn/complete",
    "/auth/recovery/complete",
    "/auth/recovery/redeem",
})

_AUTHENTICATED_ENDPOINTS = frozenset({
    "auth.register_page",
    "auth.register_begin",
    "auth.register_complete",
    "auth.stepup_begin",
    "auth.stepup_complete",
    "auth.stepup_totp_complete",
    "auth.stepup_revoke",
    "auth.totp_enrollment_begin",
    "auth.totp_enrollment_complete",
    "auth.totp_remove",
    "auth.webauthn_credential_remove",
    "auth.account_security_page",
    "auth.recovery_complete",
})


@auth_bp.before_request
async def _rate_limit_auth():
    """IP-based rate limiting for sensitive auth endpoints (§10).

    Uses ``AuthSettings.auth_rate_limit`` (default: ``"10/minute"``).
    Returns HTTP 429 + ``Retry-After: 60`` if the limit is exceeded.
    """
    if request.method != "POST" or request.path not in _RATE_LIMITED_PATHS:
        return

    from arborpress.web.ratelimit import check_rate_limit

    cfg = get_settings()
    ip = request.remote_addr or "unknown"
    if not check_rate_limit(f"auth:{ip}", cfg.auth.auth_rate_limit):
        from quart import Response

        return Response(
            '{"error": "Zu viele Anfragen \u2013 bitte warten"}',
            status=429,
            headers={"Content-Type": "application/json", "Retry-After": "60"},
        )


@auth_bp.before_request
async def _auth_session_guard() -> None:
    """Honor DB session revocation before account-bound auth operations."""
    if request.endpoint not in _AUTHENTICATED_ENDPOINTS or not session.get("user_id"):
        return
    from arborpress.auth.sessions import refresh_session_identity

    async for db in get_db_session():
        if await refresh_session_identity(db, session) is None:
            session.clear()
            await db.commit()
            abort(401, "Session expired or revoked")
        await db.commit()
        break


def _get_webauthn() -> WebAuthnService:
    """Synchronous fallback factory (config-only, no DB-backed policy).

    Kept for code paths that cannot easily await; new code should use
    :func:`_get_webauthn_async` so admin policy and the RP-ID change
    guard apply.
    """
    cfg = get_settings()
    from arborpress.auth.webauthn import resolve_origin, resolve_rp_id

    return WebAuthnService(
        rp_id=resolve_rp_id(cfg.web.base_url),
        rp_name="ArborPress",
        origin=resolve_origin(cfg.web.base_url),
    )


async def _get_webauthn_async() -> WebAuthnService:
    """Build a fully configured WebAuthnService from DB site_settings.

    Aborts with HTTP 503 if the deployment URL changed and the
    operator has not confirmed the new RP ID via /admin/webauthn
    (W3C WebAuthn L3 §5.3 RP ID lock-out protection).
    """
    from arborpress.auth.webauthn import RPIDChangeBlocked, build_webauthn_service

    cfg = get_settings()
    async for db in get_db_session():
        try:
            return await build_webauthn_service(db, cfg.web.base_url)
        except RPIDChangeBlocked as exc:
            log.error("WebAuthn unavailable: %s", exc)
            from quart import Response
            abort(Response(
                json.dumps({
                    "error": "rp_id_change_blocked",
                    "message": str(exc),
                    "current_rp_id": exc.current,
                    "locked_rp_id": exc.expected,
                    "credential_count": exc.credential_count,
                }),
                status=503,
                headers={"Content-Type": "application/json"},
            ))
    # Should never reach here – get_db_session yields at least once.
    return _get_webauthn()


# ---------------------------------------------------------------------------
# HTML-Seiten
# ---------------------------------------------------------------------------


@auth_bp.get("/login")
async def login_page():
    from arborpress.web.routes.sso import get_configured_providers
    return await render_template(
        "auth/login.html",
        sso_providers=get_configured_providers(),
        install_enrollment_available=bool(session.get("install_enrollment")),
    )


@auth_bp.get("/recovery")
async def recovery_ticket_page():
    """The account recovery ticket is a one-time bearer proof."""
    return await render_template("auth/recovery.html", ticket_error=None)


@auth_bp.post("/recovery/redeem")
async def recovery_ticket_redeem():
    """Consume an administrator-issued ticket into a restricted session."""
    from arborpress.auth.pending import (
        RECOVERY_AUTHORIZATION_PURPOSE,
        consume_pending,
        create_pending,
        utcnow_naive,
    )
    from arborpress.auth.sessions import (
        RECOVERY_PURPOSE,
        RECOVERY_SESSION_PURPOSE,
        RECOVERY_SESSION_TTL_SECONDS,
        create_user_session,
    )
    from arborpress.models.user import AuthPending

    form = await request.form
    ticket = str(form.get("ticket") or "").strip()
    reason = "malformed"
    locator = ""
    secret = b""
    try:
        if len(ticket) > 128 or ticket.count(".") != 1:
            raise ValueError("ticket format")
        locator, secret_text = ticket.split(".", 1)
        if str(uuid.UUID(locator)) != locator:
            raise ValueError("ticket locator")
        if len(secret_text) != 43:
            raise ValueError("ticket secret")
        secret = base64.b64decode(
            secret_text + "=", altchars=b"-_", validate=True
        )
        if (
            len(secret) != 32
            or base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii")
            != secret_text
        ):
            raise ValueError("ticket secret")
    except (ValueError, TypeError):
        reason = "invalid_format"

    async for db in get_db_session():
        from arborpress.auth.policy import lock_user_for_credential_change

        if reason != "malformed":
            await write_audit_event(
                event_type="recovery_ticket_failed", outcome="failure",
                detail=f"purpose={RECOVERY_PURPOSE};reason={reason}", db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html", ticket_error="Dieses Recovery-Ticket ist ungültig."
            ), 400

        preview = await db.get(AuthPending, locator)
        if preview is None or preview.purpose != RECOVERY_AUTHORIZATION_PURPOSE:
            await write_audit_event(
                event_type="recovery_ticket_failed", outcome="failure",
                detail=f"purpose={RECOVERY_PURPOSE};reason=invalid_locator", db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html", ticket_error="Dieses Recovery-Ticket ist ungültig."
            ), 400

        user_id = str(preview.user_id or "")
        if not user_id:
            await write_audit_event(
                event_type="recovery_ticket_failed", outcome="failure",
                detail=f"purpose={RECOVERY_PURPOSE};reason=invalid_target", db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html", ticket_error="Dieses Recovery-Ticket ist ungültig."
            ), 400

        user = await lock_user_for_credential_change(db, user_id)
        pending = (await db.execute(
            select(AuthPending).where(AuthPending.id == locator).with_for_update()
        )).scalar_one_or_none()
        if (
            user is None
            or not user.is_active
            or pending is None
            or pending.user_id != user_id
            or pending.purpose != RECOVERY_AUTHORIZATION_PURPOSE
        ):
            await write_audit_event(
                event_type="recovery_ticket_failed", outcome="failure",
                actor_id=user_id or None, target_id=user_id or None,
                detail=f"purpose={RECOVERY_PURPOSE};reason=invalid_target", db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html", ticket_error="Dieses Recovery-Ticket ist ungültig."
            ), 400

        try:
            authorization_context = json.loads(pending.context or "{}")
        except (TypeError, ValueError):
            authorization_context = {}
        if not isinstance(authorization_context, dict):
            authorization_context = {}
        if pending.consumed_at is not None:
            event_type = (
                "recovery_ticket_superseded"
                if authorization_context.get("superseded")
                else "recovery_ticket_replay"
            )
            await write_audit_event(
                event_type=event_type, outcome="blocked",
                actor_id=user_id, target_id=user_id,
                detail=f"purpose={RECOVERY_PURPOSE};authorization_id={pending.id}",
                db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html",
                ticket_error="Dieses Ticket wurde bereits verwendet oder ersetzt.",
            ), 409
        if pending.expires_at.replace(tzinfo=None) <= utcnow_naive():
            pending.consumed_at = utcnow_naive()
            await write_audit_event(
                event_type="recovery_ticket_expired", outcome="failure",
                actor_id=user_id, target_id=user_id,
                detail=f"purpose={RECOVERY_PURPOSE};authorization_id={pending.id}",
                db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html", ticket_error="Dieses Recovery-Ticket ist abgelaufen."
            ), 410
        if (
            authorization_context.get("purpose") != RECOVERY_PURPOSE
            or not authorization_context.get("authorized_by")
            or not isinstance(authorization_context.get("baseline_webauthn_ids"), list)
            or not isinstance(authorization_context.get("baseline_totp_ids"), list)
            or pending.challenge is None
            or not hmac.compare_digest(
                bytes(pending.challenge), hashlib.sha256(secret).digest()
            )
        ):
            await write_audit_event(
                event_type="recovery_ticket_failed", outcome="failure",
                actor_id=user_id, target_id=user_id,
                detail=f"purpose={RECOVERY_PURPOSE};reason=proof_or_context_invalid",
                db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html", ticket_error="Dieses Recovery-Ticket ist ungültig."
            ), 400

        authorization = await consume_pending(
            db,
            pending_id=locator,
            purpose=RECOVERY_AUTHORIZATION_PURPOSE,
            user_id=user_id,
        )
        if authorization is None:
            await write_audit_event(
                event_type="recovery_ticket_replay", outcome="blocked",
                actor_id=user_id, target_id=user_id,
                detail=f"purpose={RECOVERY_PURPOSE};authorization_id={locator}",
                db=db,
            )
            await db.commit()
            return await render_template(
                "auth/recovery.html", ticket_error="Dieses Ticket wurde bereits verwendet."
            ), 409

        recovery_context = {
            "session_id": "",
            "recovery_purpose": RECOVERY_PURPOSE,
            "authorized_by": str(authorization_context["authorized_by"]),
            "baseline_webauthn_ids": [
                str(value) for value in authorization_context["baseline_webauthn_ids"]
            ],
            "baseline_totp_ids": [
                str(value) for value in authorization_context["baseline_totp_ids"]
            ],
            "recovery_webauthn_ids": [],
            "recovery_totp_ids": [],
            "auth_method": "recovery_ticket",
        }
        await create_user_session(
            db, user, auth_method="recovery", assurance_level="recovery",
            recovery_only=True, ttl_seconds=RECOVERY_SESSION_TTL_SECONDS,
        )
        recovery_context["session_id"] = str(session.get("session_id") or "")
        recovery_pending = await create_pending(
            db,
            purpose=RECOVERY_SESSION_PURPOSE,
            user_id=user_id,
            ttl_seconds=RECOVERY_SESSION_TTL_SECONDS,
            context=recovery_context,
        )
        session["recovery_id"] = recovery_pending.id
        await write_audit_event(
            event_type="recovery_ticket_redeemed", outcome="success",
            actor_id=user_id, target_id=user_id,
            detail=f"purpose={RECOVERY_PURPOSE};authorization_id={authorization.id}",
            db=db,
        )
        await write_audit_event(
            event_type="recovery_proof_succeeded", outcome="success",
            actor_id=user_id, target_id=user_id,
            detail=f"purpose={RECOVERY_PURPOSE};method=recovery_ticket",
            db=db,
        )
        await write_audit_event(
            event_type="recovery_session_created", outcome="success",
            actor_id=user_id, target_id=user_id,
            detail=(
                f"purpose={RECOVERY_PURPOSE};ttl_seconds="
                f"{RECOVERY_SESSION_TTL_SECONDS};authorized_by="
                f"{recovery_context['authorized_by']}"
            ),
            db=db,
        )
        await write_audit_event(
            event_type="recovery_started", outcome="success",
            actor_id=user_id, target_id=user_id,
            detail=f"purpose={RECOVERY_PURPOSE};method=recovery_ticket",
            db=db,
        )
        await db.commit()
        return redirect(url_for("auth.account_security_page"))


@auth_bp.get("/register")
async def register_page():
    install = session.get("install_enrollment") or {}
    username = session.get("user_name") or install.get("username") or ""
    if not username:
        return redirect(url_for("auth.login_page"))
    return await render_template(
        "auth/register.html",
        prefill_username=username,
        initial_enrollment=bool(install),
        recovery_only=bool(session.get("recovery_only")),
    )


# ---------------------------------------------------------------------------
# WebAuthn-Registrierung
# ---------------------------------------------------------------------------


@auth_bp.post("/register/begin")
async def register_begin():
    """Begin install enrollment or a stepped-up enrollment for the current user."""
    data = await request.get_json() or {}
    wa = await _get_webauthn_async()
    user_id = str(session.get("user_id") or "") or None
    recovery_only = bool(session.get("recovery_only"))
    if user_id and not recovery_only:
        try:
            await assert_stepup(
                session, user_id, "add_webauthn_credential", target=user_id
            )
        except PermissionError:
            abort(403, "Fresh step-up for this account is required")
    async for db in get_db_session():
        from arborpress.auth.pending import create_pending
        from arborpress.auth.sessions import get_active_recovery_state
        from arborpress.core.site_settings import get_webauthn_settings
        from arborpress.models.user import User, WebAuthnCredential

        user = None
        recovery_state = None
        recovery_context = {}
        planned: dict[str, str] = {}
        existing: list[bytes] = []
        if session.get("user_id"):
            user_id = str(session["user_id"])
            user = await db.get(User, user_id)
            if user is None or not user.is_active:
                abort(401)
            if recovery_only:
                recovery_state = await get_active_recovery_state(db, session)
                if recovery_state is None:
                    abort(403)
                _, recovery_context = recovery_state
            settings = await get_webauthn_settings(db)
            count_stmt = select(func.count()).select_from(WebAuthnCredential).where(
                WebAuthnCredential.user_id == user_id
            )
            if recovery_only:
                baseline = [
                    str(value) for value in recovery_context.get("baseline_webauthn_ids", [])
                ]
                if baseline:
                    count_stmt = count_stmt.where(WebAuthnCredential.id.not_in(baseline))
            count = (await db.execute(count_stmt)).scalar_one() or 0
            limit = min(100, int(settings.get("webauthn_credential_limit", 10)))
            if count >= limit:
                await write_audit_event(
                    event_type="auth_lockout_prevention", outcome="blocked",
                    actor_id=user_id, target_id=user_id,
                    detail="webauthn_credential_limit", db=db,
                )
                await db.commit()
                abort(409, "Credential-Limit erreicht")
            rows = await db.execute(select(WebAuthnCredential.credential_id).where(
                WebAuthnCredential.user_id == user_id
            ))
            existing = [row[0] for row in rows.fetchall()]
        else:
            install = session.get("install_enrollment")
            if not install:
                abort(403, "Registration requires the install token or an authenticated account")
            from arborpress.core.config import is_installed
            if is_installed():
                session.pop("install_enrollment", None)
                abort(403, "Initial installation is already complete")
            if float(install.get("expires_at", 0)) <= datetime.now(UTC).timestamp():
                session.pop("install_enrollment", None)
                abort(403, "Install enrollment expired; rerun the install wizard")
            username = str(install.get("username") or "").strip()
            display_name = str(install.get("display_name") or username).strip()[:128]
            email = str(install.get("email") or "").strip().lower()
            if not username or not is_valid_username(username):
                abort(400, "Invalid initial username")
            found = (await db.execute(select(User).where(
                (func.lower(User.username) == username.lower())
                | (func.lower(User.email) == email if email else False)
            ))).scalar_one_or_none()
            if found:
                abort(409, "Initial account already exists")
            planned = {
                "username": username,
                "display_name": display_name or username,
                "email": email,
            }

        enrollment_kind = str(data.get("enrollment_kind") or "security_key")
        if enrollment_kind not in {"security_key", "passkey"}:
            abort(400, "Invalid enrollment kind")
        attachment = "cross-platform" if enrollment_kind == "security_key" else None
        username = user.username if user is not None else planned["username"]
        display_name = user.display_name if user is not None else planned["display_name"]
        # Initial identity is opaque to the authenticator and not persisted yet.
        handle_source = user_id or secrets.token_hex(16)
        user_handle = urlsafe_b64encode(handle_source.encode()).rstrip(b"=")
        opts = wa.generate_registration_options(
            user_id=user_handle,
            user_name=username,
            user_display_name=display_name or username,
            existing_credentials=existing,
            authenticator_attachment=attachment,
        )
        settings = await get_webauthn_settings(db)
        pending = await create_pending(
            db,
            purpose="webauthn_enrollment" if user_id else "install_enrollment",
            user_id=user_id,
            challenge=opts.challenge,
            ttl_seconds=int(settings.get("challenge_ttl_seconds", 300)),
            label=str(data.get("label") or "").strip()[:128] or None,
            username=planned.get("username"),
            display_name=planned.get("display_name"),
            email=planned.get("email"),
            context={
                "enrollment_kind": enrollment_kind,
                "recovery_only": recovery_only,
                "session_id": str(session.get("session_id") or "") if recovery_only else None,
                "recovery_id": str(session.get("recovery_id") or "") if recovery_only else None,
                "install_nonce": (session.get("install_enrollment") or {}).get("nonce"),
            },
        )
        session["register_pending_id"] = pending.id
        if recovery_only:
            await write_audit_event(
                event_type="recovery_enrollment_begin", outcome="success",
                actor_id=user_id, target_id=user_id, db=db,
            )
        await db.commit()
    from webauthn.helpers import options_to_json
    return jsonify(json.loads(options_to_json(opts))), 200


@auth_bp.post("/register/complete")
async def register_complete():
    """Persist a credential or initial identity only after UV verification."""
    from webauthn.helpers import parse_registration_credential_json

    raw = await request.get_json()
    pending_id = session.pop("register_pending_id", None)
    if not pending_id:
        abort(400, "Keine aktive Registrierungssession")

    wa = await _get_webauthn_async()
    async for db in get_db_session():
        from arborpress.auth.pending import consume_pending
        from arborpress.core.site_settings import get_webauthn_settings
        from arborpress.models.user import (
            AccountType,
            AuthPending,
            User,
            UserRole,
            WebAuthnCredential,
        )

        pending_preview = await db.get(AuthPending, pending_id)
        if pending_preview is None:
            abort(400, "Enrollment abgelaufen")
        user_id = pending_preview.user_id
        purpose = "webauthn_enrollment" if user_id else "install_enrollment"
        if user_id and str(session.get("user_id") or "") != user_id:
            abort(403)
        preview_context = json.loads(pending_preview.context or "{}")
        if preview_context.get("recovery_only"):
            from arborpress.auth.sessions import get_active_recovery_state

            recovery_state = await get_active_recovery_state(db, session)
            if (
                recovery_state is None
                or preview_context.get("session_id") != session.get("session_id")
                or preview_context.get("recovery_id") != session.get("recovery_id")
            ):
                abort(403, "Recovery enrollment is bound to another session")
        if not user_id:
            from arborpress.core.config import is_installed
            install = session.get("install_enrollment") or {}
            if (
                is_installed()
                or not install
                or float(install.get("expires_at", 0)) <= datetime.now(UTC).timestamp()
                or preview_context.get("install_nonce") != install.get("nonce")
            ):
                abort(403, "Initial installation trust expired or was consumed")
        pending = await consume_pending(
            db, pending_id=pending_id, purpose=purpose, user_id=user_id
        )
        if pending is None or pending.challenge is None:
            abort(400, "Enrollment abgelaufen oder bereits verwendet")
        await db.commit()
        try:
            credential = parse_registration_credential_json(raw)
            verification = wa.verify_registration(
                credential, expected_challenge=pending.challenge
            )
            if not verification.user_verified:
                raise ValueError("user verification required")
        except Exception as exc:
            await write_audit_event(
                event_type="mfa_enrollment_failure", outcome="failure",
                actor_id=user_id, target_id=user_id,
                detail="webauthn_verification_failed", db=db,
            )
            if preview_context.get("recovery_only"):
                await write_audit_event(
                    event_type="recovery_enrollment_failed", outcome="failure",
                    actor_id=str(user_id), target_id=str(user_id),
                    detail="purpose=account_credential_recovery;method=webauthn",
                    db=db,
                )
            await db.commit()
            log.warning("WebAuthn registration verification failed: %s", exc)
            abort(400, "Registrierung fehlgeschlagen")

        if user_id:
            from arborpress.auth.policy import lock_user_for_credential_change

            user = await lock_user_for_credential_change(db, user_id)
        else:
            user = None
        if user_id and user is None:
            abort(404)
        if preview_context.get("recovery_only"):
            from arborpress.auth.sessions import get_active_recovery_state

            recovery_state = await get_active_recovery_state(db, session)
            if recovery_state is None:
                await db.commit()
                abort(403, "Recovery session expired during enrollment")
            _, recovery_context = recovery_state
        if user is None:
            if not pending.username:
                abort(400, "Initial identity missing")
            from arborpress.core.config import is_installed
            if is_installed():
                abort(409, "Initial installation is already complete")
            existing_admin = (await db.execute(select(User).where(
                User.role == UserRole.ADMIN,
                User.is_active.is_(True),
            ))).scalars().first()
            if existing_admin is not None:
                abort(409, "An administrator already exists")
            identity_conflict = (await db.execute(select(User).where(
                (func.lower(User.username) == pending.username.lower())
                | (
                    func.lower(User.email) == pending.email.lower()
                    if pending.email else False
                )
            ))).scalars().first()
            if identity_conflict is not None:
                abort(409, "Initial username or email is already in use")
            user = User(
                username=pending.username,
                display_name=pending.display_name or pending.username,
                email=pending.email or None,
                account_type=AccountType.PUBLIC,
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(user)
            await db.flush()
        settings = await get_webauthn_settings(db)
        count_stmt = select(func.count()).select_from(WebAuthnCredential).where(
            WebAuthnCredential.user_id == str(user.id)
        )
        if preview_context.get("recovery_only"):
            baseline = [
                str(value) for value in recovery_context.get("baseline_webauthn_ids", [])
            ]
            if baseline:
                count_stmt = count_stmt.where(WebAuthnCredential.id.not_in(baseline))
        count = (await db.execute(count_stmt)).scalar_one() or 0
        limit = min(100, int(settings.get("webauthn_credential_limit", 10)))
        if count >= limit:
            await write_audit_event(
                event_type="auth_lockout_prevention", outcome="blocked",
                actor_id=str(user.id), target_id=str(user.id),
                detail="webauthn_credential_limit_at_complete", db=db,
            )
            await db.commit()
            abort(409, "Credential-Limit erreicht")
        label = (pending.label or str(raw.get("label") or "Security key").strip())[:128]
        label = label or "Security key"
        raw_transports = raw.get("transports", [])
        transports = (
            [item for item in raw_transports if item in {"usb", "nfc", "ble", "internal", "hybrid"}]
            if isinstance(raw_transports, list) else []
        )
        attachment = raw.get("authenticatorAttachment")
        if attachment not in {"platform", "cross-platform"}:
            attachment = None
        device_type = getattr(verification, "credential_device_type", None)
        backup_eligible = (
            None if device_type is None
            else getattr(device_type, "value", None) == "multi_device"
        )
        backup_state_value = getattr(verification, "credential_backed_up", None)
        cred = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=str(verification.aaguid) if verification.aaguid is not None else None,
            label=label,
            transports=json.dumps(transports),
            transport=transports[0] if transports else None,
            authenticator_attachment=attachment,
            is_platform=attachment == "platform" if attachment else None,
            backup_eligible=backup_eligible,
            backup_state=bool(backup_state_value) if backup_state_value is not None else None,
            uv_capable=True,
            verification_status=(
                "recovery_pending" if preview_context.get("recovery_only") else "verified_uv"
            ),
        )
        db.add(cred)
        await db.flush()
        if preview_context.get("recovery_only"):
            from arborpress.auth.sessions import append_recovery_credential_id

            if not await append_recovery_credential_id(
                db,
                user_id=str(user.id),
                recovery_id=str(session.get("recovery_id") or ""),
                session_id=str(session.get("session_id") or ""),
                credential_type="webauthn",
                credential_id=str(cred.id),
            ):
                abort(403, "Recovery state changed during credential registration")
        await write_audit_event(
            event_type="webauthn_credential_added", outcome="success",
            actor_id=str(user.id), actor_name=user.username,
            target_id=str(cred.id), detail=f"label={label}", db=db,
        )
        initial_enrollment = purpose == "install_enrollment"
        recovery_enrollment = bool(
            json.loads(pending.context or "{}").get("recovery_only")
        )
        if recovery_enrollment:
            await write_audit_event(
                event_type="recovery_credential_added", outcome="success",
                actor_id=str(user.id), target_id=str(cred.id),
                detail="credential_type=webauthn;purpose=account_credential_recovery",
                db=db,
            )
            if await get_active_recovery_state(db, session) is None:
                abort(403, "Recovery session expired during enrollment")
        await db.commit()

    if initial_enrollment:
        from arborpress.core.config import install_token_path, installed_marker_path

        marker = installed_marker_path()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("installed\n", encoding="utf-8")
        token_path = install_token_path()
        if token_path.exists():
            token_path.unlink()

    from arborpress.core.events import emit
    if not session.get("user_id"):
        session.clear()
    await emit("auth.credential_registered", user_id=str(user.id), label=label)

    return jsonify({
        "status": "ok", "label": label,
        "recovery_only": bool(session.get("recovery_only")),
    }), 201


# ---------------------------------------------------------------------------
# WebAuthn-Login
# ---------------------------------------------------------------------------


@auth_bp.post("/login/begin")
async def login_begin():
    """Username-first login: only credentials belonging to the resolved user."""
    data = await request.get_json() or {}
    identifier = str(data.get("identifier") or data.get("user_name") or "").strip()
    if not identifier or len(identifier) > 254:
        abort(400, "identifier required")
    wa = await _get_webauthn_async()
    async for db in get_db_session():
        from arborpress.auth.pending import create_pending
        from arborpress.core.site_settings import get_webauthn_settings
        from arborpress.models.user import User, WebAuthnCredential

        user = (await db.execute(select(User).where(
            (func.lower(User.username) == identifier.lower())
            | (func.lower(User.email) == identifier.lower())
        ))).scalar_one_or_none()
        allowed: list[bytes] = []
        if user and user.is_active:
            rows = await db.execute(select(WebAuthnCredential.credential_id).where(
                WebAuthnCredential.user_id == str(user.id),
                WebAuthnCredential.uv_capable.is_not(False),
                WebAuthnCredential.verification_status != "recovery_pending",
            ))
            allowed = [row[0] for row in rows.fetchall()]
        else:
            user = None
        opts = wa.generate_authentication_options(allowed_credentials=allowed)
        settings = await get_webauthn_settings(db)
        pending = await create_pending(
            db, purpose="webauthn_login", user_id=str(user.id) if user else None,
            challenge=opts.challenge,
            ttl_seconds=int(settings.get("challenge_ttl_seconds", 300)),
            context={"identifier_supplied": True},
        )
        session["login_pending_id"] = pending.id
        await db.commit()
    from webauthn.helpers import options_to_json
    return jsonify(json.loads(options_to_json(opts))), 200


@auth_bp.post("/login/complete")
async def login_complete():
    """Verify the assertion against the exact account from login begin."""
    from webauthn.helpers import parse_authentication_credential_json

    raw = await request.get_json()
    pending_id = session.pop("login_pending_id", None)
    if not pending_id or not isinstance(raw, dict):
        abort(400, "Keine aktive Auth-Session")
    wa = await _get_webauthn_async()
    async for db in get_db_session():
        from arborpress.auth.pending import consume_pending
        from arborpress.auth.sessions import create_user_session
        from arborpress.auth.webauthn import decode_credential_id
        from arborpress.models.user import AuthPending, User, WebAuthnCredential

        preview = await db.get(AuthPending, pending_id)
        if preview is None or preview.user_id is None:
            abort(401, "Authentifizierung fehlgeschlagen")
        user_id = str(preview.user_id)
        pending = await consume_pending(
            db, pending_id=pending_id, purpose="webauthn_login", user_id=user_id
        )
        if pending is None or pending.challenge is None:
            abort(400, "Challenge abgelaufen oder bereits verwendet")
        # Commit one-shot consumption before assertion verification so every
        # failure path is non-replayable.
        await db.commit()
        try:
            credential_id = decode_credential_id(str(raw.get("rawId") or raw.get("id") or ""))
            if raw.get("id") and decode_credential_id(str(raw["id"])) != credential_id:
                raise ValueError("credential id mismatch")
        except ValueError:
            abort(401, "Authentifizierung fehlgeschlagen")
        db_cred = (await db.execute(select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.uv_capable.is_not(False),
            WebAuthnCredential.verification_status != "recovery_pending",
        ))).scalar_one_or_none()
        if db_cred is None:
            await write_audit_event(
                event_type="login_failure",
                outcome="failure",
                ip=request.remote_addr,
                actor_id=user_id,
                target_id=user_id,
                detail="credential_not_allowed_for_pending_user",
                db=db,
            )
            await db.commit()
            abort(401, "Authentifizierung fehlgeschlagen")

        user = await db.get(User, db_cred.user_id)
        if user is None or not user.is_active:
            await write_audit_event(
                event_type="login_failure",
                outcome="failure",
                actor_id=str(db_cred.user_id),
                target_id=str(db_cred.user_id),
                ip=request.remote_addr,
                detail="account_inactive",
                db=db,
            )
            await db.commit()
            abort(401, "Konto nicht aktiv")

        # §2 Account-Sperre prüfen (Lockout nach N Fehlversuchen)
        _now = datetime.now(UTC)
        # locked_until aus DB kann tz-naive sein – Vergleich ohne tz-Info
        _locked_until = user.locked_until
        if _locked_until is not None:
            _lu = _locked_until.replace(tzinfo=None) if _locked_until.tzinfo else _locked_until
            _nu = _now.replace(tzinfo=None)
            if _lu > _nu:
                await write_audit_event(
                    event_type="login_blocked",
                    outcome="blocked",
                    actor_id=str(user.id),
                    actor_name=user.username,
                    ip=request.remote_addr,
                    detail=f"locked_until={_locked_until.isoformat()}",
                    db=db,
                )
                await db.commit()
                abort(423, "Konto temporär gesperrt – bitte später erneut versuchen")

        try:
            credential = parse_authentication_credential_json(raw)
            verification = wa.verify_authentication(
                credential=credential,
                expected_challenge=pending.challenge,
                credential_public_key=db_cred.public_key,
                current_sign_count=db_cred.sign_count,
            )
        except Exception as exc:
            # §2 Fehlversuchs-Counter erhöhen, ggf. Konto sperren
            _cfg = get_settings()
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if (
                _cfg.auth.lockout_threshold > 0
                and user.failed_login_count >= _cfg.auth.lockout_threshold
            ):
                _lock_at = datetime.now(UTC).replace(tzinfo=None)
                user.locked_until = _lock_at + timedelta(seconds=_cfg.auth.lockout_duration)
                _detail = f"attempt={user.failed_login_count} account_locked"
            else:
                _detail = f"attempt={user.failed_login_count}"
            db.add(user)
            await write_audit_event(
                event_type="login_failure",
                outcome="failure",
                actor_id=str(user.id),
                actor_name=user.username,
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                detail=_detail,
                db=db,
            )
            await db.commit()
            log.warning("WebAuthn auth failed for user=%s: %s", user.username, exc)
            await emit_fail(user.id)
            abort(401, "Authentifizierung fehlgeschlagen")

        # §2 Fehlversuchs-Counter zurücksetzen nach erfolgreichem Login
        if user.failed_login_count or user.locked_until:
            user.failed_login_count = 0
            user.locked_until = None
            db.add(user)

        db_cred.sign_count = (
            verification.new_sign_count if wa.counter_strict
            else max(db_cred.sign_count, verification.new_sign_count)
        )
        db_cred.last_used_at = datetime.now(UTC).replace(tzinfo=None)
        await create_user_session(
            db, user,
            auth_method="webauthn_uv",
            assurance_level="phishing_resistant_uv",
        )

        # §16 Erfolgreichen Login in Audit-Log schreiben
        await write_audit_event(
            event_type="login_success",
            outcome="success",
            actor_id=str(user.id),
            actor_name=user.username,
            target_id=str(user.id),
            detail="method=webauthn_uv assurance=phishing_resistant_uv",
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            db=db,
        )
        await db.commit()

    from arborpress.core.events import emit
    await emit("auth.login_success", user_id=str(user.id))

    return jsonify({"status": "ok", "user": user.username}), 200


async def emit_fail(user_id: object) -> None:
    from arborpress.core.events import emit
    await emit("auth.login_failure", user_id=str(user_id))


# ---------------------------------------------------------------------------
# Password/SSO second factor and TOTP lifecycle
# ---------------------------------------------------------------------------


@auth_bp.get("/mfa")
async def mfa_page():
    pending_id = session.get("password_mfa_pending_id") or session.get("sso_mfa_pending_id")
    if not pending_id:
        return redirect(url_for("auth.login_page"))
    async for db in get_db_session():
        from arborpress.auth.pending import as_utc_naive, utcnow_naive
        from arborpress.models.user import AuthPending
        pending = await db.get(AuthPending, pending_id)
        if (
            pending is None
            or pending.purpose not in {"password_mfa", "sso_mfa"}
            or pending.consumed_at is not None
            or as_utc_naive(pending.expires_at) <= utcnow_naive()
        ):
            session.pop("password_mfa_pending_id", None)
            session.pop("sso_mfa_pending_id", None)
            return redirect(url_for("auth.login_page"))
        context = json.loads(pending.context or "{}")
        methods = context.get("methods", [])
        return await render_template("auth/mfa.html", methods=methods)


def _login_mfa_parent() -> tuple[str | None, str | None]:
    if session.get("password_mfa_pending_id"):
        return str(session["password_mfa_pending_id"]), "password_mfa"
    if session.get("sso_mfa_pending_id"):
        return str(session["sso_mfa_pending_id"]), "sso_mfa"
    return None, None


@auth_bp.post("/mfa/webauthn/begin")
async def login_mfa_webauthn_begin():
    parent_id, parent_purpose = _login_mfa_parent()
    if not parent_id or not parent_purpose:
        abort(401)
    wa = await _get_webauthn_async()
    async for db in get_db_session():
        from arborpress.auth.pending import as_utc_naive, create_pending, utcnow_naive
        from arborpress.core.site_settings import get_webauthn_settings
        from arborpress.models.user import AuthPending, WebAuthnCredential
        parent = await db.get(AuthPending, parent_id)
        if (
            parent is None or parent.purpose != parent_purpose or parent.user_id is None
            or parent.consumed_at is not None
            or as_utc_naive(parent.expires_at) <= utcnow_naive()
        ):
            abort(401)
        rows = await db.execute(select(WebAuthnCredential.credential_id).where(
            WebAuthnCredential.user_id == parent.user_id,
            WebAuthnCredential.uv_capable.is_not(False),
            WebAuthnCredential.verification_status != "recovery_pending",
        ))
        allowed = [row[0] for row in rows.fetchall()]
        if not allowed:
            abort(403)
        opts = wa.generate_authentication_options(allowed_credentials=allowed)
        settings = await get_webauthn_settings(db)
        pending = await create_pending(
            db, purpose="login_mfa_webauthn", user_id=parent.user_id,
            challenge=opts.challenge,
            ttl_seconds=int(settings.get("challenge_ttl_seconds", 300)),
            context={"parent_id": parent_id, "parent_purpose": parent_purpose},
        )
        session["login_mfa_pending_id"] = pending.id
        await db.commit()
        from webauthn.helpers import options_to_json
        return jsonify(json.loads(options_to_json(opts))), 200


@auth_bp.post("/mfa/webauthn/complete")
async def login_mfa_webauthn_complete():
    from webauthn.helpers import parse_authentication_credential_json

    raw = await request.get_json() or {}
    pending_id = session.pop("login_mfa_pending_id", None)
    if not pending_id:
        abort(401)
    wa = await _get_webauthn_async()
    async for db in get_db_session():
        from arborpress.auth.pending import consume_pending
        from arborpress.auth.sessions import create_user_session
        from arborpress.auth.webauthn import decode_credential_id
        from arborpress.models.user import AuthPending, User, WebAuthnCredential
        preview = await db.get(AuthPending, pending_id)
        if preview is None or preview.user_id is None or preview.challenge is None:
            abort(401)
        user_id = str(preview.user_id)
        pending = await consume_pending(
            db, pending_id=pending_id, purpose="login_mfa_webauthn", user_id=user_id
        )
        if pending is None:
            abort(401)
        await db.commit()
        try:
            credential_id = decode_credential_id(str(raw.get("rawId") or raw.get("id") or ""))
            if raw.get("id") and decode_credential_id(str(raw["id"])) != credential_id:
                raise ValueError("credential id mismatch")
        except ValueError:
            abort(401)
        db_cred = (await db.execute(select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.uv_capable.is_not(False),
            WebAuthnCredential.verification_status != "recovery_pending",
        ))).scalar_one_or_none()
        if db_cred is None:
            abort(401)
        try:
            credential = parse_authentication_credential_json(raw)
            verification = wa.verify_authentication(
                credential, pending.challenge, db_cred.public_key, db_cred.sign_count
            )
        except Exception:
            await write_audit_event(
                event_type="login_failure", outcome="failure", actor_id=user_id,
                target_id=user_id, detail="password_or_sso_webauthn_mfa_failed", db=db,
            )
            await db.commit()
            abort(401)
        parent_id = json.loads(pending.context or "{}").get("parent_id")
        parent_preview = await db.get(AuthPending, parent_id)
        if parent_preview is None:
            abort(401)
        parent_purpose = parent_preview.purpose
        parent = await consume_pending(
            db, pending_id=parent_id, purpose=parent_purpose, user_id=user_id
        )
        if parent is None or parent_purpose not in {"password_mfa", "sso_mfa"}:
            abort(401)
        user = await db.get(User, user_id)
        if user is None or not user.is_active or (
            parent_purpose == "sso_mfa" and user.sso_disabled
        ):
            abort(401)
        parent_context = json.loads(parent.context or "{}")
        auth_method = (
            "password+webauthn" if parent_purpose == "password_mfa"
            else f"{parent_context.get('auth_method', 'sso')}+webauthn"
        )
        db_cred.sign_count = (
            verification.new_sign_count if wa.counter_strict
            else max(db_cred.sign_count, verification.new_sign_count)
        )
        db_cred.last_used_at = datetime.now(UTC).replace(tzinfo=None)
        await create_user_session(
            db, user, auth_method=auth_method, assurance_level="multi_factor_uv"
        )
        session.pop("password_mfa_pending_id", None)
        session.pop("sso_mfa_pending_id", None)
        await write_audit_event(
            event_type="login_success", outcome="success", actor_id=user_id,
            actor_name=user.username, target_id=user_id,
            detail=f"method={auth_method} assurance=multi_factor_uv", db=db,
        )
        await db.commit()
        return jsonify({"status": "ok", "user": user.username}), 200


@auth_bp.post("/mfa/totp/complete")
async def login_mfa_totp_complete():
    data = await request.get_json() or {}
    code = str(data.get("code") or "").strip()
    parent_id, parent_purpose = _login_mfa_parent()
    if not parent_id or not parent_purpose or not code:
        abort(401)
    async for db in get_db_session():
        from arborpress.auth.mfa import TOTPService, decrypt_secret
        from arborpress.auth.pending import consume_pending
        from arborpress.auth.sessions import create_user_session
        from arborpress.models.user import AuthPending, MFADevice, MFADeviceType, User
        parent = await db.get(AuthPending, parent_id)
        if parent is None or parent.user_id is None or parent.purpose != parent_purpose:
            abort(401)
        if parent.consumed_at is not None:
            abort(401)
        user_id = str(parent.user_id)
        devices = (await db.execute(select(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
            MFADevice.verification_status.in_(("verified", "unknown")),
        ))).scalars().all()
        matched = None
        service = TOTPService()
        for device in devices:
            try:
                secret = decrypt_secret(device.secret_enc)
                if service.verify(secret, code, user_id=user_id):
                    matched = device
                    break
            except Exception:
                log.debug("Could not verify a TOTP device for user %s", user_id, exc_info=True)
                continue
        if matched is None:
            await write_audit_event(
                event_type="login_failure", outcome="failure", actor_id=user_id,
                target_id=user_id, detail="totp_mfa_failed", db=db,
            )
            await db.commit()
            abort(401, "Invalid authentication code")
        if matched.verification_status == "unknown":
            # A correct current code proves possession of a pre-migration
            # secret whose original enrollment ceremony did not record status.
            matched.verification_status = "verified"
            await write_audit_event(
                event_type="totp_legacy_confirmed", outcome="success",
                actor_id=user_id, target_id=user_id,
                detail=f"device_id={matched.id}", db=db,
            )
        pending = await consume_pending(
            db, pending_id=parent_id, purpose=parent_purpose, user_id=user_id
        )
        if pending is None:
            abort(401)
        user = await db.get(User, user_id)
        if user is None or not user.is_active or (
            parent_purpose == "sso_mfa" and user.sso_disabled
        ):
            abort(401)
        matched.last_used_at = datetime.now(UTC).replace(tzinfo=None)
        parent_context = json.loads(pending.context or "{}")
        auth_method = (
            "password+totp" if parent_purpose == "password_mfa"
            else f"{parent_context.get('auth_method', 'sso')}+totp"
        )
        await create_user_session(
            db, user, auth_method=auth_method, assurance_level="multi_factor_totp"
        )
        session.pop("password_mfa_pending_id", None)
        session.pop("sso_mfa_pending_id", None)
        await write_audit_event(
            event_type="login_success", outcome="success", actor_id=user_id,
            actor_name=user.username, target_id=user_id,
            detail=f"method={auth_method} assurance=multi_factor_totp", db=db,
        )
        await db.commit()
        return jsonify({"status": "ok", "user": user.username}), 200


@auth_bp.post("/totp/begin")
async def totp_enrollment_begin():
    user_id = str(session.get("user_id") or "")
    recovery_only = bool(session.get("recovery_only"))
    if not user_id:
        abort(401)
    data = await request.get_json() or {}
    label = str(data.get("label") or "Authenticator").strip()[:128]
    if not label:
        abort(400, "label required")
    if not recovery_only:
        try:
            await assert_stepup(
                session, user_id, "add_totp_credential", target=user_id
            )
        except PermissionError:
            abort(403, "Fresh step-up required")
    async for db in get_db_session():
        from arborpress.auth.mfa import TOTPService, encrypt_secret, get_device_limit
        from arborpress.auth.pending import create_pending
        from arborpress.auth.sessions import get_active_recovery_state
        from arborpress.models.user import MFADevice, MFADeviceType
        recovery_state = (
            await get_active_recovery_state(db, session) if recovery_only else None
        )
        if recovery_only and recovery_state is None:
            abort(403, "Recovery session expired or invalid")
        recovery_context = recovery_state[1] if recovery_state is not None else {}
        count_stmt = select(func.count()).select_from(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
        )
        if recovery_only:
            baseline = [
                str(value) for value in recovery_context.get("baseline_totp_ids", [])
            ]
            if baseline:
                count_stmt = count_stmt.where(MFADevice.id.not_in(baseline))
        count = (await db.execute(count_stmt)).scalar_one() or 0
        limit = await get_device_limit(db, MFADeviceType.TOTP)
        if count >= limit:
            await write_audit_event(
                event_type="auth_lockout_prevention", outcome="blocked",
                actor_id=user_id, target_id=user_id, detail="totp_credential_limit", db=db,
            )
            await db.commit()
            abort(409, "TOTP-Limit erreicht")
        from arborpress.core.site_settings import get_webauthn_settings
        settings = await get_webauthn_settings(db)
        service = TOTPService()
        secret = service.generate_secret()
        pending = await create_pending(
            db, purpose="totp_enrollment", user_id=user_id, label=label,
            ttl_seconds=int(settings.get("challenge_ttl_seconds", 300)),
            context={
                "secret_enc": base64.b64encode(encrypt_secret(secret)).decode("ascii"),
                "recovery_only": recovery_only,
                "session_id": str(session.get("session_id") or "") if recovery_only else None,
                "recovery_id": str(session.get("recovery_id") or "") if recovery_only else None,
            },
        )
        session["totp_enrollment_pending_id"] = pending.id
        await db.commit()
        return jsonify({
            "pending_id": pending.id,
            "provisioning_uri": service.provisioning_uri(
                secret, account_name=f"{session.get('user_name')}:{label}"
            ),
            "label": label,
            "expires_in": int(settings.get("challenge_ttl_seconds", 300)),
        }), 200


@auth_bp.post("/totp/complete")
async def totp_enrollment_complete():
    user_id = str(session.get("user_id") or "")
    pending_id = session.pop("totp_enrollment_pending_id", None)
    data = await request.get_json() or {}
    code = str(data.get("code") or "").strip()
    if not user_id or not pending_id or not code:
        abort(400)
    async for db in get_db_session():
        from arborpress.auth.mfa import TOTPService, decrypt_secret, get_device_limit
        from arborpress.auth.pending import consume_pending
        from arborpress.models.user import MFADevice, MFADeviceType
        pending = await consume_pending(
            db, pending_id=pending_id, purpose="totp_enrollment", user_id=user_id
        )
        if pending is None:
            abort(400, "Enrollment expired or already used")
        context = json.loads(pending.context or "{}")
        recovery_only = bool(context.get("recovery_only"))
        if recovery_only:
            from arborpress.auth.sessions import get_active_recovery_state

            recovery_state = await get_active_recovery_state(db, session)
            if (
                recovery_state is None
                or context.get("session_id") != session.get("session_id")
                or context.get("recovery_id") != session.get("recovery_id")
            ):
                abort(403, "Recovery enrollment is bound to another session")
        await db.commit()
        try:
            secret_enc = base64.b64decode(context["secret_enc"], validate=True)
            secret = decrypt_secret(secret_enc)
        except Exception:
            abort(400, "Enrollment expired")
        service = TOTPService()
        if not service.verify(secret, code, user_id=user_id):
            await write_audit_event(
                event_type="mfa_enrollment_failure", outcome="failure",
                actor_id=user_id, target_id=user_id, detail="totp_code_invalid", db=db,
            )
            if recovery_only:
                await write_audit_event(
                    event_type="recovery_enrollment_failed", outcome="failure",
                    actor_id=user_id, target_id=user_id,
                    detail="purpose=account_credential_recovery;method=totp",
                    db=db,
                )
            await db.commit()
            abort(400, "Invalid authenticator code")
        from arborpress.auth.policy import lock_user_for_credential_change

        user = await lock_user_for_credential_change(db, user_id)
        if user is None or not user.is_active:
            abort(401)
        if recovery_only:
            from arborpress.auth.sessions import get_active_recovery_state

            if await get_active_recovery_state(db, session) is None:
                await db.commit()
                abort(403, "Recovery session expired during enrollment")
        recovery_context = {}
        if recovery_only:
            recovery_state = await get_active_recovery_state(db, session)
            if recovery_state is None:
                await db.commit()
                abort(403, "Recovery session expired during enrollment")
            _, recovery_context = recovery_state
        count_stmt = select(func.count()).select_from(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
        )
        if recovery_only:
            baseline = [
                str(value) for value in recovery_context.get("baseline_totp_ids", [])
            ]
            if baseline:
                count_stmt = count_stmt.where(MFADevice.id.not_in(baseline))
        count = (await db.execute(count_stmt)).scalar_one() or 0
        limit = await get_device_limit(db, MFADeviceType.TOTP)
        if count >= limit:
            await write_audit_event(
                event_type="auth_lockout_prevention", outcome="blocked",
                actor_id=user_id, target_id=user_id,
                detail="totp_credential_limit_at_complete", db=db,
            )
            await db.commit()
            abort(409, "TOTP-Limit erreicht")
        device = MFADevice(
            user_id=user_id, device_type=MFADeviceType.TOTP,
            label=pending.label or "Authenticator", secret_enc=secret_enc,
            is_active=True,
            verification_status="recovery_pending" if recovery_only else "verified",
            last_used_at=datetime.now(UTC).replace(tzinfo=None),
        )
        db.add(device)
        await db.flush()
        if recovery_only:
            from arborpress.auth.sessions import append_recovery_credential_id

            if not await append_recovery_credential_id(
                db,
                user_id=user_id,
                recovery_id=str(session.get("recovery_id") or ""),
                session_id=str(session.get("session_id") or ""),
                credential_type="totp",
                credential_id=str(device.id),
            ):
                abort(403, "Recovery state changed during credential registration")
        await write_audit_event(
            event_type="totp_added", outcome="success", actor_id=user_id,
            target_id=str(device.id), detail=f"label={device.label}", db=db,
        )
        if recovery_only:
            await write_audit_event(
                event_type="recovery_credential_added", outcome="success",
                actor_id=user_id, target_id=str(device.id),
                detail="credential_type=totp;purpose=account_credential_recovery",
                db=db,
            )
            if await get_active_recovery_state(db, session) is None:
                abort(403, "Recovery session expired during enrollment")
        await db.commit()
        return jsonify({"status": "ok", "label": device.label}), 201


@auth_bp.post("/totp/<device_id>/remove")
async def totp_remove(device_id: str):
    user_id = str(session.get("user_id") or "")
    recovery_only = bool(session.get("recovery_only"))
    if not user_id:
        abort(401)
    if recovery_only:
        abort(403, "Existing TOTP credentials are retired when recovery completes")
    async for db in get_db_session():
        from arborpress.auth.policy import (
            credential_removal_decision,
            lock_user_for_credential_change,
            recovery_has_new_auth_path,
        )
        from arborpress.auth.sessions import get_active_recovery_state
        from arborpress.models.user import MFADevice, MFADeviceType
        user = await lock_user_for_credential_change(db, user_id)
        if user is None or not user.is_active:
            abort(401)
        recovery_state = (
            await get_active_recovery_state(db, session) if recovery_only else None
        )
        if recovery_only and recovery_state is None:
            abort(403, "Recovery session expired or invalid")
        evidence = None
        if not recovery_only:
            try:
                evidence = await assert_stepup(
                    session, user_id, "remove_totp_credential", target=device_id,
                    required_evidence={"webauthn": "user_verified", "totp": "otp_verified"},
                    db=db,
                )
            except PermissionError:
                await db.commit()
                abort(403, "Fresh FIDO2 or TOTP step-up required")
        device = (await db.execute(
            select(MFADevice).where(
                MFADevice.id == device_id,
                MFADevice.user_id == user_id,
                MFADevice.device_type == MFADeviceType.TOTP,
            ).with_for_update()
        )).scalar_one_or_none()
        if device is None:
            await db.commit()
            abort(404)
        if recovery_only:
            _, recovery_context = recovery_state
            baseline = {
                str(value) for value in recovery_context.get("baseline_totp_ids", [])
            }
            if (
                str(device.id) not in baseline
                or not await recovery_has_new_auth_path(
                    db, user, recovery_context, exclude_mfa_id=str(device.id)
                )
            ):
                await write_audit_event(
                    event_type="recovery_credential_removal_blocked", outcome="blocked",
                    actor_id=user_id, target_id=device_id,
                    detail="credential_type=totp;replacement_path_required",
                    db=db,
                )
                await db.commit()
                abort(409, "Erst einen neuen nutzbaren Authentifizierungspfad registrieren")
            decision = None
        else:
            decision = await credential_removal_decision(
                db, user_id=user_id, credential_type="totp",
                target_id=device_id, evidence=evidence,
            )
        if decision is not None and not decision.allowed:
            event_type = (
                "auth_lockout_prevention"
                if decision.reason in {"last_totp_requires_webauthn"}
                else "credential_removal_blocked"
            )
            await write_audit_event(
                event_type=event_type, outcome="blocked",
                actor_id=user_id, actor_name=user.username,
                target_id=device_id,
                detail=(
                    f"credential_type=totp;reason={decision.reason};"
                    f"auth_method={evidence.auth_method if evidence else 'unknown'};"
                    f"usable_totp={decision.usable_count}"
                ), db=db,
            )
            await db.commit()
            abort(
                409,
                "Mit dieser Best\u00e4tigung kann dieses TOTP-Credential nicht entfernt werden",
            )
        await db.delete(device)
        auth_method = (
            evidence.auth_method
            if evidence is not None
            else ("recovery" if recovery_only else "unknown")
        )
        assurance = (
            evidence.assurance_level
            if evidence is not None
            else ("recovery" if recovery_only else "unknown")
        )
        await write_audit_event(
            event_type="totp_removed", outcome="success", actor_id=user_id,
            actor_name=user.username, target_id=device_id,
            detail=(
                f"auth_method={auth_method};"
                f"assurance={assurance};"
                f"confirming_credential_id={evidence.confirming_credential_id if evidence else ''};"
                f"confirming_mfa_device_id={evidence.confirming_mfa_device_id if evidence else ''}"
            ), db=db,
        )
        if recovery_only:
            await write_audit_event(
                event_type="recovery_credential_removed", outcome="success",
                actor_id=user_id, target_id=device_id,
                detail="credential_type=totp;purpose=account_credential_recovery",
                db=db,
            )
        await db.commit()
        return jsonify({"status": "removed"}), 200


@auth_bp.post("/credentials/<credential_uuid>/remove")
async def webauthn_credential_remove(credential_uuid: str):
    user_id = str(session.get("user_id") or "")
    recovery_only = bool(session.get("recovery_only"))
    if not user_id:
        abort(401)
    if recovery_only:
        abort(403, "Existing FIDO2 credentials are retired when recovery completes")
    async for db in get_db_session():
        from arborpress.auth.policy import (
            credential_removal_decision,
            lock_user_for_credential_change,
            recovery_has_new_auth_path,
        )
        from arborpress.auth.sessions import get_active_recovery_state
        from arborpress.models.user import WebAuthnCredential
        user = await lock_user_for_credential_change(db, user_id)
        if user is None or not user.is_active:
            abort(401)
        recovery_state = (
            await get_active_recovery_state(db, session) if recovery_only else None
        )
        if recovery_only and recovery_state is None:
            abort(403, "Recovery session expired or invalid")
        evidence = None
        if not recovery_only:
            try:
                evidence = await assert_stepup(
                    session, user_id, "remove_webauthn_credential", target=credential_uuid,
                    required_evidence={"webauthn": "user_verified"},
                    db=db,
                )
            except PermissionError:
                await db.commit()
                abort(403, "Fresh FIDO2 step-up with user verification required")
        credential = (await db.execute(
            select(WebAuthnCredential).where(
                WebAuthnCredential.id == credential_uuid,
                WebAuthnCredential.user_id == user_id,
            ).with_for_update()
        )).scalar_one_or_none()
        if credential is None:
            await db.commit()
            abort(404)
        if recovery_only:
            _, recovery_context = recovery_state
            baseline = {
                str(value)
                for value in recovery_context.get("baseline_webauthn_ids", [])
            }
            if (
                str(credential.id) not in baseline
                or not await recovery_has_new_auth_path(
                    db, user, recovery_context, exclude_webauthn_id=str(credential.id)
                )
            ):
                await write_audit_event(
                    event_type="recovery_credential_removal_blocked", outcome="blocked",
                    actor_id=user_id, target_id=credential_uuid,
                    detail="credential_type=webauthn;replacement_path_required",
                    db=db,
                )
                await db.commit()
                abort(409, "Erst einen neuen nutzbaren Authentifizierungspfad registrieren")
            decision = None
        else:
            decision = await credential_removal_decision(
                db, user_id=user_id, credential_type="webauthn",
                target_id=credential_uuid, evidence=evidence,
            )
        if decision is not None and not decision.allowed:
            event_type = (
                "auth_lockout_prevention"
                if decision.reason == "last_webauthn_credential"
                else "credential_removal_blocked"
            )
            await write_audit_event(
                event_type=event_type, outcome="blocked",
                actor_id=user_id, actor_name=user.username,
                target_id=credential_uuid,
                detail=(
                    f"credential_type=webauthn;reason={decision.reason};"
                    f"auth_method={evidence.auth_method if evidence else 'unknown'};"
                    f"usable_webauthn={decision.usable_count}"
                ), db=db,
            )
            await db.commit()
            abort(
                409,
                "Mit dieser Best\u00e4tigung kann dieses FIDO2-Credential nicht entfernt werden",
            )
        label = credential.label
        await db.delete(credential)
        auth_method = (
            evidence.auth_method
            if evidence is not None
            else ("recovery" if recovery_only else "unknown")
        )
        assurance = (
            evidence.assurance_level
            if evidence is not None
            else ("recovery" if recovery_only else "unknown")
        )
        await write_audit_event(
            event_type="webauthn_credential_removed", outcome="success",
            actor_id=user_id, actor_name=user.username, target_id=credential_uuid,
            detail=(
                f"label={label};auth_method={auth_method};"
                f"assurance={assurance};"
                f"confirming_credential_id={evidence.confirming_credential_id if evidence else ''}"
            ), db=db,
        )
        if recovery_only:
            await write_audit_event(
                event_type="recovery_credential_removed", outcome="success",
                actor_id=user_id, target_id=credential_uuid,
                detail="credential_type=webauthn;purpose=account_credential_recovery",
                db=db,
            )
        await db.commit()
        return jsonify({"status": "removed"}), 200


@auth_bp.get("/security")
async def account_security_page():
    user_id = str(session.get("user_id") or "")
    if not user_id:
        return redirect(url_for("auth.login_page"))
    async for db in get_db_session():
        from arborpress.auth.policy import recovery_has_new_auth_path
        from arborpress.auth.sessions import get_active_recovery_state
        from arborpress.models.user import MFADevice, User, WebAuthnCredential
        user = await db.get(User, user_id)
        if user is None or not user.is_active:
            abort(401)
        credentials = (await db.execute(select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id
        ))).scalars().all()
        credentials.sort(
            key=lambda item: (
                item.authenticator_attachment != "cross-platform",
                item.created_at or datetime.min,
            )
        )
        devices = (await db.execute(select(MFADevice).where(
            MFADevice.user_id == user_id
        ))).scalars().all()
        recovery_state = (
            await get_active_recovery_state(db, session)
            if session.get("recovery_only") else None
        )
        if session.get("recovery_only") and recovery_state is None:
            await db.commit()
            abort(403, "Recovery session expired or invalid")
        has_recovery_path = False
        recovery_baseline_webauthn_ids: set[str] = set()
        recovery_baseline_totp_ids: set[str] = set()
        if recovery_state is not None:
            _, recovery_context = recovery_state
            recovery_baseline_webauthn_ids = {
                str(value)
                for value in recovery_context.get("baseline_webauthn_ids", [])
            }
            recovery_baseline_totp_ids = {
                str(value) for value in recovery_context.get("baseline_totp_ids", [])
            }
            has_recovery_path = await recovery_has_new_auth_path(
                db, user, recovery_context
            )
        return await render_template(
            "auth/security.html", user=user, credentials=credentials,
            devices=devices, recovery_only=bool(session.get("recovery_only")),
            recovery_has_new_auth_path=has_recovery_path,
            recovery_baseline_webauthn_ids=recovery_baseline_webauthn_ids,
            recovery_baseline_totp_ids=recovery_baseline_totp_ids,
        )


@auth_bp.post("/recovery/complete")
async def recovery_complete():
    """Atomically replace all pre-recovery credentials and end recovery."""
    user_id = str(session.get("user_id") or "")
    if not user_id or not session.get("recovery_only"):
        abort(403, "Recovery session required")
    async for db in get_db_session():
        from arborpress.auth.mfa import get_device_limit
        from arborpress.auth.pending import consume_pending
        from arborpress.auth.policy import (
            lock_user_for_credential_change,
            recovery_has_new_auth_path,
        )
        from arborpress.auth.sessions import (
            RECOVERY_SESSION_PURPOSE,
            discard_recovery_enrollments,
            get_active_recovery_state,
            invalidate_normal_auth_pendings,
        )
        from arborpress.core.site_settings import get_webauthn_settings
        from arborpress.models.user import (
            MFADevice,
            MFADeviceType,
            UserSession,
            WebAuthnCredential,
        )

        state = await get_active_recovery_state(db, session)
        if state is None:
            await db.commit()
            abort(403, "Recovery session expired or invalid")
        pending, context = state
        user = await lock_user_for_credential_change(db, user_id)
        if user is None or not user.is_active:
            abort(401)
        state = await get_active_recovery_state(db, session)
        if state is None or state[0].id != pending.id:
            await db.commit()
            abort(403, "Recovery session expired or changed")
        pending, context = state
        if not await recovery_has_new_auth_path(db, user, context):
            await write_audit_event(
                event_type="recovery_completion_blocked", outcome="blocked",
                actor_id=user_id, target_id=user_id,
                detail="purpose=account_credential_recovery;new_verified_fido2_required",
                db=db,
            )
            await db.commit()
            abort(409, "Recovery requires a newly verified FIDO2 credential")

        baseline_webauthn = {
            str(value) for value in context.get("baseline_webauthn_ids", [])
        }
        baseline_totp = {
            str(value) for value in context.get("baseline_totp_ids", [])
        }
        recovery_webauthn_ids = {
            str(value) for value in context.get("recovery_webauthn_ids", [])
        }
        recovery_totp_ids = {
            str(value) for value in context.get("recovery_totp_ids", [])
        }
        settings = await get_webauthn_settings(db)
        webauthn_limit = min(100, max(1, int(settings.get("webauthn_credential_limit", 10))))
        totp_limit = await get_device_limit(db, MFADeviceType.TOTP)

        webauthn_rows = (await db.execute(select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id
        ).with_for_update())).scalars().all()
        final_webauthn = [
            item for item in webauthn_rows if str(item.id) not in baseline_webauthn
        ]
        totp_rows = (await db.execute(select(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
        ).with_for_update())).scalars().all()
        final_totp = [
            item for item in totp_rows
            if item.is_active and str(item.id) not in baseline_totp
        ]
        if len(final_webauthn) > webauthn_limit or len(final_totp) > totp_limit:
            await write_audit_event(
                event_type="recovery_completion_blocked", outcome="blocked",
                actor_id=user_id, target_id=user_id,
                detail=(
                    "purpose=account_credential_recovery;"
                    "final_credential_limit_exceeded"
                ),
                db=db,
            )
            await db.commit()
            abort(409, "The recovered credential set exceeds the configured limit")

        staged_webauthn = [
            item for item in webauthn_rows
            if str(item.id) in recovery_webauthn_ids
            and str(item.id) not in baseline_webauthn
            and item.verification_status == "recovery_pending"
            and item.uv_capable is True
        ]
        if not staged_webauthn:
            await write_audit_event(
                event_type="recovery_completion_blocked", outcome="blocked",
                actor_id=user_id, target_id=user_id,
                detail="purpose=account_credential_recovery;staged_fido2_missing",
                db=db,
            )
            await db.commit()
            abort(409, "Recovery requires a newly verified FIDO2 credential")
        staged_totp = [
            item for item in totp_rows
            if str(item.id) in recovery_totp_ids
            and str(item.id) not in baseline_totp
            and item.is_active
            and item.verification_status == "recovery_pending"
        ]

        consumed = await consume_pending(
            db,
            pending_id=pending.id,
            purpose=RECOVERY_SESSION_PURPOSE,
            user_id=user_id,
        )
        if consumed is None:
            abort(403, "Recovery session already consumed or expired")
        await invalidate_normal_auth_pendings(
            db,
            user_id=user_id,
            actor_id=user_id,
            reason="recovery_completed",
        )

        # Retire every credential present at authorization time. New factors
        # are promoted only after all ownership and limit checks have passed.
        for credential in webauthn_rows:
            if str(credential.id) in baseline_webauthn:
                await db.delete(credential)
                await write_audit_event(
                    event_type="webauthn_credential_removed", outcome="success",
                    actor_id=user_id, actor_name=user.username,
                    target_id=str(credential.id),
                    detail="method=recovery;purpose=account_credential_recovery",
                    db=db,
                )
                await write_audit_event(
                    event_type="recovery_credential_removed", outcome="success",
                    actor_id=user_id, target_id=str(credential.id),
                    detail="credential_type=webauthn;purpose=account_credential_recovery",
                    db=db,
                )
        for device in totp_rows:
            if str(device.id) in baseline_totp:
                await db.delete(device)
                await write_audit_event(
                    event_type="totp_removed", outcome="success",
                    actor_id=user_id, actor_name=user.username,
                    target_id=str(device.id), detail="method=recovery",
                    db=db,
                )
                await write_audit_event(
                    event_type="recovery_credential_removed", outcome="success",
                    actor_id=user_id, target_id=str(device.id),
                    detail="credential_type=totp;purpose=account_credential_recovery",
                    db=db,
                )
        for credential in staged_webauthn:
            credential.verification_status = "verified_uv"
        for device in staged_totp:
            device.verification_status = "verified"
            device.is_active = True

        # Consume any in-progress enrollment challenges without deleting the
        # promoted factors; the cleanup helper only deletes recovery_pending rows.
        await discard_recovery_enrollments(
            db, pending=pending, context=context, reason="completed"
        )
        db_session = await db.get(UserSession, str(session.get("session_id")))
        if db_session is None or db_session.user_id != user_id:
            abort(403)
        db_session.is_valid = False
        await write_audit_event(
            event_type="recovery_completed", outcome="success",
            actor_id=user_id, target_id=user_id,
            detail=(
                "purpose=account_credential_recovery;"
                f"revoked_webauthn={len(baseline_webauthn)};"
                f"revoked_totp={len(baseline_totp)};next=normal_login"
            ),
            db=db,
        )
        await db.commit()
        session.clear()
        return jsonify({"status": "recovery_completed", "login_required": True}), 200


# ---------------------------------------------------------------------------
# Break-Glass Passwort-Login (§2 – nur wenn legacy_password_enabled=true)
# ---------------------------------------------------------------------------


@auth_bp.post("/breakglass")
async def breakglass_login():
    """Verify the optional password factor under the normal login policy."""
    cfg = get_settings()
    if not cfg.auth.legacy_password_enabled:
        abort(404)

    form = await request.form
    user_name = (form.get("user_name") or "").strip()
    password = form.get("password") or ""
    if not user_name or not password:
        abort(400, "Benutzername und Passwort erforderlich")

    from arborpress.auth.breakglass import needs_rehash, verify_password
    from arborpress.auth.pending import create_pending
    from arborpress.auth.policy import requires_second_factor, usable_webauthn_credential_ids
    from arborpress.core.site_settings import get_webauthn_settings
    from arborpress.models.user import MFADevice, MFADeviceType, User

    async for db in get_db_session():
        user = (await db.execute(select(User).where(
            func.lower(User.username) == user_name.lower()
        ).with_for_update())).scalar_one_or_none()
        if (
            user is None
            or not user.is_active
            or not user.legacy_password_enabled
            or not user.legacy_password_hash
        ):
            from arborpress.auth.breakglass import _hasher
            try:
                _hasher.verify("$argon2id$dummy", password)
            except Exception:  # noqa: BLE001 - dummy verification is expected to fail
                log.debug("Dummy password verification failed as expected")
            abort(401, "Invalid credentials")

        from arborpress.auth.policy import lock_user_for_credential_change
        user = await lock_user_for_credential_change(db, str(user.id))
        if user is None or not user.is_active:
            abort(401, "Invalid credentials")
        now = datetime.now(UTC).replace(tzinfo=None)
        locked_until = user.locked_until
        if locked_until is not None:
            until = locked_until.replace(tzinfo=None) if locked_until.tzinfo else locked_until
            if until > now:
                await write_audit_event(
                    event_type="login_blocked", outcome="blocked",
                    actor_id=str(user.id), actor_name=user.username,
                    ip=request.remote_addr, detail=f"locked_until={locked_until.isoformat()}",
                    db=db,
                )
                await db.commit()
                abort(423, "Konto temporär gesperrt – bitte später erneut versuchen")

        if not verify_password(user.legacy_password_hash, password, admin_id=str(user.id)):
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if (
                cfg.auth.lockout_threshold > 0
                and user.failed_login_count >= cfg.auth.lockout_threshold
            ):
                user.locked_until = now + timedelta(seconds=cfg.auth.lockout_duration)
                detail = f"breakglass attempt={user.failed_login_count} account_locked"
            else:
                detail = f"breakglass attempt={user.failed_login_count}"
            await write_audit_event(
                event_type="login_failure", outcome="failure",
                actor_id=str(user.id), actor_name=user.username,
                ip=request.remote_addr, user_agent=request.headers.get("User-Agent"),
                detail=detail, db=db,
            )
            await db.commit()
            abort(401, "Invalid credentials")

        user.failed_login_count = 0
        user.locked_until = None
        if needs_rehash(user.legacy_password_hash):
            from arborpress.auth.breakglass import hash_password
            user.legacy_password_hash = hash_password(password)

        webauthn_ids = await usable_webauthn_credential_ids(db, str(user.id))
        methods: set[str] = {"webauthn"} if webauthn_ids else set()
        totp_count = (await db.execute(select(func.count()).select_from(MFADevice).where(
            MFADevice.user_id == str(user.id),
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
            MFADevice.verification_status.in_(("verified", "unknown")),
        ))).scalar_one() or 0
        if totp_count:
            methods.add("totp")

        wa_settings = await get_webauthn_settings(db)
        if requires_second_factor(
            user, "password", methods,
            auth_settings=cfg.auth, webauthn_settings=wa_settings,
        ):
            pending = await create_pending(
                db, purpose="password_mfa", user_id=str(user.id),
                ttl_seconds=int(wa_settings.get("challenge_ttl_seconds", 300)),
                context={"methods": sorted(methods), "auth_method": "password"},
            )
            session.clear()
            session["password_mfa_pending_id"] = pending.id
            await write_audit_event(
                event_type="breakglass_password_accepted", outcome="success",
                actor_id=str(user.id), target_id=str(user.id),
                detail="second_factor_required", db=db,
            )
            await db.commit()
            return redirect(url_for("auth.mfa_page"))

        await write_audit_event(
            event_type="breakglass_password_blocked", outcome="blocked",
            actor_id=str(user.id), target_id=str(user.id),
            detail="password_alone_not_accepted;second_factor_required", db=db,
        )
        await db.commit()
        abort(403, "Password alone cannot create a session; use an enrolled second factor")


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@auth_bp.post("/logout")
async def logout():
    user_id = session.get("user_id")
    session_id = session.get("session_id")
    recovery_only = bool(session.get("recovery_only"))
    recovery_id = session.get("recovery_id")
    session.clear()
    if session_id:
        from arborpress.auth.sessions import (
            RECOVERY_SESSION_PURPOSE,
            invalidate_recovery_session,
        )
        from arborpress.core.audit import write_audit_event as audit_recovery_event
        from arborpress.models.user import AuthPending, UserSession
        async for db in get_db_session():
            if recovery_only and user_id:
                from arborpress.auth.policy import lock_user_for_credential_change

                await lock_user_for_credential_change(db, str(user_id))
            await db.execute(
                update(UserSession)
                .where(UserSession.id == session_id)
                .values(is_valid=False)
            )
            if recovery_only and recovery_id:
                pending = await db.get(AuthPending, str(recovery_id))
                if (
                    pending is not None
                    and pending.user_id == str(user_id)
                    and pending.purpose == RECOVERY_SESSION_PURPOSE
                    and pending.consumed_at is None
                ):
                    try:
                        recovery_context = json.loads(pending.context or "{}")
                    except (TypeError, ValueError):
                        recovery_context = {}
                    if isinstance(recovery_context, dict):
                        await invalidate_recovery_session(
                            db,
                            pending=pending,
                            context=recovery_context,
                            reason="logout",
                        )
                    else:
                        from arborpress.auth.pending import utcnow_naive
                        pending.consumed_at = utcnow_naive()
                await audit_recovery_event(
                    event_type="recovery_aborted", outcome="success",
                    actor_id=str(user_id), target_id=str(user_id),
                    detail="purpose=account_credential_recovery;reason=logout",
                    db=db,
                )
            await db.commit()
    if user_id:
        from arborpress.core.events import emit
        await emit("auth.logout", user_id=user_id)
    return jsonify({"status": "logged_out"}), 200


# ---------------------------------------------------------------------------
# Step-up (§2 sudo-mode)
# ---------------------------------------------------------------------------


@auth_bp.post("/stepup/begin")
async def stepup_begin():
    """Start a short action-, target-, user-, and session-bound step-up."""
    user_id = session.get("user_id")
    if not user_id:
        abort(401, "Nicht eingeloggt")
    data = await request.get_json() or {}
    action = str(data.get("action") or "change_security_settings")
    if action not in STEPUP_POLICIES:
        abort(400, "Unregistered step-up action")
    if STEPUP_POLICIES[action] == "target" and not data.get("target"):
        abort(400, "This step-up action requires a target")
    target = str(data.get("target") or "instance")
    if session.get("recovery_only"):
        abort(403, "Recovery-only sessions cannot grant step-up")
    from webauthn.helpers import options_to_json

    async for db in get_db_session():
        from arborpress.auth.pending import create_pending
        from arborpress.auth.policy import usable_totp_device_ids
        from arborpress.core.site_settings import get_webauthn_settings
        from arborpress.models.user import WebAuthnCredential
        cred_stmt = select(WebAuthnCredential.credential_id).where(
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.uv_capable.is_not(False),
            WebAuthnCredential.verification_status != "recovery_pending",
        )
        result = await db.execute(cred_stmt)
        allowed = [row[0] for row in result.fetchall()]
        totp_ids = await usable_totp_device_ids(db, str(user_id))
        totp_can_step_up = action == "remove_totp_credential" and bool(totp_ids)
        if not allowed and not totp_can_step_up:
            abort(403, "No permitted credential is available for step-up")
        settings = await get_webauthn_settings(db)
        context = {
            "action": action,
            "target": target,
            "session_id": str(session.get("session_id") or ""),
            "allowed_methods": ["webauthn", "totp"] if totp_can_step_up else ["webauthn"],
        }
        if allowed:
            wa = await _get_webauthn_async()
            opts = wa.generate_authentication_options(allowed_credentials=allowed)
            pending = await create_pending(
                db, purpose="stepup", user_id=str(user_id), challenge=opts.challenge,
                ttl_seconds=int(settings.get("challenge_ttl_seconds", 300)),
                context=context,
            )
            payload = json.loads(options_to_json(opts))
            payload["totp_available"] = totp_can_step_up
        else:
            pending = await create_pending(
                db, purpose="stepup", user_id=str(user_id), challenge=None,
                ttl_seconds=int(settings.get("challenge_ttl_seconds", 300)),
                context=context,
            )
            payload = {"totp_only": True}
        session["stepup_pending_id"] = pending.id
        await db.commit()
    return jsonify(payload), 200


@auth_bp.post("/stepup/complete")
async def stepup_complete():
    """Complete a UV-required WebAuthn step-up without changing authorization."""
    from webauthn.helpers import parse_authentication_credential_json

    raw = await request.get_json()
    if not isinstance(raw, dict):
        abort(400, "WebAuthn assertion required")
    pending_id = session.pop("stepup_pending_id", None)
    user_id = session.get("user_id")

    if not pending_id or not user_id:
        abort(401)

    wa = await _get_webauthn_async()

    async for db in get_db_session():
        from arborpress.auth.pending import consume_pending
        from arborpress.auth.webauthn import decode_credential_id
        from arborpress.models.user import AuthPending, WebAuthnCredential
        preview = await db.get(AuthPending, pending_id)
        if preview is None:
            abort(401)
        context = json.loads(preview.context or "{}")
        if context.get("session_id") != str(session.get("session_id") or ""):
            await write_audit_event(
                event_type="sensitive_stepup_failed", outcome="failure",
                actor_id=str(user_id), target_id=str(user_id),
                detail="stepup_pending_session_mismatch", db=db,
            )
            await db.commit()
            abort(401)
        if "webauthn" not in context.get("allowed_methods", ["webauthn"]):
            abort(403)
        pending = await consume_pending(
            db, pending_id=pending_id, purpose="stepup", user_id=str(user_id)
        )
        if pending is None or pending.challenge is None:
            abort(401, "Step-up challenge expired or already used")
        await db.commit()
        try:
            credential_id = decode_credential_id(str(raw.get("rawId") or raw.get("id") or ""))
            if raw.get("id") and decode_credential_id(str(raw["id"])) != credential_id:
                raise ValueError("credential id mismatch")
        except ValueError:
            abort(401)
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.uv_capable.is_not(False),
            WebAuthnCredential.verification_status != "recovery_pending",
        )
        result = await db.execute(stmt)
        db_cred = result.scalar_one_or_none()
        if db_cred is None:
            abort(401)

        try:
            credential = parse_authentication_credential_json(raw)
            verification = wa.verify_authentication(
                credential=credential,
                expected_challenge=pending.challenge,
                credential_public_key=db_cred.public_key,
                current_sign_count=db_cred.sign_count,
            )
            if getattr(verification, "user_verified", None) is not True:
                raise ValueError("user verification required")
        except Exception as exc:
            await write_audit_event(
                event_type="sensitive_stepup_failed", outcome="failure",
                actor_id=str(user_id), target_id=str(user_id),
                detail="webauthn_verification_failed", db=db,
            )
            await db.commit()
            log.warning("WebAuthn step-up failed: %s", exc)
            abort(401, "Step-up fehlgeschlagen")
        db_cred.sign_count = (
            verification.new_sign_count if wa.counter_strict
            else max(db_cred.sign_count, verification.new_sign_count)
        )
        db_cred.last_used_at = datetime.now(UTC).replace(tzinfo=None)
        context = json.loads(pending.context or "{}")
        action = str(context.get("action") or "")
        target = str(context.get("target") or "instance")
        if action not in STEPUP_POLICIES:
            await db.commit()
            abort(403, "Unregistered step-up action")
        await grant_stepup(
            session, user_id=str(user_id), action=action, target=target,
            auth_method="webauthn", assurance_level="user_verified",
            confirming_credential_id=str(db_cred.id), db=db,
        )
        await db.commit()

    from arborpress.core.events import emit
    await emit("auth.stepup_granted", user_id=user_id)

    return jsonify({"status": "stepup_granted"}), 200


@auth_bp.post("/stepup/totp/complete")
async def stepup_totp_complete():
    """Complete TOTP step-up for TOTP credential removal using shared grants."""
    user_id = str(session.get("user_id") or "")
    pending_id = session.get("stepup_pending_id")
    data = await request.get_json() or {}
    code = str(data.get("code") or "").strip()
    if not user_id or not pending_id or not code:
        abort(400, "An active step-up and TOTP code are required")

    async for db in get_db_session():
        from arborpress.auth.mfa import TOTPService, decrypt_secret
        from arborpress.auth.pending import consume_pending
        from arborpress.models.user import AuthPending, MFADevice, MFADeviceType
        preview = await db.get(AuthPending, pending_id)
        if preview is None or preview.user_id != user_id or preview.purpose != "stepup":
            abort(401)
        context = json.loads(preview.context or "{}")
        if (
            context.get("session_id") != str(session.get("session_id") or "")
            or context.get("action") != "remove_totp_credential"
            or "totp" not in context.get("allowed_methods", [])
        ):
            await write_audit_event(
                event_type="sensitive_stepup_failed", outcome="failure",
                actor_id=user_id, target_id=user_id,
                detail="totp_stepup_scope_or_session_mismatch", db=db,
            )
            await db.commit()
            session.pop("stepup_pending_id", None)
            abort(403)
        pending = await consume_pending(
            db, pending_id=pending_id, purpose="stepup", user_id=user_id
        )
        if pending is None:
            session.pop("stepup_pending_id", None)
            abort(401, "Step-up challenge expired or already used")
        # Consume before verifying: an invalid OTP cannot be retried against
        # the same pending action/target context.
        await db.commit()
        devices = (await db.execute(
            select(MFADevice).where(
                MFADevice.user_id == user_id,
                MFADevice.device_type == MFADeviceType.TOTP,
                MFADevice.is_active.is_(True),
                MFADevice.verification_status.in_(('verified', 'unknown')),
            ).with_for_update()
        )).scalars().all()
        service = TOTPService()
        matches = []
        for device in devices:
            try:
                secret = decrypt_secret(device.secret_enc)
                if service.verify(secret, code, user_id=user_id):
                    matches.append(device)
            except Exception:
                log.debug(
                    "Could not verify a step-up TOTP device for user %s",
                    user_id,
                    exc_info=True,
                )
                continue
        if len(matches) != 1:
            await write_audit_event(
                event_type="sensitive_stepup_failed", outcome="failure",
                actor_id=user_id, target_id=str(context.get("target") or user_id),
                detail="totp_stepup_code_invalid_or_ambiguous", db=db,
            )
            await db.commit()
            session.pop("stepup_pending_id", None)
            abort(401, "TOTP step-up failed")
        matched = matches[0]
        if matched.verification_status == "unknown":
            matched.verification_status = "verified"
            await write_audit_event(
                event_type="totp_legacy_confirmed", outcome="success",
                actor_id=user_id, target_id=str(matched.id),
                detail="confirmed_during_stepup", db=db,
            )
        matched.last_used_at = datetime.now(UTC).replace(tzinfo=None)
        target = str(context.get("target") or "")
        action = str(context.get("action") or "")
        if action not in STEPUP_POLICIES:
            session.pop("stepup_pending_id", None)
            abort(403)
        await grant_stepup(
            session, user_id=user_id, action=action, target=target,
            auth_method="totp", assurance_level="otp_verified",
            confirming_mfa_device_id=str(matched.id), db=db,
        )
        await db.commit()
        session.pop("stepup_pending_id", None)
    from arborpress.core.events import emit
    await emit("auth.stepup_granted", user_id=user_id)
    return jsonify({"status": "stepup_granted", "auth_method": "totp"}), 200


@auth_bp.post("/stepup/revoke")
async def stepup_revoke():
    """Widerruft Step-up manuell (§2)."""
    user_id = session.get("user_id")
    if user_id:
        await revoke_stepup(session, user_id=user_id)
        from arborpress.core.events import emit
        await emit("auth.stepup_revoked", user_id=user_id)
    return jsonify({"status": "stepup_revoked"}), 200
