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

import json
import logging
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta

from quart import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func, select, update

from arborpress.auth.stepup import grant_stepup, revoke_stepup
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
})


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
        base = cfg.web.base_url.rstrip("/")
        origin = request.headers.get("Origin") or request.headers.get("Referer", "")
        if origin and not origin.startswith(base):
            abort(403, "Cross-origin request rejected")
        return
    if "application/json" in content_type:
        # Non-enumerated JSON path – apply Origin check as sanity guard
        cfg = get_settings()
        base = cfg.web.base_url.rstrip("/")
        origin = request.headers.get("Origin") or request.headers.get("Referer", "")
        if origin and not origin.startswith(base):
            abort(403, "Cross-origin request rejected")
        return
    await validate_csrf()


# Auth-Endpunkte, die dem IP-basierten Rate-Limit unterliegen (§10)
_RATE_LIMITED_PATHS = frozenset({
    "/auth/login/begin",
    "/auth/login/complete",
    "/auth/register/begin",
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


def _get_webauthn() -> WebAuthnService:
    cfg = get_settings()
    from urllib.parse import urlparse
    parsed = urlparse(cfg.web.base_url)
    _host = parsed.hostname or "localhost"
    # WebAuthn spec: rp_id must be ASCII/Punycode – no Unicode for IDN domains
    if _host not in ("localhost", "127.0.0.1", "::1"):
        try:
            import idna as _idna  # idna>=3.7 (IDNA 2008)
            _host = _idna.encode(_host, alg="TRANSITIONAL").decode("ascii")
        except Exception:
            _host = _host.encode("idna").decode("ascii")
    return WebAuthnService(
        rp_id=_host,
        rp_name="ArborPress",
        origin=cfg.web.base_url,
    )


# ---------------------------------------------------------------------------
# HTML-Seiten
# ---------------------------------------------------------------------------


@auth_bp.get("/login")
async def login_page():
    return await render_template("auth/login.html")


@auth_bp.get("/register")
async def register_page():
    prefill = session.pop("install_prefill_user", "")
    return await render_template("auth/register.html", prefill_username=prefill)


# ---------------------------------------------------------------------------
# WebAuthn-Registrierung
# ---------------------------------------------------------------------------


@auth_bp.post("/register/begin")
async def register_begin():
    """Startet die WebAuthn-Credential-Registrierung (§2)."""
    data = await request.get_json()
    if not data or "user_name" not in data:
        abort(400, "user_name fehlt")

    user_name: str = data["user_name"].strip()
    if not user_name or not is_valid_username(user_name):
        abort(400, "user_name invalid – only letters, digits, dot, hyphen, underscore allowed")

    display_name: str = str(data.get("display_name") or user_name).strip()[:128]

    wa = _get_webauthn()

    async for db in get_db_session():
        from arborpress.models.user import User
        # Check whether user already exists
        stmt = select(User).where(func.lower(User.username) == user_name.lower())
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user is None:
            # Neuen User anlegen
            user = User(
                username=user_name,
                display_name=display_name,
            )
            db.add(user)
            await db.flush()  # ID generieren ohne commit

        # Existing credentials for exclude_credentials
        from arborpress.models.user import WebAuthnCredential
        cred_stmt = select(WebAuthnCredential.credential_id).where(
            WebAuthnCredential.user_id == user.id
        )
        cred_result = await db.execute(cred_stmt)
        existing = [row[0] for row in cred_result.fetchall()]

        # User-ID als Bytes (§2 – opaque handle, nicht die DB-UUID direkt)
        user_handle = urlsafe_b64encode(str(user.id).encode()).rstrip(b"=")

        opts = wa.generate_registration_options(
            user_id=user_handle,
            user_name=user_name,
            user_display_name=user.display_name or user_name,
            existing_credentials=existing,
        )

        # Challenge + user ID in session (§10 no disclosure externally)
        session["reg_challenge"] = opts.challenge
        session["reg_user_id"] = str(user.id)

        await db.commit()

    return jsonify(json.loads(opts.model_dump_json())), 200


@auth_bp.post("/register/complete")
async def register_complete():
    """Completes WebAuthn registration and stores credential (§2)."""
    from webauthn.helpers.structs import RegistrationCredential

    raw = await request.get_json()
    challenge = session.pop("reg_challenge", None)
    user_id_str = session.pop("reg_user_id", None)

    if not challenge or not user_id_str:
        abort(400, "Keine aktive Registrierungssession")

    wa = _get_webauthn()

    try:
        credential = RegistrationCredential.parse_raw(json.dumps(raw))
        verification = wa.verify_registration(credential, expected_challenge=challenge)
    except Exception as exc:
        log.warning("WebAuthn-Registrierung fehlgeschlagen: %s", exc)
        abort(400, "Registrierung fehlgeschlagen")

    label: str = (str(raw.get("label") or "Security key").strip())[:128] or "Security key"

    async for db in get_db_session():
        from arborpress.models.user import User, WebAuthnCredential
        user = await db.get(User, user_id_str)
        if user is None:
            abort(404)

        cred = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=str(verification.aaguid),
            label=label,
            transports=json.dumps(raw.get("transports", [])),
            uv_capable=verification.user_verified,
        )
        db.add(cred)
        await db.commit()

    from arborpress.core.events import emit
    await emit("auth.credential_registered", user_id=user_id_str, label=label)

    return jsonify({"status": "ok", "label": label}), 201


# ---------------------------------------------------------------------------
# WebAuthn-Login
# ---------------------------------------------------------------------------


@auth_bp.post("/login/begin")
async def login_begin():
    """Generiert Authentication-Challenge (§2)."""
    data = await request.get_json() or {}
    user_name: str | None = data.get("user_name")

    wa = _get_webauthn()
    allowed_credentials: list[bytes] = []

    if user_name:
        async for db in get_db_session():
            from arborpress.models.user import User, WebAuthnCredential
            stmt = select(User).where(func.lower(User.username) == user_name.lower())
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()

            if user:
                cred_stmt = select(WebAuthnCredential.credential_id).where(
                    WebAuthnCredential.user_id == user.id
                )
                cred_result = await db.execute(cred_stmt)
                allowed_credentials = [row[0] for row in cred_result.fetchall()]

    opts = wa.generate_authentication_options(allowed_credentials=allowed_credentials or None)
    session["auth_challenge"] = opts.challenge
    if user_name:
        session["auth_user_name"] = user_name

    return jsonify(json.loads(opts.model_dump_json())), 200


@auth_bp.post("/login/complete")
async def login_complete():
    """Verifiziert die Authentication-Response und erstellt Session (§2)."""
    from webauthn.helpers.structs import AuthenticationCredential

    raw = await request.get_json()
    challenge = session.pop("auth_challenge", None)

    if not challenge:
        abort(400, "Keine aktive Auth-Session")

    wa = _get_webauthn()
    credential_id: bytes = bytes.fromhex(raw.get("id", "").replace("-", ""))

    async for db in get_db_session():

        from sqlalchemy import update

        from arborpress.models.user import User, WebAuthnCredential

        # Credential in DB suchen
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id
        )
        result = await db.execute(stmt)
        db_cred = result.scalar_one_or_none()
        if db_cred is None:
            await write_audit_event(
                event_type="login_failure",
                outcome="failure",
                ip=request.remote_addr,
                detail="credential_not_found",
                db=db,
            )
            await db.commit()
            abort(401, "Credential nicht gefunden")

        user = await db.get(User, db_cred.user_id)
        if user is None or not user.is_active:
            await write_audit_event(
                event_type="login_failure",
                outcome="failure",
                actor_id=str(db_cred.user_id),
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
            credential = AuthenticationCredential.parse_raw(json.dumps(raw))
            verification = wa.verify_authentication(
                credential=credential,
                expected_challenge=challenge,
                credential_public_key=db_cred.public_key,
                current_sign_count=db_cred.sign_count,
            )
        except Exception as exc:
            # §2 Fehlversuchs-Counter erhöhen, ggf. Konto sperren
            _cfg = get_settings()
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if _cfg.auth.lockout_threshold > 0 and user.failed_login_count >= _cfg.auth.lockout_threshold:
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

        # Sign-Count + last_used_at aktualisieren
        await db.execute(
            update(WebAuthnCredential)
            .where(WebAuthnCredential.id == db_cred.id)
            .values(
                sign_count=verification.new_sign_count,
                last_used_at=datetime.now(UTC),
            )
        )
        await db.commit()

        # Session anlegen (§2)
        session.clear()
        session["user_id"] = str(user.id)
        session["user_name"] = user.username
        session["user_role"] = user.role.value
        session["account_type"] = user.account_type.value

        # DB-Session anlegen
        cfg = get_settings()
        ttl: timedelta = cfg.auth.admin_session_ttl
        now = datetime.now(UTC)
        # TLS-Erkennung via Reverse-Proxy-Header (§10)
        proto = (
            request.headers.get("X-Forwarded-Proto", "")
            or request.headers.get("X-Forwarded-Ssl", "")
        )
        is_tls = proto.lower() in ("https", "on") or request.url.startswith("https")
        raw_ua = request.headers.get("User-Agent", "")
        from arborpress.models.user import UserSession
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

        # §16 Erfolgreichen Login in Audit-Log schreiben
        await write_audit_event(
            event_type="login_success",
            outcome="success",
            actor_id=str(user.id),
            actor_name=user.username,
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
# Break-Glass Passwort-Login (§2 – nur wenn legacy_password_enabled=true)
# ---------------------------------------------------------------------------


@auth_bp.post("/breakglass")
async def breakglass_login():
    """Notfall-Passwort-Login (§2 Break-Glass).

    Nur aktiv wenn ``auth.legacy_password_enabled = true`` in config.toml.
    Nutzt Argon2id-Verifikation (§2) und schreibt obligatorisch ins Audit-Log.
    """
    cfg = get_settings()
    if not cfg.auth.legacy_password_enabled:
        abort(404)

    await validate_csrf()

    form = await request.form
    user_name = (form.get("user_name") or "").strip()
    password = form.get("password") or ""

    if not user_name or not password:
        abort(400, "Benutzername und Passwort erforderlich")

    from arborpress.auth.breakglass import needs_rehash, verify_password
    from arborpress.models.user import User

    async for db in get_db_session():
        stmt = select(User).where(func.lower(User.username) == user_name.lower())
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        user_invalid = (
            user is None
            or not user.is_active
            or not user.legacy_password_enabled
            or not user.legacy_password_hash
        )
        if user_invalid:
            # Timing-safe: run dummy-hash check anyway to harden against timing attacks
            from arborpress.auth.breakglass import _hasher
            try:
                _hasher.verify("$argon2id$dummy", password)
            except Exception as _e:  # noqa: BLE001
                log.debug("Dummy-Verifikation (erwartet): %s", _e)
            abort(401, "Invalid credentials")

        if not verify_password(user.legacy_password_hash, password, admin_id=str(user.id)):
            abort(401, "Invalid credentials")

        # Rehash bei veralteten Parametern
        if needs_rehash(user.legacy_password_hash):
            from sqlalchemy import update as sa_update

            from arborpress.auth.breakglass import hash_password
            await db.execute(
                sa_update(User).where(User.id == user.id)
                .values(legacy_password_hash=hash_password(password))
            )
            await db.commit()

        # Session anlegen (identisch zu WebAuthn-Login)
        session.clear()
        session["user_id"] = str(user.id)
        session["user_name"] = user.username
        session["user_role"] = user.role.value
        session["account_type"] = user.account_type.value

        cfg_auth = cfg.auth
        now = datetime.now(UTC)
        ttl = timedelta(seconds=cfg_auth.admin_session_ttl)
        proto = (
            request.headers.get("X-Forwarded-Proto", "")
            or request.headers.get("X-Forwarded-Ssl", "")
        )
        is_tls = proto.lower() in ("https", "on") or request.url.startswith("https")
        raw_ua = request.headers.get("User-Agent", "")
        from arborpress.models.user import UserSession
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

    from arborpress.core.events import emit
    await emit("auth.login_success", user_id=str(user.id))

    return redirect(url_for("admin.dashboard"))


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@auth_bp.post("/logout")
async def logout():
    user_id = session.get("user_id")
    session_id = session.get("session_id")
    session.clear()
    if session_id:
        from arborpress.models.user import UserSession
        async for db in get_db_session():
            await db.execute(
                update(UserSession)
                .where(UserSession.id == session_id)
                .values(is_valid=False)
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
    """Startet Step-up Re-Authentifizierung (§2)."""
    user_id = session.get("user_id")
    if not user_id:
        abort(401, "Nicht eingeloggt")

    wa = _get_webauthn()

    async for db in get_db_session():
        from arborpress.models.user import WebAuthnCredential
        cred_stmt = select(WebAuthnCredential.credential_id).where(
            WebAuthnCredential.user_id == user_id
        )
        result = await db.execute(cred_stmt)
        allowed = [row[0] for row in result.fetchall()]

    opts = wa.generate_authentication_options(allowed_credentials=allowed or None)
    session["stepup_challenge"] = opts.challenge
    return jsonify(json.loads(opts.model_dump_json())), 200


@auth_bp.post("/stepup/complete")
async def stepup_complete():
    """Completes step-up and grants elevated privileges (§2)."""
    from webauthn.helpers.structs import AuthenticationCredential

    raw = await request.get_json()
    challenge = session.pop("stepup_challenge", None)
    user_id = session.get("user_id")

    if not challenge or not user_id:
        abort(401)

    wa = _get_webauthn()
    credential_id: bytes = bytes.fromhex(raw.get("id", "").replace("-", ""))

    async for db in get_db_session():
        from arborpress.models.user import WebAuthnCredential
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id,
            WebAuthnCredential.user_id == user_id,
        )
        result = await db.execute(stmt)
        db_cred = result.scalar_one_or_none()
        if db_cred is None:
            abort(401)

        try:
            credential = AuthenticationCredential.parse_raw(json.dumps(raw))
            wa.verify_authentication(
                credential=credential,
                expected_challenge=challenge,
                credential_public_key=db_cred.public_key,
                current_sign_count=db_cred.sign_count,
            )
        except Exception:
            abort(401, "Step-up fehlgeschlagen")

    grant_stepup(session, user_id=user_id)

    from arborpress.core.events import emit
    await emit("auth.stepup_granted", user_id=user_id)

    return jsonify({"status": "stepup_granted"}), 200


@auth_bp.post("/stepup/revoke")
async def stepup_revoke():
    """Widerruft Step-up manuell (§2)."""
    user_id = session.get("user_id")
    if user_id:
        revoke_stepup(session, user_id=user_id)
        from arborpress.core.events import emit
        await emit("auth.stepup_revoked", user_id=user_id)
    return jsonify({"status": "stepup_revoked"}), 200
