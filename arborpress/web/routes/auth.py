"""Auth-Routen – WebAuthn-Registrierung und -Login (§2).

Endpunkte:
  POST /auth/register/begin       – Challenge für Credential-Registrierung
  POST /auth/register/complete    – Verifikation + DB-Persistierung
  POST /auth/login/begin          – Challenge für Login
  POST /auth/login/complete       – Verifikation + Session anlegen
  POST /auth/logout               – Session beenden
  POST /auth/stepup/begin         – Step-up-Challenge (§2 sudo-mode)
  POST /auth/stepup/complete      – Step-up bestätigen
  GET  /auth/login                – Login-HTML-Seite
  GET  /auth/register             – Registrierungs-HTML-Seite
"""

from __future__ import annotations

import json
import logging
import os
from base64 import urlsafe_b64encode

from quart import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import select

from arborpress.auth.stepup import grant_stepup, revoke_stepup
from arborpress.auth.webauthn import WebAuthnService
from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.auth")

auth_bp = Blueprint("auth", __name__, template_folder="../../templates")


@auth_bp.before_request
async def _auth_csrf_check() -> None:
    """CSRF-Schutz für HTML-Form-POSTs (§10).

    JSON-API-Requests (WebAuthn challenge/response) werden ausgenommen und
    stattdessen durch den Origin/Referer-Check in _origin_check() gesichert.
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    content_type = request.content_type or ""
    if "application/json" in content_type:
        return  # JSON-API: Origin/Referer-Check ist ausreichend
    validate_csrf()


def _get_webauthn() -> WebAuthnService:
    cfg = get_settings()
    from urllib.parse import urlparse
    parsed = urlparse(cfg.web.base_url)
    return WebAuthnService(
        rp_id=parsed.hostname or "localhost",
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
    return await render_template("auth/register.html")


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
    if not user_name or len(user_name) > 64:
        abort(400, "user_name ungültig")

    wa = _get_webauthn()

    async for db in get_db_session():
        from arborpress.models.user import User
        # Prüfen ob User bereits existiert
        stmt = select(User).where(User.username == user_name)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user is None:
            # Neuen User anlegen
            user = User(
                username=user_name,
                display_name=data.get("display_name", user_name),
            )
            db.add(user)
            await db.flush()  # ID generieren ohne commit

        # Existierende Credentials für exclude_credentials
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

        # Challenge + User-ID in Session (§10 kein Offenlegung nach außen)
        session["reg_challenge"] = opts.challenge
        session["reg_user_id"] = str(user.id)

        await db.commit()

    return jsonify(json.loads(opts.model_dump_json())), 200


@auth_bp.post("/register/complete")
async def register_complete():
    """Schließt die WebAuthn-Registrierung ab und speichert Credential (§2)."""
    from webauthn import base64url_to_bytes
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

    label: str = raw.get("label") or "Sicherheitsschlüssel"

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
            stmt = select(User).where(User.username == user_name)
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
        from arborpress.models.user import User, WebAuthnCredential
        from sqlalchemy import update
        from datetime import datetime, timezone

        # Credential in DB suchen
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id
        )
        result = await db.execute(stmt)
        db_cred = result.scalar_one_or_none()
        if db_cred is None:
            abort(401, "Credential nicht gefunden")

        user = await db.get(User, db_cred.user_id)
        if user is None or not user.is_active:
            abort(401, "Konto nicht aktiv")

        try:
            credential = AuthenticationCredential.parse_raw(json.dumps(raw))
            verification = wa.verify_authentication(
                credential=credential,
                expected_challenge=challenge,
                credential_public_key=db_cred.public_key,
                current_sign_count=db_cred.sign_count,
            )
        except Exception as exc:
            log.warning("WebAuthn-Auth fehlgeschlagen für user=%s: %s", user.username, exc)
            await emit_fail(user.id)
            abort(401, "Authentifizierung fehlgeschlagen")

        # Sign-Count + last_used_at aktualisieren
        await db.execute(
            update(WebAuthnCredential)
            .where(WebAuthnCredential.id == db_cred.id)
            .values(
                sign_count=verification.new_sign_count,
                last_used_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

        # Session anlegen (§2)
        session.clear()
        session["user_id"] = str(user.id)
        session["user_name"] = user.username
        session["user_role"] = user.role.value
        session["account_type"] = user.account_type.value

    from arborpress.core.events import emit
    await emit("auth.login_success", user_id=str(user.id))

    return jsonify({"status": "ok", "user": user.username}), 200


async def emit_fail(user_id: object) -> None:
    from arborpress.core.events import emit
    await emit("auth.login_failure", user_id=str(user_id))


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@auth_bp.post("/logout")
async def logout():
    user_id = session.get("user_id")
    session.clear()
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
    """Schließt Step-up ab und gewährt erhöhte Rechte (§2)."""
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
