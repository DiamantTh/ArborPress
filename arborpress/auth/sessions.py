"""One session creation path for every successful authentication flow."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from quart import abort, request, session
from sqlalchemy import select, update

from arborpress.core.config import get_settings
from arborpress.models.user import UserSession

RECOVERY_AUTHORIZATION_TTL_SECONDS = 24 * 60 * 60
RECOVERY_SESSION_TTL_SECONDS = 15 * 60
RECOVERY_PURPOSE = "account_credential_recovery"
RECOVERY_SESSION_PURPOSE = "recovery_session"
_NORMAL_AUTH_PENDING_PURPOSES = (
    "webauthn_login",
    "password_mfa",
    "sso_mfa",
    "login_mfa_webauthn",
    "stepup",
    "webauthn_enrollment",
    "totp_enrollment",
)


async def create_user_session(
    db: Any,
    user: Any,
    *,
    auth_method: str,
    assurance_level: str,
    recovery_only: bool = False,
    ttl_seconds: int | None = None,
) -> UserSession:
    """Set the Quart identity and add a metadata-rich DB session row.

    A normal login and a recovery authorization are mutually exclusive. The
    user-row lock serializes this check with recovery authorization, so an
    SSO, WebAuthn, or password/MFA login cannot race a recovery ticket issue.
    """
    if not recovery_only:
        from arborpress.auth.policy import lock_user_for_credential_change

        locked_user = await lock_user_for_credential_change(db, str(user.id))
        if locked_user is None or not locked_user.is_active:
            abort(401)
        if await has_active_recovery(db, str(user.id)):
            abort(423, "Account recovery is active; normal login is temporarily blocked")

    cfg = get_settings()
    now = datetime.now(UTC)
    proto = request.headers.get("X-Forwarded-Proto", "") or request.headers.get(
        "X-Forwarded-Ssl", ""
    )
    is_tls = str(proto).lower() in ("https", "on") or request.url.startswith("https")
    raw_ua = request.headers.get("User-Agent", "")
    db_session = UserSession(
        user_id=str(user.id),
        expires_at=now + timedelta(
            seconds=(
                max(1, int(ttl_seconds))
                if ttl_seconds is not None
                else cfg.auth.admin_session_ttl
            )
        ),
        last_seen_at=now,
        client_ip=request.remote_addr,
        user_agent=raw_ua[:512] if raw_ua else None,
        is_tls=is_tls,
        is_cli=False,
        auth_method=auth_method[:64],
        assurance_level=assurance_level[:32],
    )
    db.add(db_session)
    await db.flush()

    session.clear()
    session["user_id"] = str(user.id)
    session["user_name"] = user.username
    session["user_role"] = user.role.value
    session["account_type"] = user.account_type.value
    session["auth_method"] = auth_method[:64]
    session["assurance_level"] = assurance_level[:32]
    session["recovery_only"] = bool(recovery_only)
    session["session_id"] = db_session.id
    if recovery_only:
        session["recovery_purpose"] = RECOVERY_PURPOSE
    return db_session


async def has_active_recovery(db: Any, user_id: str) -> bool:
    """Whether a user has a live recovery authorization or recovery session."""
    from arborpress.auth.pending import as_utc_naive, utcnow_naive
    from arborpress.core.audit import write_audit_event
    from arborpress.models.user import AuthPending

    now = utcnow_naive()
    pending_rows = (await db.execute(
        select(AuthPending).where(
            AuthPending.user_id == str(user_id),
            AuthPending.purpose == RECOVERY_SESSION_PURPOSE,
            AuthPending.consumed_at.is_(None),
        )
    )).scalars().all()
    for pending in pending_rows:
        try:
            context = json.loads(pending.context or "{}")
        except (TypeError, ValueError):
            context = None
        expired = as_utc_naive(pending.expires_at) <= now
        if expired:
            if isinstance(context, dict):
                await invalidate_recovery_session(
                    db, pending=pending, context=context, reason="expired"
                )
            else:
                pending.consumed_at = now
            await write_audit_event(
                event_type="recovery_expired", outcome="failure",
                actor_id=str(user_id), target_id=str(user_id),
                detail=f"purpose={RECOVERY_PURPOSE};reason=expired",
                db=db,
            )
            continue
        if (
            not isinstance(context, dict)
            or context.get("recovery_purpose") != RECOVERY_PURPOSE
        ):
            # Live but malformed recovery state fails closed.
            return True
        session_id = str(context.get("session_id") or "")
        db_session = await db.get(UserSession, session_id) if session_id else None
        if (
            db_session is not None
            and db_session.user_id == str(user_id)
            and db_session.is_valid
            and not db_session.is_expired
            and db_session.auth_method == "recovery"
            and db_session.assurance_level == "recovery"
        ):
            return True
        await invalidate_recovery_session(
            db, pending=pending, context=context, reason="session_revoked"
        )
        await write_audit_event(
            event_type="recovery_aborted", outcome="success",
            actor_id=str(user_id), target_id=str(user_id),
            detail=f"purpose={RECOVERY_PURPOSE};reason=session_revoked",
            db=db,
        )

    authorization = (await db.execute(
        select(AuthPending.id).where(
            AuthPending.user_id == str(user_id),
            AuthPending.purpose == "recovery_authorization",
            AuthPending.consumed_at.is_(None),
            AuthPending.expires_at > now,
        ).limit(1)
    )).scalar_one_or_none()
    return authorization is not None


async def append_recovery_credential_id(
    db: Any,
    *,
    user_id: str,
    recovery_id: str,
    session_id: str,
    credential_type: str,
    credential_id: str,
) -> bool:
    """Bind a verified staged credential to this exact recovery operation."""
    from arborpress.auth.pending import as_utc_naive, utcnow_naive
    from arborpress.models.user import AuthPending

    key = {
        "webauthn": "recovery_webauthn_ids",
        "totp": "recovery_totp_ids",
    }.get(credential_type)
    if key is None:
        return False
    pending = (await db.execute(
        select(AuthPending).where(
            AuthPending.id == str(recovery_id),
            AuthPending.user_id == str(user_id),
            AuthPending.purpose == RECOVERY_SESSION_PURPOSE,
            AuthPending.consumed_at.is_(None),
        ).with_for_update()
    )).scalar_one_or_none()
    if pending is None or as_utc_naive(pending.expires_at) <= utcnow_naive():
        return False
    try:
        context = json.loads(pending.context or "{}")
    except (TypeError, ValueError):
        return False
    if (
        not isinstance(context, dict)
        or context.get("session_id") != str(session_id)
        or context.get("recovery_purpose") != RECOVERY_PURPOSE
    ):
        return False
    values = context.setdefault(key, [])
    if not isinstance(values, list):
        return False
    value = str(credential_id)
    if value not in values:
        values.append(value)
    pending.context = json.dumps(context, separators=(",", ":"))
    await db.flush()
    return True


async def discard_recovery_enrollments(
    db: Any,
    *,
    pending: Any,
    context: dict[str, Any],
    reason: str,
) -> None:
    """Remove only unfinalized factors recorded by one recovery operation."""
    from arborpress.core.audit import write_audit_event
    from arborpress.models.user import (
        AuthPending,
        MFADevice,
        MFADeviceType,
        WebAuthnCredential,
    )

    user_id = str(pending.user_id or "")
    if not user_id:
        return
    webauthn_values = context.get("recovery_webauthn_ids", [])
    totp_values = context.get("recovery_totp_ids", [])
    recovery_webauthn = {
        str(value) for value in webauthn_values if isinstance(value, (str, int))
    } if isinstance(webauthn_values, list) else set()
    recovery_totp = {
        str(value) for value in totp_values if isinstance(value, (str, int))
    } if isinstance(totp_values, list) else set()
    if recovery_webauthn:
        rows = (await db.execute(select(WebAuthnCredential).where(
            WebAuthnCredential.id.in_(recovery_webauthn),
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.verification_status == "recovery_pending",
        ))).scalars().all()
        for credential in rows:
            await db.delete(credential)
            await write_audit_event(
                event_type="recovery_credential_discarded", outcome="success",
                actor_id=user_id, target_id=str(credential.id),
                detail=f"credential_type=webauthn;purpose={RECOVERY_PURPOSE};reason={reason}",
                db=db,
            )
    if recovery_totp:
        rows = (await db.execute(select(MFADevice).where(
            MFADevice.id.in_(recovery_totp),
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.verification_status == "recovery_pending",
        ))).scalars().all()
        for device in rows:
            await db.delete(device)
            await write_audit_event(
                event_type="recovery_credential_discarded", outcome="success",
                actor_id=user_id, target_id=str(device.id),
                detail=f"credential_type=totp;purpose={RECOVERY_PURPOSE};reason={reason}",
                db=db,
            )

    session_id = str(context.get("session_id") or "")
    recovery_id = str(pending.id)
    if session_id:
        enrollment_rows = (await db.execute(select(AuthPending).where(
            AuthPending.user_id == user_id,
            AuthPending.purpose.in_(("webauthn_enrollment", "totp_enrollment")),
            AuthPending.consumed_at.is_(None),
        ))).scalars().all()
        now = datetime.now(UTC).replace(tzinfo=None)
        for enrollment in enrollment_rows:
            try:
                enrollment_context = json.loads(enrollment.context or "{}")
            except (TypeError, ValueError):
                continue
            if (
                enrollment_context.get("recovery_only")
                and enrollment_context.get("session_id") == session_id
                and enrollment_context.get("recovery_id") == recovery_id
            ):
                enrollment.consumed_at = now


async def invalidate_recovery_session(
    db: Any,
    *,
    pending: Any,
    context: dict[str, Any],
    reason: str,
) -> None:
    """Discard staged factors and invalidate a recovery-only DB session."""
    from arborpress.auth.pending import utcnow_naive

    await discard_recovery_enrollments(
        db, pending=pending, context=context, reason=reason
    )
    pending.consumed_at = utcnow_naive()
    session_id = str(context.get("session_id") or "")
    db_session = await db.get(UserSession, session_id) if session_id else None
    if db_session is not None and db_session.user_id == str(pending.user_id):
        db_session.is_valid = False


async def invalidate_normal_auth_pendings(
    db: Any,
    *,
    user_id: str,
    actor_id: str,
    reason: str,
) -> int:
    """Invalidate in-flight ordinary login/enrollment ceremonies for recovery."""
    from arborpress.auth.pending import utcnow_naive
    from arborpress.core.audit import write_audit_event
    from arborpress.models.user import AuthPending

    rows = (await db.execute(select(AuthPending).where(
        AuthPending.user_id == str(user_id),
        AuthPending.purpose.in_(_NORMAL_AUTH_PENDING_PURPOSES),
        AuthPending.consumed_at.is_(None),
    ).with_for_update())).scalars().all()
    now = utcnow_naive()
    purposes: set[str] = set()
    for pending in rows:
        pending.consumed_at = now
        purposes.add(pending.purpose)
    if rows:
        await write_audit_event(
            event_type="recovery_pending_invalidated", outcome="success",
            actor_id=str(actor_id), target_id=str(user_id),
            detail=(
                f"purpose={RECOVERY_PURPOSE};reason={reason};"
                f"count={len(rows)};pending_purposes={','.join(sorted(purposes))}"
            ),
            db=db,
        )
    return len(rows)


async def get_active_recovery_state(
    db: Any,
    cookie_session: Any,
    db_session: UserSession | None = None,
) -> tuple[Any, dict[str, Any]] | None:
    """Return the live pending recovery state bound to this user session."""
    if (
        not cookie_session.get("recovery_only")
        or cookie_session.get("auth_method") != "recovery"
        or cookie_session.get("assurance_level") != "recovery"
        or cookie_session.get("recovery_purpose") != RECOVERY_PURPOSE
    ):
        return None

    from arborpress.auth.pending import as_utc_naive, utcnow_naive
    from arborpress.models.user import AuthPending

    user_id = str(cookie_session.get("user_id") or "")
    session_id = str(cookie_session.get("session_id") or "")
    pending_id = str(cookie_session.get("recovery_id") or "")
    if not user_id or not session_id or not pending_id:
        return None
    if db_session is None:
        db_session = await db.get(UserSession, session_id)
    if (
        db_session is None
        or db_session.id != session_id
        or db_session.user_id != user_id
        or not db_session.is_valid
        or db_session.auth_method != "recovery"
        or db_session.assurance_level != "recovery"
        or db_session.is_expired
    ):
        return None

    pending = await db.get(AuthPending, pending_id)
    if (
        pending is None
        or pending.user_id != user_id
        or pending.purpose != RECOVERY_SESSION_PURPOSE
        or pending.consumed_at is not None
    ):
        return None
    try:
        context = json.loads(pending.context or "{}")
    except (TypeError, ValueError):
        return None
    if (
        not isinstance(context, dict)
        or context.get("session_id") != session_id
        or context.get("recovery_purpose") != RECOVERY_PURPOSE
        or context.get("auth_method") != "recovery_ticket"
        or not context.get("authorized_by")
    ):
        return None
    if as_utc_naive(pending.expires_at) <= utcnow_naive():
        from arborpress.core.audit import write_audit_event

        await invalidate_recovery_session(
            db, pending=pending, context=context, reason="expired"
        )
        await write_audit_event(
            event_type="recovery_expired",
            outcome="failure",
            actor_id=user_id,
            target_id=user_id,
            detail="purpose=account_credential_recovery;pending_expired",
            db=db,
        )
        return None
    return pending, context


async def refresh_session_identity(db: Any, cookie_session: Any) -> Any | None:
    """Validate the DB session and refresh role claims before authorization."""
    from arborpress.models.user import AuthPending, User, UserSession

    user_id = str(cookie_session.get("user_id") or "")
    session_id = str(cookie_session.get("session_id") or "")
    if not user_id or not session_id:
        return None

    user = await db.get(User, user_id)
    db_session = await db.get(UserSession, session_id)
    if db_session is not None and db_session.auth_method == "recovery":
        from arborpress.auth.policy import lock_user_for_credential_change

        if await lock_user_for_credential_change(db, user_id) is None:
            return None
        if db_session.is_expired:
            from arborpress.auth.pending import utcnow_naive
            from arborpress.core.audit import write_audit_event

            pending_id = str(cookie_session.get("recovery_id") or "")
            pending = await db.get(AuthPending, pending_id) if pending_id else None
            now = utcnow_naive()
            if (
                pending is not None
                and pending.user_id == user_id
                and pending.purpose == RECOVERY_SESSION_PURPOSE
                and pending.consumed_at is None
            ):
                try:
                    context = json.loads(pending.context or "{}")
                except (TypeError, ValueError):
                    context = {}
                if isinstance(context, dict):
                    await invalidate_recovery_session(
                        db, pending=pending, context=context, reason="expired"
                    )
                else:
                    pending.consumed_at = now
            db_session.is_valid = False
            await write_audit_event(
                event_type="recovery_expired",
                outcome="failure",
                actor_id=user_id,
                target_id=user_id,
                detail="purpose=account_credential_recovery;state_expired",
                db=db,
            )
            return None
        if not db_session.is_valid:
            from arborpress.auth.pending import utcnow_naive
            from arborpress.core.audit import write_audit_event
            from arborpress.models.user import AuthPending

            pending_id = str(cookie_session.get("recovery_id") or "")
            pending = await db.get(AuthPending, pending_id) if pending_id else None
            if (
                pending is not None
                and pending.user_id == user_id
                and pending.purpose == RECOVERY_SESSION_PURPOSE
                and pending.consumed_at is None
            ):
                try:
                    context = json.loads(pending.context or "{}")
                except (TypeError, ValueError):
                    context = {}
                if isinstance(context, dict):
                    await invalidate_recovery_session(
                        db, pending=pending, context=context, reason="session_revoked"
                    )
                else:
                    pending.consumed_at = utcnow_naive()
            await write_audit_event(
                event_type="recovery_aborted", outcome="success",
                actor_id=user_id, target_id=user_id,
                detail="purpose=account_credential_recovery;reason=session_revoked",
                db=db,
            )
            return None
        if not cookie_session.get("recovery_only"):
            from arborpress.core.audit import write_audit_event

            pending_id = str(cookie_session.get("recovery_id") or "")
            pending = await db.get(AuthPending, pending_id) if pending_id else None
            if (
                pending is not None
                and pending.user_id == user_id
                and pending.purpose == RECOVERY_SESSION_PURPOSE
                and pending.consumed_at is None
            ):
                try:
                    context = json.loads(pending.context or "{}")
                except (TypeError, ValueError):
                    context = {}
                if isinstance(context, dict):
                    await invalidate_recovery_session(
                        db, pending=pending, context=context,
                        reason="recovery_marker_missing",
                    )
            db_session.is_valid = False
            await write_audit_event(
                event_type="recovery_session_invalid",
                outcome="blocked",
                actor_id=user_id,
                target_id=user_id,
                detail="purpose=account_credential_recovery;reason=recovery_marker_missing",
                db=db,
            )
            return None
        if await get_active_recovery_state(db, cookie_session, db_session) is None:
            if db_session.is_valid:
                from arborpress.core.audit import write_audit_event

                db_session.is_valid = False
                await write_audit_event(
                    event_type="recovery_session_invalid",
                    outcome="blocked",
                    actor_id=user_id,
                    target_id=user_id,
                    detail="purpose=account_credential_recovery;reason=state_missing_consumed_or_mismatch",
                    db=db,
                )
            return None
    elif cookie_session.get("recovery_only"):
        return None
    if (
        user is None
        or not user.is_active
        or db_session is None
        or db_session.user_id != user_id
        or not db_session.is_valid
        or db_session.is_expired
    ):
        return None

    cookie_session["user_name"] = user.username
    cookie_session["user_role"] = user.role.value
    cookie_session["account_type"] = user.account_type.value
    await db.execute(
        update(UserSession)
        .where(UserSession.id == session_id)
        .values(last_seen_at=datetime.now(UTC))
    )
    return user
