"""One session creation path for every successful authentication flow."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from quart import request, session
from sqlalchemy import update

from arborpress.core.config import get_settings
from arborpress.models.user import UserSession

RECOVERY_AUTHORIZATION_TTL_SECONDS = 24 * 60 * 60
RECOVERY_SESSION_TTL_SECONDS = 15 * 60
RECOVERY_PURPOSE = "account_credential_recovery"
RECOVERY_SESSION_PURPOSE = "recovery_session"


async def create_user_session(
    db: Any,
    user: Any,
    *,
    auth_method: str,
    assurance_level: str,
    recovery_only: bool = False,
    ttl_seconds: int | None = None,
) -> UserSession:
    """Set the Quart identity and add a metadata-rich DB session row."""
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
    if as_utc_naive(pending.expires_at) <= utcnow_naive():
        pending.consumed_at = utcnow_naive()
        db_session.is_valid = False
        from arborpress.core.audit import write_audit_event

        await write_audit_event(
            event_type="recovery_expired",
            outcome="failure",
            actor_id=user_id,
            target_id=user_id,
            detail="purpose=account_credential_recovery;pending_expired",
            db=db,
        )
        return None
    try:
        context = json.loads(pending.context or "{}")
    except (TypeError, ValueError):
        return None
    if (
        not isinstance(context, dict)
        or context.get("session_id") != session_id
        or context.get("recovery_purpose") != RECOVERY_PURPOSE
        or context.get("auth_method") != "breakglass"
        or not context.get("authorized_by")
    ):
        return None
    return pending, context


async def refresh_session_identity(db: Any, cookie_session: Any) -> Any | None:
    """Validate the DB session and refresh role claims before authorization."""
    from arborpress.models.user import User, UserSession

    user_id = str(cookie_session.get("user_id") or "")
    session_id = str(cookie_session.get("session_id") or "")
    if not user_id or not session_id:
        return None

    user = await db.get(User, user_id)
    db_session = await db.get(UserSession, session_id)
    if db_session is not None and db_session.auth_method == "recovery":
        if db_session.is_expired:
            from arborpress.auth.pending import utcnow_naive
            from arborpress.core.audit import write_audit_event
            from arborpress.models.user import AuthPending

            pending_id = str(cookie_session.get("recovery_id") or "")
            pending = await db.get(AuthPending, pending_id) if pending_id else None
            now = utcnow_naive()
            if (
                pending is not None
                and pending.user_id == user_id
                and pending.purpose == RECOVERY_SESSION_PURPOSE
                and pending.consumed_at is None
            ):
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
            return None
        if not cookie_session.get("recovery_only"):
            from arborpress.core.audit import write_audit_event

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
