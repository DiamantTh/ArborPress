"""One session creation path for every successful authentication flow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from quart import request, session
from sqlalchemy import update

from arborpress.core.config import get_settings
from arborpress.models.user import UserSession


async def create_user_session(
    db: Any,
    user: Any,
    *,
    auth_method: str,
    assurance_level: str,
    recovery_only: bool = False,
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
        expires_at=now + timedelta(seconds=cfg.auth.admin_session_ttl),
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
    return db_session


async def refresh_session_identity(db: Any, cookie_session: Any) -> Any | None:
    """Validate the DB session and refresh role claims before authorization."""
    from arborpress.models.user import User, UserSession

    user_id = str(cookie_session.get("user_id") or "")
    session_id = str(cookie_session.get("session_id") or "")
    if not user_id or not session_id:
        return None

    user = await db.get(User, user_id)
    db_session = await db.get(UserSession, session_id)
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
