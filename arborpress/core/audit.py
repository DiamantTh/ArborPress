"""Unified audit-log helper (§2 §10 §16).

Writes every security-relevant event to TWO sinks:

1. **File logger** (``arborpress.audit``) – always active when
   ``[logging] audit_log = true`` (the default).  Operators tail this
   file or forward it to a SIEM without any schema changes.

2. **DB table** (``audit_events``) – opt-in via
   ``[logging] db_audit_log = true`` in config.toml.  Enables a searchable,
   exportable audit trail in the admin UI (requires a fresh install or the
   schema to include the ``audit_events`` table).

Usage::

    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="login_failure",
        outcome="failure",
        actor_id=str(user.id),
        actor_name=user.username,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        detail="attempt=3",
        db=db,            # pass async session; caller must commit afterwards
    )
    await db.commit()
"""

from __future__ import annotations

import logging
from typing import Any

_audit = logging.getLogger("arborpress.audit")


async def write_audit_event(
    *,
    event_type: str,
    outcome: str,
    ip: str | None = None,
    actor_id: str | None = None,
    actor_name: str | None = None,
    user_agent: str | None = None,
    detail: str | None = None,
    db: Any = None,
) -> None:
    """Write a security event to the audit log (file + optionally DB).

    Parameters
    ----------
    event_type:
        Machine-readable event name, e.g. ``"login_failure"``,
        ``"login_blocked"``, ``"login_success"``.
    outcome:
        ``"success"`` | ``"failure"`` | ``"blocked"``.
    ip:
        Client IP address (IPv4 or IPv6, max 45 chars).
    actor_id:
        UUID of the user who triggered the event (nullable).
    actor_name:
        Username (denormalized – readable after user deletion).
    user_agent:
        Raw ``User-Agent`` header value (truncated to 512 chars).
    detail:
        Free-form reason string, e.g. ``"attempt=3 account_locked"``.
    db:
        Open async SQLAlchemy session.  Required for DB writes.
        The caller is responsible for calling ``await db.commit()``
        after this function returns so that the event and any other
        pending changes are flushed atomically.
    """
    # --- always: file logger ---------------------------------------------
    _audit.warning(
        "%s outcome=%s actor=%s ip=%s%s",
        event_type.upper(),
        outcome,
        actor_name or actor_id or "unknown",
        ip or "unknown",
        f" | {detail}" if detail else "",
    )

    # --- opt-in: DB row --------------------------------------------------
    if db is None:
        return

    from arborpress.core.config import get_settings
    if not get_settings().logging.db_audit_log:
        return

    from arborpress.models.audit import AuditEvent
    db.add(AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        actor_name=actor_name,
        ip=ip,
        user_agent=(user_agent or "")[:512] or None,
        outcome=outcome,
        detail=detail,
    ))
