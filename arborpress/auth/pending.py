"""Persistence helpers for short-lived, one-shot authentication state."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, or_, select, update

from arborpress.models.user import AuthPending


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def as_utc_naive(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo else value


async def create_pending(
    db: Any,
    *,
    purpose: str,
    user_id: str | None,
    ttl_seconds: int,
    challenge: bytes | None = None,
    label: str | None = None,
    username: str | None = None,
    display_name: str | None = None,
    email: str | None = None,
    context: dict[str, Any] | None = None,
) -> AuthPending:
    now = utcnow_naive()
    # Keep abandoned public login attempts and completed ceremonies from
    # accumulating indefinitely. All retained pending rows are live.
    await db.execute(
        delete(AuthPending).where(
            or_(AuthPending.expires_at <= now, AuthPending.consumed_at.is_not(None))
        )
    )
    pending = AuthPending(
        id=str(uuid.uuid4()),
        purpose=purpose,
        user_id=user_id,
        challenge=challenge,
        label=label,
        username=username,
        display_name=display_name,
        email=email,
        context=json.dumps(context or {}, separators=(",", ":")),
        created_at=now,
        expires_at=now + timedelta(seconds=max(1, ttl_seconds)),
    )
    db.add(pending)
    await db.flush()
    return pending


async def consume_pending(
    db: Any,
    *,
    pending_id: str,
    purpose: str,
    user_id: str | None = None,
) -> AuthPending | None:
    """Atomically consume a matching, unexpired pending record once."""
    pending = (await db.execute(
        select(AuthPending).where(AuthPending.id == pending_id)
    )).scalar_one_or_none()
    if pending is None or pending.purpose != purpose:
        return None
    if user_id is not None and pending.user_id != str(user_id):
        return None
    if pending.consumed_at is not None or as_utc_naive(pending.expires_at) <= utcnow_naive():
        return None

    result = await db.execute(
        update(AuthPending)
        .where(
            AuthPending.id == pending_id,
            AuthPending.purpose == purpose,
            AuthPending.consumed_at.is_(None),
            AuthPending.expires_at > utcnow_naive(),
        )
        .values(consumed_at=utcnow_naive())
    )
    if result.rowcount != 1:
        return None
    await db.flush()
    return pending
