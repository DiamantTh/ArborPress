"""Persistence and channel-neutral notification APIs."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from arborpress.models.notification import (
    NotificationChannelPreference,
    NotificationEvent,
    NotificationTypePreference,
    NotificationWSTicket,
    WebPushDelivery,
    WebPushSubscription,
)

log = logging.getLogger("arborpress.notifications.service")

NOTIFICATION_TYPES: dict[str, dict[str, Any]] = {
    "comment.appeal_reviewed": {
        "title": "Kommentar-Berufung entschieden",
        "message": "Deine Berufung zu einer Moderationsentscheidung wurde geprüft.",
        "fields": {"outcome": re.compile(r"^(upheld|overturned)$")},
        "importance": "normal",
        "channels": {"live_wss": True, "web_push": True, "email": True},
        "default_channels": {"live_wss": True, "web_push": False, "email": False},
        "email_template": "notification.generic",
    },
    "comment.moderation_decision": {
        "title": "Moderationsentscheidung zu deinem Kommentar",
        "message": "Zu einem deiner Kommentare liegt eine Moderationsentscheidung vor.",
        "fields": {"outcome": re.compile(r"^(approve|reject|spam|delete|restore)$")},
        "importance": "normal",
        "channels": {"live_wss": True, "web_push": True, "email": True},
        "default_channels": {"live_wss": True, "web_push": False, "email": False},
        "email_template": "notification.generic",
    },
    "comment.revision_decision": {
        "title": "Entscheidung zu deiner Kommentaränderung",
        "message": "Zu einer Änderung deines Kommentars liegt eine Entscheidung vor.",
        "fields": {"outcome": re.compile(r"^(approve|reject|restore)$")},
        "importance": "normal",
        "channels": {"live_wss": True, "web_push": True, "email": True},
        "default_channels": {"live_wss": True, "web_push": False, "email": False},
        "email_template": "notification.generic",
    },
    "plugin.auto_disabled": {
        "title": "Plugin automatisch deaktiviert",
        "message": "Ein Plugin wurde nach wiederholten Laufzeitfehlern deaktiviert.",
        "fields": {"plugin_id": re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")},
        "importance": "high",
        "channels": {"live_wss": True, "web_push": True, "email": True},
        "default_channels": {"live_wss": True, "web_push": False, "email": False},
        "email_template": "notification.generic",
    },
}


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _safe_path(path: str | None) -> str | None:
    if path is None:
        return None
    if len(path) > 1024 or not path.startswith("/") or path.startswith("//"):
        raise ValueError("Notification target must be a same-origin absolute path")
    if "\\" in path or any(ord(char) < 32 for char in path):
        raise ValueError("Invalid notification target path")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Notification target must be same-origin")
    return path


def _validate_payload(notification_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    definition = NOTIFICATION_TYPES.get(notification_type)
    if definition is None or not isinstance(payload, dict):
        raise ValueError("Unsupported notification type or payload")
    if set(payload) - set(definition["fields"]):
        raise ValueError("Notification payload contains unsupported fields")
    safe: dict[str, str] = {}
    for key, validator in definition["fields"].items():
        if key in payload:
            value = payload[key]
            if not isinstance(value, str) or not validator.fullmatch(value):
                raise ValueError("Notification payload field is invalid")
            safe[key] = value
    # Enforce a compact JSON DTO even if the catalog grows later.
    if len(json.dumps(safe, separators=(",", ":"))) > 1024:
        raise ValueError("Notification payload is too large")
    return safe


async def create_notification(
    db: Any,
    *,
    user_id: str,
    notification_type: str,
    payload: dict[str, Any],
    target_path: str | None = None,
    dedupe_key: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
) -> NotificationEvent | None:
    """Create an inbox event and route opted-in channels in caller transaction.

    Inbox persistence is independent of channel preferences. WSS, push, and email
    are delivery choices and can fail without removing the durable inbox record.
    """
    safe_payload = _validate_payload(notification_type, payload)
    definition = NOTIFICATION_TYPES[notification_type]
    if dedupe_key is not None and len(dedupe_key) > 160:
        raise ValueError("Dedupe key is too long")
    type_preference = await db.scalar(
        select(NotificationTypePreference).where(
            NotificationTypePreference.user_id == str(user_id),
            NotificationTypePreference.notification_type == notification_type,
        )
    )
    if type_preference is not None and not type_preference.enabled:
        if dedupe_key is not None:
            existing = await db.scalar(
                select(NotificationEvent).where(
                    NotificationEvent.user_id == str(user_id),
                    NotificationEvent.dedupe_key == dedupe_key,
                )
            )
            if existing is not None:
                return cast(NotificationEvent, existing)
        return None
    event = NotificationEvent(
        id=str(uuid.uuid4()),
        user_id=str(user_id),
        notification_type=notification_type,
        payload=safe_payload,
        target_path=_safe_path(target_path),
        importance=definition["importance"],
        dedupe_key=dedupe_key,
        source_type=source_type,
        source_id=source_id,
    )
    try:
        async with db.begin_nested():
            db.add(event)
            await db.flush()
    except IntegrityError:
        if dedupe_key is None:
            raise
        existing = await db.scalar(
            select(NotificationEvent).where(
                NotificationEvent.user_id == str(user_id),
                NotificationEvent.dedupe_key == dedupe_key,
            )
        )
        if existing is None:
            raise
        return cast(NotificationEvent, existing)
    preference = await db.get(NotificationChannelPreference, str(user_id))
    type_enabled = type_preference.enabled if type_preference else True
    type_channels = definition["channels"]
    push_enabled = (
        type_enabled
        and bool(type_channels["web_push"])
        and (
            type_preference.web_push_enabled
            if type_preference
            else definition["default_channels"]["web_push"]
        )
        and preference is not None
        and preference.web_push_enabled
    )
    if push_enabled:
        subscriptions = await db.scalars(
            select(WebPushSubscription).where(
                WebPushSubscription.user_id == str(user_id),
                WebPushSubscription.disabled_at.is_(None),
            )
        )
        for subscription in subscriptions:
            db.add(
                WebPushDelivery(
                    id=str(uuid.uuid4()),
                    notification_id=event.id,
                    subscription_id=subscription.id,
                    status="pending",
                    attempts=0,
                    max_attempts=5,
                )
            )
    email_enabled = (
        type_enabled
        and bool(type_channels["email"])
        and (
            type_preference.email_enabled
            if type_preference
            else definition["default_channels"]["email"]
        )
    )
    if email_enabled:
        from arborpress.mail.template_engine import enqueue_template_mail
        from arborpress.models.user import User

        user = await db.get(User, str(user_id))
        if user is not None and user.is_active and user.email:
            from arborpress.core.config import get_settings

            try:
                async with db.begin_nested():
                    await enqueue_template_mail(
                        db,
                        template_id=str(definition["email_template"]),
                        to=str(user.email),
                        context={
                            "display_name": str(user.display_name),
                            "notification_title": str(definition["title"]),
                            "notification_message": str(definition["message"]),
                            "site_name": "ArborPress",
                            "action_url": (
                                get_settings().web.base_url.rstrip("/") + event.target_path
                                if event.target_path
                                else ""
                            ),
                        },
                        user_locale=user.locale,
                        site_locale=get_settings().web.default_lang,
                        idempotency_key=f"notification:{event.id}",
                        purpose="notification",
                    )
            except Exception as exc:
                log.warning(
                    "Notification email enqueue failed event_id=%s error_type=%s",
                    event.id,
                    type(exc).__name__,
                )
    return event


async def list_notifications(
    db: Any, *, user_id: str, page: int = 1, per_page: int = 25
) -> list[NotificationEvent]:
    page = max(1, page)
    per_page = min(100, max(1, per_page))
    result = await db.scalars(
        select(NotificationEvent)
        .where(NotificationEvent.user_id == str(user_id), NotificationEvent.archived_at.is_(None))
        .order_by(NotificationEvent.created_at.desc(), NotificationEvent.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    return list(result)


async def unread_count(db: Any, *, user_id: str) -> int:
    return int(
        await db.scalar(
            select(func.count(NotificationEvent.id)).where(
                NotificationEvent.user_id == str(user_id),
                NotificationEvent.read_at.is_(None),
                NotificationEvent.archived_at.is_(None),
            )
        )
        or 0
    )


async def mark_notification_read(db: Any, *, user_id: str, notification_id: str) -> bool:
    result = await db.execute(
        update(NotificationEvent)
        .where(
            NotificationEvent.id == notification_id,
            NotificationEvent.user_id == str(user_id),
            NotificationEvent.read_at.is_(None),
        )
        .values(read_at=utcnow())
    )
    return bool(result.rowcount == 1)


async def mark_all_read(db: Any, *, user_id: str) -> int:
    result = await db.execute(
        update(NotificationEvent)
        .where(NotificationEvent.user_id == str(user_id), NotificationEvent.read_at.is_(None))
        .values(read_at=utcnow())
    )
    return int(result.rowcount or 0)


async def expire_ws_tickets(db: Any, *, now: datetime | None = None) -> int:
    cutoff = (now or utcnow()) - timedelta(days=1)
    result = await db.execute(
        delete(NotificationWSTicket).where(NotificationWSTicket.expires_at < cutoff)
    )
    return int(result.rowcount or 0)


def new_ws_ticket() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def hash_endpoint(endpoint: str) -> str:
    return hashlib.sha256(endpoint.encode()).hexdigest()


def validate_push_endpoint(endpoint: str) -> None:
    parsed = urlsplit(endpoint)
    if (
        len(endpoint) > 2048
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.hostname.lower() in {"localhost", "localhost.localdomain"}
    ):
        raise ValueError("Push endpoint must be a public HTTPS URL")
    import ipaddress

    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("Push endpoint must not target a private address")


async def consume_ws_ticket(
    db: Any,
    *,
    ticket: str,
    user_id: str,
    session_id: str,
    origin: str,
    now: datetime | None = None,
) -> bool:
    digest = hashlib.sha256(ticket.encode()).hexdigest()
    result = await db.execute(
        update(NotificationWSTicket)
        .where(
            NotificationWSTicket.token_hash == digest,
            NotificationWSTicket.user_id == str(user_id),
            NotificationWSTicket.session_id == str(session_id),
            NotificationWSTicket.purpose == "notification_ws",
            NotificationWSTicket.expected_origin == origin,
            NotificationWSTicket.expires_at > (now or utcnow()),
            NotificationWSTicket.consumed_at.is_(None),
        )
        .values(consumed_at=now or utcnow())
    )
    return bool(result.rowcount == 1)
