"""Bounded durable Web Push delivery worker."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import uuid
from datetime import timedelta
from importlib import import_module
from typing import Any, cast

from sqlalchemy import select, update

from arborpress.core.config import get_settings
from arborpress.core.db import get_session_factory
from arborpress.models.notification import (
    NotificationChannelPreference,
    NotificationEvent,
    WebPushDelivery,
    WebPushSubscription,
)
from arborpress.notifications.service import NOTIFICATION_TYPES, utcnow

log = logging.getLogger("arborpress.notifications.push")
LEASE_SECONDS = 90
MAX_DELIVERIES_PER_PASS = 20


async def _claim(db: Any, *, worker_id: str) -> WebPushDelivery | None:
    now = utcnow()
    await db.execute(
        update(WebPushDelivery)
        .where(
            WebPushDelivery.status == "leased",
            WebPushDelivery.lease_until <= now,
            WebPushDelivery.attempts >= WebPushDelivery.max_attempts,
        )
        .values(status="dead", lease_owner=None, lease_until=None, last_error="lease_expired")
    )
    ready = WebPushDelivery.status.in_(["pending", "retry"]) & (
        WebPushDelivery.next_attempt_at.is_(None) | (WebPushDelivery.next_attempt_at <= now)
    )
    expired = (WebPushDelivery.status == "leased") & (WebPushDelivery.lease_until <= now)
    candidate = await db.scalar(
        select(WebPushDelivery.id)
        .where(WebPushDelivery.attempts < WebPushDelivery.max_attempts, ready | expired)
        .order_by(WebPushDelivery.created_at, WebPushDelivery.id)
        .limit(1)
    )
    if candidate is None:
        return None
    result = await db.execute(
        update(WebPushDelivery)
        .where(
            WebPushDelivery.id == candidate,
            WebPushDelivery.attempts < WebPushDelivery.max_attempts,
            ready | expired,
        )
        .values(
            status="leased",
            lease_owner=worker_id,
            lease_until=now + timedelta(seconds=LEASE_SECONDS),
            attempts=WebPushDelivery.attempts + 1,
            updated_at=now,
        )
    )
    if result.rowcount != 1:
        return None
    await db.flush()
    return cast(WebPushDelivery | None, await db.get(WebPushDelivery, candidate))


def _send(subscription: WebPushSubscription, payload: dict[str, str]) -> tuple[int, str | None]:
    cfg = get_settings().notifications
    private_key = cfg.vapid_private_key.get_secret_value()
    if not private_key:
        raise RuntimeError("vapid_not_configured")
    from arborpress.core.validators import is_safe_external_url

    if not is_safe_external_url(subscription.endpoint):
        raise RuntimeError("push_endpoint_blocked")
    requests = import_module("requests")
    from pywebpush import WebPushException, webpush

    safe_session = requests.Session()
    safe_session.trust_env = False
    original_post = safe_session.post

    def post_no_redirect(url: str, **kwargs: Any) -> Any:
        kwargs["allow_redirects"] = False
        return original_post(url, **kwargs)

    safe_session.post = post_no_redirect

    try:
        response = webpush(
            subscription_info={
                "endpoint": subscription.endpoint,
                "keys": {"p256dh": subscription.p256dh, "auth": subscription.auth_secret},
            },
            data=json.dumps(payload, separators=(",", ":")),
            vapid_private_key=private_key,
            vapid_claims={"sub": cfg.vapid_subject},
            timeout=10,
            requests_session=safe_session,
        )
        return int(response.status_code), None
    except WebPushException as exc:
        response = getattr(exc, "response", None)
        code = int(getattr(response, "status_code", 0) or 0)
        retry_after = response.headers.get("Retry-After") if response is not None else None
        return code, retry_after


async def _deliver_one(db: Any, row: WebPushDelivery, *, worker_id: str) -> None:
    sub = await db.get(WebPushSubscription, row.subscription_id)
    event = await db.get(NotificationEvent, row.notification_id)
    preference = await db.get(NotificationChannelPreference, event.user_id) if event else None
    if (
        sub is None
        or event is None
        or sub.disabled_at is not None
        or preference is None
        or not preference.web_push_enabled
    ):
        row.status = "cancelled"
        row.lease_owner = None
        row.lease_until = None
        await db.commit()
        return
    definition = NOTIFICATION_TYPES.get(event.notification_type)
    if definition is None:
        row.status = "dead"
        row.last_error = "unsupported_notification_type"
        row.lease_owner = None
        row.lease_until = None
        await db.commit()
        return
    payload = {
        "title": str(definition["title"]),
        "body": str(definition["message"]),
        "path": event.target_path or "/notifications",
    }
    try:
        code, retry_after = await asyncio.to_thread(_send, sub, payload)
        if 200 <= code < 300:
            row.status = "sent"
            row.last_error = None
            sub.last_success_at = utcnow()
            sub.failure_count = 0
        elif code in (404, 410):
            row.status = "expired_subscription"
            row.last_error = f"http_{code}"
            sub.disabled_at = utcnow()
        elif code == 429 or code >= 500 or code == 0:
            _schedule_retry(row, retry_after=retry_after)
            row.last_error = f"transient_http_{code}"
            sub.failure_count += 1
        else:
            row.status = "dead"
            row.last_error = f"permanent_http_{code}"
            sub.failure_count += 1
    except Exception as exc:
        # Never persist request URLs, payloads, keys, or raw provider errors.
        if type(exc).__name__ == "RuntimeError" and str(exc) == "vapid_not_configured":
            _schedule_retry(row)
            row.last_error = "vapid_not_configured"
        else:
            _schedule_retry(row)
            row.last_error = "push_transport_error"
        log.warning("Push delivery failed id=%s error_type=%s", row.id, type(exc).__name__)
    row.lease_owner = None
    row.lease_until = None
    row.updated_at = utcnow()
    await db.commit()


def _schedule_retry(row: WebPushDelivery, *, retry_after: str | None = None) -> None:
    if row.attempts >= row.max_attempts:
        row.status = "dead"
        return
    delay = min(3600, 30 * (2 ** max(0, row.attempts - 1)))
    delay = delay * (80 + secrets.randbelow(41)) // 100
    if retry_after and retry_after.isdigit():
        delay = min(86400, max(delay, int(retry_after)))
    row.status = "retry"
    row.next_attempt_at = utcnow() + timedelta(seconds=delay)


async def process_push_queue(*, limit: int = MAX_DELIVERIES_PER_PASS) -> int:
    processed = 0
    worker_id = f"push-{uuid.uuid4()}"
    for _ in range(max(1, min(limit, 100))):
        factory = get_session_factory()
        async with factory() as db:
            row = await _claim(db, worker_id=worker_id)
            if row is None:
                await db.commit()
                break
            await db.commit()
            row_id = row.id
        async with factory() as db:
            row = await db.get(WebPushDelivery, row_id)
            if row is not None and row.lease_owner == worker_id:
                await _deliver_one(db, row, worker_id=worker_id)
        processed += 1
    return processed


async def run_notification_worker(
    interval: int | None = None,
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run bounded push delivery; only one worker process per instance owns it."""
    from arborpress.runtime.paths import ensure_instance_layout, get_runtime_paths

    paths = get_runtime_paths()
    ensure_instance_layout(paths)
    lock_path = paths.run / "notification-worker.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        try:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except ImportError:
            acquired = True
        except BlockingIOError:
            return
        poll = interval or get_settings().notifications.worker_poll_seconds
        while stop_event is None or not stop_event.is_set():
            try:
                await process_push_queue()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error("Notification worker failed error_type=%s", type(exc).__name__)
            try:
                if stop_event is None:
                    await asyncio.sleep(poll)
                else:
                    await asyncio.wait_for(stop_event.wait(), timeout=poll)
            except TimeoutError:
                pass
    finally:
        if acquired:
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
            except ImportError:
                pass
        os.close(fd)
