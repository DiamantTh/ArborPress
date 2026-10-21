"""SSR inbox, opt-in endpoints, and same-origin live notifications socket."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import re
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from quart import (
    Blueprint,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    websocket,
)
from quart.typing import ResponseReturnValue
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session, get_session_factory
from arborpress.models.notification import (
    NotificationChannelPreference,
    NotificationEvent,
    NotificationWSTicket,
    WebPushDelivery,
    WebPushSubscription,
)
from arborpress.models.user import User
from arborpress.notifications.service import (
    consume_ws_ticket,
    expire_ws_tickets,
    hash_endpoint,
    list_notifications,
    mark_all_read,
    mark_notification_read,
    new_ws_ticket,
    unread_count,
    utcnow,
    validate_push_endpoint,
)
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.notifications")
notifications_bp = Blueprint("notifications", __name__)
WS_PROTOCOL = "arborpress.notifications.v1"
MAX_WS_FRAME = 16 * 1024


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{scheme}://{rendered_host}{suffix}"


def _expected_origin() -> str:
    configured = urlsplit(get_settings().web.base_url)
    if configured.scheme == "http" and configured.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        return ""
    if configured.scheme not in {"http", "https"}:
        return ""
    return _normalize_origin(f"{configured.scheme}://{configured.netloc}")


def _vapid_configured() -> bool:
    config = get_settings().notifications
    return bool(config.vapid_private_key.get_secret_value() and config.vapid_public_key)


async def _socket_send(payload: dict[str, Any]) -> bool:
    try:
        await asyncio.wait_for(websocket.send_json(payload), timeout=10)
        return True
    except Exception:
        return False


async def _authenticated_user(db: AsyncSession) -> User | None:
    from arborpress.auth.sessions import refresh_session_identity

    user = cast(User | None, await refresh_session_identity(db, session))
    if user is None or not user.is_active or session.get("recovery_only"):
        return None
    return user


@notifications_bp.get("/notifications")
async def inbox() -> ResponseReturnValue:
    async for db in get_db_session():
        user = await _authenticated_user(db)
        if user is None:
            abort(401)
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            abort(400)
        events = await list_notifications(db, user_id=str(user.id), page=page)
        unread = await unread_count(db, user_id=str(user.id))
        preference = await db.get(NotificationChannelPreference, user.id)
        subscriptions = await db.scalars(
            select(WebPushSubscription).where(
                WebPushSubscription.user_id == str(user.id),
                WebPushSubscription.disabled_at.is_(None),
            )
        )
        from arborpress.notifications.service import NOTIFICATION_TYPES

        event_views = [
            {
                "event": event,
                "title": NOTIFICATION_TYPES[event.notification_type]["title"],
                "message": NOTIFICATION_TYPES[event.notification_type]["message"],
            }
            for event in events
            if event.notification_type in NOTIFICATION_TYPES
        ]
        await db.commit()
        return await render_template(
            "notifications/inbox.html",
            events=event_views,
            unread_count=unread,
            page=page,
            preference=preference,
            subscriptions=list(subscriptions),
            vapid_public_key=get_settings().notifications.vapid_public_key,
            vapid_configured=_vapid_configured(),
            ws_url=("wss://" if get_settings().web.base_url.startswith("https://") else "ws://")
            + urlsplit(get_settings().web.base_url).netloc
            + url_for("notifications.notifications_socket"),
        )
    abort(503)


@notifications_bp.post("/notifications/<notification_id>/read")
async def notification_read(notification_id: str) -> ResponseReturnValue:
    await validate_csrf()
    async for db in get_db_session():
        user = await _authenticated_user(db)
        if user is None:
            abort(401)
        await mark_notification_read(db, user_id=str(user.id), notification_id=notification_id)
        await db.commit()
    return redirect(url_for("notifications.inbox"))


@notifications_bp.post("/notifications/read-all")
async def notifications_read_all() -> ResponseReturnValue:
    await validate_csrf()
    async for db in get_db_session():
        user = await _authenticated_user(db)
        if user is None:
            abort(401)
        await mark_all_read(db, user_id=str(user.id))
        await db.commit()
    return redirect(url_for("notifications.inbox"))


@notifications_bp.post("/notifications/preferences")
async def preferences_update() -> ResponseReturnValue:
    await validate_csrf()
    form = await request.form
    async for db in get_db_session():
        user = await _authenticated_user(db)
        if user is None:
            abort(401)
        preference = await db.get(NotificationChannelPreference, user.id)
        if preference is None:
            preference = NotificationChannelPreference(user_id=user.id)
            db.add(preference)
        preference.live_wss_enabled = form.get("live_wss_enabled") == "on"
        preference.web_push_enabled = form.get("web_push_enabled") == "on" and _vapid_configured()
        if not preference.web_push_enabled:
            await db.execute(
                update(WebPushDelivery)
                .where(
                    WebPushDelivery.status.in_(["pending", "retry"]),
                    WebPushDelivery.subscription_id.in_(
                        select(WebPushSubscription.id).where(
                            WebPushSubscription.user_id == str(user.id)
                        )
                    ),
                )
                .values(status="cancelled", lease_owner=None, lease_until=None)
            )
        await db.commit()
    return redirect(url_for("notifications.inbox"))


@notifications_bp.post("/notifications/ws-ticket")
async def issue_ws_ticket() -> ResponseReturnValue:
    await validate_csrf()
    origin = _normalize_origin(request.headers.get("Origin", ""))
    if not origin or origin != _expected_origin():
        abort(403)
    async for db in get_db_session():
        user = await _authenticated_user(db)
        session_id = str(session.get("session_id") or "")
        if user is None or not session_id:
            abort(401)
        preference = await db.get(NotificationChannelPreference, user.id)
        if preference is None or not preference.live_wss_enabled:
            abort(403)
        from arborpress.models.user import UserSession

        db_session = await db.get(UserSession, session_id)
        if (
            db_session is None
            or db_session.user_id != user.id
            or not db_session.is_valid
            or db_session.is_expired
        ):
            abort(401)
        token, digest = new_ws_ticket()
        ttl = get_settings().notifications.ticket_ttl_seconds
        await expire_ws_tickets(db)
        db.add(
            NotificationWSTicket(
                token_hash=digest,
                user_id=user.id,
                session_id=session_id,
                purpose="notification_ws",
                expected_origin=origin,
                expires_at=utcnow() + timedelta(seconds=ttl),
            )
        )
        await db.commit()
        return jsonify({"ticket": token, "protocol": WS_PROTOCOL, "expires_in": ttl})
    abort(503)


@notifications_bp.get("/notifications/web-push/key")
async def web_push_key() -> ResponseReturnValue:
    async for db in get_db_session():
        user = await _authenticated_user(db)
        if user is None:
            abort(401)
        if not _vapid_configured():
            abort(503)
        await db.commit()
        return jsonify({"publicKey": get_settings().notifications.vapid_public_key})
    abort(503)


@notifications_bp.post("/notifications/web-push/subscribe")
async def web_push_subscribe() -> ResponseReturnValue:
    await validate_csrf()
    data = await request.get_json(silent=True)
    if (
        not isinstance(data, dict)
        or set(data) != {"endpoint", "keys"}
        or not isinstance(data.get("keys"), dict)
    ):
        abort(400)
    endpoint = data.get("endpoint")
    keys = data["keys"]
    p256dh, auth_secret = keys.get("p256dh"), keys.get("auth")
    if (
        not all(isinstance(v, str) for v in (endpoint, p256dh, auth_secret))
        or len(p256dh) > 256
        or len(auth_secret) > 256
    ):
        abort(400)
    assert isinstance(endpoint, str)
    assert isinstance(p256dh, str)
    assert isinstance(auth_secret, str)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", p256dh) or not re.fullmatch(
        r"[A-Za-z0-9_-]+", auth_secret
    ):
        abort(400)
    try:
        decoded_p256dh = base64.urlsafe_b64decode(p256dh + "=" * (-len(p256dh) % 4))
        decoded_auth = base64.urlsafe_b64decode(auth_secret + "=" * (-len(auth_secret) % 4))
    except (ValueError, binascii.Error):
        abort(400)
    if len(decoded_p256dh) != 65 or decoded_p256dh[0] != 4 or len(decoded_auth) != 16:
        abort(400)
    try:
        validate_push_endpoint(endpoint)
    except ValueError:
        abort(400)
    from arborpress.core.validators import is_safe_external_url

    if not await asyncio.to_thread(is_safe_external_url, endpoint):
        abort(400)
    async for db in get_db_session():
        user = await _authenticated_user(db)
        if user is None:
            abort(401)
        pref = await db.get(NotificationChannelPreference, user.id)
        if pref is None or not pref.web_push_enabled or not _vapid_configured():
            abort(403)
        endpoint_digest = hash_endpoint(endpoint)
        subscription = await db.scalar(
            select(WebPushSubscription).where(
                WebPushSubscription.user_id == user.id,
                WebPushSubscription.endpoint_hash == endpoint_digest,
            )
        )
        if subscription is None:
            subscription = WebPushSubscription(
                user_id=user.id,
                endpoint=endpoint,
                endpoint_hash=endpoint_digest,
                p256dh=p256dh,
                auth_secret=auth_secret,
            )
            db.add(subscription)
        else:
            subscription.endpoint = endpoint
            subscription.p256dh = p256dh
            subscription.auth_secret = auth_secret
            subscription.disabled_at = None
        await db.commit()
        return jsonify({"status": "subscribed"}), 201
    abort(503)


@notifications_bp.post("/notifications/web-push/unsubscribe")
async def web_push_unsubscribe() -> ResponseReturnValue:
    await validate_csrf()
    data = await request.get_json(silent=True)
    subscription_id = data.get("subscription_id") if isinstance(data, dict) else None
    endpoint = data.get("endpoint") if isinstance(data, dict) else None
    async for db in get_db_session():
        user = await _authenticated_user(db)
        if user is None:
            abort(401)
        if subscription_id is None and endpoint is None:
            await db.execute(
                update(WebPushSubscription)
                .where(
                    WebPushSubscription.user_id == user.id,
                    WebPushSubscription.disabled_at.is_(None),
                )
                .values(disabled_at=utcnow())
            )
            await db.execute(
                update(WebPushDelivery)
                .where(
                    WebPushDelivery.subscription_id.in_(
                        select(WebPushSubscription.id).where(WebPushSubscription.user_id == user.id)
                    ),
                    WebPushDelivery.status.in_(["pending", "retry"]),
                )
                .values(status="cancelled", lease_owner=None, lease_until=None)
            )
        elif subscription_id is not None:
            sub = await db.scalar(
                select(WebPushSubscription).where(
                    WebPushSubscription.id == str(subscription_id),
                    WebPushSubscription.user_id == user.id,
                )
            )
            if sub is not None:
                sub.disabled_at = utcnow()
                await db.execute(
                    update(WebPushDelivery)
                    .where(
                        WebPushDelivery.subscription_id == sub.id,
                        WebPushDelivery.status.in_(["pending", "retry"]),
                    )
                    .values(status="cancelled", lease_owner=None, lease_until=None)
                )
        elif isinstance(endpoint, str):
            sub = await db.scalar(
                select(WebPushSubscription).where(
                    WebPushSubscription.endpoint_hash == hash_endpoint(endpoint),
                    WebPushSubscription.user_id == user.id,
                )
            )
            if sub is not None:
                sub.disabled_at = utcnow()
                await db.execute(
                    update(WebPushDelivery)
                    .where(
                        WebPushDelivery.subscription_id == sub.id,
                        WebPushDelivery.status.in_(["pending", "retry"]),
                    )
                    .values(status="cancelled", lease_owner=None, lease_until=None)
                )
        await db.commit()
        return jsonify({"status": "unsubscribed"})
    abort(503)


@notifications_bp.websocket("/notifications/ws")
async def notifications_socket() -> None:
    origin = _normalize_origin(websocket.headers.get("Origin", ""))
    if not origin or origin != _expected_origin():
        await websocket.close(4403)
        return
    session_id = str(session.get("session_id") or "")
    async with get_session_factory()() as db:
        user = await _authenticated_user(db)
        if user is None or not session_id:
            await websocket.close(4401)
            return
        user_id = str(user.id)
        preference = await db.get(NotificationChannelPreference, user_id)
        if preference is None or not preference.live_wss_enabled:
            await websocket.close(4403)
            return
        await db.commit()
    try:
        first = await asyncio.wait_for(websocket.receive(), timeout=5)
        if not isinstance(first, str) or len(first.encode()) > MAX_WS_FRAME:
            raise ValueError
        message = json.loads(first)
        if (
            not isinstance(message, dict)
            or set(message) - {"protocol", "ticket", "last_seen_notification_id"}
            or message.get("protocol") != WS_PROTOCOL
            or not isinstance(message.get("ticket"), str)
        ):
            raise ValueError
        cursor = message.get("last_seen_notification_id")
        if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 36):
            raise ValueError
    except TimeoutError, ValueError, json.JSONDecodeError:
        await websocket.close(4400)
        return

    async with get_session_factory()() as db:
        if not await consume_ws_ticket(
            db,
            ticket=message["ticket"],
            user_id=user_id,
            session_id=session_id,
            origin=origin,
        ):
            await db.rollback()
            await websocket.close(4401)
            return
        await db.commit()
    if not await _socket_send({"type": "ready", "protocol": WS_PROTOCOL}):
        return
    cursor_created = None
    resync = False
    if cursor:
        async with get_session_factory()() as db:
            cursor_row = await db.scalar(
                select(NotificationEvent).where(
                    NotificationEvent.id == cursor,
                    NotificationEvent.user_id == user_id,
                )
            )
            if cursor_row is not None:
                cursor_created = cursor_row.created_at
    last_id = cursor if cursor_created is not None else ""
    if cursor_created is None or cursor_created < utcnow() - timedelta(days=30):
        resync = cursor_created is not None
        cursor_created = utcnow() - timedelta(days=7)
    last_sent_id = last_id
    sent_count = 0
    for _ in range(10000):
        async with get_session_factory()() as db:
            from arborpress.models.user import UserSession

            ws_session = await db.get(UserSession, session_id)
            current_user = await db.get(type(user), user_id)
            if (
                ws_session is None
                or not ws_session.is_valid
                or ws_session.is_expired
                or current_user is None
                or not current_user.is_active
            ):
                await websocket.close(4401)
                return
            current_pref = await db.get(NotificationChannelPreference, user_id)
            if current_pref is None or not current_pref.live_wss_enabled:
                await websocket.close(4403)
                return
            rows = await db.scalars(
                select(NotificationEvent)
                .where(
                    NotificationEvent.user_id == user_id,
                    NotificationEvent.archived_at.is_(None),
                    (NotificationEvent.created_at > cursor_created)
                    | (
                        (NotificationEvent.created_at == cursor_created)
                        & (NotificationEvent.id > last_sent_id)
                    ),
                )
                .order_by(NotificationEvent.created_at, NotificationEvent.id)
                .limit(50)
            )
            events = list(rows)
            unread = await unread_count(db, user_id=user_id)
        if resync:
            if not await _socket_send({"type": "resync_required"}):
                return
            resync = False
        for event in events:
            from arborpress.notifications.service import NOTIFICATION_TYPES

            definition = NOTIFICATION_TYPES.get(event.notification_type)
            if definition is None:
                continue
            if not await _socket_send(
                {
                    "type": "notification",
                    "notification": {
                        "id": event.id,
                        "notification_type": event.notification_type,
                        "payload": event.payload,
                        "title": definition["title"],
                        "message": definition["message"],
                        "target_path": event.target_path,
                        "created_at": event.created_at.isoformat(),
                        "read": event.read_at is not None,
                    },
                }
            ):
                return
            cursor_created = event.created_at
            last_sent_id = event.id
            sent_count += 1
            if sent_count >= 250:
                await _socket_send({"type": "resync_required"})
                await websocket.close(1013)
                return
        if not await _socket_send({"type": "unread_count", "count": unread}):
            return
        try:
            incoming = await asyncio.wait_for(websocket.receive(), timeout=3)
            if not isinstance(incoming, str) or len(incoming.encode()) > MAX_WS_FRAME:
                await websocket.close(4400)
                return
            request_message = json.loads(incoming)
            if request_message == {"type": "ping"}:
                if not await _socket_send({"type": "pong"}):
                    return
            else:
                await websocket.close(4400)
                return
        except TimeoutError:
            pass
        except ValueError, json.JSONDecodeError:
            await websocket.close(4400)
            return
        except Exception:
            # Quart surfaces a client close as a WebSocket disconnect exception.
            return


@notifications_bp.get("/service-worker.js")
async def service_worker() -> ResponseReturnValue:
    from quart import send_file

    path = Path(__file__).parents[2] / "static" / "js" / "notification-sw.js"
    response = await send_file(path, mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response
