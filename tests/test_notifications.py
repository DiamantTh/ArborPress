"""Persistent notification inbox, ticket, and channel isolation contracts."""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.models.notification import (
    NotificationChannelPreference,
    NotificationWSTicket,
    WebPushDelivery,
    WebPushSubscription,
)
from arborpress.models.user import AccountType, User, UserRole, UserSession
from arborpress.notifications.service import (
    consume_ws_ticket,
    create_notification,
    hash_endpoint,
    list_notifications,
    mark_notification_read,
    new_ws_ticket,
    unread_count,
    utcnow,
    validate_push_endpoint,
)


def _user() -> User:
    suffix = uuid.uuid4().hex[:10]
    return User(
        username=f"notify-{suffix}",
        display_name=f"Notify {suffix}",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )


@pytest.mark.asyncio
async def test_inbox_is_owner_scoped_idempotent_and_payload_is_catalog_limited(db_session):
    user, stranger = _user(), _user()
    db_session.add_all([user, stranger])
    await db_session.flush()
    event = await create_notification(
        db_session,
        user_id=str(user.id),
        notification_type="comment.moderation_decision",
        payload={"outcome": "reject"},
        target_path="/notifications",
        dedupe_key="decision:one",
    )
    same = await create_notification(
        db_session,
        user_id=str(user.id),
        notification_type="comment.moderation_decision",
        payload={"outcome": "reject"},
        target_path="/notifications",
        dedupe_key="decision:one",
    )
    assert same.id == event.id
    assert await unread_count(db_session, user_id=str(user.id)) == 1
    assert await unread_count(db_session, user_id=str(stranger.id)) == 0
    assert len(await list_notifications(db_session, user_id=str(stranger.id))) == 0
    assert (
        await mark_notification_read(db_session, user_id=str(stranger.id), notification_id=event.id)
        is False
    )
    assert (
        await mark_notification_read(db_session, user_id=str(user.id), notification_id=event.id)
        is True
    )
    assert (
        await mark_notification_read(db_session, user_id=str(user.id), notification_id=event.id)
        is False
    )
    assert await unread_count(db_session, user_id=str(user.id)) == 0

    with pytest.raises(ValueError, match="unsupported fields"):
        await create_notification(
            db_session,
            user_id=str(user.id),
            notification_type="comment.moderation_decision",
            payload={"outcome": "reject", "email": "private@example.test"},
        )
    with pytest.raises(ValueError, match="same-origin"):
        await create_notification(
            db_session,
            user_id=str(user.id),
            notification_type="comment.moderation_decision",
            payload={"outcome": "reject"},
            target_path="https://evil.example/",
        )


@pytest.mark.asyncio
async def test_opted_in_push_creates_durable_per_subscription_delivery(db_session):
    user = _user()
    db_session.add(user)
    await db_session.flush()
    endpoint = "https://push.example.test/send/a"
    subscription = WebPushSubscription(
        user_id=str(user.id),
        endpoint=endpoint,
        endpoint_hash=hash_endpoint(endpoint),
        p256dh="public-key",
        auth_secret="auth-key",  # noqa: S106 - inert fixture values
    )
    db_session.add_all(
        [
            subscription,
            NotificationChannelPreference(user_id=str(user.id), web_push_enabled=True),
        ]
    )
    await db_session.flush()
    event = await create_notification(
        db_session,
        user_id=str(user.id),
        notification_type="comment.appeal_reviewed",
        payload={"outcome": "overturned"},
    )
    delivery = await db_session.scalar(
        select(WebPushDelivery).where(WebPushDelivery.notification_id == event.id)
    )
    assert delivery is not None
    assert delivery.subscription_id == subscription.id
    assert delivery.status == "pending"


@pytest.mark.asyncio
async def test_ws_ticket_is_session_origin_bound_expiring_and_one_shot(db_session):
    user = _user()
    db_session.add(user)
    await db_session.flush()
    session_row = UserSession(
        user_id=str(user.id),
        expires_at=utcnow() + timedelta(hours=1),
        last_seen_at=utcnow(),
        is_valid=True,
    )
    db_session.add(session_row)
    await db_session.flush()
    token, digest = new_ws_ticket()
    now = utcnow()
    db_session.add(
        NotificationWSTicket(
            token_hash=digest,
            user_id=str(user.id),
            session_id=session_row.id,
            purpose="notification_ws",
            expected_origin="https://blog.example.test",
            expires_at=now + timedelta(seconds=45),
        )
    )
    await db_session.flush()
    assert not await consume_ws_ticket(
        db_session,
        ticket=token,
        user_id=str(user.id),
        session_id=session_row.id,
        origin="https://attacker.example.test",
        now=now,
    )
    assert await consume_ws_ticket(
        db_session,
        ticket=token,
        user_id=str(user.id),
        session_id=session_row.id,
        origin="https://blog.example.test",
        now=now,
    )
    assert not await consume_ws_ticket(
        db_session,
        ticket=token,
        user_id=str(user.id),
        session_id=session_row.id,
        origin="https://blog.example.test",
        now=now,
    )


def test_push_endpoint_requires_https_and_rejects_private_or_credentialed_urls():
    validate_push_endpoint("https://push.example.test/subscription")
    for endpoint in (
        "http://push.example.test/subscription",
        "https://localhost/subscription",
        "https://127.0.0.1/subscription",
        "https://user:secret@push.example.test/subscription",
    ):
        with pytest.raises(ValueError):
            validate_push_endpoint(endpoint)


def test_origin_and_ticket_primitives_are_canonical_and_unpredictable():
    from arborpress.web.routes.notifications import _normalize_origin

    assert _normalize_origin("HTTPS://Blog.Example.Test:443") == "https://blog.example.test"
    assert _normalize_origin("https://blog.example.test/path") == ""
    token, digest = new_ws_ticket()
    assert len(token) >= 43
    assert digest == hashlib.sha256(token.encode()).hexdigest()
    assert token != digest


def test_vapid_private_key_uses_deployment_secret_override(tmp_path, monkeypatch):
    from arborpress.core.config import Settings

    config_file = tmp_path / "config.toml"
    config_file.write_text(
        '[notifications]\nvapid_private_key = "file-value"\nvapid_public_key = "public"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ARBORPRESS_NOTIFICATIONS__VAPID_PRIVATE_KEY", "injected-secret")
    settings = Settings.from_path(config_file)
    assert settings.notifications.vapid_private_key.get_secret_value() == "injected-secret"
    assert settings.notifications.vapid_public_key == "public"


def test_push_retry_policy_is_bounded_and_respects_numeric_retry_after():
    from arborpress.notifications.push import _schedule_retry

    row = SimpleNamespace(attempts=2, max_attempts=5, status="leased", next_attempt_at=None)
    _schedule_retry(row, retry_after="90")
    assert row.status == "retry"
    assert row.next_attempt_at > utcnow() + timedelta(seconds=89)
    row.attempts = row.max_attempts
    _schedule_retry(row)
    assert row.status == "dead"


@pytest.mark.asyncio
async def test_wss_route_uses_ticket_as_first_message_and_returns_catchup(
    client, app, test_engine, monkeypatch
):
    from arborpress.core.config import get_settings

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    get_settings().web.base_url = "http://localhost:8066"
    user = _user()
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        db.add(user)
        await db.flush()
        session_row = UserSession(
            user_id=str(user.id),
            expires_at=utcnow() + timedelta(hours=1),
            last_seen_at=utcnow(),
            is_valid=True,
        )
        db.add_all(
            [
                session_row,
                NotificationChannelPreference(user_id=str(user.id), live_wss_enabled=True),
            ]
        )
        await db.flush()
        notification = await create_notification(
            db,
            user_id=str(user.id),
            notification_type="comment.appeal_reviewed",
            payload={"outcome": "upheld"},
        )
        await db.commit()
        user_id, session_id, notification_id = str(user.id), session_row.id, notification.id

    csrf = "a" * 64
    async with client.session_transaction() as browser_session:
        browser_session.update(
            {
                "user_id": user_id,
                "session_id": session_id,
                "_csrf_token": csrf,
            }
        )
    response = await client.post(
        "/notifications/ws-ticket",
        headers={"Origin": "http://localhost:8066", "X-CSRF-Token": csrf},
    )
    assert response.status_code == 200
    ticket = await response.get_json()
    assert "ticket" in ticket

    async with client.websocket(
        "/notifications/ws", headers={"Origin": "http://localhost:8066"}
    ) as socket:
        await socket.send_json({"protocol": ticket["protocol"], "ticket": ticket["ticket"]})
        assert (await socket.receive_json())["type"] == "ready"
        notification_message = await socket.receive_json()
        assert notification_message["notification"]["id"] == notification_id
        assert (await socket.receive_json())["type"] == "unread_count"
        await socket.close(1000)
