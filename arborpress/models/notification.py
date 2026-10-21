"""Persistent user notifications and delivery state."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from arborpress.core.db import Base


class NotificationEvent(Base):
    """Channel-independent, user-scoped notification inbox item."""

    __tablename__ = "notification_events"
    __table_args__ = (
        Index("ix_notification_user_created", "user_id", "created_at", "id"),
        Index("ix_notification_user_read", "user_id", "read_at"),
        UniqueConstraint("user_id", "dedupe_key", name="uq_notification_user_dedupe"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    notification_type: Mapped[str] = mapped_column(String(96), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    target_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    importance: Mapped[str] = mapped_column(String(16), nullable=False, default="normal")
    dedupe_key: Mapped[str | None] = mapped_column(String(160), nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )


class NotificationChannelPreference(Base):
    """Explicit per-user, opt-in channel preferences (false by default)."""

    __tablename__ = "notification_channel_preferences"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    live_wss_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    web_push_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )


class NotificationTypePreference(Base):
    """Explicit per-type channel choices; omitted rows use conservative catalog defaults."""

    __tablename__ = "notification_type_preferences"
    __table_args__ = (
        UniqueConstraint("user_id", "notification_type", name="uq_notification_type_preference"),
        Index("ix_notification_type_preference_user", "user_id", "notification_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    notification_type: Mapped[str] = mapped_column(String(96), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    live_wss_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    web_push_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )


class NotificationWSTicket(Base):
    """Short-lived, one-shot proof bound to one authenticated session and origin."""

    __tablename__ = "notification_ws_tickets"
    __table_args__ = (Index("ix_notification_ws_ticket_expiry", "expires_at"),)

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_sessions.id", ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, default="notification_ws")
    expected_origin: Mapped[str] = mapped_column(String(512), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class WebPushSubscription(Base):
    """Browser subscription secrets are private and never exposed in views."""

    __tablename__ = "web_push_subscriptions"
    __table_args__ = (
        UniqueConstraint("user_id", "endpoint_hash", name="uq_webpush_user_endpoint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    endpoint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    p256dh: Mapped[str] = mapped_column(String(256), nullable=False)
    auth_secret: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failure_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class WebPushDelivery(Base):
    """Durable push attempt, unique per notification/subscription."""

    __tablename__ = "web_push_deliveries"
    __table_args__ = (
        UniqueConstraint("notification_id", "subscription_id", name="uq_webpush_delivery_target"),
        Index("ix_webpush_due", "status", "next_attempt_at", "lease_until"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    notification_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("notification_events.id", ondelete="CASCADE"), nullable=False
    )
    subscription_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("web_push_subscriptions.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5, server_default="5"
    )
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now(), onupdate=func.now()
    )
