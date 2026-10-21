"""Add persistent notification inbox, WSS tickets and Web Push delivery.

Revision ID: 0007_notifications_live_and_web_push
Revises: 0006_smtp_profiles_mail_outbox
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_notifications_live_and_web_push"
down_revision: str | None = "0006_smtp_profiles_mail_outbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("notification_type", sa.String(96), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("target_path", sa.String(1024), nullable=True),
        sa.Column("importance", sa.String(16), nullable=False, server_default="normal"),
        sa.Column("dedupe_key", sa.String(160), nullable=True),
        sa.Column("source_type", sa.String(32), nullable=True),
        sa.Column("source_id", sa.String(36), nullable=True),
        sa.Column("read_at", sa.DateTime(), nullable=True),
        sa.Column("archived_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "dedupe_key", name="uq_notification_user_dedupe"),
    )
    op.create_index(
        "ix_notification_user_created", "notification_events", ["user_id", "created_at", "id"]
    )
    op.create_index("ix_notification_user_read", "notification_events", ["user_id", "read_at"])

    op.create_table(
        "notification_channel_preferences",
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("live_wss_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("web_push_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "notification_ws_tickets",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("user_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("expected_origin", sa.String(512), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_notification_ws_ticket_expiry", "notification_ws_tickets", ["expires_at"])

    op.create_table(
        "web_push_subscriptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("endpoint", sa.Text(), nullable=False),
        sa.Column("endpoint_hash", sa.String(64), nullable=False),
        sa.Column("p256dh", sa.String(256), nullable=False),
        sa.Column("auth_secret", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("user_id", "endpoint_hash", name="uq_webpush_user_endpoint"),
    )
    op.create_index("ix_web_push_subscriptions_user_id", "web_push_subscriptions", ["user_id"])

    op.create_table(
        "web_push_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "notification_id",
            sa.String(36),
            sa.ForeignKey("notification_events.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "subscription_id",
            sa.String(36),
            sa.ForeignKey("web_push_subscriptions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "notification_id", "subscription_id", name="uq_webpush_delivery_target"
        ),
    )
    op.create_index("ix_web_push_deliveries_status", "web_push_deliveries", ["status"])
    op.create_index(
        "ix_webpush_due", "web_push_deliveries", ["status", "next_attempt_at", "lease_until"]
    )


def downgrade() -> None:
    op.drop_index("ix_webpush_due", table_name="web_push_deliveries")
    op.drop_index("ix_web_push_deliveries_status", table_name="web_push_deliveries")
    op.drop_table("web_push_deliveries")
    op.drop_index("ix_web_push_subscriptions_user_id", table_name="web_push_subscriptions")
    op.drop_table("web_push_subscriptions")
    op.drop_index("ix_notification_ws_ticket_expiry", table_name="notification_ws_tickets")
    op.drop_table("notification_ws_tickets")
    op.drop_table("notification_channel_preferences")
    op.drop_index("ix_notification_user_read", table_name="notification_events")
    op.drop_index("ix_notification_user_created", table_name="notification_events")
    op.drop_table("notification_events")
