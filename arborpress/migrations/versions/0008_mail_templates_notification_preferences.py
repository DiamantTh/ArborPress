"""Add package mail template overrides and per-type notification preferences.

Revision ID: 0008_mail_templates_notification_preferences
Revises: 0007_notifications_live_and_web_push
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_mail_templates_notification_preferences"
down_revision: str | None = "0007_notifications_live_and_web_push"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("locale", sa.String(16), nullable=True))
    op.add_column("mail_queue", sa.Column("template_id", sa.String(96), nullable=True))
    op.add_column("mail_queue", sa.Column("template_locale", sa.String(16), nullable=True))
    op.add_column("mail_queue", sa.Column("template_revision", sa.String(96), nullable=True))

    op.create_table(
        "mail_template_overrides",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("template_id", sa.String(96), nullable=False),
        sa.Column("locale", sa.String(16), nullable=False),
        sa.Column("subject_source", sa.Text(), nullable=False),
        sa.Column("plain_source", sa.Text(), nullable=False),
        sa.Column("html_source", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("current_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_by",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("template_id", "locale", name="uq_mail_template_override"),
    )
    op.create_table(
        "mail_template_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("template_id", sa.String(96), nullable=False),
        sa.Column("locale", sa.String(16), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("subject_source", sa.Text(), nullable=False),
        sa.Column("plain_source", sa.Text(), nullable=False),
        sa.Column("html_source", sa.Text(), nullable=True),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column(
            "previous_revision_id",
            sa.String(36),
            sa.ForeignKey("mail_template_revisions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "template_id", "locale", "revision_number", name="uq_mail_template_revision_number"
        ),
    )
    op.create_index(
        "ix_mail_template_revision_history",
        "mail_template_revisions",
        ["template_id", "locale", "revision_number"],
    )

    op.create_table(
        "notification_type_preferences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("notification_type", sa.String(96), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("live_wss_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("web_push_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "notification_type", name="uq_notification_type_preference"),
    )
    op.create_index(
        "ix_notification_type_preference_user",
        "notification_type_preferences",
        ["user_id", "notification_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_notification_type_preference_user", table_name="notification_type_preferences")
    op.drop_table("notification_type_preferences")
    op.drop_index("ix_mail_template_revision_history", table_name="mail_template_revisions")
    op.drop_table("mail_template_revisions")
    op.drop_table("mail_template_overrides")
    op.drop_column("mail_queue", "template_revision")
    op.drop_column("mail_queue", "template_locale")
    op.drop_column("mail_queue", "template_id")
    op.drop_column("users", "locale")
