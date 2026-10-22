"""Add explicit local actors, remote actor cache and durable inbox intake.

Revision ID: 0009_activitypub_foundation
Revises: 0008_mail_templates_notification_preferences
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_activitypub_foundation"
down_revision: str | None = "0008_mail_templates_notification_preferences"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "federation_instance_identity",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("canonical_origin", sa.String(512), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "local_federation_actors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("actor_uri", sa.String(512), nullable=False),
        sa.Column("preferred_username", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "current_keypair_id",
            sa.String(36),
            sa.ForeignKey("actor_keypairs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", name="uq_local_federation_actor_user"),
        sa.UniqueConstraint("actor_uri", name="uq_local_federation_actor_uri"),
        sa.UniqueConstraint("preferred_username", name="uq_local_federation_actor_username"),
    )
    op.create_index(
        "ix_local_federation_actor_enabled",
        "local_federation_actors",
        ["enabled", "preferred_username"],
    )
    op.create_table(
        "remote_actors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_uri", sa.String(2048), nullable=False, unique=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("preferred_username", sa.String(256), nullable=True),
        sa.Column("display_name", sa.String(512), nullable=True),
        sa.Column("summary_text", sa.Text(), nullable=True),
        sa.Column("inbox_uri", sa.String(2048), nullable=False),
        sa.Column("shared_inbox_uri", sa.String(2048), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("etag", sa.String(512), nullable=True),
        sa.Column("modified", sa.String(128), nullable=True),
    )
    op.create_index("ix_remote_actors_domain", "remote_actors", ["domain"])
    op.create_table(
        "remote_actor_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "remote_actor_id",
            sa.String(36),
            sa.ForeignKey("remote_actors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(2048), nullable=False, unique=True),
        sa.Column("owner_uri", sa.String(2048), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_remote_actor_key_owner", "remote_actor_keys", ["owner_uri"])
    op.create_table(
        "federation_inbox_activities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("activity_uri", sa.String(2048), nullable=False),
        sa.Column("activity_type", sa.String(64), nullable=False),
        sa.Column("actor_uri", sa.String(2048), nullable=False),
        sa.Column(
            "target_actor_id",
            sa.String(36),
            sa.ForeignKey("local_federation_actors.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source_domain", sa.String(253), nullable=False),
        sa.Column("body_sha256", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("processing_state", sa.String(16), nullable=False, server_default="received"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("received_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("processed_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("activity_uri", name="uq_federation_activity_uri"),
        sa.UniqueConstraint("activity_uri", "body_sha256", name="uq_federation_activity_body"),
    )
    op.create_index(
        "ix_federation_inbox_activities_source_domain",
        "federation_inbox_activities",
        ["source_domain"],
    )
    op.create_index(
        "ix_federation_inbox_activities_processing_state",
        "federation_inbox_activities",
        ["processing_state"],
    )
    op.create_index(
        "ix_federation_inbox_received",
        "federation_inbox_activities",
        ["processing_state", "received_at"],
    )
    op.create_table(
        "federation_domain_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("domain", sa.String(253), nullable=False, unique=True),
        sa.Column("rule", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "created_by",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.CheckConstraint("rule in ('allow', 'block')", name="ck_federation_domain_rule"),
    )


def downgrade() -> None:
    op.drop_table("federation_domain_rules")
    op.drop_index("ix_federation_inbox_received", table_name="federation_inbox_activities")
    op.drop_index(
        "ix_federation_inbox_activities_processing_state", table_name="federation_inbox_activities"
    )
    op.drop_index(
        "ix_federation_inbox_activities_source_domain", table_name="federation_inbox_activities"
    )
    op.drop_table("federation_inbox_activities")
    op.drop_index("ix_remote_actor_key_owner", table_name="remote_actor_keys")
    op.drop_table("remote_actor_keys")
    op.drop_index("ix_remote_actors_domain", table_name="remote_actors")
    op.drop_table("remote_actors")
    op.drop_index("ix_local_federation_actor_enabled", table_name="local_federation_actors")
    op.drop_table("local_federation_actors")
    op.drop_table("federation_instance_identity")
