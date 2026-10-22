"""Add durable federation deliveries and remote comment attribution.

Revision ID: 0010_federation_follow_delivery_comments
Revises: 0009_activitypub_foundation
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_federation_follow_delivery_comments"
down_revision: str | None = "0009_activitypub_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "federation_outbox_activities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("activity_uri", sa.String(2048), nullable=False, unique=True),
        sa.Column("actor_uri", sa.String(2048), nullable=False),
        sa.Column("activity_type", sa.String(32), nullable=False),
        sa.Column("object_uri", sa.String(2048), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(24), nullable=False),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("source_revision", sa.String(64), nullable=False),
        sa.Column("audience_public", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "source_type", "source_id", "source_revision", name="uq_fed_outbox_source_revision"
        ),
    )
    op.create_index(
        "ix_fed_outbox_actor_created",
        "federation_outbox_activities",
        ["actor_uri", "created_at"],
    )
    op.create_table(
        "federation_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "activity_id",
            sa.String(36),
            sa.ForeignKey("federation_outbox_activities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_inbox", sa.String(2048), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="8"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("activity_id", "target_inbox", name="uq_federation_delivery_target"),
    )
    op.create_index(
        "ix_federation_delivery_due", "federation_deliveries", ["status", "next_attempt_at"]
    )
    op.create_index(
        "ix_federation_delivery_lease", "federation_deliveries", ["status", "lease_until"]
    )
    with op.batch_alter_table("federation_inbox_activities") as batch:
        batch.add_column(sa.Column("lease_owner", sa.String(128), nullable=True))
        batch.add_column(sa.Column("lease_until", sa.DateTime(), nullable=True))
    with op.batch_alter_table("comments") as batch:
        batch.add_column(sa.Column("remote_actor_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("remote_object_uri", sa.String(2048), nullable=True))
        batch.create_foreign_key(
            "fk_comment_remote_actor",
            "remote_actors",
            ["remote_actor_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_unique_constraint("uq_comment_remote_object_uri", ["remote_object_uri"])
        batch.create_check_constraint(
            "ck_remote_comment_author_exclusive",
            "remote_actor_id IS NULL OR (author_user_id IS NULL AND author_email IS NULL)",
        )
    op.create_index("ix_comments_remote_actor_id", "comments", ["remote_actor_id"])


def downgrade() -> None:
    op.drop_index("ix_comments_remote_actor_id", table_name="comments")
    with op.batch_alter_table("comments") as batch:
        batch.drop_constraint("ck_remote_comment_author_exclusive", type_="check")
        batch.drop_constraint("uq_comment_remote_object_uri", type_="unique")
        batch.drop_constraint("fk_comment_remote_actor", type_="foreignkey")
        batch.drop_column("remote_object_uri")
        batch.drop_column("remote_actor_id")
    with op.batch_alter_table("federation_inbox_activities") as batch:
        batch.drop_column("lease_until")
        batch.drop_column("lease_owner")
    op.drop_index("ix_federation_delivery_lease", table_name="federation_deliveries")
    op.drop_index("ix_federation_delivery_due", table_name="federation_deliveries")
    op.drop_table("federation_deliveries")
    op.drop_index("ix_fed_outbox_actor_created", table_name="federation_outbox_activities")
    op.drop_table("federation_outbox_activities")
