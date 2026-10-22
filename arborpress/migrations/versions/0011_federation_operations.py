"""Add federation key history and richer domain rules.

Revision ID: 0011_federation_operations
Revises: 0010_federation_follow_delivery_comments
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_federation_operations"
down_revision: str | None = "0010_federation_follow_delivery_comments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("federation_domain_rules") as batch:
        batch.add_column(
            sa.Column("include_subdomains", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(sa.Column("note", sa.String(512), nullable=True))
    op.create_table(
        "federation_actor_key_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "actor_id",
            sa.String(36),
            sa.ForeignKey("local_federation_actors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(512), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("retired_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("actor_id", "fingerprint_sha256", name="uq_fed_actor_key_fingerprint"),
    )
    op.create_index(
        "ix_federation_actor_key_history_actor",
        "federation_actor_key_history",
        ["actor_id", "retired_at"],
    )
    with op.batch_alter_table("comments") as batch:
        batch.add_column(sa.Column("federation_inbox_activity_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_comments_federation_inbox_activity",
            "federation_inbox_activities",
            ["federation_inbox_activity_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.create_index(
        "ix_comments_federation_inbox_activity_id",
        "comments",
        ["federation_inbox_activity_id"],
    )
    with op.batch_alter_table("remote_actors") as batch:
        batch.add_column(
            sa.Column("health_state", sa.String(16), nullable=False, server_default="active")
        )
        batch.add_column(sa.Column("last_error", sa.String(128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remote_actors") as batch:
        batch.drop_column("last_error")
        batch.drop_column("health_state")
    op.drop_index("ix_comments_federation_inbox_activity_id", table_name="comments")
    with op.batch_alter_table("comments") as batch:
        batch.drop_constraint("fk_comments_federation_inbox_activity", type_="foreignkey")
        batch.drop_column("federation_inbox_activity_id")
    op.drop_index(
        "ix_federation_actor_key_history_actor", table_name="federation_actor_key_history"
    )
    op.drop_table("federation_actor_key_history")
    with op.batch_alter_table("federation_domain_rules") as batch:
        batch.drop_column("note")
        batch.drop_column("include_subdomains")
