"""Add immutable comment moderation decisions and author appeals.

Revision ID: 0003_comment_moderation_appeals
Revises: 0002_comment_core
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_comment_moderation_appeals"
down_revision: str | None = "0002_comment_core"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "moderation_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("actor_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(48), nullable=False),
        sa.Column("human_reason", sa.Text(), nullable=True),
        sa.Column("rule_reference", sa.String(256), nullable=True),
        sa.Column("restriction_type", sa.String(32), nullable=False),
        sa.Column("decision_source", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "supersedes_decision_id",
            sa.String(36),
            sa.ForeignKey("moderation_decisions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "target_type IN ('comment', 'revision')", name="ck_moderation_target_type"
        ),
        sa.CheckConstraint(
            "decision_source IN ('human', 'automated', 'assisted')",
            name="ck_moderation_decision_source",
        ),
    )
    op.create_index(
        "ix_moderation_target_created",
        "moderation_decisions",
        ["target_type", "target_id", "created_at"],
    )
    op.create_index(
        "ix_moderation_reason_created",
        "moderation_decisions",
        ["reason_code", "created_at"],
    )
    op.create_table(
        "comment_moderation_appeals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "decision_id",
            sa.String(36),
            sa.ForeignKey("moderation_decisions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "appellant_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")
        ),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="pending"),
        sa.Column(
            "reviewer_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL")
        ),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=True),
        sa.Column("reviewer_reason", sa.Text(), nullable=True),
        sa.Column(
            "replacement_decision_id",
            sa.String(36),
            sa.ForeignKey("moderation_decisions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("self_review_exception", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("decision_id", name="uq_comment_appeal_decision"),
        sa.CheckConstraint(
            "state IN ('pending', 'upheld', 'overturned', 'dismissed')",
            name="ck_comment_appeal_state",
        ),
    )
    op.create_index(
        "ix_comment_appeal_state_created",
        "comment_moderation_appeals",
        ["state", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_comment_appeal_state_created", table_name="comment_moderation_appeals")
    op.drop_table("comment_moderation_appeals")
    op.drop_index("ix_moderation_reason_created", table_name="moderation_decisions")
    op.drop_index("ix_moderation_target_created", table_name="moderation_decisions")
    op.drop_table("moderation_decisions")
