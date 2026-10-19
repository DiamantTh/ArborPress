"""Add content author relations and scoped authorization relations.

Revision ID: 0004_authors_and_object_relations
Revises: 0003_comment_moderation_appeals
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_authors_and_object_relations"
down_revision: str | None = "0003_comment_moderation_appeals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "post_author_relations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "post_id", sa.String(36), sa.ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "added_by_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint("post_id", "user_id", name="uq_post_author_user"),
        sa.UniqueConstraint("post_id", "role", "position", name="uq_post_author_position"),
        sa.CheckConstraint("role IN ('primary', 'coauthor')", name="ck_post_author_role"),
        sa.CheckConstraint(
            "(role = 'primary' AND position = 0) OR (role = 'coauthor' AND position > 0)",
            name="ck_post_author_position",
        ),
    )
    op.create_index("ix_post_authors_user_post", "post_author_relations", ["user_id", "post_id"])

    op.create_table(
        "object_relations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "subject_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("object_type", sa.String(24), nullable=False, server_default="content"),
        sa.Column("object_id", sa.String(36), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "granted_by_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "subject_user_id", "object_type", "object_id", "relation", name="uq_object_relation"
        ),
        sa.CheckConstraint("object_type = 'content'", name="ck_object_relation_type"),
        sa.CheckConstraint(
            "relation IN ('editor', 'comment_moderator')", name="ck_object_relation_name"
        ),
    )
    op.create_index(
        "ix_object_relation_object", "object_relations", ["object_type", "object_id", "relation"]
    )
    op.create_index(
        "ix_object_relation_subject", "object_relations", ["subject_user_id", "relation"]
    )

    # Keep the existing author_id column as a synchronized compatibility
    # projection, but migrate its current meaning into the canonical relation.
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, author_id FROM posts WHERE author_id IS NOT NULL"))
    for post_id, user_id in rows:
        bind.execute(
            sa.text(
                "INSERT INTO post_author_relations "
                "(id, post_id, user_id, role, position, added_by_user_id) "
                "VALUES (:id, :post_id, :user_id, 'primary', 0, NULL)"
            ),
            {"id": str(uuid.uuid4()), "post_id": post_id, "user_id": user_id},
        )


def downgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT post_id, user_id FROM post_author_relations "
            "WHERE role = 'primary' AND post_id IN (SELECT id FROM posts)"
        )
    )
    for post_id, user_id in rows:
        bind.execute(
            sa.text("UPDATE posts SET author_id = :user_id WHERE id = :post_id"),
            {"post_id": post_id, "user_id": user_id},
        )
    op.drop_index("ix_object_relation_subject", table_name="object_relations")
    op.drop_index("ix_object_relation_object", table_name="object_relations")
    op.drop_table("object_relations")
    op.drop_index("ix_post_authors_user_post", table_name="post_author_relations")
    op.drop_table("post_author_relations")
