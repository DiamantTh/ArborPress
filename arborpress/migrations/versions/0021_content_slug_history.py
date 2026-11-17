"""Keep all historic public slugs for stable redirects.

Revision ID: 0021_content_slug_history
Revises: 0020_content_translation_groups
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_content_slug_history"
down_revision: str | None = "0020_content_translation_groups"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "content_slug_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("content_kind", sa.String(16), nullable=False),
        sa.Column("content_id", sa.String(36), nullable=False),
        sa.Column("language", sa.String(8), nullable=False, server_default=""),
        sa.Column("slug", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "content_kind", "language", "slug", name="uq_content_slug_history_route"
        ),
    )
    op.create_index(
        "ix_content_slug_history_object",
        "content_slug_history",
        ["content_kind", "content_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_content_slug_history_object", table_name="content_slug_history")
    op.drop_table("content_slug_history")
