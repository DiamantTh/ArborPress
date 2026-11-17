"""Add explicit translation sets for public content.

Revision ID: 0020_content_translation_groups
Revises: 0019_portable_import_receipts
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_content_translation_groups"
down_revision: str | None = "0019_portable_import_receipts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "content_translation_groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("content_kind", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("content_kind IN ('post', 'page')", name="ck_translation_group_kind"),
    )
    with op.batch_alter_table("posts") as batch:
        batch.add_column(
            sa.Column(
                "translation_group_id",
                sa.String(36),
                sa.ForeignKey(
                    "content_translation_groups.id",
                    ondelete="SET NULL",
                    name="fk_posts_translation_group",
                ),
                nullable=True,
            )
        )
        batch.create_unique_constraint(
            "uq_posts_translation_lang", ["translation_group_id", "lang"]
        )
    with op.batch_alter_table("pages") as batch:
        batch.add_column(
            sa.Column(
                "translation_group_id",
                sa.String(36),
                sa.ForeignKey(
                    "content_translation_groups.id",
                    ondelete="SET NULL",
                    name="fk_pages_translation_group",
                ),
                nullable=True,
            )
        )
        batch.create_unique_constraint(
            "uq_pages_translation_lang", ["translation_group_id", "lang"]
        )


def downgrade() -> None:
    with op.batch_alter_table("pages") as batch:
        batch.drop_constraint("uq_pages_translation_lang", type_="unique")
        batch.drop_column("translation_group_id")
    with op.batch_alter_table("posts") as batch:
        batch.drop_constraint("uq_posts_translation_lang", type_="unique")
        batch.drop_column("translation_group_id")
    op.drop_table("content_translation_groups")
