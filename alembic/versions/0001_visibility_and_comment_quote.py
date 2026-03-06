"""Sichtbarkeit (posts/pages) und Kommentar-Zitat-Referenz.

Revision ID: 0001
Revises:
Create Date: 2026-03-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    # Enum-Typ einmalig anlegen (PostgreSQL braucht das explizit)
    visibility_enum = sa.Enum(
        "public", "hidden", "private",
        name="postvisibility",
    )
    if is_pg:
        visibility_enum.create(bind, checkfirst=True)

    # ---- posts.visibility -------------------------------------------------
    op.add_column(
        "posts",
        sa.Column(
            "visibility",
            sa.Enum("public", "hidden", "private",
                    name="postvisibility", create_constraint=False),
            nullable=False,
            server_default="public",
        ),
    )

    # ---- pages.visibility -------------------------------------------------
    # create_type=False: Typ existiert bereits (s.o.)
    op.add_column(
        "pages",
        sa.Column(
            "visibility",
            sa.Enum("public", "hidden", "private",
                    name="postvisibility", create_constraint=False),
            nullable=False,
            server_default="public",
        ),
    )

    # ---- comments.quote_of_id --------------------------------------------
    op.add_column(
        "comments",
        sa.Column(
            "quote_of_id",
            sa.String(36),
            sa.ForeignKey("comments.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("comments", "quote_of_id")
    op.drop_column("pages", "visibility")
    op.drop_column("posts", "visibility")

    # Enum-Typ nur bei PostgreSQL explizit entfernen
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS postvisibility")
