"""Add database-native full-text indexes for public content search.

Revision ID: 0017_search_indexes
Revises: 0016_oauth_resource_idempotency
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0017_search_indexes"
down_revision: str | None = "0016_oauth_resource_idempotency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for table in ("posts", "pages"):
            op.execute(
                f"CREATE INDEX ix_{table}_search_vector ON {table} USING gin "
                "(to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(body_md, '')))"
            )
    elif dialect == "mysql":
        # MariaDB maintains FULLTEXT indexes as rows change, so create/update/
        # publish/unpublish/delete lifecycle stays transactional with content.
        for table in ("posts", "pages"):
            op.create_index(
                f"ix_{table}_search_fulltext",
                table,
                ["title", "body_md"],
                mysql_prefix="FULLTEXT",
            )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for table in ("pages", "posts"):
            op.execute(f"DROP INDEX IF EXISTS ix_{table}_search_vector")
    elif dialect == "mysql":
        for table in ("pages", "posts"):
            op.drop_index(f"ix_{table}_search_fulltext", table_name=table)
