"""Add core-managed plugin storage and scheduled jobs.

Revision ID: 0005_plugin_capabilities_storage_jobs
Revises: 0004_authors_and_object_relations
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_plugin_capabilities_storage_jobs"
down_revision: str | None = "0004_authors_and_object_relations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "plugin_storage_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plugin_id", sa.String(128), nullable=False),
        sa.Column("key", sa.String(256), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("plugin_id", "key", name="uq_plugin_storage_key"),
    )
    op.create_index(
        "ix_plugin_storage_plugin_updated",
        "plugin_storage_entries",
        ["plugin_id", "updated_at"],
    )
    op.create_table(
        "plugin_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plugin_id", sa.String(128), nullable=False),
        sa.Column("task", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("run_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("last_error", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "plugin_id", "task", "idempotency_key", name="uq_plugin_job_idempotency"
        ),
    )
    op.create_index("ix_plugin_jobs_due", "plugin_jobs", ["status", "run_at"])
    op.create_index("ix_plugin_jobs_plugin_status", "plugin_jobs", ["plugin_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_plugin_jobs_plugin_status", table_name="plugin_jobs")
    op.drop_index("ix_plugin_jobs_due", table_name="plugin_jobs")
    op.drop_table("plugin_jobs")
    op.drop_index("ix_plugin_storage_plugin_updated", table_name="plugin_storage_entries")
    op.drop_table("plugin_storage_entries")
