"""Add SMTP profiles and lease-aware mail outbox delivery metadata.

Revision ID: 0006_smtp_profiles_mail_outbox
Revises: 0005_plugin_capabilities_storage_jobs
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_smtp_profiles_mail_outbox"
down_revision: str | None = "0005_plugin_capabilities_storage_jobs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "smtp_profiles",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("transport", sa.String(16), nullable=False, server_default="starttls"),
        sa.Column("username", sa.String(254), nullable=True),
        sa.Column("secret_enc", sa.LargeBinary(), nullable=True),
        sa.Column("from_address", sa.String(254), nullable=False),
        sa.Column("from_name", sa.String(128), nullable=True),
        sa.Column("envelope_domain", sa.String(253), nullable=True),
        sa.Column("reply_to", sa.String(254), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="20"),
        sa.Column("max_connections", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )

    with op.batch_alter_table("mail_queue") as batch:
        batch.add_column(
            sa.Column("recipient_kind", sa.String(8), nullable=False, server_default="to")
        )
        batch.add_column(
            sa.Column("visible_to", sa.JSON(), nullable=False, server_default=sa.text("'[]'"))
        )
        batch.add_column(
            sa.Column("visible_cc", sa.JSON(), nullable=False, server_default=sa.text("'[]'"))
        )
        batch.add_column(
            sa.Column("headers", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch.add_column(
            sa.Column("profile_id", sa.String(64), nullable=False, server_default="transactional")
        )
        batch.add_column(sa.Column("message_type", sa.String(128), nullable=True))
        batch.add_column(sa.Column("message_id", sa.String(255), nullable=False, server_default=""))
        batch.add_column(sa.Column("envelope_sender", sa.String(254), nullable=True))
        batch.add_column(sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(
            sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5")
        )
        batch.add_column(sa.Column("lease_owner", sa.String(128), nullable=True))
        batch.add_column(sa.Column("lease_until", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("dsn_status", sa.String(16), nullable=True))
        batch.add_column(sa.Column("dsn_enhanced_code", sa.String(32), nullable=True))
        batch.add_column(sa.Column("dsn_envid", sa.String(64), nullable=True))
        batch.add_column(sa.Column("verp_token", sa.String(48), nullable=True))
        batch.add_column(sa.Column("updated_at", sa.DateTime(), nullable=True))
        batch.create_unique_constraint("uq_mail_queue_verp_token", ["verp_token"])

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.drop_constraint("uq_mail_queue_verp_token", "mail_queue", type_="unique")
        op.alter_column(
            "mail_queue",
            "status",
            existing_type=sa.Enum(name="mailstatus"),
            type_=sa.String(16),
            postgresql_using="status::text",
        )
    else:
        with op.batch_alter_table("mail_queue") as batch:
            batch.alter_column(
                "status",
                existing_type=sa.Enum("PENDING", "SENT", "FAILED", "CANCELLED", name="mailstatus"),
                type_=sa.String(16),
                existing_nullable=False,
            )
    op.execute(
        "UPDATE mail_queue SET status = CASE status "
        "WHEN 'PENDING' THEN 'pending' WHEN 'SENT' THEN 'sent' "
        "WHEN 'FAILED' THEN 'dead' WHEN 'CANCELLED' THEN 'cancelled' "
        "ELSE lower(status) END"
    )
    op.execute("UPDATE mail_queue SET updated_at = created_at WHERE updated_at IS NULL")
    rows = bind.execute(sa.text("SELECT id FROM mail_queue WHERE message_id = ''")).all()
    for row in rows:
        bind.execute(
            sa.text("UPDATE mail_queue SET message_id = :value WHERE id = :id"),
            {"value": f"<{row.id}@arborpress.invalid>", "id": row.id},
        )
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("mail_queue") as batch:
            batch.alter_column("updated_at", existing_type=sa.DateTime(), nullable=False)
    else:
        op.alter_column("mail_queue", "updated_at", existing_type=sa.DateTime(), nullable=False)
    op.create_index("ix_mail_queue_due", "mail_queue", ["status", "next_attempt_at", "lease_until"])
    op.create_index("ix_mail_queue_profile_status", "mail_queue", ["profile_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_mail_queue_profile_status", table_name="mail_queue")
    op.drop_index("ix_mail_queue_due", table_name="mail_queue")
    op.drop_table("smtp_profiles")
    # Preserve all rows while mapping the expanded queue states back to the
    # original enum values. Retry/lease detail is necessarily collapsed.
    op.execute(
        "UPDATE mail_queue SET status = CASE status "
        "WHEN 'pending' THEN 'PENDING' WHEN 'retry' THEN 'PENDING' "
        "WHEN 'leased' THEN 'PENDING' WHEN 'sent' THEN 'SENT' "
        "WHEN 'dead' THEN 'FAILED' WHEN 'cancelled' THEN 'CANCELLED' "
        "ELSE 'FAILED' END"
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.alter_column(
            "mail_queue",
            "status",
            existing_type=sa.String(16),
            type_=sa.Enum("PENDING", "SENT", "FAILED", "CANCELLED", name="mailstatus"),
            postgresql_using="status::mailstatus",
        )
    else:
        with op.batch_alter_table("mail_queue") as batch:
            batch.drop_constraint("uq_mail_queue_verp_token", type_="unique")
            batch.alter_column(
                "status",
                existing_type=sa.String(16),
                type_=sa.Enum("PENDING", "SENT", "FAILED", "CANCELLED", name="mailstatus"),
                existing_nullable=False,
            )
    with op.batch_alter_table("mail_queue") as batch:
        for name in (
            "recipient_kind",
            "visible_to",
            "visible_cc",
            "headers",
            "profile_id",
            "message_type",
            "message_id",
            "envelope_sender",
            "priority",
            "max_attempts",
            "lease_owner",
            "lease_until",
            "dsn_status",
            "dsn_enhanced_code",
            "dsn_envid",
            "verp_token",
            "updated_at",
        ):
            batch.drop_column(name)
