"""Instance OpenPGP identity and recipient-bound mail policy.

Revision ID: 0022_openpgp_mail
Revises: 0021_content_slug_history
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_openpgp_mail"
down_revision: str | None = "0021_content_slug_history"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "instance_openpgp_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("openpgp_user_id", sa.String(512), nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("public_key_armored", sa.Text(), nullable=False),
        sa.Column("private_key_enc", sa.LargeBinary(), nullable=False),
        sa.Column("passphrase_enc", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("retired_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("fingerprint", name="uq_instance_openpgp_fingerprint"),
    )
    op.create_index(
        "ix_instance_openpgp_current",
        "instance_openpgp_keys",
        ["is_current", "status"],
    )
    op.add_column(
        "users",
        sa.Column(
            "pgp_encryption_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "user_pgp_keys", sa.Column("openpgp_user_id", sa.String(512), nullable=True)
    )
    op.add_column(
        "user_pgp_keys",
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
    )
    op.add_column("user_pgp_keys", sa.Column("revoked_at", sa.DateTime(), nullable=True))
    op.add_column("mail_queue", sa.Column("recipient_user_id", sa.String(36), nullable=True))
    op.add_column(
        "mail_queue",
        sa.Column(
            "recipient_encryption_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    # Existing pending rows are resolved exactly once by the worker before send.
    # This avoids interpreting an old queued account message as external plaintext.
    op.add_column(
        "mail_queue",
        sa.Column(
            "recipient_identity_checked",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "mail_queue",
        sa.Column("attachments", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("mail_queue", "attachments")
    op.drop_column("mail_queue", "recipient_encryption_required")
    op.drop_column("mail_queue", "recipient_identity_checked")
    op.drop_column("mail_queue", "recipient_user_id")
    op.drop_column("user_pgp_keys", "revoked_at")
    op.drop_column("user_pgp_keys", "status")
    op.drop_column("user_pgp_keys", "openpgp_user_id")
    op.drop_column("users", "pgp_encryption_enabled")
    op.drop_index("ix_instance_openpgp_current", table_name="instance_openpgp_keys")
    op.drop_table("instance_openpgp_keys")
