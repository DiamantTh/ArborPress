"""Introduce explicit comment states, threads, revisions, votes and policy fields.

Revision ID: 0002_comment_core
Revises: 0001_pre_alembic_baseline
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime, timedelta

import sqlalchemy as sa
from alembic import op

revision: str = "0002_comment_core"
down_revision: str | None = "0001_pre_alembic_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    old_enum = sa.Enum("PENDING", "CONFIRMED", "APPROVED", "REJECTED", "SPAM", name="commentstatus")
    pending = list(
        bind.execute(
            sa.text("SELECT id, confirmation_token, created_at, approved_at, status FROM comments")
        ).mappings()
    )

    with op.batch_alter_table("comments") as batch:
        if dialect == "postgresql":
            batch.alter_column(
                "status",
                existing_type=old_enum,
                type_=sa.String(length=32),
                existing_nullable=False,
                postgresql_using="status::text",
            )
        else:
            batch.alter_column(
                "status",
                existing_type=old_enum,
                type_=sa.String(length=32),
                existing_nullable=False,
            )
        batch.alter_column("author_email", existing_type=sa.String(length=256), nullable=True)
        batch.drop_column("confirmation_token")
        batch.add_column(sa.Column("author_user_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("confirmation_token_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("confirmation_expires_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("confirmation_sent_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("published_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("edited_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("parent_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_comments_author_user_id_users",
            "users",
            ["author_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_comments_parent_id_comments", "comments", ["parent_id"], ["id"], ondelete="SET NULL"
        )

    legacy_map = {
        "PENDING": "pending_confirmation",
        "CONFIRMED": "pending_moderation",
        "APPROVED": "approved",
        "REJECTED": "rejected",
        "SPAM": "spam",
    }
    for row in pending:
        status = legacy_map.get(str(row["status"]).upper(), "pending_moderation")
        token = row["confirmation_token"]
        created_at = row["created_at"]
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        approved_at = row["approved_at"]
        if isinstance(approved_at, str):
            approved_at = datetime.fromisoformat(approved_at)
        expires = created_at + timedelta(hours=24) if status == "pending_confirmation" else None
        token_hash = (
            hashlib.sha256(str(token).encode("utf-8")).hexdigest() if token and expires else None
        )
        bind.execute(
            sa.text(
                "UPDATE comments SET status=:status, confirmation_token_hash=:token_hash, "
                "confirmation_expires_at=:expires, confirmation_sent_at=:sent, "
                "published_at=:published "
                "WHERE id=:id"
            ),
            {
                "status": status,
                "token_hash": token_hash,
                "expires": expires,
                "sent": row["created_at"] if token_hash else None,
                "published": (approved_at or created_at) if status == "approved" else None,
                "id": row["id"],
            },
        )
    if dialect == "postgresql":
        # The former SQLAlchemy Enum was a native PostgreSQL type. The column
        # now uses varchar; remove the orphaned legacy type deliberately.
        bind.execute(sa.text("DROP TYPE commentstatus"))

    op.create_index("ix_comments_author_user_id", "comments", ["author_user_id"])
    op.create_index("ix_comments_confirmation_token_hash", "comments", ["confirmation_token_hash"])
    op.create_index("ix_comments_parent_id", "comments", ["parent_id"])
    op.create_index("ix_comments_quote_of_id", "comments", ["quote_of_id"])
    op.create_index("ix_comments_post_created", "comments", ["post_id", "created_at", "id"])

    with op.batch_alter_table("posts") as batch:
        batch.add_column(sa.Column("comments_enabled", sa.Boolean(), nullable=True))
        batch.add_column(sa.Column("guest_confirmation_required", sa.Boolean(), nullable=True))
        batch.add_column(sa.Column("comment_moderation_mode", sa.String(length=24), nullable=True))

    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("comment_trusted", sa.Boolean(), nullable=False, server_default=sa.false())
        )

    op.create_table(
        "comment_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "comment_id",
            sa.String(36),
            sa.ForeignKey("comments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "editor_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("previous_body", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("pending_key", sa.String(36), nullable=True),
        sa.Column("is_author_edit", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("comment_id", "revision_number", name="uq_comment_revision_number"),
        sa.UniqueConstraint("pending_key", name="uq_comment_revision_pending_key"),
    )
    op.create_index(
        "ix_comment_revisions_comment_created", "comment_revisions", ["comment_id", "created_at"]
    )
    op.create_table(
        "comment_votes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "comment_id",
            sa.String(36),
            sa.ForeignKey("comments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("value", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "comment_id", name="uq_comment_vote_user_comment"),
        sa.CheckConstraint("value IN (-1, 1)", name="ck_comment_vote_value"),
    )
    op.create_index("ix_comment_votes_comment", "comment_votes", ["comment_id"])


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("comment_votes", "comment_revisions"):
        op.drop_table(table)
    op.drop_index("ix_comments_post_created", table_name="comments")
    op.drop_index("ix_comments_quote_of_id", table_name="comments")
    op.drop_index("ix_comments_parent_id", table_name="comments")
    op.drop_index("ix_comments_author_user_id", table_name="comments")
    op.drop_index("ix_comments_confirmation_token_hash", table_name="comments")

    # Old confirmation URLs cannot be recovered from their digests. Generate
    # fresh opaque legacy tokens for remaining confirmation-pending comments;
    # operators must resend those messages after a downgrade.
    import secrets

    for row in bind.execute(sa.text("SELECT id, status FROM comments")).mappings():
        old_status = {
            "pending_confirmation": "PENDING",
            "pending_moderation": "CONFIRMED",
            "approved": "APPROVED",
            "rejected": "REJECTED",
            "spam": "SPAM",
            "deleted": "REJECTED",
        }.get(row["status"], "PENDING")
        bind.execute(
            sa.text(
                "UPDATE comments SET status=:status, confirmation_token_hash=NULL WHERE id=:id"
            ),
            {"status": old_status, "id": row["id"]},
        )

    with op.batch_alter_table("comments") as batch:
        batch.drop_constraint("fk_comments_parent_id_comments", type_="foreignkey")
        batch.drop_constraint("fk_comments_author_user_id_users", type_="foreignkey")
        batch.drop_column("parent_id")
        batch.drop_column("author_user_id")
        batch.drop_column("confirmation_token_hash")
        batch.drop_column("confirmation_expires_at")
        batch.drop_column("confirmation_sent_at")
        batch.drop_column("published_at")
        batch.drop_column("edited_at")
        batch.alter_column("author_email", existing_type=sa.String(256), nullable=False)
        batch.alter_column(
            "status",
            existing_type=sa.String(32),
            type_=sa.Enum(
                "PENDING", "CONFIRMED", "APPROVED", "REJECTED", "SPAM", name="commentstatus"
            ),
            existing_nullable=False,
        )
        batch.add_column(sa.Column("confirmation_token", sa.String(64), nullable=True))
    for row in bind.execute(sa.text("SELECT id FROM comments")).mappings():
        bind.execute(
            sa.text("UPDATE comments SET confirmation_token=:token WHERE id=:id"),
            {"token": secrets.token_urlsafe(32)[:64], "id": row["id"]},
        )
    with op.batch_alter_table("comments") as batch:
        batch.alter_column("confirmation_token", existing_type=sa.String(64), nullable=False)

    with op.batch_alter_table("posts") as batch:
        batch.drop_column("comment_moderation_mode")
        batch.drop_column("guest_confirmation_required")
        batch.drop_column("comments_enabled")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("comment_trusted")
