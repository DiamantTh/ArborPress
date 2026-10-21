"""SMTP profiles and the authoritative database-backed mail delivery outbox."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from arborpress.core.db import Base


class MailStatus(enum.StrEnum):
    PENDING = "pending"
    LEASED = "leased"
    RETRY = "retry"
    SENT = "sent"
    DEAD = "dead"
    CANCELLED = "cancelled"
    # Compatibility aliases for callers that used the pre-9A vocabulary.
    FAILED = "dead"


class SMTPProfile(Base):
    """Instance-local SMTP transport metadata; credentials are encrypted at rest."""

    __tablename__ = "smtp_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    host: Mapped[str] = mapped_column(String(253), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    transport: Mapped[str] = mapped_column(String(16), nullable=False, default="starttls")
    username: Mapped[str | None] = mapped_column(String(254), nullable=True)
    secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    from_address: Mapped[str] = mapped_column(String(254), nullable=False)
    from_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    envelope_domain: Mapped[str | None] = mapped_column(String(253), nullable=True)
    reply_to: Mapped[str | None] = mapped_column(String(254), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    max_connections: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class MailQueue(Base):
    """Single-recipient delivery row in ArborPress' durable outbox.

    Message payload is kept on this row because all historical producers submit one
    recipient. Header recipients are separate from the SMTP envelope; a Bcc delivery
    intentionally has no Bcc header value.
    """

    __tablename__ = "mail_queue"
    __table_args__ = (
        Index("ix_mail_queue_due", "status", "next_attempt_at", "lease_until"),
        Index("ix_mail_queue_profile_status", "profile_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    recipient: Mapped[str] = mapped_column(String(254), nullable=False)
    recipient_kind: Mapped[str] = mapped_column(String(8), nullable=False, default="to")
    visible_to: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    visible_cc: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    body_text: Mapped[str] = mapped_column(Text, nullable=False)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    profile_id: Mapped[str] = mapped_column(String(64), nullable=False, default="transactional")
    message_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    template_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    template_locale: Mapped[str | None] = mapped_column(String(16), nullable=True)
    template_revision: Mapped[str | None] = mapped_column(String(96), nullable=True)
    message_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    envelope_sender: Mapped[str | None] = mapped_column(String(254), nullable=True)
    pgp_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=MailStatus.PENDING)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    dsn_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    dsn_enhanced_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dsn_envid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verp_token: Mapped[str | None] = mapped_column(String(48), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MailTemplateOverride(Base):
    """Current instance-local template source; package files remain immutable."""

    __tablename__ = "mail_template_overrides"
    __table_args__ = (UniqueConstraint("template_id", "locale", name="uq_mail_template_override"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    template_id: Mapped[str] = mapped_column(String(96), nullable=False)
    locale: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_source: Mapped[str] = mapped_column(Text, nullable=False)
    plain_source: Mapped[str] = mapped_column(Text, nullable=False)
    html_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    current_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class MailTemplateRevision(Base):
    """Immutable validated source snapshot for an override or reset operation."""

    __tablename__ = "mail_template_revisions"
    __table_args__ = (
        UniqueConstraint(
            "template_id", "locale", "revision_number", name="uq_mail_template_revision_number"
        ),
        Index("ix_mail_template_revision_history", "template_id", "locale", "revision_number"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    template_id: Mapped[str] = mapped_column(String(96), nullable=False)
    locale: Mapped[str] = mapped_column(String(16), nullable=False)
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    subject_source: Mapped[str] = mapped_column(Text, nullable=False)
    plain_source: Mapped[str] = mapped_column(Text, nullable=False)
    html_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_revision_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("mail_template_revisions.id", ondelete="SET NULL"), nullable=True
    )
