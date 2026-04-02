"""Mail-Queue-Modell (§13)."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from arborpress.core.db import Base


class MailStatus(enum.StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MailQueue(Base):
    """Ausgehende Mail-Warteschlange (§13 – async outbox queue).

    §13: Retries mit Backoff, Idempotenz-Key, minimales sensibles Logging.
    Private Keys werden hier niemals gespeichert.
    """

    __tablename__ = "mail_queue"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # Idempotenz-Key (§13)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    recipient: Mapped[str] = mapped_column(String(254), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    # Text-Body (PGP-verschlüsselt wenn recipient.pgp_encrypt_mail)
    body_text: Mapped[str] = mapped_column(Text, nullable=False)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    # OpenPGP §13 – verschlüsselter Payload nur wenn aktiviert
    pgp_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Kein sensibles Logging – nur Metadaten
    status: Mapped[MailStatus] = mapped_column(
        Enum(MailStatus), nullable=False, default=MailStatus.PENDING
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
