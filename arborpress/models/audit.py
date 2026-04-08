"""Audit-Event-Log-Tabelle (§2 §10 §16 – opt-in via logging.db_audit_log).

The table is always included in the schema (created by ``create_all_tables``).
Rows are only written when ``[logging] db_audit_log = true`` in config.toml.
This allows operators to enable persistent DB audit trails without code changes.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from arborpress.core.db import Base


class AuditEvent(Base):
    """One security-relevant event in the DB audit log.

    Enabled by ``[logging] db_audit_log = true``.
    Integer PK (instead of UUID) – optimal for high-volume append-only tables.
    No FK to ``users`` – log stays intact after user deletion.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # What happened
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Who did it (nullable – credential_not_found has no actor)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # Denormalized: readable even after user deletion
    actor_name: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Network context
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Result: "success" | "failure" | "blocked"
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)

    # Free-form detail / reason string
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), index=True
    )
