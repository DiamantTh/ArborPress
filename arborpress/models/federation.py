"""Persistent local and remote ActivityPub federation state."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from arborpress.core.db import Base


class FederationInstanceIdentity(Base):
    """Pinned public origin once the instance publishes its first Actor ID."""

    __tablename__ = "federation_instance_identity"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    canonical_origin: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class LocalFederationActor(Base):
    """An explicitly enabled, stable ActivityPub identity for a local user."""

    __tablename__ = "local_federation_actors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    actor_uri: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    preferred_username: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="0")
    current_keypair_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("actor_keypairs.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_local_federation_actor_enabled", "enabled", "preferred_username"),)


class RemoteActor(Base):
    """Small, expiring cache for a validated remote actor document."""

    __tablename__ = "remote_actors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_uri: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    preferred_username: Mapped[str | None] = mapped_column(String(256), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    summary_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    inbox_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    shared_inbox_uri: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    etag: Mapped[str | None] = mapped_column(String(512), nullable=True)
    modified: Mapped[str | None] = mapped_column(String(128), nullable=True)


class RemoteActorKey(Base):
    """Cached public key material bound to the remote actor that owns it."""

    __tablename__ = "remote_actor_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    remote_actor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("remote_actors.id", ondelete="CASCADE"), nullable=False
    )
    key_id: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    owner_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (Index("ix_remote_actor_key_owner", "owner_uri"),)


class FederationInboxActivity(Base):
    """Durable, deduplicated intake; phase 10A deliberately performs no side effects."""

    __tablename__ = "federation_inbox_activities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    activity_uri: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    activity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_actor_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("local_federation_actors.id", ondelete="SET NULL"), nullable=True
    )
    source_domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    body_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    processing_state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="received", server_default="received", index=True
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    processed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("activity_uri", "body_sha256", name="uq_federation_activity_body"),
        Index("ix_federation_inbox_received", "processing_state", "received_at"),
    )


class FederationOutboxActivity(Base):
    """Immutable local ActivityPub activity, separate from per-inbox delivery."""

    __tablename__ = "federation_outbox_activities"
    __table_args__ = (
        UniqueConstraint(
            "source_type", "source_id", "source_revision", name="uq_fed_outbox_source_revision"
        ),
        Index("ix_fed_outbox_actor_created", "actor_uri", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    activity_uri: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    actor_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    activity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    object_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(24), nullable=False)
    source_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    audience_public: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class FederationDelivery(Base):
    """Leased delivery of one immutable activity to one remote inbox."""

    __tablename__ = "federation_deliveries"
    __table_args__ = (
        UniqueConstraint("activity_id", "target_inbox", name="uq_federation_delivery_target"),
        Index("ix_federation_delivery_due", "status", "next_attempt_at"),
        Index("ix_federation_delivery_lease", "status", "lease_until"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    activity_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("federation_outbox_activities.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_inbox: Mapped[str] = mapped_column(String(2048), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=8, server_default="8"
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class FederationDomainRule(Base):
    """Normalized host allow/block rules for inbound and outbound federation."""

    __tablename__ = "federation_domain_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain: Mapped[str] = mapped_column(String(253), nullable=False, unique=True)
    rule: Mapped[str] = mapped_column(String(8), nullable=False)  # allow | block
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
