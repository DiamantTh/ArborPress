"""Object-scoped authorization relations; global roles remain in User.role."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from arborpress.core.db import Base
from arborpress.models.user import User


class ObjectRelationName(enum.StrEnum):
    EDITOR = "editor"
    COMMENT_MODERATOR = "comment_moderator"


class ObjectRelation(Base):
    """A positive, explicitly granted relation on a supported content object."""

    __tablename__ = "object_relations"
    __table_args__ = (
        UniqueConstraint(
            "subject_user_id", "object_type", "object_id", "relation", name="uq_object_relation"
        ),
        CheckConstraint("object_type = 'content'", name="ck_object_relation_type"),
        CheckConstraint(
            "relation IN ('editor', 'comment_moderator')", name="ck_object_relation_name"
        ),
        Index("ix_object_relation_object", "object_type", "object_id", "relation"),
        Index("ix_object_relation_subject", "subject_user_id", "relation"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    subject_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    object_type: Mapped[str] = mapped_column(String(24), nullable=False, default="content")
    object_id: Mapped[str] = mapped_column(String(36), nullable=False)
    relation: Mapped[ObjectRelationName] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    granted_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    subject: Mapped[User] = relationship("User", foreign_keys=[subject_user_id], lazy="joined")
    granted_by: Mapped[User | None] = relationship("User", foreign_keys=[granted_by_user_id])
