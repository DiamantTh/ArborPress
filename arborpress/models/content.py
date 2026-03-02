"""Content-Modelle: Post, Page, Tag, Media (§1, §6, §7)."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    Column,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from arborpress.core.db import Base


# ---------------------------------------------------------------------------
# Tags (§1, §6 /tag/{tag})
# ---------------------------------------------------------------------------


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    # §7 optional language tag
    lang: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)


# Many-to-many: posts ↔ tags
post_tags = Table(
    "post_tags",
    Base.metadata,
    Column("post_id", String(36), ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class PostStatus(str, enum.Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    SCHEDULED = "scheduled"
    ARCHIVED = "archived"


class Post(Base):
    """Blog-Post (§1, URL §6 /p/{slug} or /@{handle}/p/{slug}).

    §7: lang-Feld für Multi-Language-Support.
    §6: slug_old für 301-Redirects bei Slug-Änderung.
    """

    __tablename__ = "posts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # §6 stable short-ID for /o/{id}
    short_id: Mapped[str] = mapped_column(String(12), unique=True, nullable=False)
    author_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    slug: Mapped[str] = mapped_column(String(256), nullable=False)
    slug_old: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    excerpt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[PostStatus] = mapped_column(
        Enum(PostStatus), nullable=False, default=PostStatus.DRAFT
    )
    # §7 language
    lang: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    # §5 ActivityPub object ID (set when federated)
    ap_object_id: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Captcha-Typ für Kommentarformular (NULL = globalen Standard aus config verwenden)
    # Erlaubte Werte: none|math|custom|hcaptcha|friendly_captcha|altcha|mcaptcha|mosparo|turnstile
    captcha_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    tags: Mapped[list[Tag]] = relationship(secondary=post_tags, lazy="selectin")


class PageType(str, enum.Enum):
    CUSTOM = "custom"
    IMPRESSUM = "impressum"   # §1 system pages
    PRIVACY = "privacy"
    RULES = "rules"


class Page(Base):
    """Statische Seite (§1 /page/{slug}, kann Systemseite sein).

    §7: lang für mehrsprachige System-Seiten.
    """

    __tablename__ = "pages"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    slug: Mapped[str] = mapped_column(String(256), nullable=False)
    slug_old: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    page_type: Mapped[PageType] = mapped_column(
        Enum(PageType), nullable=False, default=PageType.CUSTOM
    )
    lang: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    # §10 noindex for admin-only pages
    noindex: Mapped[bool] = mapped_column(Boolean, default=False)
    # Soll die Seite im Footer-Menü erscheinen?
    show_in_footer: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class CommentStatus(str, enum.Enum):
    PENDING    = "pending"     # eingereicht, noch nicht per E-Mail bestätigt
    CONFIRMED  = "confirmed"   # E-Mail-Bestätigung erfolgt, wartet auf Freischaltung
    APPROVED   = "approved"    # vom Admin freigeschaltet – öffentlich sichtbar
    REJECTED   = "rejected"    # vom Admin abgelehnt
    SPAM       = "spam"        # als Spam markiert


class Comment(Base):
    """Kommentar zu einem Blog-Post (zweistufige Moderation: E-Mail + Admin).

    Ablauf:
      1. Nutzer sendet Formular  → status=PENDING,  confirmation_token gesetzt
      2. Nutzer klickt Mail-Link → status=CONFIRMED, confirmed_at gesetzt
      3. Admin schaltet frei    → status=APPROVED,  approved_at gesetzt
    """

    __tablename__ = "comments"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    post_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    # Autor-Angaben (kein Account erforderlich)
    author_name: Mapped[str]  = mapped_column(String(128), nullable=False)
    author_email: Mapped[str] = mapped_column(String(256), nullable=False)
    author_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    body: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[CommentStatus] = mapped_column(
        Enum(CommentStatus), nullable=False, default=CommentStatus.PENDING
    )
    # UUID-Token für E-Mail-Bestätigung
    confirmation_token: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: str(uuid.uuid4())
    )
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    approved_at:  Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Moderationsnotiz des Admins (intern)
    mod_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent:  Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    post: Mapped["Post"] = relationship("Post", back_populates="comments", lazy="selectin")


# Kommentare-Rückbeziehung auf Post registrieren
Post.comments = relationship(
    "Comment",
    back_populates="post",
    lazy="selectin",
    primaryjoin="and_(Comment.post_id==Post.id, Comment.status=='approved')",
    order_by="Comment.created_at",
)


class Media(Base):
    """Media-Objekt (§1, URL §6 /media/{yyyy}/{mm}/{file}).

    Stable URLs: Dateiname wird niemals geändert nach Publikation.
    """

    __tablename__ = "media"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    uploader_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Pfad relativ zu MEDIA_ROOT: yyyy/mm/filename
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    alt_text: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    width: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    height: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    uploaded_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
