"""Content-Modelle: Post, Page, Tag, Category, Media (§1, §6, §7)."""

from __future__ import annotations

import difflib
import enum
import re
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    false,
    func,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from arborpress.core.db import Base
from arborpress.models.user import User

# ---------------------------------------------------------------------------
# Tags (§1, §6 /tag/{tag})
# ---------------------------------------------------------------------------


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    # §7 optional language tag
    lang: Mapped[str | None] = mapped_column(String(8), nullable=True)


# Many-to-many: posts ↔ tags
post_tags = Table(
    "post_tags",
    Base.metadata,
    Column("post_id", String(36), ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class PostStatus(enum.StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"
    SCHEDULED = "scheduled"
    ARCHIVED = "archived"


class PostVisibility(enum.StrEnum):
    """Visibility level of a post or page.

    public  – visible in lists/search/tags (default)
    hidden  – accessible via direct URL, but NOT in lists/search/tags
    private – fully locked (HTTP 404 for anonymous visitors)
    """

    PUBLIC = "public"
    HIDDEN = "hidden"
    PRIVATE = "private"


class Post(Base):
    """Blog post (§1, URL §6 /p/{slug} or /@{handle}/p/{slug}).

    §7: lang field for multi-language support.
    §6: slug_old for 301 redirects on slug change.
    """

    __tablename__ = "posts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # §6 stable short-ID for /o/{id}
    short_id: Mapped[str] = mapped_column(String(12), unique=True, nullable=False)
    author_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    slug: Mapped[str] = mapped_column(String(256), nullable=False)
    slug_old: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Strukturiertes Block-Format für Editor.js-Adapter.
    # Gespeichert als JSON-Dokument (PostgreSQL/MariaDB: native JSON;
    # SQLite: TEXT mit SQLAlchemy-Serialisierung).
    # None wenn der Post nicht via Editor.js erstellt wurde.
    body_json: Mapped[dict | None] = mapped_column(JSON(none_as_null=True), nullable=True)
    excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[PostStatus] = mapped_column(
        Enum(PostStatus), nullable=False, default=PostStatus.DRAFT
    )
    # Visibility: public | hidden | private
    visibility: Mapped[PostVisibility] = mapped_column(
        Enum(PostVisibility), nullable=False, default=PostVisibility.PUBLIC
    )
    # §7 language
    lang: Mapped[str | None] = mapped_column(String(8), nullable=True)
    # §5 ActivityPub object ID (set when federated)
    ap_object_id: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Captcha type for comment form (NULL = use global default from config)
    # Allowed values: none|math|custom|hcaptcha|friendly_captcha|altcha|mcaptcha|mosparo|turnstile
    captcha_type: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Nullable per-post comment policy overrides; NULL inherits SiteSettings.
    comments_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    guest_confirmation_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    comment_moderation_mode: Mapped[str | None] = mapped_column(String(24), nullable=True)

    # Visibility in lists
    is_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """Always at the top of the post list, regardless of published_at."""

    is_featured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """Visually highlighted in the theme (e.g. hero tile on the homepage)."""

    noindex: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """robots: noindex – accessible, but not indexed by search engines."""

    # Reading time: calculated when saving (Markdown words / 200 wpm; min. 1)
    reading_time_min: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    tags: Mapped[list[Tag]] = relationship(secondary=post_tags, lazy="selectin")
    author_relations: Mapped[list[PostAuthorRelation]] = relationship(
        "PostAuthorRelation",
        back_populates="post",
        cascade="all, delete-orphan",
        order_by="PostAuthorRelation.position",
        lazy="selectin",
    )
    # Public rendering needs the author's public identity without issuing a
    # lazy query after the request-scoped database session has closed.
    author: Mapped[User | None] = relationship("User", foreign_keys=[author_id], lazy="selectin")

    @staticmethod
    def calc_reading_time(body_md: str, body_json: dict | None = None) -> int:
        """Estimate reading time in minutes.

        Formula:
          - Prose words / 200  (adult average ~200 wpm)
          - Code blocks count as 0.5 extra minutes each
          - Minimum: 1 minute

        When body_json (Editor.js blocks) is supplied, text is extracted
        from blocks instead of parsing body_md.
        Code blocks are not counted as words because
        code is read considerably slower than prose.
        """
        if body_json and isinstance(body_json, dict):
            blocks = body_json.get("blocks", [])
            prose_parts: list[str] = []
            code_block_count = 0
            for block in blocks:
                btype = block.get("type", "")
                data = block.get("data", {})
                if btype in ("paragraph", "header", "quote"):
                    prose_parts.append(data.get("text", ""))
                elif btype == "list":
                    for item in data.get("items", []):
                        prose_parts.append(
                            item if isinstance(item, str) else item.get("content", "")
                        )
                elif btype in ("code", "raw"):
                    code_block_count += 1
                elif btype == "table":
                    for row in data.get("content", []):
                        prose_parts.extend(row)
            prose = " ".join(prose_parts)
            # Strip HTML tags that Editor.js may include inline
            prose = re.sub(r"<[^>]+>", " ", prose)
            words = len(prose.split())
            minutes = words / 200 + code_block_count * 0.5
            return max(1, round(minutes))

        # Fallback: Markdown-Parsing
        # Extract and remove code blocks
        code_blocks = re.findall(r"```[\s\S]*?```", body_md)
        prose = re.sub(r"```[\s\S]*?```", " ", body_md)
        # Remove inline code and Markdown syntax
        prose = re.sub(r"`[^`]+`", " ", prose)
        prose = re.sub(r"[#*_~\[\]()>|-]", " ", prose)
        words = len(prose.split())
        minutes = words / 200 + len(code_blocks) * 0.5
        return max(1, round(minutes))

    @property
    def rendered_html(self) -> str:
        return self.body_html


class PostAuthorRole(enum.StrEnum):
    PRIMARY = "primary"
    COAUTHOR = "coauthor"


class PostAuthorRelation(Base):
    """Editorial authorship, distinct from authorization relations."""

    __tablename__ = "post_author_relations"
    __table_args__ = (
        UniqueConstraint("post_id", "user_id", name="uq_post_author_user"),
        UniqueConstraint("post_id", "role", "position", name="uq_post_author_position"),
        CheckConstraint("role IN ('primary', 'coauthor')", name="ck_post_author_role"),
        CheckConstraint(
            "(role = 'primary' AND position = 0) OR (role = 'coauthor' AND position > 0)",
            name="ck_post_author_position",
        ),
        Index("ix_post_authors_user_post", "user_id", "post_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    role: Mapped[PostAuthorRole] = mapped_column(
        Enum(
            PostAuthorRole,
            native_enum=False,
            length=16,
            values_callable=lambda items: [item.value for item in items],
        ),
        nullable=False,
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    added_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    post: Mapped[Post] = relationship("Post", back_populates="author_relations")
    user: Mapped[User] = relationship("User", foreign_keys=[user_id], lazy="joined")


class PageType(enum.StrEnum):
    CUSTOM = "custom"
    IMPRESSUM = "impressum"  # §1 system pages
    PRIVACY = "privacy"
    RULES = "rules"


class Page(Base):
    """Static page (§1 /page/{slug}, can be a system page).

    §7: lang for multilingual system pages.
    """

    __tablename__ = "pages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    slug: Mapped[str] = mapped_column(String(256), nullable=False)
    slug_old: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    page_type: Mapped[PageType] = mapped_column(
        Enum(PageType), nullable=False, default=PageType.CUSTOM
    )
    lang: Mapped[str | None] = mapped_column(String(8), nullable=True)
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    # Visibility in lists
    visibility: Mapped[PostVisibility] = mapped_column(
        Enum(PostVisibility), nullable=False, default=PostVisibility.PUBLIC
    )
    # §10 noindex for admin-only pages
    noindex: Mapped[bool] = mapped_column(Boolean, default=False)
    # Should the page appear in the footer menu?
    show_in_footer: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    @property
    def rendered_html(self) -> str:
        return self.body_html


class CommentStatus(enum.StrEnum):
    PENDING_CONFIRMATION = "pending_confirmation"
    PENDING_MODERATION = "pending_moderation"
    APPROVED = "approved"
    REJECTED = "rejected"
    SPAM = "spam"
    DELETED = "deleted"


class CommentRevisionStatus(enum.StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class Comment(Base):
    """A comment whose publication state is independent of guest confirmation."""

    __tablename__ = "comments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    author_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Autor-Angaben (kein Account erforderlich)
    author_name: Mapped[str] = mapped_column(String(128), nullable=False)
    author_email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    author_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    body: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[CommentStatus] = mapped_column(
        Enum(
            CommentStatus,
            native_enum=False,
            length=32,
            values_callable=lambda items: [item.value for item in items],
        ),
        nullable=False,
        default=CommentStatus.PENDING_CONFIRMATION,
    )
    # Only a SHA-256 token digest is persisted; the random URL token is mail-only.
    confirmation_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    confirmation_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    confirmation_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    edited_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    parent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("comments.id", ondelete="SET NULL"), nullable=True, index=True
    )

    quote_of_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("comments.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Admin moderation note (internal)
    mod_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # GeoIP-derived country code (ISO 3166-1 alpha-2, e.g. "DE") – used for flag display
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    # RDAP/WHOIS data (JSON string) – stored for admin info panel, never shown publicly
    rdap_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    post: Mapped[Post] = relationship("Post", back_populates="comments", lazy="selectin")
    author_user: Mapped[User | None] = relationship("User", foreign_keys=[author_user_id])
    parent: Mapped[Comment | None] = relationship(
        "Comment", remote_side="Comment.id", foreign_keys=[parent_id], back_populates="replies"
    )
    replies: Mapped[list[Comment]] = relationship(
        "Comment", foreign_keys=[parent_id], back_populates="parent", order_by="Comment.created_at"
    )

    # Quoted comment (flat structure instead of deep nesting)
    # foreign() marks the FK side; the right is the remote (parent) side.
    quoted: Mapped[Comment | None] = relationship(
        "Comment",
        primaryjoin="foreign(Comment.quote_of_id) == Comment.id",
        uselist=False,
        lazy="selectin",
    )

    @property
    def is_edited(self) -> bool:
        return self.edited_at is not None


Index("ix_comments_post_created", Comment.post_id, Comment.created_at, Comment.id)


class CommentRevision(Base):
    """A proposed or applied body snapshot; not a general-purpose VCS."""

    __tablename__ = "comment_revisions"
    __table_args__ = (
        UniqueConstraint("comment_id", "revision_number", name="uq_comment_revision_number"),
        UniqueConstraint("pending_key", name="uq_comment_revision_pending_key"),
        Index("ix_comment_revisions_comment_created", "comment_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    comment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("comments.id", ondelete="CASCADE"), nullable=False
    )
    editor_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_body: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[CommentRevisionStatus] = mapped_column(
        Enum(
            CommentRevisionStatus,
            native_enum=False,
            length=16,
            values_callable=lambda items: [item.value for item in items],
        ),
        nullable=False,
        default=CommentRevisionStatus.PENDING,
    )
    # Non-NULL only while this is the one pending author proposal for a comment.
    pending_key: Mapped[str | None] = mapped_column(String(36), nullable=True)
    is_author_edit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    comment: Mapped[Comment] = relationship("Comment", lazy="selectin")


class CommentVote(Base):
    """One effective registered-user vote per comment; zero is represented by no row."""

    __tablename__ = "comment_votes"
    __table_args__ = (
        UniqueConstraint("user_id", "comment_id", name="uq_comment_vote_user_comment"),
        CheckConstraint("value IN (-1, 1)", name="ck_comment_vote_value"),
        Index("ix_comment_votes_comment", "comment_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    comment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("comments.id", ondelete="CASCADE"), nullable=False
    )
    value: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class ModerationDecision(Base):
    """Immutable moderation record for a comment or one of its revisions."""

    __tablename__ = "moderation_decisions"
    __table_args__ = (
        CheckConstraint("target_type IN ('comment', 'revision')", name="ck_moderation_target_type"),
        CheckConstraint(
            "decision_source IN ('human', 'automated', 'assisted')",
            name="ck_moderation_decision_source",
        ),
        Index("ix_moderation_target_created", "target_type", "target_id", "created_at"),
        Index("ix_moderation_reason_created", "reason_code", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    target_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(48), nullable=False)
    human_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)
    restriction_type: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_source: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    supersedes_decision_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("moderation_decisions.id", ondelete="SET NULL"), nullable=True
    )


class CommentModerationAppeal(Base):
    """One author appeal against a concrete immutable moderation decision."""

    __tablename__ = "comment_moderation_appeals"
    __table_args__ = (
        UniqueConstraint("decision_id", name="uq_comment_appeal_decision"),
        CheckConstraint(
            "state IN ('pending', 'upheld', 'overturned', 'dismissed')",
            name="ck_comment_appeal_state",
        ),
        Index("ix_comment_appeal_state_created", "state", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    decision_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("moderation_decisions.id", ondelete="RESTRICT"), nullable=False
    )
    appellant_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    reviewer_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reviewer_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    replacement_decision_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("moderation_decisions.id", ondelete="SET NULL"), nullable=True
    )
    self_review_exception: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )


# Register comments back-reference on Post
Post.comments = relationship(
    "Comment",
    back_populates="post",
    lazy="selectin",
    primaryjoin="and_(Comment.post_id==Post.id, Comment.status=='approved')",
    order_by=lambda: (Comment.created_at, Comment.id),
)


class Media(Base):
    """Media object (§1, URL §6 /media/{yyyy}/{mm}/{file}).

    Stable URLs: filename is never changed after publication.
    """

    __tablename__ = "media"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    uploader_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Path relative to MEDIA_ROOT: yyyy/mm/filename
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    alt_text: Mapped[str | None] = mapped_column(String(512), nullable=True)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # External original URL (set when the image was downloaded automatically)
    original_url: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)

    uploaded_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class OEmbedCache(Base):
    """Server-side cached oEmbed HTML (no visitor request to third parties).

    Populated when saving a post if the author uses an
    ``{{embed:url}}`` shortcode.
    """

    __tablename__ = "oembed_cache"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Original post URL (unique key)
    url: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    provider_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Sanitised HTML without <script> tags
    html: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    # Expiry date – re-fetched on next render after expiry
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


# ---------------------------------------------------------------------------
# Kategorien (§1 – hierarchische Taxonomie, parallel zu Tags)
#
# Tags  = flache Stichworte, frei vergeben, viele pro Post
# Kategorien = hierarchisch (Eltern/Kind), redaktionell gepflegt,
#              typisch 1-2 pro Post (z. B. "Technik → Python → Tutorial")
# ---------------------------------------------------------------------------

post_categories = Table(
    "post_categories",
    Base.metadata,
    Column("post_id", String(36), ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "category_id",
        Integer,
        ForeignKey("categories.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Category(Base):
    """Hierarchical category (tree structure via parent_id).

    Example:
      Technology (parent=None)
        └─ Python (parent=Technology)
             └─ Tutorial (parent=Python)
    """

    __tablename__ = "categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Hierarchy: NULL = root category
    parent_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("categories.id", ondelete="SET NULL"), nullable=True
    )
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lang: Mapped[str | None] = mapped_column(String(8), nullable=True)

    # Parent category
    parent: Mapped[Category | None] = relationship(
        "Category",
        foreign_keys=[parent_id],
        back_populates="children",
        remote_side="Category.id",
    )
    # Child categories
    children: Mapped[list[Category]] = relationship(
        "Category",
        foreign_keys=[parent_id],
        back_populates="parent",
        order_by="Category.sort_order",
    )


# Register categories back-reference on Post
Post.categories = relationship(
    "Category",
    secondary=post_categories,
    lazy="selectin",
)


# ---------------------------------------------------------------------------
# Post revisions (version history with diff)
# ---------------------------------------------------------------------------


class PostRevision(Base):
    """Version history of a blog post.

    Created automatically on save.
    Contains the full Markdown text and a unified diff to the previous
    state for the diff view in the admin.

    Cleanup strategy: admin can purge revisions with rev_number < N;
    recommended threshold: keep 50 revisions per post.
    """

    __tablename__ = "post_revisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    # Sequential revision number per post (1, 2, 3, …)
    rev_number: Mapped[int] = mapped_column(Integer, nullable=False)
    # Snapshot
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    # Unified diff to the previous state (NULL for revision 1)
    diff_to_prev: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Who saved the change (NULL = system/import)
    changed_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Optional summary of the change ("Fixed typo")
    change_summary: Mapped[str | None] = mapped_column(String(256), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    @staticmethod
    def make_diff(old_md: str, new_md: str) -> str:
        """Produce a unified diff (as text) between two Markdown states.

        Returns an empty string if there are no changes.
        Line-by-line output, compatible with standard ``diff`` tools.
        """
        old_lines = old_md.splitlines(keepends=True)
        new_lines = new_md.splitlines(keepends=True)
        diff = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile="revision-prev",
                tofile="revision-new",
                lineterm="",
            )
        )
        return "".join(diff)


# ---------------------------------------------------------------------------
# Post access tokens (multiple per post for password-protected posts)
# ---------------------------------------------------------------------------


class PostAccessToken(Base):
    """Access token for password-protected posts.

    A post can have multiple tokens, e.g.:
      - "Early readers"   (max. 100 uses, expires in 30 days)
      - "Press access"    (unlimited, no expiry)
      - "Friends"         (5 uses)

    Example flow:
      1. Visitor opens /p/<slug> → form "Please enter password"
      2. Visitor enters token → backend compares against all hashes
      3. Match + valid → short-lived cookie set (e.g. 24 h) → content visible
      4. use_count incremented; max_uses checked
    """

    __tablename__ = "post_access_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    # Display name in admin (e.g. "Press access", "Early readers")
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    # Argon2/bcrypt hash of the plaintext token
    token_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    # Usage limit: NULL = unlimited
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Expiry date: NULL = no expiry
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    @property
    def is_valid(self) -> bool:
        """Checks whether the token is still usable (limit + expiry)."""
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        if self.max_uses is not None and self.use_count >= self.max_uses:
            return False
        return True
