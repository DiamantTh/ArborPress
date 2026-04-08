"""Content-Modelle: Post, Page, Tag, Category, Media (§1, §6, §7)."""

from __future__ import annotations

import difflib
import enum
import re
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
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
    PUBLIC  = "public"
    HIDDEN  = "hidden"
    PRIVATE = "private"


class Post(Base):
    """Blog post (§1, URL §6 /p/{slug} or /@{handle}/p/{slug}).

    §7: lang field for multi-language support.
    §6: slug_old for 301 redirects on slug change.
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
    slug_old: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
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

    @staticmethod
    def calc_reading_time(body_md: str) -> int:
        """Estimate reading time in minutes.

        Formula:
          - Prose words / 200  (adult average ~200 wpm)
          - Code blocks count as 0.5 extra minutes each
          - Minimum: 1 minute

        Code blocks are not counted as words because
        code is read considerably slower than prose.
        """
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


class PageType(enum.StrEnum):
    CUSTOM = "custom"
    IMPRESSUM = "impressum"   # §1 system pages
    PRIVACY = "privacy"
    RULES = "rules"


class Page(Base):
    """Static page (§1 /page/{slug}, can be a system page).

    §7: lang for multilingual system pages.
    """

    __tablename__ = "pages"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
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
    PENDING    = "pending"     # submitted, not yet confirmed via e-mail
    CONFIRMED  = "confirmed"   # e-mail confirmation done, awaiting approval
    APPROVED   = "approved"    # approved by admin – publicly visible
    REJECTED   = "rejected"    # rejected by admin
    SPAM       = "spam"        # marked as spam


class Comment(Base):
    """Comment on a blog post (two-stage moderation: e-mail + admin).

    Flow:
      1. User submits form  → status=PENDING,  confirmation_token set
      2. User clicks mail link → status=CONFIRMED, confirmed_at set
      3. Admin approves    → status=APPROVED,  approved_at set
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
    author_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    body: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[CommentStatus] = mapped_column(
        Enum(CommentStatus), nullable=False, default=CommentStatus.PENDING
    )
    # UUID token for e-mail confirmation
    confirmation_token: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: str(uuid.uuid4())
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    approved_at:  Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Quote reference: flat comment structure instead of deep nesting
    # Points to the quoted comment (same post).
    quote_of_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("comments.id", ondelete="SET NULL"), nullable=True
    )

    # Admin moderation note (internal)
    mod_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent:  Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    post: Mapped[Post] = relationship("Post", back_populates="comments", lazy="selectin")

    # Quoted comment (flat structure instead of deep nesting)
    # foreign() marks the FK side; the right is the remote (parent) side.
    quoted: Mapped[Comment | None] = relationship(
        "Comment",
        primaryjoin="foreign(Comment.quote_of_id) == Comment.id",
        uselist=False,
        lazy="selectin",
    )


# Register comments back-reference on Post
Post.comments = relationship(
    "Comment",
    back_populates="post",
    lazy="selectin",
    primaryjoin="and_(Comment.post_id==Post.id, Comment.status=='approved')",
    order_by="Comment.created_at",
)


class Media(Base):
    """Media object (§1, URL §6 /media/{yyyy}/{mm}/{file}).

    Stable URLs: filename is never changed after publication.
    """

    __tablename__ = "media"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
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

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
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
        "category_id", Integer,
        ForeignKey("categories.id", ondelete="CASCADE"), primary_key=True,
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

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
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
        diff = list(difflib.unified_diff(
            old_lines, new_lines,
            fromfile="revision-prev",
            tofile="revision-new",
            lineterm="",
        ))
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

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
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
