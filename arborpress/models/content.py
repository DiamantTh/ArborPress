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
    """Sichtbarkeitsstufe eines Beitrags oder einer Seite.

    public  – in Listen/Suche/Tags sichtbar (Standard)
    hidden  – per direkter URL erreichbar, jedoch NICHT in Listen/Suche/Tags
    private – komplett gesperrt (HTTP 404 für anonyme Besucher)
    """
    PUBLIC  = "public"
    HIDDEN  = "hidden"
    PRIVATE = "private"


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
    slug_old: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[PostStatus] = mapped_column(
        Enum(PostStatus), nullable=False, default=PostStatus.DRAFT
    )
    # Sichtbarkeit: public | hidden | private
    visibility: Mapped[PostVisibility] = mapped_column(
        Enum(PostVisibility), nullable=False, default=PostVisibility.PUBLIC
    )
    # §7 language
    lang: Mapped[str | None] = mapped_column(String(8), nullable=True)
    # §5 ActivityPub object ID (set when federated)
    ap_object_id: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Captcha-Typ für Kommentarformular (NULL = globalen Standard aus config verwenden)
    # Erlaubte Werte: none|math|custom|hcaptcha|friendly_captcha|altcha|mcaptcha|mosparo|turnstile
    captcha_type: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Sichtbarkeit in Listen
    is_pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """Immer oben in der Post-Liste, unabhängig von published_at."""

    is_featured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """Visuell hervorgehoben im Theme (z. B. Hero-Kachel auf der Startseite)."""

    noindex: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    """robots: noindex – erreichbar, aber nicht in Suchmaschinen indexiert."""

    # Lesedauer: beim Speichern berechnet (Markdown-Wörter / 200 wpm; min. 1)
    reading_time_min: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    tags: Mapped[list[Tag]] = relationship(secondary=post_tags, lazy="selectin")

    @staticmethod
    def calc_reading_time(body_md: str) -> int:
        """Lesedauer in Minuten schätzen.

        Formel:
          - Prose-Wörter / 200  (Erw.-Durchschnitt ~200 wpm)
          - Code-Blöcke zählen je 0,5 Minuten extra
          - Minimum: 1 Minute

        Probe-Code-Blöcke werden nicht als Wörter mitgezählt, weil man
        Code deutlich langsamer überfliegt als Fließtext.
        """
        # Code-Blöcke extrahieren und entfernen
        code_blocks = re.findall(r"```[\s\S]*?```", body_md)
        prose = re.sub(r"```[\s\S]*?```", " ", body_md)
        # Inline-Code und Markdown-Syntax entfernen
        prose = re.sub(r"`[^`]+`", " ", prose)
        prose = re.sub(r"[#*_~\[\]()>|-]", " ", prose)
        words = len(prose.split())
        minutes = words / 200 + len(code_blocks) * 0.5
        return max(1, round(minutes))


class PageType(enum.StrEnum):
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
    slug_old: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    page_type: Mapped[PageType] = mapped_column(
        Enum(PageType), nullable=False, default=PageType.CUSTOM
    )
    lang: Mapped[str | None] = mapped_column(String(8), nullable=True)
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    # Sichtbarkeit: public | hidden | private
    # Bei Systemseiten (IMPRESSUM/PRIVACY/RULES) löst private/hidden eine
    # Admin-CP-Warnung aus.
    visibility: Mapped[PostVisibility] = mapped_column(
        Enum(PostVisibility), nullable=False, default=PostVisibility.PUBLIC
    )
    # §10 noindex for admin-only pages
    noindex: Mapped[bool] = mapped_column(Boolean, default=False)
    # Soll die Seite im Footer-Menü erscheinen?
    show_in_footer: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class CommentStatus(enum.StrEnum):
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
    author_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    body: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[CommentStatus] = mapped_column(
        Enum(CommentStatus), nullable=False, default=CommentStatus.PENDING
    )
    # UUID-Token für E-Mail-Bestätigung
    confirmation_token: Mapped[str] = mapped_column(
        String(64), nullable=False, default=lambda: str(uuid.uuid4())
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    approved_at:  Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Zitat-Referenz: flache Kommentarstruktur statt tiefem Nesting
    # Zeigt auf den kommentierten Kommentar (derselbe Post).
    quote_of_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("comments.id", ondelete="SET NULL"), nullable=True
    )

    # Moderationsnotiz des Admins (intern)
    mod_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent:  Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    post: Mapped[Post] = relationship("Post", back_populates="comments", lazy="selectin")

    # Zitierter Kommentar (flache Struktur statt tiefem Nesting)
    # foreign() markiert die FK-Seite; rechts steht die remote (Parent-) Seite.
    quoted: Mapped[Comment | None] = relationship(
        "Comment",
        primaryjoin="foreign(Comment.quote_of_id) == Comment.id",
        uselist=False,
        lazy="selectin",
    )


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
    uploader_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Pfad relativ zu MEDIA_ROOT: yyyy/mm/filename
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    alt_text: Mapped[str | None] = mapped_column(String(512), nullable=True)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Externes Original-URL (gesetzt wenn das Bild automatisch heruntergeladen wurde)
    original_url: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)

    uploaded_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class OEmbedCache(Base):
    """Serverseitig gecachtes oEmbed-HTML (kein Besucher-Request zu Drittanbietern).

    Wird beim Post-Speichern befüllt wenn der Autor einen
    ``{{embed:url}}``-Shortcode verwendet.
    """

    __tablename__ = "oembed_cache"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # Original Post-URL (eindeutiger Schlüssel)
    url: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    provider_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Bereinigtes HTML ohne <script>-Tags
    html: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    # Ablaufdatum – nach Ablauf beim nächsten Render neu geholt
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
    Column("category_id", Integer, ForeignKey("categories.id", ondelete="CASCADE"), primary_key=True),
)


class Category(Base):
    """Hierarchische Kategorie (Baum-Struktur via parent_id).

    Beispiel:
      Technik (parent=None)
        └─ Python (parent=Technik)
             └─ Tutorial (parent=Python)
    """

    __tablename__ = "categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Hierarchie: NULL = Root-Kategorie
    parent_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("categories.id", ondelete="SET NULL"), nullable=True
    )
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lang: Mapped[str | None] = mapped_column(String(8), nullable=True)

    # Eltern-Kategorie
    parent: Mapped[Category | None] = relationship(
        "Category",
        foreign_keys=[parent_id],
        back_populates="children",
        remote_side="Category.id",
    )
    # Kind-Kategorien
    children: Mapped[list[Category]] = relationship(
        "Category",
        foreign_keys=[parent_id],
        back_populates="parent",
        order_by="Category.sort_order",
    )


# Kategorien-Rückbeziehung auf Post registrieren
Post.categories = relationship(
    "Category",
    secondary=post_categories,
    lazy="selectin",
)


# ---------------------------------------------------------------------------
# Post-Revisionen (Versionsverlauf mit Diff)
# ---------------------------------------------------------------------------

class PostRevision(Base):
    """Versionsverlauf eines Blog-Posts.

    Wird beim Speichern automatisch angelegt.
    Enthält den vollständigen Markdown-Text sowie einen
    unified-diff zum vorherigen Stand für die Diff-Ansicht im Admin.

    Aufräum-Strategie: Admin kann ältere Revisionen ab rev_number < N purgen;
    empfohlener Schwellenwert: 50 Revisionen pro Post behalten.
    """

    __tablename__ = "post_revisions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    post_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    # Fortlaufende Revisionsnummer pro Post (1, 2, 3, …)
    rev_number: Mapped[int] = mapped_column(Integer, nullable=False)
    # Snapshot
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    # Unified diff zum vorherigen Stand (NULL bei Revision 1)
    diff_to_prev: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Wer hat die Änderung gespeichert (NULL = System/Import)
    changed_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Optionale Zusammenfassung der Änderung ("Tippfehler bereinigt")
    change_summary: Mapped[str | None] = mapped_column(String(256), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    @staticmethod
    def make_diff(old_md: str, new_md: str) -> str:
        """Erzeuge einen unified diff (als Text) zwischen zwei Markdown-Ständen.

        Gibt einen leeren String zurück wenn es keine Änderungen gibt.
        Zeilenweise Darstellung, kompatibel mit standard ``diff``-Tools.
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
# Passwortschutz für Posts (mehrere Zugangstokens pro Post)
# ---------------------------------------------------------------------------

class PostAccessToken(Base):
    """Zugangstoken für passwortgeschützte Posts.

    Ein Post kann mehrere Tokens haben, z. B.:
      - "Frühe Leser"   (max. 100 Nutzungen, läuft in 30 Tagen ab)
      - "Pressezugang"  (unlimitiert, kein Ablauf)
      - "Freunde"       (5 Nutzungen)

    Beispiel-Ablauf:
      1. Besucher ruft /p/<slug> auf → Formular "Bitte Passwort eingeben"
      2. Besucher gibt Token ein → Backend vergleicht gegen alle Hashes
      3. Treffer + gültig → kurzlebiges Cookie gesetzt (z. B. 24h) → Inhalt sichtbar
      4. use_count wird erhöht; max_uses wird geprüft
    """

    __tablename__ = "post_access_tokens"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    post_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False
    )
    # Anzeigename im Admin (z. B. "Pressezugang", "Frühe Leser")
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    # Argon2/bcrypt-Hash des Klartext-Tokens
    token_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    # Nutzungslimit: NULL = unlimitiert
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Ablaufdatum: NULL = kein Ablauf
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    @property
    def is_valid(self) -> bool:
        """Prüft ob der Token noch verwendbar ist (Limit + Ablauf)."""
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        if self.max_uses is not None and self.use_count >= self.max_uses:
            return False
        return True
