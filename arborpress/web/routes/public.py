"""Öffentliche Content-Routen (§6 URL-Schema, §7 I18N, §9 server-rendered).

Kanonische URL-Hierarchie:
  /               – Post-Liste (Startseite)
  /p/<slug>       – Post
  /o/<short_id>   – Short-ID → 301 zum kanonischen Slug
  /page/<slug>    – Statische Seite
  /tag/<tag>      – Tag-Übersicht
  /search?q=      – Volltext-Suche
  /media/…        – Mediendateien (stable URL, §6)
  /@<handle>      – Nutzerprofil (PUBLIC-Konten, §4)
  /@<handle>/p/<slug>  – Post eines Nutzers
"""

from __future__ import annotations

import datetime as dt
import logging
import mimetypes
import os
from email.utils import formatdate as _rfc822

from quart import (
    Blueprint,
    Response,
    abort,
    redirect,
    render_template,
    request,
    url_for,
)
from slugify import slugify
from sqlalchemy import select

from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.public")

public_bp = Blueprint("public", __name__)

_PER_PAGE = 20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_slug(slug: str) -> str:
    """§6 – Slugs immer lowercase, URL-safe."""
    return slugify(slug, lowercase=True, separator="-")


async def _get_footer_pages() -> list:
    """Lädt Pflichtseiten für den Footer (§1 Impressum/Datenschutz/Regeln).

    Nur Seiten mit visibility=PUBLIC erscheinen im Footer.
    """
    try:
        from arborpress.models.content import Page, PageType, PostVisibility
        async for db in get_db_session():
            stmt = select(Page).where(
                Page.page_type.in_([
                    PageType.IMPRESSUM, PageType.PRIVACY, PageType.RULES,
                ]),
                Page.is_published == True,  # noqa: E712
                Page.visibility == PostVisibility.PUBLIC,
            ).order_by(Page.page_type)
            result = await db.execute(stmt)
            return result.scalars().all()
    except Exception:
        return []
    return []


async def _render(template: str, **ctx):
    footer_pages = await _get_footer_pages()
    return await render_template(template, footer_pages=footer_pages, **ctx)


# ---------------------------------------------------------------------------
# Startseite / Post-Liste
# ---------------------------------------------------------------------------


@public_bp.get("/")
async def index():
    """Post-Liste (§6 / §9 server-rendered)."""
    page = int(request.args.get("page", 1))
    lang = request.args.get("lang")

    from arborpress.models.content import Post, PostStatus

    try:
        from arborpress.models.content import PostVisibility
        async for db in get_db_session():
            stmt = (
                select(Post)
                .where(
                    Post.status == PostStatus.PUBLISHED,
                    Post.visibility == PostVisibility.PUBLIC,
                )
                .order_by(Post.published_at.desc())
            )
            if lang:
                stmt = stmt.where(Post.lang == lang)

            total_stmt = select(Post).where(
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
            total_result = await db.execute(total_stmt)
            total = len(total_result.scalars().all())

            stmt = stmt.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE)
            result = await db.execute(stmt)
            posts = result.scalars().all()

            class _Pagination:
                pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
                has_prev = page > 1
                has_next = page < pages
                prev_num = page - 1
                next_num = page + 1

            return await _render("index.html", posts=posts, pagination=_Pagination())
    except Exception as exc:
        log.warning("Index-Abfrage fehlgeschlagen: %s", exc)
        return await _render("index.html", posts=[], pagination=None)


# ---------------------------------------------------------------------------
# Post-Detail
# ---------------------------------------------------------------------------


@public_bp.get("/p/<slug>")
async def post_detail(slug: str):
    """Einzelner Post (§6)."""
    canonical = _canonical_slug(slug)
    if canonical != slug:
        return redirect(url_for("public.post_detail", slug=canonical), 301)

    from arborpress.core.captcha import get_captcha_challenge, get_effective_captcha_type
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import Post, PostStatus, PostVisibility

    async for db in get_db_session():
        # Post laden (status=published reicht; visibility wird separat geprüft)
        stmt = select(Post).where(
            Post.slug == canonical,
            Post.status == PostStatus.PUBLISHED,
        )
        result = await db.execute(stmt)
        post = result.scalar_one_or_none()

        if post is None:
            # Versuch: alter Slug → 301
            old_stmt = select(Post).where(Post.slug_old == canonical)
            old_result = await db.execute(old_stmt)
            old_post = old_result.scalar_one_or_none()
            if old_post:
                return redirect(url_for("public.post_detail", slug=old_post.slug), 301)
            abort(404)

        # private: Artikel ist komplett gesperrt
        if post.visibility == PostVisibility.PRIVATE:
            abort(404)
        # hidden: Artikel ist erreichbar, aber nicht verlinkt – kein abort

        captcha_section = await get_section("captcha", db)
        captcha_type    = get_effective_captcha_type(post.captcha_type, captcha_section)
        captcha_ctx     = get_captcha_challenge(captcha_type, captcha_section)

        # --- Verwandte Artikel (Tag-Überlappung, max. 3) ---
        related_posts: list = []
        post_tag_ids = [t.id for t in (post.tags or [])]
        if post_tag_ids:
            from sqlalchemy import func

            from arborpress.models.content import post_tags as _post_tags_table

            overlap_subq = (
                select(
                    _post_tags_table.c.post_id,
                    func.count(_post_tags_table.c.tag_id).label("overlap"),
                )
                .where(
                    _post_tags_table.c.tag_id.in_(post_tag_ids),
                    _post_tags_table.c.post_id != post.id,
                )
                .group_by(_post_tags_table.c.post_id)
                .subquery()
            )
            rel_stmt = (
                select(Post, overlap_subq.c.overlap)
                .join(overlap_subq, Post.id == overlap_subq.c.post_id)
                .where(
                    Post.status     == PostStatus.PUBLISHED,
                    Post.visibility == PostVisibility.PUBLIC,
                )
                .order_by(overlap_subq.c.overlap.desc(), Post.published_at.desc())
                .limit(3)
            )
            rel_result = await db.execute(rel_stmt)
            related_posts = [row[0] for row in rel_result.all()]

    return await _render("post.html", post=post, captcha=captcha_ctx,
                         related_posts=related_posts)


# ---------------------------------------------------------------------------
# Short-ID /o/{short_id}
# ---------------------------------------------------------------------------


@public_bp.get("/o/<short_id>")
async def shortlink(short_id: str):
    """ActivityPub / Kurz-Link → 301 zum kanonischen Slug (§6)."""
    from arborpress.models.content import Post, PostVisibility

    async for db in get_db_session():
        stmt = select(Post).where(Post.short_id == short_id)
        result = await db.execute(stmt)
        post = result.scalar_one_or_none()

    if post is None:
        abort(404)
    # private Posts sind auch über Short-Link nicht erreichbar
    if post.visibility == PostVisibility.PRIVATE:
        abort(404)
    return redirect(url_for("public.post_detail", slug=post.slug), 301)


# ---------------------------------------------------------------------------
# Statische Seiten
# ---------------------------------------------------------------------------


@public_bp.get("/page/<slug>")
async def page_detail(slug: str):
    """Statische Seite – Impressum, Datenschutz, Regeln (§1, §6)."""
    canonical = _canonical_slug(slug)
    if canonical != slug:
        return redirect(url_for("public.page_detail", slug=canonical), 301)

    from arborpress.models.content import Page, PostVisibility

    async for db in get_db_session():
        # is_published prüfen; visibility separat behandeln
        stmt = select(Page).where(
            Page.slug == canonical,
            Page.is_published == True,  # noqa: E712
        )
        result = await db.execute(stmt)
        page = result.scalar_one_or_none()

    if page is None:
        abort(404)
    # private: Seite komplett gesperrt
    if page.visibility == PostVisibility.PRIVATE:
        abort(404)
    # hidden: erreichbar, aber nicht in Navigation/Fußzeile verlinkt
    return await _render("page.html", page=page)


# ---------------------------------------------------------------------------
# Tag-Übersicht
# ---------------------------------------------------------------------------


@public_bp.get("/tag/<tag>")
async def tag_archive(tag: str):
    """Posts eines Tags (§6)."""
    canonical = _canonical_slug(tag)
    if canonical != tag:
        return redirect(url_for("public.tag_archive", tag=canonical), 301)

    from arborpress.models.content import Post, PostStatus, Tag

    async for db in get_db_session():
        tag_stmt = select(Tag).where(Tag.slug == canonical)
        tag_result = await db.execute(tag_stmt)
        tag_obj = tag_result.scalar_one_or_none()

        if tag_obj is None:
            abort(404)

        from arborpress.models.content import PostVisibility
        posts_stmt = (
            select(Post)
            .where(
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
                Post.tags.contains(tag_obj),
            )
            .order_by(Post.published_at.desc())
        )
        posts_result = await db.execute(posts_stmt)
        posts = posts_result.scalars().all()

    return await _render("tag.html", tag=tag_obj.label, posts=posts)


# ---------------------------------------------------------------------------
# Suche
# ---------------------------------------------------------------------------


@public_bp.get("/search")
async def search():
    """Volltext-Suche (§12 FTS, §6)."""
    q = request.args.get("q", "").strip()
    results = []

    if q:
        from arborpress.core.db_capabilities import get_capabilities
        from arborpress.models.content import Post, PostStatus, PostVisibility

        caps = get_capabilities()

        try:
            async for db in get_db_session():
                if caps and caps.fts_provider == "pg_fts":
                    from sqlalchemy import func, text
                    stmt = (
                        select(Post)
                        .where(
                            Post.status == PostStatus.PUBLISHED,
                            Post.visibility == PostVisibility.PUBLIC,
                        )
                        .where(
                            func.to_tsvector("simple", Post.title + " " + Post.body_md)
                            .op("@@")(func.plainto_tsquery("simple", q))
                        )
                        .limit(50)
                    )
                elif caps and caps.fts_provider == "mariadb_fulltext":
                    from sqlalchemy import text
                    stmt = (
                        select(Post)
                        .where(
                            Post.status == PostStatus.PUBLISHED,
                            Post.visibility == PostVisibility.PUBLIC,
                        )
                        .where(text("MATCH(title, body_md) AGAINST(:q IN BOOLEAN MODE)"))
                        .params(q=q)
                        .limit(50)
                    )
                else:
                    # Fallback: LIKE (§12)
                    from arborpress.models.content import PostVisibility
                    stmt = (
                        select(Post)
                        .where(
                            Post.status == PostStatus.PUBLISHED,
                            Post.visibility == PostVisibility.PUBLIC,
                        )
                        .where(Post.title.ilike(f"%{q}%"))
                        .limit(50)
                    )

                result = await db.execute(stmt)
                posts = result.scalars().all()
                results = [
                    {
                        "title": p.title,
                        "url": url_for("public.post_detail", slug=p.slug),
                        "excerpt": p.excerpt,
                    }
                    for p in posts
                ]
        except Exception as exc:
            log.warning("Suche fehlgeschlagen: %s", exc)

    return await _render("search.html", q=q, results=results)


# ---------------------------------------------------------------------------
# Media – stabile URLs (§6)
# ---------------------------------------------------------------------------


@public_bp.get("/media/<int:yyyy>/<int:mm>/<filename>")
async def media_serve(yyyy: int, mm: int, filename: str):
    """Mediendateien – stabile URL, aggressives Caching (§6).

    Dateipfad: <media_root>/yyyy/mm/filename
    Sicherheit: kein Path-Traversal (filename darf kein / oder .. enthalten)
    """
    # Pfad-Traversal verhindern
    safe_name = os.path.basename(filename)
    if safe_name != filename or ".." in filename:
        abort(400)

    cfg = get_settings()
    media_path = cfg.web.media_dir / str(yyyy) / f"{mm:02d}" / safe_name

    if not media_path.exists():
        abort(404)

    # Streaming via aiofiles
    import aiofiles
    from quart import Response

    mime, _ = mimetypes.guess_type(str(media_path))
    mime = mime or "application/octet-stream"

    async def stream_file():
        async with aiofiles.open(media_path, "rb") as f:
            while chunk := await f.read(65536):
                yield chunk

    resp = Response(stream_file(), mimetype=mime)
    # Cache-Header werden von SecurityHeadersMiddleware gesetzt (§10)
    return resp


# ---------------------------------------------------------------------------
# Nutzerprofil /@{handle} (§4 PUBLIC-Konten, §6)
# ---------------------------------------------------------------------------


@public_bp.get("/@<handle>")
async def author_profile(handle: str):
    """Öffentliches Profil – nur PUBLIC-Konten (§4 Sicherheitstrennung)."""
    from arborpress.models.user import AccountType, User

    async for db in get_db_session():
        stmt = select(User).where(
            User.username == handle,
            User.account_type == AccountType.PUBLIC,
            User.is_active == True,  # noqa: E712
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

    if user is None:
        abort(404)

    # Posts dieses Nutzers – nur öffentlich verlinkte
    from arborpress.models.content import Post, PostStatus, PostVisibility
    async for db in get_db_session():
        posts_stmt = (
            select(Post)
            .where(
                Post.author_id == user.id,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
            .order_by(Post.published_at.desc())
            .limit(20)
        )
        posts_result = await db.execute(posts_stmt)
        posts = posts_result.scalars().all()

    return await _render("index.html", posts=posts, pagination=None, author=user)


@public_bp.get("/@<handle>/p/<slug>")
async def author_post(handle: str, slug: str):
    """Post eines bestimmten Autors /@{handle}/p/{slug} (§6)."""
    canonical = _canonical_slug(slug)
    if canonical != slug:
        return redirect(url_for("public.author_post", handle=handle, slug=canonical), 301)

    from arborpress.models.content import Post, PostStatus
    from arborpress.models.user import AccountType, User

    async for db in get_db_session():
        author_stmt = select(User).where(
            User.username == handle,
            User.account_type == AccountType.PUBLIC,
        )
        author_result = await db.execute(author_stmt)
        author = author_result.scalar_one_or_none()
        if author is None:
            abort(404)

        post_stmt = select(Post).where(
            Post.slug == canonical,
            Post.author_id == author.id,
            Post.status == PostStatus.PUBLISHED,
        )
        post_result = await db.execute(post_stmt)
        post = post_result.scalar_one_or_none()

    if post is None:
        abort(404)
    # private: auch über Autoren-URL gesperrt
    from arborpress.models.content import PostVisibility
    if post.visibility == PostVisibility.PRIVATE:
        abort(404)
    return await _render("post.html", post=post)


# ---------------------------------------------------------------------------
# Kommentar-Routen (zweistufige Moderation: E-Mail + Admin)
# ---------------------------------------------------------------------------


@public_bp.post("/p/<slug>/comment")
async def post_comment_submit(slug: str):
    """Kommentar einreichen.

    Ablauf:
      1. CSRF-Token prüfen (§10)
      2. Captcha prüfen (Typ richtet sich nach Post-Override oder globalem Standard)
      3. Formular validieren
      4. Comment(status=PENDING) in DB anlegen
      5. Bestätigungs-E-Mail an Autor senden
      6. Weiterleitung zum Artikel mit Hinweis-Flash
    """
    validate_csrf()
    from datetime import datetime as dt

    from quart import flash

    from arborpress.core.captcha import get_effective_captcha_type, verify_captcha
    from arborpress.core.mail import send_comment_confirmation
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus

    canonical = _canonical_slug(slug)

    async for db in get_db_session():
        stmt = select(Post).where(
            Post.slug == canonical,
            Post.status == PostStatus.PUBLISHED,
        )
        result = await db.execute(stmt)
        post = result.scalar_one_or_none()
        if post is None:
            abort(404)

        form = await request.form

        # --- Captcha- und Kommentar-Einstellungen laden ---
        captcha_section  = await get_section("captcha", db)
        comments_section = await get_section("comments", db)

        # --- Captcha-Prüfung ---
        captcha_type = get_effective_captcha_type(post.captcha_type, captcha_section)
        ok, err = await verify_captcha(captcha_type, form, captcha_section)
        if not ok:
            await flash(err or "Bitte löse das Captcha korrekt.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        author_name  = (form.get("author_name",  "") or "").strip()
        author_email = (form.get("author_email", "") or "").strip()
        author_url   = (form.get("author_url",   "") or "").strip() or None
        body         = (form.get("body",          "") or "").strip()
        # Zitat-Referenz: optional, muss zum selben Post gehören
        quote_of_raw = (form.get("quote_of_id",  "") or "").strip() or None
        quote_of_id  = None
        if quote_of_raw:
            quoted_stmt = select(Comment).where(
                Comment.id == quote_of_raw,
                Comment.post_id == post.id,
                Comment.status == CommentStatus.APPROVED,
            )
            quoted_result = await db.execute(quoted_stmt)
            if quoted_result.scalar_one_or_none():
                quote_of_id = quote_of_raw

        if not author_name or not author_email or not body:
            await flash("Bitte fülle alle Pflichtfelder aus.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        # DSGVO-Zustimmung prüfen
        if not form.get("consent"):
            await flash("Bitte stimme der Datenschutzerklärung zu.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        # Grobes E-Mail-Format-Check
        if "@" not in author_email or "." not in author_email.split("@")[-1]:
            await flash("Bitte gib eine gültige E-Mail-Adresse ein.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        # Rate-Limit (einfache IP-Prüfung)
        rate_limit = comments_section.get("rate_limit_per_hour", 10)
        if rate_limit > 0:
            from datetime import timedelta

            from sqlalchemy import and_
            one_hour_ago = dt.utcnow() - timedelta(hours=1)
            ip = request.remote_addr or ""
            rl_stmt = select(Comment).where(
                and_(
                    Comment.ip_address == ip,
                    Comment.created_at >= one_hour_ago,
                )
            )
            rl_result = await db.execute(rl_stmt)
            if len(rl_result.scalars().all()) >= rate_limit:
                await flash("Zu viele Kommentare – bitte später erneut versuchen.", "error")
                return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        import uuid as _uuid
        # --- Sperrliste prüfen (Soft-Block: sofort als SPAM markieren) ---
        blocklist_raw = comments_section.get("blocklist", "") or ""
        blocklist     = [
            term.strip().lower()
            for term in blocklist_raw.splitlines()
            if term.strip()
        ]
        _check_fields = " ".join([
            author_name.lower(),
            author_email.lower(),
            (author_url or "").lower(),
            body.lower(),
            (request.remote_addr or "").lower(),
        ])
        blocked = any(term in _check_fields for term in blocklist)

        comment = Comment(
            id=str(_uuid.uuid4()),
            post_id=post.id,
            author_name=author_name,
            author_email=author_email,
            author_url=author_url,
            body=body,
            quote_of_id=quote_of_id,
            status=CommentStatus.SPAM if blocked else CommentStatus.PENDING,
            confirmation_token=str(_uuid.uuid4()),
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:512],
        )
        db.add(comment)
        await db.commit()
        await db.refresh(comment)

        # Bestätigungs-Mail senden (wenn Backend != none und nicht geblockt)
        if blocked:
            # Stilles Akzeptieren – dem Absender keine Rückmeldung geben
            await flash(
                "Danke für deinen Kommentar!",
                "success",
            )
        elif comments_section.get("require_email_confirmation", True):
            await send_comment_confirmation(comment, post)
            await flash(
                "Danke für deinen Kommentar! Bitte bestätige ihn über den Link "
                "in der E-Mail, die wir an dich gesendet haben.",
                "success",
            )
        else:
            # Wenn Bestätigung deaktiviert: direkt auf CONFIRMED setzen
            comment.status = CommentStatus.CONFIRMED
            await db.commit()
            await flash(
                "Danke für deinen Kommentar! Er wird nach Prüfung freigeschaltet.",
                "success",
            )

    return redirect(url_for("public.post_detail", slug=canonical))


@public_bp.get("/comment/confirm/<token>")
async def comment_confirm(token: str):
    """E-Mail-Bestätigung des Kommentars.

    Setzt status=CONFIRMED und sendet Admin-Benachrichtigung.
    """
    from datetime import datetime as dt

    from arborpress.core.mail import send_comment_notification
    from arborpress.models.content import Comment, CommentStatus

    async for db in get_db_session():
        stmt = select(Comment).where(Comment.confirmation_token == token)
        result = await db.execute(stmt)
        comment = result.scalar_one_or_none()

        if comment is None:
            abort(404)

        if comment.status == CommentStatus.PENDING:
            comment.status       = CommentStatus.CONFIRMED
            comment.confirmed_at = dt.utcnow()
            await db.commit()
            await db.refresh(comment)
            # Admin informieren
            await send_comment_notification(comment, comment.post)

        already = comment.status in (
            CommentStatus.APPROVED,
            CommentStatus.REJECTED,
            CommentStatus.SPAM,
        )

    return await _render(
        "comment_confirmed.html",
        comment=comment,
        already_processed=already,
    )


# ---------------------------------------------------------------------------
# RSS- und Atom-Feeds
# ---------------------------------------------------------------------------

_FEED_LIMIT = 20
_RSS_MIME   = "application/rss+xml; charset=utf-8"
_ATOM_MIME  = "application/atom+xml; charset=utf-8"


def _post_url(base: str, post) -> str:
    """Absolute URL zu einem Post-Objekt."""
    return base.rstrip("/") + url_for("public.post_detail", slug=post.slug)


def _rfc3339(d: dt.datetime | None) -> str:
    """ISO-8601 / RFC 3339-Datum für Atom.  Immer UTC + Z-Suffix."""
    if d is None:
        return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rfc822_ts(d: dt.datetime | None) -> str:
    """RFC-822-Datum für RSS 2.0."""
    if d is None:
        return _rfc822(dt.datetime.utcnow().timestamp(), usegmt=True)
    return _rfc822(d.timestamp(), usegmt=True)


def _xml_esc(s: str) -> str:
    """Minimales XML-Escaping für CDATA-Attribute."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


async def _feed_posts():
    """Gibt die letzten _FEED_LIMIT veröffentlichten, öffentlichen Posts zurück."""
    from arborpress.models.content import Post, PostStatus, PostVisibility

    async for db in get_db_session():
        stmt = (
            select(Post)
            .where(
                Post.status     == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
            .order_by(Post.published_at.desc())
            .limit(_FEED_LIMIT)
        )
        result = await db.execute(stmt)
        return result.scalars().all()
    return []


@public_bp.get("/feed.xml")
async def rss_feed():
    """RSS-2.0-Feed aller öffentlichen Posts (max. 20).

    URL: /feed.xml
    Auto-Discovery: <link rel="alternate" type="application/rss+xml" …>
    """
    from arborpress.core.site_settings import get_section

    cfg      = get_settings()
    base_url = cfg.web.base_url.rstrip("/")

    async for db in get_db_session():
        general = await get_section("general", db)
        break
    else:
        general = {}

    title       = _xml_esc(general.get("site_title",       "ArborPress"))
    description = _xml_esc(general.get("site_description", ""))
    language    = general.get("site_language", "de")
    posts       = await _feed_posts()

    now_rfc     = _rfc822_ts(dt.datetime.utcnow())
    last_build  = _rfc822_ts(posts[0].published_at if posts else None)

    items = []
    for p in posts:
        link    = _post_url(base_url, p)
        excerpt = _xml_esc((p.excerpt or "").strip())
        desc_elem = (
            f"<description>{excerpt}</description>" if excerpt else "<description/>"
        )
        items.append(
            f"    <item>\n"
            f"      <title>{_xml_esc(p.title)}</title>\n"
            f"      <link>{link}</link>\n"
            f"      <guid isPermaLink=\"true\">{link}</guid>\n"
            f"      <pubDate>{_rfc822_ts(p.published_at)}</pubDate>\n"
            f"      {desc_elem}\n"
            f"    </item>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n'
        "  <channel>\n"
        f"    <title>{title}</title>\n"
        f"    <link>{base_url}/</link>\n"
        f"    <description>{description}</description>\n"
        f"    <language>{language}</language>\n"
        f"    <lastBuildDate>{last_build}</lastBuildDate>\n"
        f"    <pubDate>{now_rfc}</pubDate>\n"
        f'    <atom:link href="{base_url}/feed.xml" rel="self" '
        f'type="application/rss+xml"/>\n'
        + "\n".join(items) + "\n"
        "  </channel>\n"
        "</rss>"
    )
    return Response(xml, content_type=_RSS_MIME)


@public_bp.get("/feed/atom.xml")
async def atom_feed():
    """Atom-1.0-Feed aller öffentlichen Posts (max. 20).

    URL: /feed/atom.xml
    Auto-Discovery: <link rel="alternate" type="application/atom+xml" …>
    """
    from arborpress.core.site_settings import get_section

    cfg      = get_settings()
    base_url = cfg.web.base_url.rstrip("/")

    async for db in get_db_session():
        general = await get_section("general", db)
        break
    else:
        general = {}

    title   = _xml_esc(general.get("site_title", "ArborPress"))
    posts   = await _feed_posts()
    updated = _rfc3339(posts[0].published_at if posts else None)

    entries = []
    for p in posts:
        link    = _post_url(base_url, p)
        excerpt = _xml_esc((p.excerpt or "").strip())
        entries.append(
            f"  <entry>\n"
            f"    <id>{link}</id>\n"
            f"    <title>{_xml_esc(p.title)}</title>\n"
            f"    <link href=\"{link}\"/>\n"
            f"    <updated>{_rfc3339(p.published_at)}</updated>\n"
            + (f"    <summary>{excerpt}</summary>\n" if excerpt else "")
            + "  </entry>"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<feed xmlns="http://www.w3.org/2005/Atom">\n'
        f"  <id>{base_url}/</id>\n"
        f"  <title>{title}</title>\n"
        f"  <updated>{updated}</updated>\n"
        f'  <link href="{base_url}/" rel="alternate"/>\n'
        f'  <link href="{base_url}/feed/atom.xml" rel="self"/>\n'
        + "\n".join(entries) + "\n"
        "</feed>"
    )
    return Response(xml, content_type=_ATOM_MIME)
