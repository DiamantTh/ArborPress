"""API routes – /api/v1/ (§8 admin & public API).

Separation:
- Public API  (/api/v1/posts, /api/v1/tags …)   – no auth required
- Admin API   (/api/v1/admin/…)                  – session + step-up (§2)

CSRF note (§8 / §10):
  All state-changing endpoints check Origin/Referer OR require
  an explicit X-Requested-With header. SPA frontends send it automatically.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid as _uuid
from datetime import UTC, datetime
from pathlib import Path

from quart import (
    Blueprint,
    abort,
    current_app,  # noqa: F401
    jsonify,
    request,
    session,
)

from arborpress.auth.roles import require_role
from arborpress.core.config import get_settings
from arborpress.core.markdown import render_md_async

log = logging.getLogger("arborpress.web.api")

# ---------------------------------------------------------------------------
# Blueprints
# ---------------------------------------------------------------------------

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
api_admin_bp = Blueprint("api_admin", __name__, url_prefix="/api/v1/admin")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _origin_check() -> None:
    """Simple CSRF origin guard for state-changing API calls (§10)."""
    cfg = get_settings()
    origin = request.headers.get("Origin") or request.headers.get("Referer", "")
    if origin and not origin.startswith(cfg.web.base_url):
        abort(403, "Cross-origin request rejected")


_ADMIN_ROLES: frozenset[str] = frozenset({"admin", "editor", "author", "moderator"})


# ---------------------------------------------------------------------------
# Public API – Inhalte lesen
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Shared serialisers
# ---------------------------------------------------------------------------

def _post_summary(p) -> dict:
    return {
        "id":           p.short_id,
        "slug":         p.slug,
        "title":        p.title,
        "excerpt":      p.excerpt,
        "published_at": p.published_at.isoformat() if p.published_at else None,
        "reading_time_min": p.reading_time_min,
        "lang":         p.lang,
        "is_pinned":    p.is_pinned,
        "is_featured":  p.is_featured,
        "tags":         [{"slug": t.slug, "label": t.label} for t in (p.tags or [])],
        "url":          f"/p/{p.slug}",
    }


def _page_summary(pg) -> dict:
    return {
        "id":     pg.id,
        "slug":   pg.slug,
        "title":  pg.title,
        "type":   pg.page_type.value,
        "lang":   pg.lang,
        "url":    f"/page/{pg.slug}",
    }


def _user_public(u, post_count: int = 0) -> dict:
    return {
        "username":     u.username,
        "display_name": u.display_name,
        "bio":          u.bio,
        "website":      u.website,
        "post_count":   post_count,
        "profile_url":  f"/@{u.username}",
    }


# ---------------------------------------------------------------------------
# Public API – Inhalte lesen
# ---------------------------------------------------------------------------


@api_v1_bp.get("/posts")
async def api_posts_list():
    """Paginierte Post-Liste (§8 public API).

    Query-Parameter:
      page     – Seitennummer (default 1)
      per_page – Einträge pro Seite (max 50, default 20)
      lang     – Sprachfilter (§7)
      tag      – Tag-Slug-Filter
    """
    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post, PostStatus, PostVisibility, Tag

    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(max(1, int(request.args.get("per_page", 20))), 50)
    except ValueError:
        abort(400, "page and per_page must be integers")

    lang = request.args.get("lang")
    tag  = request.args.get("tag")

    async for db in get_db_session():
        # Base filter: public + published
        base = (
            (Post.status == PostStatus.PUBLISHED) &
            (Post.visibility == PostVisibility.PUBLIC)
        )
        if lang:
            base = base & (Post.lang == lang)

        if tag:
            from sqlalchemy import select as _sel
            from arborpress.models.content import post_tags as _pt
            tag_obj = (await db.execute(
                _sel(Tag).where(Tag.slug == tag)
            )).scalar_one_or_none()
            if tag_obj is None:
                return jsonify({"items": [], "page": page, "per_page": per_page, "total": 0})
            tag_subq = (
                _sel(_pt.c.post_id)
                .where(_pt.c.tag_id == tag_obj.id)
                .scalar_subquery()
            )
            base = base & Post.id.in_(tag_subq)

        from sqlalchemy import func, select
        total = (await db.execute(
            select(func.count()).select_from(Post).where(base)
        )).scalar_one()

        posts = (await db.execute(
            select(Post)
            .where(base)
            .order_by(Post.is_pinned.desc(), Post.published_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )).scalars().all()

        return jsonify({
            "items":    [_post_summary(p) for p in posts],
            "page":     page,
            "per_page": per_page,
            "total":    total,
            "pages":    max(1, (total + per_page - 1) // per_page),
        })


@api_v1_bp.get("/posts/<slug>")
async def api_post_detail(slug: str):
    """Einzelner Post (§8, §6 – kanonischer Slug)."""
    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from quart import url_for

    async for db in get_db_session():
        from sqlalchemy import select
        post = (await db.execute(
            select(Post).where(
                Post.slug == slug,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility != PostVisibility.PRIVATE,
            )
        )).scalar_one_or_none()

        if post is None:
            # Check old slug → 301
            old = (await db.execute(
                select(Post).where(Post.slug_old == slug)
            )).scalar_one_or_none()
            if old and old.visibility != PostVisibility.PRIVATE:
                from quart import redirect
                return redirect(f"/api/v1/posts/{old.slug}", 301)
            abort(404)

        return jsonify({
            **_post_summary(post),
            "body_html": post.body_html,
            "noindex":   post.noindex,
            "ap_object_id": post.ap_object_id,
        })


@api_v1_bp.get("/pages/<slug>")
async def api_page_detail(slug: str):
    """Statische Seite (§1 impressum/privacy/rules, §6)."""
    from arborpress.core.db import get_db_session
    from arborpress.models.content import Page, PostVisibility

    async for db in get_db_session():
        from sqlalchemy import select
        page = (await db.execute(
            select(Page).where(
                Page.slug == slug,
                Page.is_published == True,  # noqa: E712
                Page.visibility != PostVisibility.PRIVATE,
            )
        )).scalar_one_or_none()

        if page is None:
            abort(404)

        return jsonify({
            **_page_summary(page),
            "body_html": page.body_html,
        })


@api_v1_bp.get("/tags")
async def api_tags_list():
    """Tag-Liste mit Post-Anzahl (§8 public API)."""
    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post, PostStatus, PostVisibility, Tag
    from sqlalchemy import func, select
    from arborpress.models.content import post_tags as _pt

    async for db in get_db_session():
        # Count published+public posts per tag
        count_subq = (
            select(_pt.c.tag_id, func.count(_pt.c.post_id).label("cnt"))
            .join(Post, Post.id == _pt.c.post_id)
            .where(
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
            .group_by(_pt.c.tag_id)
            .subquery()
        )
        rows = (await db.execute(
            select(Tag, count_subq.c.cnt)
            .outerjoin(count_subq, Tag.id == count_subq.c.tag_id)
            .order_by(Tag.label)
        )).all()

        items = [
            {
                "slug":  t.slug,
                "label": t.label,
                "lang":  t.lang,
                "post_count": cnt or 0,
                "url":  f"/tag/{t.slug}",
            }
            for t, cnt in rows
        ]
        return jsonify({"items": items, "total": len(items)})


@api_v1_bp.get("/users/<handle>")
async def api_user_profile(handle: str):
    """Public user profile – PUBLIC accounts only (§4).

    OPERATIONAL accounts are never exposed via the API.
    """
    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from arborpress.models.user import AccountType, User
    from sqlalchemy import func, select

    async for db in get_db_session():
        user = (await db.execute(
            select(User).where(
                func.lower(User.username) == handle.lower(),
                User.account_type == AccountType.PUBLIC,
                User.is_active == True,  # noqa: E712
            )
        )).scalar_one_or_none()

        if user is None:
            abort(404)

        post_count = (await db.execute(
            select(func.count()).select_from(Post).where(
                Post.author_id == str(user.id),
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
        )).scalar_one()

        return jsonify(_user_public(user, post_count))


@api_v1_bp.get("/search")
async def api_search():
    """Full-text search (§12 FTS).

    Query parameters: q, page (default 1), per_page (default 20, max 50)
    """
    from arborpress.core.db import get_db_session
    from arborpress.core.db_capabilities import get_capabilities
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from sqlalchemy import select

    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"items": [], "total": 0})

    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(max(1, int(request.args.get("per_page", 20))), 50)
    except ValueError:
        abort(400, "page and per_page must be integers")

    try:
        caps = get_capabilities()
    except RuntimeError:
        caps = None  # not yet initialised – fall through to ILIKE

    async for db in get_db_session():
        base = (
            (Post.status == PostStatus.PUBLISHED) &
            (Post.visibility == PostVisibility.PUBLIC)
        )
        if caps and caps.fts_provider == "pg_fts":
            from sqlalchemy import func as _f
            stmt = (
                select(Post)
                .where(base)
                .where(
                    _f.to_tsvector("simple", Post.title + " " + Post.body_md)
                    .op("@@")(_f.plainto_tsquery("simple", q))
                )
                .order_by(Post.published_at.desc())
                .limit(per_page).offset((page - 1) * per_page)
            )
        elif caps and caps.fts_provider == "mariadb_fulltext":
            from sqlalchemy import text
            stmt = (
                select(Post)
                .where(base)
                .where(text("MATCH(title, body_md) AGAINST(:q IN BOOLEAN MODE)"))
                .params(q=q)
                .order_by(Post.published_at.desc())
                .limit(per_page).offset((page - 1) * per_page)
            )
        else:
            # Fallback: ILIKE
            stmt = (
                select(Post)
                .where(base)
                .where(Post.title.ilike(f"%{q}%"))
                .order_by(Post.published_at.desc())
                .limit(per_page).offset((page - 1) * per_page)
            )

        posts = (await db.execute(stmt)).scalars().all()
        return jsonify({
            "items": [_post_summary(p) for p in posts],
            "q":     q,
            "page":  page,
            "per_page": per_page,
            "total": len(posts),   # FTS total is expensive; return page count
        })
    # Should not be reached
    return jsonify({"items": [], "total": 0, "q": q})


# ---------------------------------------------------------------------------
# Admin API – §8 state-changing operations
# ---------------------------------------------------------------------------


def _require_admin_session() -> None:
    """Validates admin session. Raises 401/403 if not authenticated (§2)."""
    if not session.get("user_id"):
        abort(401, "Authentifizierung erforderlich")
    if session.get("user_role", "") not in _ADMIN_ROLES:
        abort(403, "Unzureichende Berechtigungen")


def _require_stepup(operation: str) -> None:
    """Validates step-up session for sensitive operations (§2)."""
    from quart import session

    from arborpress.auth.stepup import assert_stepup
    try:
        assert_stepup(session, session.get("user_id"), operation)
    except PermissionError as exc:
        abort(403, str(exc))


@api_admin_bp.before_request
def _admin_api_guard():
    _origin_check()
    _require_admin_session()


@api_admin_bp.get("/posts")
async def admin_api_posts_list():
    """Admin: Alle Posts inkl. Drafts, paginiert (§8 admin API)."""
    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post
    from sqlalchemy import func, select

    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(max(1, int(request.args.get("per_page", 20))), 100)
    except ValueError:
        abort(400, "page and per_page must be integers")

    status_filter = request.args.get("status")  # optional filter

    async for db in get_db_session():
        stmt = select(Post)
        if status_filter:
            from arborpress.models.content import PostStatus
            try:
                stmt = stmt.where(Post.status == PostStatus(status_filter))
            except ValueError:
                abort(400, f"Invalid status: {status_filter!r}")

        total = (await db.execute(
            select(func.count()).select_from(stmt.subquery())
        )).scalar_one()

        posts = (await db.execute(
            stmt.order_by(Post.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )).scalars().all()

        return jsonify({
            "items": [
                {
                    **_post_summary(p),
                    "status":     p.status.value,
                    "visibility": p.visibility.value,
                    "created_at": p.created_at.isoformat(),
                    "updated_at": p.updated_at.isoformat() if p.updated_at else None,
                }
                for p in posts
            ],
            "page":  page,
            "per_page": per_page,
            "total": total,
        })


@api_admin_bp.post("/posts")
async def admin_api_post_create():
    """Admin: Neuen Post anlegen (§8)."""
    from arborpress.core.db import get_db_session
    from arborpress.core.markdown import render_md_async
    from arborpress.core.validators import is_valid_slug, strip_control_chars
    from arborpress.models.content import Post, PostStatus, PostVisibility
    import secrets as _sec

    data = await request.get_json(silent=True) or {}
    title = strip_control_chars(str(data.get("title") or "")).strip()
    slug  = strip_control_chars(str(data.get("slug")  or "")).strip().lower()
    body  = str(data.get("body") or "")

    if not title:
        abort(400, "title is required")
    if not slug or not is_valid_slug(slug):
        abort(400, "slug is required and must contain only lowercase letters, digits and hyphens")

    status_val = data.get("status", "draft")
    try:
        from arborpress.models.content import PostStatus
        status = PostStatus(status_val)
    except ValueError:
        abort(400, f"Invalid status: {status_val!r}")

    vis_val = data.get("visibility", "public")
    try:
        visibility = PostVisibility(vis_val)
    except ValueError:
        abort(400, f"Invalid visibility: {vis_val!r}")

    body_html = await render_md_async(body)
    short_id  = _sec.token_urlsafe(6)[:8]  # 8-char URL-safe short ID

    from datetime import UTC, datetime
    now = datetime.now(UTC)

    post = Post(
        id=str(_uuid.uuid4()),
        short_id=short_id,
        author_id=session.get("user_id"),
        slug=slug,
        title=title,
        body_md=body,
        body_html=body_html,
        excerpt=strip_control_chars(str(data.get("excerpt") or "")).strip()[:400] or None,
        status=status,
        visibility=visibility,
        lang=data.get("lang"),
        is_pinned=bool(data.get("is_pinned", False)),
        is_featured=bool(data.get("is_featured", False)),
        noindex=bool(data.get("noindex", False)),
        reading_time_min=Post.calc_reading_time(body),
        published_at=now if status == PostStatus.PUBLISHED else None,
    )

    async for db in get_db_session():
        # Slug collision check
        from sqlalchemy import select
        exists = (await db.execute(
            select(Post.id).where(Post.slug == slug)
        )).scalar_one_or_none()
        if exists:
            abort(409, f"A post with slug {slug!r} already exists")

        db.add(post)
        await db.commit()
        return jsonify({"status": "created", "slug": slug, "id": post.id, "short_id": post.short_id}), 201


@api_admin_bp.put("/posts/<slug>")
async def admin_api_post_update(slug: str):
    """Admin: Post aktualisieren (§8) – author and above."""
    from arborpress.core.db import get_db_session
    from arborpress.core.markdown import render_md_async
    from arborpress.core.validators import strip_control_chars
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from sqlalchemy import select

    data = await request.get_json(silent=True) or {}

    async for db in get_db_session():
        post = (await db.execute(
            select(Post).where(Post.slug == slug)
        )).scalar_one_or_none()
        if post is None:
            abort(404)

        # Authors may only edit their own posts; editors/admins can edit all
        user_role = session.get("user_role", "viewer")
        if user_role not in ("admin", "editor") and str(post.author_id) != session.get("user_id"):
            abort(403, "You can only edit your own posts")

        if "title" in data:
            post.title = strip_control_chars(str(data["title"])).strip()
        if "body" in data:
            post.body_md   = str(data["body"])
            post.body_html = await render_md_async(post.body_md)
            post.reading_time_min = Post.calc_reading_time(post.body_md)
        if "excerpt" in data:
            post.excerpt = strip_control_chars(str(data["excerpt"] or "")).strip()[:400] or None
        if "status" in data:
            try:
                new_status = PostStatus(data["status"])
            except ValueError:
                abort(400, f"Invalid status: {data['status']!r}")
            if new_status == PostStatus.PUBLISHED and post.status != PostStatus.PUBLISHED:
                from datetime import UTC, datetime
                post.published_at = datetime.now(UTC)
            post.status = new_status
        if "visibility" in data:
            try:
                post.visibility = PostVisibility(data["visibility"])
            except ValueError:
                abort(400, f"Invalid visibility: {data['visibility']!r}")
        for flag in ("is_pinned", "is_featured", "noindex"):
            if flag in data:
                setattr(post, flag, bool(data[flag]))
        if "lang" in data:
            post.lang = data["lang"]

        db.add(post)
        await db.commit()
        return jsonify({"status": "updated", "slug": post.slug})


@api_admin_bp.delete("/posts/<slug>")
async def admin_api_post_delete(slug: str):
    """Admin: Post löschen (§8) – editor or above."""
    require_role("editor")
    _require_stepup("delete_post")

    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post
    from sqlalchemy import select

    async for db in get_db_session():
        post = (await db.execute(
            select(Post).where(Post.slug == slug)
        )).scalar_one_or_none()
        if post is None:
            abort(404)
        await db.delete(post)
        await db.commit()
        return jsonify({"status": "deleted", "slug": slug})


@api_admin_bp.post("/users/<username>/roles")
async def admin_api_user_set_role(username: str):
    """Admin: Benutzerrolle setzen – nur Admins (§2, §8)."""
    require_role("admin")
    _require_stepup("change_roles")

    data = await request.get_json(silent=True) or {}
    new_role = data.get("role", "")

    from arborpress.core.db import get_db_session
    from arborpress.models.user import User, UserRole
    from sqlalchemy import func, select

    try:
        role_enum = UserRole(new_role)
    except ValueError:
        abort(400, f"Invalid role: {new_role!r}. Allowed: {[r.value for r in UserRole]}")

    async for db in get_db_session():
        user = (await db.execute(
            select(User).where(func.lower(User.username) == username.lower())
        )).scalar_one_or_none()
        if user is None:
            abort(404)
        user.role = role_enum
        db.add(user)
        await db.commit()
        return jsonify({"status": "role_updated", "username": username, "role": role_enum.value})


@api_admin_bp.post("/auth/policy")
async def admin_api_set_auth_policy():
    """Admin: Auth-Policy setzen – nur Admins (§2, §8)."""
    require_role("admin")
    _require_stepup("modify_auth_policy")
    data = await request.get_json()
    return jsonify({"status": "policy_updated", "data": data})


@api_admin_bp.post("/plugins/<plugin_id>/enable")
async def admin_api_plugin_enable(plugin_id: str):
    """Admin: Plugin aktivieren – nur Admins (§15, §2)."""
    require_role("admin")
    _require_stepup("install_plugin")
    from arborpress.plugins.registry import get_registry
    reg = get_registry()
    plugin = reg.get(plugin_id)
    if plugin is None:
        abort(404, f"Plugin {plugin_id!r} not found")
    return jsonify({"status": "enabled", "plugin_id": plugin_id})


@api_admin_bp.post("/plugins/<plugin_id>/disable")
async def admin_api_plugin_disable(plugin_id: str):
    """Admin: Plugin deaktivieren – nur Admins (§15)."""
    require_role("admin")
    from arborpress.plugins.registry import get_registry
    reg = get_registry()
    plugin = reg.get(plugin_id)
    if plugin is None:
        abort(404, f"Plugin {plugin_id!r} not found")
    return jsonify({"status": "disabled", "plugin_id": plugin_id})


@api_admin_bp.get("/media")
async def admin_api_media_list():
    """Admin: Medienliste, paginiert (§6 stabile URLs)."""
    from arborpress.core.db import get_db_session
    from arborpress.models.content import Media
    from sqlalchemy import func, select

    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(max(1, int(request.args.get("per_page", 20))), 100)
    except ValueError:
        abort(400, "page and per_page must be integers")

    async for db in get_db_session():
        total = (await db.execute(
            select(func.count()).select_from(Media)
        )).scalar_one()

        items = (await db.execute(
            select(Media)
            .order_by(Media.uploaded_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )).scalars().all()

        cfg = get_settings()
        base = cfg.web.base_url.rstrip("/")

        return jsonify({
            "items": [
                {
                    "id":          m.id,
                    "filename":    m.filename,
                    "mime_type":   m.mime_type,
                    "size_bytes":  m.size_bytes,
                    "width":       m.width,
                    "height":      m.height,
                    "alt_text":    m.alt_text,
                    "url":         f"{base}/media/{m.storage_path}",
                    "uploaded_at": m.uploaded_at.isoformat() if m.uploaded_at else None,
                }
                for m in items
            ],
            "page":  page,
            "per_page": per_page,
            "total": total,
        })


# ---------------------------------------------------------------------------
# Markdown-Preview (§1 Split-View-Editor)
# ---------------------------------------------------------------------------


@api_admin_bp.post("/markdown/preview")
async def admin_api_markdown_preview():
    """Renders Markdown text to HTML for the split-view editor.

    Request:  ``{"text": "..."}``
    Response: ``{"html": "..."}``
    """
    data = await request.get_json(silent=True) or {}
    raw = data.get("text", "")
    return jsonify({"html": await render_md_async(raw)})


# ---------------------------------------------------------------------------
# Media-Upload (§6 /media/{yyyy}/{mm}/{filename}, Pillow-Dimensionen)
# ---------------------------------------------------------------------------


_ALLOWED_UPLOAD_TYPES = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/avif",
        # image/svg+xml deliberately excluded: SVG files can contain embedded
        # JavaScript (<script>, onload handlers, etc.). Even with the
        # strict CSP of this application there is an XSS risk if the browser
        # opens an uploaded SVG file directly as a top-level document.
    }
)
_MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MiB


@api_admin_bp.post("/media/upload")
async def media_upload():
    """Uploads a media file and stores it under {media_dir}/{yyyy}/{mm}/{filename}.

    Form fields:
      ``file``    – multipart/form-data file field
      ``alt_text`` – optional alt text

    Response: ``{"id", "url", "filename", "mime_type", "width", "height", "size_bytes"}``
    """
    files = await request.files
    form = await request.form
    upload = files.get("file")
    if upload is None:
        abort(400, "Kein Datei-Feld 'file' gefunden")

    mime_type: str = upload.content_type or ""
    mime_base = mime_type.split(";")[0].strip().lower()
    if mime_base not in _ALLOWED_UPLOAD_TYPES:
        abort(415, f"Dateityp nicht erlaubt: {mime_base!r}")

    data: bytes = await upload.read(_MAX_UPLOAD_SIZE + 1)
    if len(data) > _MAX_UPLOAD_SIZE:
        abort(413, "File exceeds 20 MiB limit")

    cfg = get_settings()
    now = datetime.now(UTC)
    yyyy = now.year
    mm = now.month

    import mimetypes as _mt
    original_name = os.path.basename(upload.filename or "upload")
    stem, ext = os.path.splitext(original_name)
    if not ext:
        guessed = _mt.guess_extension(mime_base) or ".bin"
        ext = guessed

    file_id = _uuid.uuid4().hex[:16]
    safe_filename = f"{file_id}{ext}"
    dest_dir = cfg.web.media_dir / str(yyyy) / f"{mm:02d}"
    dest_path = dest_dir / safe_filename

    # Dimensions via Pillow (raster images only)
    width: int | None = None
    height: int | None = None
    if mime_base not in ("image/svg+xml",):
        try:
            from io import BytesIO

            from PIL import Image
            img = Image.open(BytesIO(data))
            width, height = img.size
        except Exception:
            log.debug("Pillow konnte Bilddimensionen nicht lesen", exc_info=True)

    # Datei asynchron schreiben
    await asyncio.to_thread(_write_upload, dest_dir, dest_path, data)

    # DB-Eintrag
    storage_path = f"{yyyy}/{mm:02d}/{safe_filename}"
    alt_text = (form.get("alt_text") or "").strip() or None

    from arborpress.core.db import get_db_session
    from arborpress.models.content import Media

    media_obj = Media(
        id=str(_uuid.uuid4()),
        uploader_id=session.get("user_id"),  # type: ignore[attr-defined]
        filename=safe_filename,
        mime_type=mime_base,
        size_bytes=len(data),
        storage_path=storage_path,
        alt_text=alt_text,
        width=width,
        height=height,
    )
    async for db in get_db_session():
        db.add(media_obj)
        await db.commit()

    url = f"{cfg.web.base_url.rstrip('/')}/media/{yyyy}/{mm:02d}/{safe_filename}"
    return jsonify(
        {
            "id": media_obj.id,
            "url": url,
            "filename": safe_filename,
            "mime_type": mime_base,
            "width": width,
            "height": height,
            "size_bytes": len(data),
        }
    ), 201


def _write_upload(dest_dir: Path, dest_path: Path, data: bytes) -> None:
    """Writes file atomically (sync, for asyncio.to_thread)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dest_path)


# ---------------------------------------------------------------------------
# Content-Export API (§8 – Formate: json | md | html | xml)
# ---------------------------------------------------------------------------
#
# GET /api/v1/posts/{slug}/export?format=json       – Editor.js-Dokument (body_json)
# GET /api/v1/posts/{slug}/export?format=md         – Markdown (body_md)
# GET /api/v1/posts/{slug}/export?format=html       – gerendertes HTML (body_html)
# GET /api/v1/posts/{slug}/export?format=xml        – Atom-ähnliche XML-Repräsentation
#
# Öffentlich nur für published+public Posts. Die Admin-Variante (alle Zustände)
# liegt unter /api/v1/admin/posts/{slug}/export.


def _post_export_xml(post) -> str:
    """Erzeugt eine einfache XML-Darstellung eines Posts (kein Atom-Namespace)."""
    import xml.etree.ElementTree as ET  # stdlib, kein Sicherheitsproblem (nur schreiben)
    root   = ET.Element("post")
    fields = {
        "id":          post.short_id,
        "slug":        post.slug,
        "title":       post.title,
        "lang":        post.lang or "",
        "status":      post.status.value,
        "visibility":  post.visibility.value,
        "published_at": post.published_at.isoformat() if post.published_at else "",
        "reading_time_min": str(post.reading_time_min),
        "body_md":     post.body_md or "",
        "body_html":   post.body_html or "",
    }
    for key, val in fields.items():
        el = ET.SubElement(root, key)
        el.text = val
    tags_el = ET.SubElement(root, "tags")
    for tag in (post.tags or []):
        t = ET.SubElement(tags_el, "tag")
        t.set("slug", tag.slug)
        t.text = tag.label
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


@api_v1_bp.get("/posts/<slug>/export")
async def api_post_export(slug: str):
    """Öffentlicher Content-Export eines published+public Posts.

    Query-Parameter:
      format  –  json | md | html | xml   (default: json)
    """
    import json as _json

    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from sqlalchemy import select

    fmt = request.args.get("format", "json").lower().strip()
    if fmt not in ("json", "md", "html", "xml"):
        abort(400, "format must be one of: json, md, html, xml")

    async for db in get_db_session():
        result = await db.execute(
            select(Post).where(
                Post.slug == slug,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
        )
        post = result.scalar_one_or_none()
        if post is None:
            abort(404)

        if fmt == "json":
            payload = post.body_json or {}
            return jsonify({
                "format":  "editorjs",
                "version": "2.x",
                "slug":    post.slug,
                "title":   post.title,
                "body":    payload,
            })

        if fmt == "md":
            from quart import Response
            return Response(
                post.body_md or "",
                mimetype="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{slug}.md"'},
            )

        if fmt == "html":
            from quart import Response
            return Response(
                post.body_html or "",
                mimetype="text/html; charset=utf-8",
            )

        # fmt == "xml"
        from quart import Response
        return Response(
            _post_export_xml(post),
            mimetype="application/xml; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{slug}.xml"'},
        )


@api_admin_bp.get("/posts/<slug>/export")
async def admin_api_post_export(slug: str):
    """Admin-Export: alle Post-Zustände (draft, scheduled, archived …).

    Gleiche format-Parameter wie der öffentliche Endpunkt.
    Zusätzlich: format=full liefert alle Felder als JSON.
    """
    import json as _json

    from arborpress.core.db import get_db_session
    from arborpress.models.content import Post
    from sqlalchemy import select

    _admin_api_guard()
    fmt = request.args.get("format", "full").lower().strip()
    if fmt not in ("json", "md", "html", "xml", "full"):
        abort(400, "format must be one of: json, md, html, xml, full")

    async for db in get_db_session():
        result = await db.execute(select(Post).where(Post.slug == slug))
        post = result.scalar_one_or_none()
        if post is None:
            abort(404)

        if fmt == "full":
            return jsonify({
                "id":          post.id,
                "short_id":    post.short_id,
                "slug":        post.slug,
                "title":       post.title,
                "status":      post.status.value,
                "visibility":  post.visibility.value,
                "lang":        post.lang,
                "published_at": post.published_at.isoformat() if post.published_at else None,
                "created_at":  post.created_at.isoformat() if post.created_at else None,
                "updated_at":  post.updated_at.isoformat() if post.updated_at else None,
                "reading_time_min": post.reading_time_min,
                "tags":        [{"slug": t.slug, "label": t.label} for t in (post.tags or [])],
                "body_md":     post.body_md,
                "body_html":   post.body_html,
                "body_json":   post.body_json,
            })

        if fmt == "json":
            return jsonify({
                "format": "editorjs",
                "slug":   post.slug,
                "title":  post.title,
                "body":   post.body_json or {},
            })

        if fmt == "md":
            from quart import Response
            return Response(
                post.body_md or "",
                mimetype="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{slug}.md"'},
            )

        if fmt == "html":
            from quart import Response
            return Response(post.body_html or "", mimetype="text/html; charset=utf-8")

        # fmt == "xml"
        from quart import Response
        return Response(
            _post_export_xml(post),
            mimetype="application/xml; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{slug}.xml"'},
        )

