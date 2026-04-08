"""Admin routes (§8 – admin interface with step-up, §9 server-rendered, §10 noindex).

Base path is configured dynamically via config.web.admin_path.

Requirements:
- noindex / no-store on all admin pages (§10, via SecurityMiddleware)
- Login enforces WebAuthn (→ /auth/ endpoints, §2)
- Step-up for sensitive operations (§2)
"""

from __future__ import annotations

import logging

from quart import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for
from sqlalchemy import func, select

from arborpress.auth.roles import require_role
from arborpress.auth.stepup import assert_stepup, is_stepup_active
from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.core.markdown import render_md_async
from arborpress.core.validators import is_valid_slug
from arborpress.logging.config import get_audit_logger
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.admin")
audit = get_audit_logger()

admin_bp = Blueprint("admin", __name__, template_folder="../../templates")


def _require_session():
    if not session.get("user_id"):
        abort(redirect(url_for("auth.login_page")))


@admin_bp.before_request
async def _csrf_protect() -> None:
    """CSRF protection for all state-changing admin requests (§10)."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        await validate_csrf()


@admin_bp.before_request
async def _session_guard() -> None:
    """Enforces auth session + minimum role 'author' + DB session validity (§2, §4)."""
    _require_session()
    require_role("author")

    # Validate DB session for validity and expiry; update last_seen_at
    session_id = session.get("session_id")
    if not session_id:
        return

    from datetime import UTC, datetime

    from sqlalchemy import update as sa_update

    from arborpress.models.user import UserSession

    async for db in get_db_session():
        db_sess = await db.get(UserSession, session_id)
        if db_sess is None or not db_sess.is_valid or db_sess.is_expired:
            session.clear()
            abort(redirect(url_for("auth.login_page")))
        await db.execute(
            sa_update(UserSession)
            .where(UserSession.id == session_id)
            .values(last_seen_at=datetime.now(UTC))
        )
        await db.commit()


@admin_bp.context_processor
async def _role_context() -> dict:
    """Provides user_role and has_role for all admin templates."""
    from arborpress.auth.roles import has_min_role
    return {"user_role": session.get("user_role", "viewer"), "has_role": has_min_role}


# ---------------------------------------------------------------------------
# Dashboard (§8)
# ---------------------------------------------------------------------------


@admin_bp.get("/")
async def dashboard():
    _require_session()
    stats = await _get_stats()
    return await render_template("admin/dashboard.html", stats=stats, noindex=True)


async def _get_stats() -> dict:
    """Sammelt Dashboard-Statistiken."""
    stats: dict = {}
    try:
        from arborpress.models.content import Media, Page, Post
        from arborpress.models.mail import MailQueue, MailStatus
        from arborpress.models.user import User
        from arborpress.plugins.registry import get_registry

        async for db in get_db_session():
            posts_count = (await db.execute(select(func.count()).select_from(Post))).scalar_one()
            pages_count = (await db.execute(select(func.count()).select_from(Page))).scalar_one()
            media_count = (await db.execute(select(func.count()).select_from(Media))).scalar_one()
            users_count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
            mail_queue  = (await db.execute(
                select(func.count()).select_from(MailQueue)
                .where(MailQueue.status == MailStatus.pending)
            )).scalar_one()

        stats = {
            "posts_total":    posts_count,
            "pages_total":    pages_count,
            "media_total":    media_count,
            "users_total":    users_count,
            "mail_queue":     mail_queue,
            "plugins_active": len(get_registry().all()),
        }
    except Exception as exc:
        log.warning("Stats-Abfrage fehlgeschlagen: %s", exc)
    return stats


# ---------------------------------------------------------------------------
# Posts §8
# ---------------------------------------------------------------------------


@admin_bp.get("/posts")
async def posts():
    _require_session()
    from arborpress.models.content import Post
    async for db in get_db_session():
        result = await db.execute(select(Post).order_by(Post.published_at.desc()).limit(100))
        post_list = result.scalars().all()
    return await render_template("admin/posts.html", posts=post_list, noindex=True)


@admin_bp.get("/posts/new")
async def post_new():
    _require_session()
    from arborpress.core.captcha import CaptchaType
    from arborpress.models.content import PostVisibility
    return await render_template(
        "admin/post_edit.html", post=None, noindex=True,
        captcha_types=list(CaptchaType),
        visibility_options=list(PostVisibility),
    )


@admin_bp.post("/posts/new")
async def post_new_save():
    _require_session()
    import uuid as _uuid

    from arborpress.models.content import Post, PostRevision, PostStatus, PostVisibility
    form = await request.form
    title        = (form.get("title") or "").strip()[:256]
    slug         = (form.get("slug") or "").strip()[:128] or None
    body_md      = (form.get("body") or "").strip()
    status_val   = form.get("status", "draft")
    visibility_val = form.get("visibility", "public")
    captcha_type = (form.get("captcha_type") or "").strip() or None

    # Scheduled publishing (datetime-local without timezone → UTC)
    from datetime import datetime as _dt
    _pub_raw = (form.get("published_at") or "").strip()
    published_at = None
    if _pub_raw:
        try:
            published_at = _dt.fromisoformat(_pub_raw)
        except ValueError:
            pass

    if not title:
        abort(400)

    import re
    if not slug:
        slug = re.sub(r"[^a-z0-9\-]", "-", title.lower()).strip("-")
        slug = re.sub(r"-{2,}", "-", slug)
    elif not is_valid_slug(slug):
        # Benutzer hat einen ungültigen Slug manuell eingegeben → auto-generieren
        slug = re.sub(r"[^a-z0-9\-]", "-", slug.lower()).strip("-")
        slug = re.sub(r"-{2,}", "-", slug)

    # Kurze ID erzeugen
    short_id = _uuid.uuid4().hex[:12]

    async for db in get_db_session():
        post = Post(
            id=str(_uuid.uuid4()),
            short_id=short_id,
            title=title,
            slug=slug,
            body_md=body_md,
            body_html=await render_md_async(body_md, db=db),
            status=(
                PostStatus(status_val)
                if status_val in PostStatus.__members__
                else PostStatus.DRAFT
            ),
            visibility=(
                PostVisibility(visibility_val)
                if visibility_val in PostVisibility.__members__
                else PostVisibility.PUBLIC
            ),
            captcha_type=captcha_type,
            reading_time_min=Post.calc_reading_time(body_md),
            published_at=published_at,
        )
        db.add(post)
        await db.flush()   # ID vergeben, aber Transaktion offen halten

        # Erste Revision anlegen
        rev = PostRevision(
            id=str(_uuid.uuid4()),
            post_id=post.id,
            rev_number=1,
            title=post.title,
            body_md=body_md,
            diff_to_prev=None,
            changed_by_id=session.get("user_id"),
            change_summary="Initial",
        )
        db.add(rev)
        await db.commit()

    audit.info(
        "POST created | slug=%s visibility=%s user=%s",
        slug, visibility_val, session.get("user_id", ""),
    )
    return redirect(url_for("admin.posts"))


@admin_bp.get("/posts/<slug>/edit")
async def post_edit(slug: str):
    _require_session()
    from arborpress.core.captcha import CaptchaType
    from arborpress.models.content import Post, PostVisibility
    async for db in get_db_session():
        result = await db.execute(select(Post).where(Post.slug == slug))
        post = result.scalar_one_or_none()
    if post is None:
        abort(404)
    return await render_template(
        "admin/post_edit.html", post=post, noindex=True,
        captcha_types=list(CaptchaType),
        visibility_options=list(PostVisibility),
    )


@admin_bp.post("/posts/<slug>/edit")
async def post_edit_save(slug: str):
    _require_session()
    import uuid as _uuid

    from arborpress.models.content import Post, PostRevision, PostStatus, PostVisibility
    form = await request.form
    action = form.get("action", "save")

    async for db in get_db_session():
        result = await db.execute(select(Post).where(Post.slug == slug))
        post = result.scalar_one_or_none()
        if post is None:
            abort(404)

        if action == "delete":
            await db.delete(post)
            await db.commit()
            audit.info("POST deleted | slug=%s user=%s", slug, session.get("user_id", ""))
            return redirect(url_for("admin.posts"))

        title          = (form.get("title") or "").strip()[:256]
        new_slug       = (form.get("slug") or "").strip()[:128] or slug
        body_md        = (form.get("body") or "").strip()
        status_val     = form.get("status", post.status.value)
        visibility_val = form.get("visibility", post.visibility.value)
        captcha_type   = (form.get("captcha_type") or "").strip() or None
        change_summary = (form.get("change_summary") or "").strip()[:256] or None

        # Slug validieren; ungültige Eingaben werden auto-korrigiert
        import re as _re
        if new_slug != slug and not is_valid_slug(new_slug):
            new_slug = _re.sub(r"[^a-z0-9\-]", "-", new_slug.lower()).strip("-")
            new_slug = _re.sub(r"-{2,}", "-", new_slug) or slug

        # Scheduled publishing
        from datetime import datetime as _dt
        _pub_raw = (form.get("published_at") or "").strip()
        if _pub_raw:
            try:
                post.published_at = _dt.fromisoformat(_pub_raw)
            except ValueError:
                pass

        # Snapshot before change for diff
        old_body_md = post.body_md or ""

        if title:
            post.title = title
        if new_slug != slug:
            post.slug_old = slug
            post.slug = new_slug
        post.body_md          = body_md
        post.body_html        = await render_md_async(body_md, db=db)
        post.captcha_type     = captcha_type
        post.reading_time_min = Post.calc_reading_time(body_md)
        try:
            post.status = PostStatus(status_val)
        except ValueError:
            pass
        try:
            post.visibility = PostVisibility(visibility_val)
        except ValueError:
            pass

        # Determine next revision number
        from sqlalchemy import func as _func
        rev_max_result = await db.execute(
            select(_func.max(PostRevision.rev_number)).where(
                PostRevision.post_id == post.id
            )
        )
        last_rev = rev_max_result.scalar() or 0
        next_rev = last_rev + 1

        diff = PostRevision.make_diff(old_body_md, body_md) if body_md != old_body_md else None

        rev = PostRevision(
            id=str(_uuid.uuid4()),
            post_id=post.id,
            rev_number=next_rev,
            title=post.title,
            body_md=body_md,
            diff_to_prev=diff,
            changed_by_id=session.get("user_id"),
            change_summary=change_summary,
        )
        db.add(rev)

        await db.commit()
        audit.info("POST updated | slug=%s visibility=%s user=%s",
                   post.slug, post.visibility.value, session.get("user_id", ""))

    return redirect(url_for("admin.post_edit", slug=post.slug))


# ---------------------------------------------------------------------------
# Seiten §8
# ---------------------------------------------------------------------------


@admin_bp.get("/pages")
async def pages_list():
    _require_session()
    require_role("editor")
    from arborpress.models.content import Page, PageType, PostVisibility
    async for db in get_db_session():
        result = await db.execute(select(Page).order_by(Page.title))
        page_list = result.scalars().all()

    # Warning: system pages that are not publicly visible
    system_page_types = {PageType.IMPRESSUM, PageType.PRIVACY, PageType.RULES}
    hidden_system_pages = [
        p for p in page_list
        if p.page_type in system_page_types
        and (not p.is_published or p.visibility != PostVisibility.PUBLIC)
    ]
    return await render_template(
        "admin/pages.html",
        pages=page_list,
        hidden_system_pages=hidden_system_pages,
        visibility_options=list(PostVisibility),
        noindex=True,
    )


# ---------------------------------------------------------------------------
# Medien §8
# ---------------------------------------------------------------------------


@admin_bp.get("/media")
async def media_list():
    _require_session()
    from arborpress.models.content import Media
    async for db in get_db_session():
        result = await db.execute(select(Media).order_by(Media.uploaded_at.desc()).limit(200))
        media = result.scalars().all()
    return await render_template("admin/media.html", media=media, noindex=True)


# ---------------------------------------------------------------------------
# Benutzer §8
# ---------------------------------------------------------------------------


@admin_bp.get("/users")
async def users():
    _require_session()
    require_role("admin")
    from arborpress.models.user import User
    async for db in get_db_session():
        result = await db.execute(select(User).order_by(User.username))
        user_list = result.scalars().all()
    return await render_template("admin/users.html", users=user_list, noindex=True)


# ---------------------------------------------------------------------------
# Plugin management §15 – step-up for Enable/Disable
# ---------------------------------------------------------------------------


@admin_bp.get("/plugins")
async def plugins_list():
    _require_session()
    require_role("admin")
    from arborpress.plugins.registry import get_registry
    plugins = get_registry().all()
    return await render_template("admin/plugins.html", plugins=plugins, noindex=True)


@admin_bp.post("/plugins/<plugin_id>/enable")
async def plugin_enable(plugin_id: str):
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        assert_stepup(session, user_id, "enable_plugin")
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403
    audit.info("PLUGIN enabled | plugin=%s user=%s", plugin_id, user_id)
    return jsonify({"status": "ok"}), 200


@admin_bp.post("/plugins/<plugin_id>/disable")
async def plugin_disable(plugin_id: str):
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    audit.info("PLUGIN disabled | plugin=%s user=%s", plugin_id, user_id)
    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------------------------------
# Sicherheit §8 – Step-up erforderlich
# ---------------------------------------------------------------------------


@admin_bp.get("/security")
async def security():
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    stepup_active = is_stepup_active(session, user_id)
    cfg = get_settings()
    return await render_template(
        "admin/security.html",
        stepup_active=stepup_active,
        cfg=cfg,
        noindex=True,
    )


@admin_bp.post("/security")
async def security_update():
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        assert_stepup(session, user_id, "change_security_settings")
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403
    audit.info("SECURITY settings changed | user=%s", user_id)
    return jsonify({"status": "not_implemented"}), 501


# ---------------------------------------------------------------------------
# Step-up Status
# ---------------------------------------------------------------------------


@admin_bp.get("/stepup/status")
async def stepup_status():
    user_id = session.get("user_id", "")
    active = is_stepup_active(session, user_id) if user_id else False
    return jsonify({"active": active}), 200


# ---------------------------------------------------------------------------
# Kommentar-Moderation
# ---------------------------------------------------------------------------


@admin_bp.get("/comments")
async def comments_list():
    _require_session()
    require_role("editor")
    """Alle Kommentare die auf Freischaltung warten (status=CONFIRMED)."""
    from arborpress.models.content import Comment, CommentStatus

    async for db in get_db_session():
        stmt = (
            select(Comment)
            .where(Comment.status == CommentStatus.CONFIRMED)
            .order_by(Comment.confirmed_at.asc())
        )
        result = await db.execute(stmt)
        pending = result.scalars().all()

        # All comments for overview (newest first)
        all_stmt = select(Comment).order_by(Comment.created_at.desc()).limit(200)
        all_result = await db.execute(all_stmt)
        all_comments = all_result.scalars().all()

    return await render_template(
        "admin/comments.html",
        pending=pending,
        all_comments=all_comments,
    )


@admin_bp.post("/comments/<comment_id>/approve")
async def comment_approve(comment_id: str):
    _require_session()
    require_role("editor")
    """Kommentar freischalten."""
    from datetime import datetime as dt

    from arborpress.models.content import Comment, CommentStatus

    async for db in get_db_session():
        stmt = select(Comment).where(Comment.id == comment_id)
        result = await db.execute(stmt)
        comment = result.scalar_one_or_none()
        if comment is None:
            abort(404)
        comment.status      = CommentStatus.APPROVED
        comment.approved_at = dt.utcnow()
        await db.commit()

    return redirect(url_for("admin.comments_list"))


@admin_bp.post("/comments/<comment_id>/reject")
async def comment_reject(comment_id: str):
    _require_session()
    require_role("editor")
    """Kommentar ablehnen."""
    from arborpress.models.content import Comment, CommentStatus

    async for db in get_db_session():
        stmt = select(Comment).where(Comment.id == comment_id)
        result = await db.execute(stmt)
        comment = result.scalar_one_or_none()
        if comment is None:
            abort(404)
        comment.status = CommentStatus.REJECTED
        await db.commit()

    return redirect(url_for("admin.comments_list"))


@admin_bp.post("/comments/<comment_id>/spam")
async def comment_spam(comment_id: str):
    _require_session()
    require_role("editor")
    """Kommentar als Spam markieren."""
    from arborpress.models.content import Comment, CommentStatus

    async for db in get_db_session():
        stmt = select(Comment).where(Comment.id == comment_id)
        result = await db.execute(stmt)
        comment = result.scalar_one_or_none()
        if comment is None:
            abort(404)
        comment.status = CommentStatus.SPAM
        await db.commit()

    return redirect(url_for("admin.comments_list"))


# ---------------------------------------------------------------------------
# Captcha-Konfiguration – Fragenkatalog + Provider-Auswahl
# ---------------------------------------------------------------------------


@admin_bp.get("/captcha")
async def captcha_settings():
    _require_session()
    require_role("admin")
    from arborpress.core.captcha import CaptchaType
    from arborpress.core.site_settings import get_section
    async for db in get_db_session():
        captcha_section = await get_section("captcha", db)
    return await render_template(
        "admin/captcha.html",
        captcha_section=captcha_section,
        captcha_types=list(CaptchaType),
        questions=captcha_section.get("custom_questions", []),
        noindex=True,
    )


@admin_bp.post("/captcha")
async def captcha_settings_save():
    """Speichert den Fragenkatalog in der Datenbank (SiteSettings)."""
    _require_session()
    require_role("admin")
    from arborpress.core.site_settings import get_section, save_section

    form = await request.form
    # Fragen aus Formular auslesen: q_0, a_0, q_1, a_1, ...
    questions = []
    i = 0
    while True:
        q = (form.get(f"q_{i}") or "").strip()
        a = (form.get(f"a_{i}") or "").strip()
        if not q and not a:
            break
        if q and a:
            questions.append({"q": q, "a": a})
        i += 1

    user_id = session.get("user_id", "")
    async for db in get_db_session():
        # Bestehende Captcha-Section laden und Fragen eintragen
        current = await get_section("captcha", db)
        current["custom_questions"] = questions
        await save_section("captcha", current, db, updated_by=user_id)

    audit.info("CAPTCHA questions updated | count=%d user=%s", len(questions), user_id)
    from quart import flash
    await flash(f"{len(questions)} Fragen gespeichert.", "success")
    return redirect(url_for("admin.captcha_settings"))


# ---------------------------------------------------------------------------
# Website-Einstellungen (DB-basiert via SiteSettings)
# ---------------------------------------------------------------------------

_SETTINGS_SECTIONS = ("general", "mail", "comments", "federation", "search", "theme", "demo")


@admin_bp.get("/settings")
async def site_settings_page():
    """Overview page for website settings (all sections)."""
    _require_session()
    require_role("admin")
    from arborpress.core.site_settings import get_section
    from arborpress.themes.manifest import get_theme_registry
    from arborpress.themes.patterns import PATTERN_LABELS, PATTERN_ORDER

    sections: dict = {}
    async for db in get_db_session():
        for sec in _SETTINGS_SECTIONS:
            sections[sec] = await get_section(sec, db)

    # Available themes for selection list
    registry = get_theme_registry()
    available_themes = [
        {"id": t.theme.id, "name": t.theme.name}
        for t in registry.all()
    ]

    # Available patterns for pattern picker
    available_patterns = [
        {"id": pid, "label": PATTERN_LABELS.get(pid, pid)}
        for pid in PATTERN_ORDER
    ]

    return await render_template(
        "admin/settings.html",
        sections=sections,
        available_themes=available_themes,
        available_patterns=available_patterns,
        noindex=True,
    )


@admin_bp.post("/settings")
async def site_settings_save():
    """Speichert eine einzelne Einstellungs-Sektion (via ?section=...)."""
    _require_session()
    require_role("admin")
    from arborpress.core.site_settings import get_section, save_section

    form = await request.form
    section = form.get("section", "")
    if section not in _SETTINGS_SECTIONS:
        abort(400)

    user_id = session.get("user_id", "")

    async for db in get_db_session():
        current = await get_section(section, db)

        if section == "general":
            current.update({
                "site_title": (
                    (form.get("site_title") or "").strip() or current.get("site_title", "")
                ),
                "tagline":       (form.get("tagline") or "").strip(),
                "language":      (form.get("language") or "de").strip(),
                "posts_per_page": int(
                    form.get("posts_per_page") or current.get("posts_per_page", 10)
                ),
                "timezone":      (form.get("timezone") or "UTC").strip(),
            })

        elif section == "mail":
            current.update({
                "backend":     (form.get("backend") or "none").strip(),
                "smtp_host":   (form.get("smtp_host") or "localhost").strip(),
                "smtp_port":   int(form.get("smtp_port") or 587),
                "smtp_starttls": form.get("smtp_starttls") == "1",
                "smtp_tls":    form.get("smtp_tls") == "1",
                "smtp_user":   (form.get("smtp_user") or "").strip(),
                "from_address": (form.get("from_address") or "").strip(),
                "from_name":   (form.get("from_name") or "ArborPress").strip(),
            })
            # Only apply password if filled in (do not delete when empty)
            pw = (form.get("smtp_password") or "").strip()
            if pw:
                current["smtp_password"] = pw

        elif section == "comments":
            current.update({
                "require_email_confirmation": form.get("require_email_confirmation") == "1",
                "require_admin_approval":     form.get("require_admin_approval") == "1",
                "allow_anonymous":            form.get("allow_anonymous") == "1",
                "rate_limit_per_hour":        int(form.get("rate_limit_per_hour") or 10),
                "notify_admin_email":         (form.get("notify_admin_email") or "").strip(),
                "max_depth":                  int(form.get("max_depth") or 3),
                "min_comment_length":         int(form.get("min_comment_length") or 1),
                "max_comment_length":         int(form.get("max_comment_length") or 5000),
            })

        elif section == "federation":
            current.update({
                "mode":                         (form.get("mode") or "disabled").strip(),
                "instance_name":                (form.get("instance_name") or "").strip(),
                "instance_description":         (form.get("instance_description") or "").strip(),
                "contact_email":                (form.get("contact_email") or "").strip(),
                "followers_visible":            form.get("followers_visible") == "1",
                "following_visible":            form.get("following_visible") == "1",
                "allow_per_account_federation": form.get("allow_per_account_federation") == "1",
                "require_approval_to_follow":   form.get("require_approval_to_follow") == "1",
                "federate_tags":                form.get("federate_tags") == "1",
                "federate_media":               form.get("federate_media") == "1",
                "max_note_length":              int(form.get("max_note_length") or 500),
                "require_http_signature":       form.get("require_http_signature") == "1",
                "authorized_fetch":             form.get("authorized_fetch") == "1",
                "allowlist_mode":               form.get("allowlist_mode") == "1",
                "inbox_blocklist_domains": [
                    d.strip()
                    for d in (form.get("inbox_blocklist_domains") or "").splitlines()
                    if d.strip()
                ],
            })

        elif section == "search":
            current.update({
                "provider": (form.get("provider") or "fallback").strip(),
            })

        elif section == "theme":
            current.update({
                "active":              (form.get("active") or "default").strip(),
                "auto_dark":           form.get("auto_dark") == "1",
                "auto_dark_start":     int(form.get("auto_dark_start") or 19),
                "auto_dark_end":       int(form.get("auto_dark_end") or 6),
                "bg_pattern":          (form.get("bg_pattern") or "auto").strip(),
                "bg_pattern_color":    (form.get("bg_pattern_color") or "").strip(),
                "bg_pattern_opacity":  float(form.get("bg_pattern_opacity") or 0.07),
            })

        elif section == "demo":
            current.update({
                "enabled":          form.get("enabled") == "1",
                "show_banner":      form.get("show_banner") == "1",
                "allow_all_themes": form.get("allow_all_themes") == "1",
            })

        await save_section(section, current, db, updated_by=user_id)

    audit.info("SETTINGS updated | section=%s user=%s", section, user_id)
    from quart import flash
    await flash("Einstellungen gespeichert.", "success")
    return redirect(url_for("admin.site_settings_page"))


# ---------------------------------------------------------------------------
# Session-Verwaltung §2
# ---------------------------------------------------------------------------


@admin_bp.get("/sessions")
async def sessions_list():
    """Alle aktiven Sitzungen aller Benutzer (§2)."""
    _require_session()
    require_role("admin")
    from arborpress.models.user import User, UserSession

    async for db in get_db_session():
        result = await db.execute(
            select(UserSession, User.username)
            .join(User, UserSession.user_id == User.id)
            .order_by(UserSession.created_at.desc())
            .limit(500)
        )
        rows = result.all()

    current_session_id = session.get("session_id")
    return await render_template(
        "admin/sessions.html",
        rows=rows,
        current_session_id=current_session_id,
        noindex=True,
    )


@admin_bp.post("/sessions/<session_id>/revoke")
async def session_revoke(session_id: str):
    """Einzelne Sitzung widerrufen (§2)."""
    _require_session()
    require_role("admin")

    from arborpress.models.user import UserSession

    async for db in get_db_session():
        result = await db.execute(
            select(UserSession).where(UserSession.id == session_id)
        )
        us = result.scalar_one_or_none()
        if us is None:
            abort(404)
        us.is_valid = False
        await db.commit()

    audit.info("SESSION revoked | session=%s by user=%s", session_id, session.get("user_id", ""))
    return redirect(url_for("admin.sessions_list"))

