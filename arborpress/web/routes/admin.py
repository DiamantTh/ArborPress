"""Admin routes (§8 – admin interface with step-up, §9 server-rendered, §10 noindex).

Base path is configured dynamically via config.web.admin_path.

Requirements:
- noindex / no-store on all admin pages (§10, via SecurityMiddleware)
- Login enforces WebAuthn (→ /auth/ endpoints, §2)
- Step-up for sensitive operations (§2)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from collections.abc import Mapping
from typing import Any, Literal, cast

from jinja2 import TemplateError
from quart import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from quart.typing import ResponseReturnValue
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from arborpress.auth.password_tools import (
    assess_password_strength,
    generate_diceware_passphrase,
    generate_random_password,
    validate_password_policy,
)
from arborpress.auth.roles import require_role
from arborpress.auth.stepup import assert_stepup, is_stepup_active
from arborpress.core.audit import write_audit_event
from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.core.markdown import (
    editorjs_to_html,
    editorjs_to_md,
    html_to_md,
    render_md_async,
    sanitize_html,
)
from arborpress.core.validators import is_valid_slug
from arborpress.logging.config import get_audit_logger
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.admin")
audit = get_audit_logger()

admin_bp = Blueprint("admin", __name__, template_folder="../../templates")


async def _render_users_page(*, breakglass_result: dict[str, str] | None = None):
    from arborpress.models.user import User

    async for db in get_db_session():
        result = await db.execute(select(User).order_by(User.username))
        user_list = result.scalars().all()
    return await render_template(
        "admin/users.html",
        users=user_list,
        breakglass_result=breakglass_result,
        noindex=True,
    )


async def _resolve_body(form, db) -> tuple[str, str, dict | None]:
    """Gibt (body_md, body_html, body_json) für einen Save-Handler zurück.

    Unterstützt drei Modi (gesteuert durch das Hidden-Field _editor_type):
      "markdown" (default / built-in Markdown editor or plain textarea):
          body = Markdown-Text → render_md_async() → HTML
          body_json = None
      "html" (explicit HTML-form transport):
          body = HTML-String → sanitize_html() → body_html
                             → html_to_md()   → body_md (Export/Import)
          body_json = None
      "editorjs" (Editor.js document transport retained for compatibility):
          body = JSON-String (Editor.js-Dokument)
                             → editorjs_to_html() → body_html
                             → editorjs_to_md()   → body_md
          body_json = geparster dict (nativer Transport/Export)

    Der Wert aus _editor_type kommt vom Adapter und wird vom Template als
    Hidden-Field gesetzt bevor der Form-Submit erfolgt.
    """
    import json as _json

    raw = (form.get("body") or "").strip()
    editor_type = (form.get("_editor_type") or "markdown").strip()

    if editor_type == "editorjs":
        try:
            doc = _json.loads(raw)
        except ValueError, TypeError:
            doc = {}
        body_html = editorjs_to_html(doc)
        body_md = editorjs_to_md(doc)
        body_json = doc if doc else None
    elif editor_type == "html":
        body_html = sanitize_html(raw)
        body_md = html_to_md(body_html)
        body_json = None
    else:
        body_md = raw
        body_html = await render_md_async(raw, db=db)
        body_json = None

    return body_md, body_html, body_json


def _require_session() -> None:
    if not session.get("user_id"):
        abort(redirect(url_for("auth.login_page")))
    if session.get("recovery_only"):
        abort(403, "Recovery-only session")


@admin_bp.before_request
async def _csrf_protect() -> None:
    """CSRF protection for all state-changing admin requests (§10)."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        await validate_csrf()


@admin_bp.before_request
async def _session_guard() -> None:
    """Enforces auth session + minimum role 'author' + DB session validity (§2, §4)."""
    _require_session()
    async for db in get_db_session():
        from arborpress.auth.sessions import refresh_session_identity

        user = await refresh_session_identity(db, session)
        if user is None:
            session.clear()
            abort(redirect(url_for("auth.login_page")))
        await db.commit()
        break
    object_scoped_endpoints = {
        "admin.post_edit",
        "admin.post_edit_save",
        "admin.post_authors_update",
        "admin.post_relation_grant",
        "admin.post_relation_revoke",
        "admin.comments_list",
        "admin.comments_transparency",
        "admin.comment_detail",
        "admin.comment_approve",
        "admin.comment_reject",
        "admin.comment_spam",
        "admin.comment_decision",
        "admin.comment_revision_decision",
        "admin.comment_appeal_review",
    }
    if request.endpoint not in object_scoped_endpoints:
        require_role("author")


@admin_bp.context_processor
async def _role_context() -> dict:
    """Provides user_role and has_role for all admin templates."""
    from arborpress.auth.roles import has_min_role

    return {
        "user_role": session.get("user_role", "viewer"),
        "current_user_id": str(session.get("user_id") or ""),
        "has_role": has_min_role,
    }


@admin_bp.errorhandler(TemplateError)
async def _theme_preview_failure(error: TemplateError) -> ResponseReturnValue:
    """Recover to the package Admin theme after any Admin render failure."""
    preview = session.get("_theme_preview")
    if session.get("user_role") != "admin":
        raise error
    if isinstance(preview, dict) and preview.get("type") == "admin":
        session.pop("_theme_preview", None)
    session["_theme_admin_safe_fallback"] = True
    log.warning(
        "Admin template rendering failed for endpoint %s; using the built-in fallback (%s).",
        request.endpoint,
        type(error).__name__,
    )
    from quart import flash

    await flash("Admin-Theme konnte diese Seite nicht rendern; Built-in-Fallback aktiv.", "error")
    try:
        response = await make_response(
            await render_template("admin/dashboard.html", stats={}, noindex=True)
        )
        response.status_code = 500
        return response
    finally:
        session.pop("_theme_admin_safe_fallback", None)


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

        plugin_registry = current_app.extensions.get("arborpress_plugin_registry")

        async for db in get_db_session():
            posts_count = (await db.execute(select(func.count()).select_from(Post))).scalar_one()
            pages_count = (await db.execute(select(func.count()).select_from(Page))).scalar_one()
            media_count = (await db.execute(select(func.count()).select_from(Media))).scalar_one()
            users_count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
            mail_queue = (
                await db.execute(
                    select(func.count())
                    .select_from(MailQueue)
                    .where(MailQueue.status == MailStatus.pending)
                )
            ).scalar_one()

        stats = {
            "posts_total": posts_count,
            "pages_total": pages_count,
            "media_total": media_count,
            "users_total": users_count,
            "mail_queue": mail_queue,
            "plugins_active": sum(
                plugin.runtime_status.value == "running" for plugin in plugin_registry.all()
            )
            if plugin_registry is not None
            else 0,
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
        from arborpress.auth.permissions import can
        from arborpress.models.user import User

        actor = await db.get(User, str(session.get("user_id") or ""))
        if not await can(db, actor, "content.edit"):
            from arborpress.models.authorization import ObjectRelation
            from arborpress.models.content import PostAuthorRelation

            actor_id = str(actor.id) if actor else ""
            assigned_authorship = select(PostAuthorRelation.post_id).where(
                PostAuthorRelation.user_id == actor_id
            )
            assigned_editorship = select(ObjectRelation.object_id).where(
                ObjectRelation.subject_user_id == actor_id,
                ObjectRelation.object_type == "content",
                ObjectRelation.relation == "editor",
            )
            result = await db.execute(
                select(Post)
                .where(
                    Post.id.in_(assigned_authorship)
                    | Post.id.in_(assigned_editorship)
                    | (Post.author_id == actor_id)
                )
                .order_by(Post.updated_at.desc())
                .limit(100)
            )
        else:
            result = await db.execute(select(Post).order_by(Post.updated_at.desc()).limit(100))
        post_list = result.scalars().all()
    return await render_template("admin/posts.html", posts=post_list, noindex=True)


@admin_bp.get("/posts/new")
async def post_new():
    _require_session()
    from arborpress.core.captcha import CaptchaType
    from arborpress.models.content import PostVisibility

    return await render_template(
        "admin/post_edit.html",
        post=None,
        noindex=True,
        captcha_types=list(CaptchaType),
        visibility_options=list(PostVisibility),
    )


@admin_bp.post("/posts/new")
async def post_new_save():
    _require_session()
    import uuid as _uuid

    from arborpress.content.authors import ensure_primary_author
    from arborpress.models.content import Post, PostRevision, PostStatus, PostVisibility

    form = await request.form
    title = (form.get("title") or "").strip()[:256]
    slug = (form.get("slug") or "").strip()[:128] or None
    status_val = form.get("status", "draft")
    if status_val != "draft":
        require_role("editor")
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
        body_md, body_html, body_json = await _resolve_body(form, db)
        post = Post(
            id=str(_uuid.uuid4()),
            short_id=short_id,
            title=title,
            slug=slug,
            body_md=body_md,
            body_html=body_html,
            body_json=body_json,
            status=(
                PostStatus(status_val) if status_val in PostStatus.__members__ else PostStatus.DRAFT
            ),
            visibility=(
                PostVisibility(visibility_val)
                if visibility_val in PostVisibility.__members__
                else PostVisibility.PUBLIC
            ),
            captcha_type=captcha_type,
            reading_time_min=Post.calc_reading_time(body_md, body_json),
            published_at=published_at,
        )
        db.add(post)
        await db.flush()  # ID vergeben, aber Transaktion offen halten
        await ensure_primary_author(
            db,
            post=post,
            user_id=str(session.get("user_id") or ""),
            actor_user_id=str(session.get("user_id") or ""),
        )

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
        slug,
        visibility_val,
        session.get("user_id", ""),
    )
    return redirect(url_for("admin.posts"))


@admin_bp.get("/posts/<slug>/edit")
async def post_edit(slug: str):
    _require_session()
    from arborpress.auth.permissions import can, object_relations_for_post
    from arborpress.content.authors import author_account_choices, post_authors
    from arborpress.core.captcha import CaptchaType
    from arborpress.models.content import Post, PostVisibility
    from arborpress.models.user import User

    async for db in get_db_session():
        result = await db.execute(select(Post).where(Post.slug == slug))
        post = result.scalar_one_or_none()
    if post is None:
        abort(404)
    async for db in get_db_session():
        actor = await db.get(User, str(session.get("user_id") or ""))
        if not await can(db, actor, "content.edit", post):
            abort(403)
        author_rows = await post_authors(db, str(post.id))
        author_choices = await author_account_choices(
            db, include_user_ids=[str(row.user_id) for row in author_rows]
        )
        can_manage_authors = await can(db, actor, "content.manage_authors", post)
        can_manage_relations = await can(db, actor, "object_relations.manage", post)
        relations = (
            await object_relations_for_post(db, str(post.id)) if can_manage_relations else []
        )
    return await render_template(
        "admin/post_edit.html",
        post=post,
        noindex=True,
        captcha_types=list(CaptchaType),
        visibility_options=list(PostVisibility),
        author_rows=author_rows,
        primary_author_id=next(
            (row.user_id for row in author_rows if row.role.value == "primary"),
            post.author_id,
        ),
        coauthor_ids=[row.user_id for row in author_rows if row.role.value == "coauthor"],
        author_choices=author_choices,
        can_manage_authors=can_manage_authors,
        object_relations=relations,
        can_manage_relations=can_manage_relations,
        relation_choices=["editor", "comment_moderator"],
    )


@admin_bp.post("/posts/<slug>/edit")
async def post_edit_save(slug: str):
    _require_session()
    import uuid as _uuid

    from arborpress.auth.permissions import can
    from arborpress.models.content import Post, PostRevision, PostStatus, PostVisibility
    from arborpress.models.user import User

    form = await request.form
    action = form.get("action", "save")

    async for db in get_db_session():
        result = await db.execute(select(Post).where(Post.slug == slug))
        post = result.scalar_one_or_none()
        if post is None:
            abort(404)
        actor = await db.get(User, str(session.get("user_id") or ""))
        if not await can(db, actor, "content.edit", post):
            abort(403)

        if action == "delete":
            require_role("editor")
            await db.delete(post)
            await db.commit()
            audit.info("POST deleted | slug=%s user=%s", slug, session.get("user_id", ""))
            return redirect(url_for("admin.posts"))

        title = (form.get("title") or "").strip()[:256]
        new_slug = (form.get("slug") or "").strip()[:128] or slug
        status_val = form.get("status", post.status.value)
        visibility_val = form.get("visibility", post.visibility.value)
        captcha_type = (form.get("captcha_type") or "").strip() or None
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
                next_published_at = _dt.fromisoformat(_pub_raw)
                if next_published_at != post.published_at:
                    require_role("editor")
                post.published_at = next_published_at
            except ValueError:
                pass

        # Snapshot before change for diff
        old_body_md = post.body_md or ""

        body_md, body_html, body_json = await _resolve_body(form, db)

        if title:
            post.title = title
        if new_slug != slug:
            post.slug_old = slug
            post.slug = new_slug
        post.body_md = body_md
        post.body_html = body_html
        post.body_json = body_json
        post.captcha_type = captcha_type
        post.reading_time_min = Post.calc_reading_time(body_md, body_json)
        try:
            next_status = PostStatus(status_val)
            if next_status != post.status:
                require_role("editor")
            if next_status in {PostStatus.PUBLISHED, PostStatus.SCHEDULED}:
                from arborpress.content.authors import has_primary_author

                if not await has_primary_author(db, str(post.id)):
                    abort(400, "Published content requires exactly one primary author.")
            post.status = next_status
        except ValueError:
            pass
        try:
            next_visibility = PostVisibility(visibility_val)
            if next_visibility != post.visibility:
                require_role("editor")
            post.visibility = next_visibility
        except ValueError:
            pass

        # Determine next revision number
        from sqlalchemy import func as _func

        rev_max_result = await db.execute(
            select(_func.max(PostRevision.rev_number)).where(PostRevision.post_id == post.id)
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
        audit.info(
            "POST updated | slug=%s visibility=%s user=%s",
            post.slug,
            post.visibility.value,
            session.get("user_id", ""),
        )

    return redirect(url_for("admin.post_edit", slug=post.slug))


@admin_bp.post("/posts/<slug>/authors")
async def post_authors_update(slug: str) -> ResponseReturnValue:
    _require_session()
    from quart import flash

    from arborpress.auth.permissions import can
    from arborpress.content.authors import AuthorRelationError, replace_post_authors
    from arborpress.models.content import Post
    from arborpress.models.user import User

    form = await request.form
    submitted_coauthors = form.getlist("coauthor_ids")
    requested_positions: dict[str, int] = {}
    for fallback_position, user_id in enumerate(submitted_coauthors, start=1):
        raw_position = form.get(f"coauthor_position_{user_id}", "")
        try:
            requested_positions[user_id] = int(raw_position) if raw_position else fallback_position
        except ValueError:
            await flash("Coauthor-Reihenfolge muss eine positive Zahl sein.", "error")
            return redirect(url_for("admin.post_edit", slug=slug), code=303)
    ordered_coauthors = sorted(
        submitted_coauthors, key=lambda user_id: (requested_positions[user_id], user_id)
    )
    async for db in get_db_session():
        post = (await db.execute(select(Post).where(Post.slug == slug))).scalar_one_or_none()
        actor = await db.get(User, str(session.get("user_id") or ""))
        if post is None:
            abort(404)
        if actor is None or not await can(db, actor, "content.manage_authors", post):
            abort(403)
        try:
            await replace_post_authors(
                db,
                post_id=str(post.id),
                primary_user_id=form.get("primary_user_id", ""),
                coauthor_user_ids=ordered_coauthors,
                actor_user_id=str(actor.id),
            )
            await db.commit()
        except AuthorRelationError as exc:
            await db.rollback()
            await flash(str(exc), "error")
            return redirect(url_for("admin.post_edit", slug=slug), code=303)
        await flash("Autoren gespeichert.", "success")
    return redirect(url_for("admin.post_edit", slug=slug), code=303)


@admin_bp.post("/posts/<slug>/relations")
async def post_relation_grant(slug: str) -> ResponseReturnValue:
    _require_session()
    from quart import flash

    from arborpress.auth.permissions import grant_object_relation
    from arborpress.models.content import Post
    from arborpress.models.user import User

    form = await request.form
    async for db in get_db_session():
        post = (await db.execute(select(Post).where(Post.slug == slug))).scalar_one_or_none()
        actor = await db.get(User, str(session.get("user_id") or ""))
        if post is None or actor is None:
            abort(404)
        try:
            await grant_object_relation(
                db,
                actor=actor,
                subject_user_id=form.get("subject_user_id", ""),
                post=post,
                relation=form.get("relation", ""),
            )
            await db.commit()
        except ValueError as exc:
            await db.rollback()
            await flash(str(exc), "error")
            return redirect(url_for("admin.post_edit", slug=slug), code=303)
        await flash("Objektberechtigung hinzugefügt.", "success")
    return redirect(url_for("admin.post_edit", slug=slug), code=303)


@admin_bp.post("/posts/<slug>/relations/<relation_id>/revoke")
async def post_relation_revoke(slug: str, relation_id: str) -> ResponseReturnValue:
    _require_session()
    from quart import flash

    from arborpress.auth.permissions import revoke_object_relation
    from arborpress.models.content import Post
    from arborpress.models.user import User

    async for db in get_db_session():
        post = (await db.execute(select(Post).where(Post.slug == slug))).scalar_one_or_none()
        actor = await db.get(User, str(session.get("user_id") or ""))
        if post is None or actor is None:
            abort(404)
        try:
            await revoke_object_relation(db, actor=actor, relation_id=relation_id, post=post)
            await db.commit()
        except ValueError as exc:
            await db.rollback()
            await flash(str(exc), "error")
            return redirect(url_for("admin.post_edit", slug=slug), code=303)
        await flash("Objektberechtigung entfernt.", "success")
    return redirect(url_for("admin.post_edit", slug=slug), code=303)


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
        p
        for p in page_list
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
    return await _render_users_page()


@admin_bp.post("/users/<user_id>/breakglass-password")
async def user_breakglass_password_set(user_id: str):
    _require_session()
    require_role("admin")
    actor_id = session.get("user_id", "")
    try:
        await assert_stepup(session, actor_id, "set_breakglass_password", target=user_id)
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403

    form = await request.form
    mode = (form.get("mode") or "manual").strip().lower()
    manual_password = form.get("password") or ""
    words = int(form.get("words") or 5)
    delimiter = form.get("delimiter") or "-"
    length = int(form.get("length") or 24)

    async for db in get_db_session():
        from arborpress.auth.breakglass import hash_password
        from arborpress.core.site_settings import get_security_settings
        from arborpress.models.user import User

        sec = await get_security_settings(db)
        user = await db.get(User, user_id)
        if user is None:
            abort(404)

        try:
            if mode == "manual":
                password = manual_password
                validate_password_policy(
                    password,
                    min_length=sec["legacy_password_min_length"],
                    max_length=sec["legacy_password_max_length"],
                    min_score=sec["legacy_password_min_score"],
                    user_inputs=[user.username, user.display_name or "", "arborpress", "admin"],
                    # HIBP only for manually entered passwords
                    check_hibp=sec["hibp_enabled"],
                    hibp_max_count=sec["hibp_max_count"],
                    hibp_timeout=sec["hibp_timeout"],
                    hibp_fail_open=sec["hibp_fail_open"],
                )
                generated = False
            elif mode in {"diceware", "xkcd"}:
                password = generate_diceware_passphrase(word_count=words, delimiter=delimiter)
                validate_password_policy(
                    password,
                    min_length=sec["legacy_password_min_length"],
                    max_length=sec["legacy_password_max_length"],
                    min_score=sec["legacy_password_min_score"],
                    user_inputs=[user.username, user.display_name or "", "arborpress", "admin"],
                )
                generated = True
            elif mode == "random":
                password = generate_random_password(length=length)
                validate_password_policy(
                    password,
                    min_length=sec["legacy_password_min_length"],
                    max_length=sec["legacy_password_max_length"],
                    min_score=sec["legacy_password_min_score"],
                    user_inputs=[user.username, user.display_name or "", "arborpress", "admin"],
                )
                generated = True
            else:
                abort(400, "Unknown password mode")
        except ValueError as exc:
            return await _render_users_page(
                breakglass_result={
                    "level": "warning",
                    "message": f"Break-Glass-Passwort fuer {user.username} abgelehnt: {exc}",
                }
            )

        password_was_enabled = bool(user.legacy_password_enabled and user.legacy_password_hash)
        user.legacy_password_hash = hash_password(password)
        user.legacy_password_enabled = True
        db.add(user)
        await write_audit_event(
            event_type="password_changed" if password_was_enabled else "password_enabled",
            outcome="success",
            actor_id=actor_id,
            target_id=str(user.id),
            detail="admin_set_breakglass_password",
            db=db,
        )
        await write_audit_event(
            event_type="breakglass_password_set",
            outcome="success",
            actor_id=actor_id,
            target_id=str(user.id),
            detail="breakglass_password_set",
            db=db,
        )
        await db.commit()

        audit.info(
            "BREAKGLASS password set | actor=%s target=%s mode=%s",
            actor_id,
            user.username,
            mode,
        )
        result = {
            "level": "success",
            "message": f"Break-Glass-Passwort fuer {user.username} gesetzt.",
        }
        if generated:
            result["generated_password"] = password
        return await _render_users_page(breakglass_result=result)


@admin_bp.post("/users/<user_id>/breakglass-password-disable")
async def user_breakglass_password_disable(user_id: str):
    _require_session()
    require_role("admin")
    actor_id = session.get("user_id", "")
    try:
        await assert_stepup(session, actor_id, "disable_password", target=user_id)
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403

    async for db in get_db_session():
        from arborpress.auth.policy import assert_auth_path_remains
        from arborpress.models.user import User

        user = await db.get(User, user_id)
        if user is None:
            abort(404)
        try:
            await assert_auth_path_remains(db, user, exclude_password=True)
        except ValueError:
            await write_audit_event(
                event_type="auth_lockout_prevention",
                outcome="blocked",
                actor_id=actor_id,
                target_id=str(user.id),
                detail="last_auth_path_password_disable",
                db=db,
            )
            await db.commit()
            return await _render_users_page(
                breakglass_result={
                    "level": "warning",
                    "message": (
                        f"Break-Glass fuer {user.username} konnte nicht deaktiviert werden: "
                        "kein WebAuthn- oder MFA-Fallback vorhanden."
                    ),
                }
            )
        user.legacy_password_enabled = False
        user.legacy_password_hash = None
        db.add(user)
        await write_audit_event(
            event_type="password_disabled",
            outcome="success",
            actor_id=actor_id,
            target_id=str(user.id),
            db=db,
        )
        await db.commit()

        audit.info("BREAKGLASS password disabled | actor=%s target=%s", actor_id, user.username)
        return await _render_users_page(
            breakglass_result={
                "level": "success",
                "message": f"Break-Glass-Passwort fuer {user.username} deaktiviert.",
            }
        )


@admin_bp.post("/users/<user_id>/auth-reset")
async def user_authenticator_reset(user_id: str):
    """Authorize a target user's short, self-service credential recovery."""
    _require_session()
    require_role("admin")
    actor_id = str(session.get("user_id") or "")
    try:
        await assert_stepup(
            session,
            actor_id,
            "admin_credential_reset",
            target=user_id,
            required_evidence={"webauthn": "user_verified"},
        )
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403

    form = await request.form
    async for db in get_db_session():
        from sqlalchemy import select, update

        from arborpress.auth.pending import (
            RECOVERY_AUTHORIZATION_PURPOSE,
            create_pending,
            utcnow_naive,
        )
        from arborpress.auth.policy import lock_user_for_credential_change
        from arborpress.auth.sessions import (
            RECOVERY_AUTHORIZATION_TTL_SECONDS,
            RECOVERY_PURPOSE,
            RECOVERY_SESSION_PURPOSE,
            invalidate_normal_auth_pendings,
            invalidate_recovery_session,
        )
        from arborpress.models.user import (
            AuthPending,
            MFADevice,
            MFADeviceType,
            UserSession,
            WebAuthnCredential,
        )

        if actor_id == str(user_id):
            abort(400, "Administrators cannot authorize recovery for their own account")
        user = await lock_user_for_credential_change(db, user_id)
        if user is None:
            abort(404)
        if form.get("confirm_username", "").strip() != user.username:
            abort(400, "Type the target username to confirm authenticator recovery")
        now = utcnow_naive()
        previous_authorizations = (
            (
                await db.execute(
                    select(AuthPending)
                    .where(
                        AuthPending.user_id == str(user.id),
                        AuthPending.purpose == RECOVERY_AUTHORIZATION_PURPOSE,
                        AuthPending.consumed_at.is_(None),
                        AuthPending.expires_at > now,
                    )
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for prior in previous_authorizations:
            try:
                prior_context = json.loads(prior.context or "{}")
            except TypeError, ValueError:
                prior_context = {}
            if isinstance(prior_context, dict):
                prior_context["superseded"] = True
                prior.context = json.dumps(prior_context, separators=(",", ":"))
            prior.consumed_at = now
            await write_audit_event(
                event_type="recovery_authorization_superseded",
                outcome="success",
                actor_id=actor_id,
                target_id=str(user.id),
                detail="purpose=account_credential_recovery",
                db=db,
            )

        # A newly authorized replacement supersedes a ticket already redeemed
        # into a restricted recovery session, including its staged factors.
        active_recovery_sessions = (
            (
                await db.execute(
                    select(AuthPending)
                    .where(
                        AuthPending.user_id == str(user.id),
                        AuthPending.purpose == RECOVERY_SESSION_PURPOSE,
                        AuthPending.consumed_at.is_(None),
                        AuthPending.expires_at > now,
                    )
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for recovery_pending in active_recovery_sessions:
            try:
                recovery_context = json.loads(recovery_pending.context or "{}")
            except TypeError, ValueError:
                recovery_context = {}
            if not isinstance(recovery_context, dict):
                recovery_context = {}
            await invalidate_recovery_session(
                db,
                pending=recovery_pending,
                context=recovery_context,
                reason="superseded",
            )
            await write_audit_event(
                event_type="recovery_aborted",
                outcome="success",
                actor_id=actor_id,
                target_id=str(user.id),
                detail="purpose=account_credential_recovery;reason=superseded",
                db=db,
            )

        await invalidate_normal_auth_pendings(
            db,
            user_id=str(user.id),
            actor_id=actor_id,
            reason="authorization_issued",
        )

        baseline_webauthn = (
            (
                await db.execute(
                    select(WebAuthnCredential.id).where(WebAuthnCredential.user_id == str(user.id))
                )
            )
            .scalars()
            .all()
        )
        baseline_totp = (
            (
                await db.execute(
                    select(MFADevice.id).where(
                        MFADevice.user_id == str(user.id),
                        MFADevice.device_type == MFADeviceType.TOTP,
                    )
                )
            )
            .scalars()
            .all()
        )
        ticket_secret = secrets.token_bytes(32)
        ticket_secret_text = base64.urlsafe_b64encode(ticket_secret).rstrip(b"=").decode("ascii")
        authorization = await create_pending(
            db,
            purpose=RECOVERY_AUTHORIZATION_PURPOSE,
            user_id=str(user.id),
            ttl_seconds=RECOVERY_AUTHORIZATION_TTL_SECONDS,
            challenge=hashlib.sha256(ticket_secret).digest(),
            context={
                "authorized_by": actor_id,
                "purpose": RECOVERY_PURPOSE,
                "baseline_webauthn_ids": [str(value) for value in baseline_webauthn],
                "baseline_totp_ids": [str(value) for value in baseline_totp],
            },
        )
        await db.execute(
            update(UserSession)
            .where(UserSession.user_id == str(user.id), UserSession.is_valid.is_(True))
            .values(is_valid=False)
        )
        await write_audit_event(
            event_type="recovery_authorized",
            outcome="success",
            actor_id=actor_id,
            target_id=str(user.id),
            detail=(
                "purpose=account_credential_recovery;"
                f"ttl_seconds={RECOVERY_AUTHORIZATION_TTL_SECONDS};"
                "method=webauthn_uv"
            ),
            db=db,
        )
        await write_audit_event(
            event_type="recovery_ticket_issued",
            outcome="success",
            actor_id=actor_id,
            target_id=str(user.id),
            detail=(
                f"purpose={RECOVERY_PURPOSE};"
                f"authorization_id={authorization.id};ttl_seconds="
                f"{RECOVERY_AUTHORIZATION_TTL_SECONDS}"
            ),
            db=db,
        )
        await db.commit()
        return await _render_users_page(
            breakglass_result={
                "level": "success",
                "message": (
                    f"Recovery fuer {user.username} ist fuer 24 Stunden autorisiert. "
                    "Alle bestehenden Ziel-Sitzungen wurden beendet. Das Ticket wird "
                    "nur jetzt angezeigt und muss dem Benutzer sicher übermittelt werden."
                ),
                "recovery_ticket": f"{authorization.id}.{ticket_secret_text}",
            }
        )


# ---------------------------------------------------------------------------
# Plugin management §15 – step-up for Enable/Disable
# ---------------------------------------------------------------------------


@admin_bp.get("/plugins")
async def plugins_list():
    _require_session()
    require_role("admin")
    registry = current_app.extensions.get("arborpress_plugin_registry")
    plugins = registry.all() if registry is not None else []
    return await render_template("admin/plugins.html", plugins=plugins, noindex=True)


@admin_bp.post("/plugins/<plugin_id>/enable")
async def plugin_enable(plugin_id: str):
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        await assert_stepup(session, user_id, "enable_plugin", target=plugin_id)
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403
    await validate_csrf()
    registry = current_app.extensions.get("arborpress_plugin_registry")
    record = registry.get(plugin_id) if registry else None
    if record is None:
        abort(404)
    from arborpress.plugins.control import enable_plugin
    from arborpress.plugins.state import PluginStateStore
    from arborpress.runtime.paths import get_runtime_paths

    try:
        await enable_plugin(
            record,
            current_app.extensions["arborpress_plugin_manager"],
            PluginStateStore(get_runtime_paths().data / "plugin-state.toml"),
        )
    except (RuntimeError, ValueError) as exc:
        return jsonify({"error": "plugin_start_failed", "message": str(exc)}), 409
    audit.info("PLUGIN enabled | plugin=%s user=%s", plugin_id, user_id)
    return jsonify({"status": "ok"}), 200


@admin_bp.post("/plugins/<plugin_id>/disable")
async def plugin_disable(plugin_id: str):
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        await assert_stepup(session, user_id, "disable_plugin", target=plugin_id)
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403
    await validate_csrf()
    registry = current_app.extensions.get("arborpress_plugin_registry")
    record = registry.get(plugin_id) if registry else None
    if record is None:
        abort(404)
    from arborpress.plugins.control import disable_plugin
    from arborpress.plugins.state import PluginStateStore
    from arborpress.runtime.paths import get_runtime_paths

    await disable_plugin(
        record,
        current_app.extensions["arborpress_plugin_manager"],
        PluginStateStore(get_runtime_paths().data / "plugin-state.toml"),
    )
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
    stepup_active = await is_stepup_active(session, user_id)
    cfg = get_settings()
    from arborpress.core.site_settings import get_security_settings

    async for db in get_db_session():
        sec = await get_security_settings(db)
        break
    return await render_template(
        "admin/security.html",
        stepup_active=stepup_active,
        cfg=cfg,
        sec=sec,
        noindex=True,
    )


@admin_bp.post("/security")
async def security_update():
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        await assert_stepup(session, user_id, "change_security_settings", target="instance")
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403

    from arborpress.core.site_settings import (
        coerce_security_payload,
        get_security_settings,
        save_section,
    )

    form = await request.form
    raw = {
        "legacy_password_min_length": form.get("legacy_password_min_length"),
        "legacy_password_max_length": form.get("legacy_password_max_length"),
        "legacy_password_min_score": form.get("legacy_password_min_score"),
        "hibp_enabled": form.get("hibp_enabled"),
        "hibp_max_count": form.get("hibp_max_count"),
        "hibp_timeout": form.get("hibp_timeout"),
        "hibp_fail_open": form.get("hibp_fail_open"),
        "totp_credential_limit": form.get("totp_credential_limit"),
        "hotp_credential_limit": form.get("hotp_credential_limit"),
        "plugin_mfa_limit": form.get("plugin_mfa_limit"),
    }
    # Checkboxes that are unchecked do not appear in the form payload at all,
    # so an explicitly missing key means the operator turned the toggle off.
    for bool_key in ("hibp_enabled", "hibp_fail_open"):
        if raw[bool_key] is None:
            raw[bool_key] = False
    # Drop entries the operator did not submit (None) so we keep current value.
    raw = {k: v for k, v in raw.items() if v is not None}

    try:
        cleaned = coerce_security_payload(raw)
    except ValueError as exc:
        async for db in get_db_session():
            sec = await get_security_settings(db)
            break
        return await render_template(
            "admin/security.html",
            stepup_active=True,
            cfg=get_settings(),
            sec=sec,
            error=str(exc),
            noindex=True,
        ), 400

    async for db in get_db_session():
        await save_section("security", cleaned, db, updated_by=user_id)
        sec = await get_security_settings(db)
        await write_audit_event(
            event_type="auth_policy_changed",
            outcome="success",
            actor_id=user_id,
            target_id="instance",
            detail="security_settings:" + ",".join(sorted(cleaned)),
            db=db,
        )
        await db.commit()
        break

    audit.info("SECURITY settings changed | user=%s keys=%s", user_id, ",".join(cleaned))
    return await render_template(
        "admin/security.html",
        stepup_active=True,
        cfg=get_settings(),
        sec=sec,
        saved=True,
        noindex=True,
    )


# ---------------------------------------------------------------------------
# WebAuthn / Passkey settings
# ---------------------------------------------------------------------------


async def _webauthn_view_context(db, **extra):
    """Build the template context for /admin/webauthn (view + post)."""
    from sqlalchemy import func, select

    from arborpress.auth.webauthn import (
        resolve_origin,
        resolve_rp_id,
        resolve_rp_name,
    )
    from arborpress.core.site_settings import get_webauthn_settings
    from arborpress.models.user import WebAuthnCredential

    cfg = get_settings()
    wa_settings = await get_webauthn_settings(db)
    resolved_rp_id = resolve_rp_id(cfg.web.base_url)
    resolved_origin = resolve_origin(cfg.web.base_url)
    resolved_rp_name = await resolve_rp_name(db)

    count_stmt = select(func.count()).select_from(WebAuthnCredential)
    credential_count = (await db.execute(count_stmt)).scalar_one() or 0

    last_known = (wa_settings.get("rp_id_last_known") or "").strip()
    rp_id_blocked = bool(
        last_known
        and last_known != resolved_rp_id
        and credential_count > 0
        and wa_settings.get("rp_id_locked", True)
    )

    ctx = {
        "wa": wa_settings,
        "resolved_rp_id": resolved_rp_id,
        "resolved_origin": resolved_origin,
        "resolved_rp_name": resolved_rp_name,
        "credential_count": credential_count,
        "rp_id_blocked": rp_id_blocked,
        "noindex": True,
    }
    ctx.update(extra)
    return ctx


@admin_bp.get("/webauthn")
async def webauthn_settings_page():
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    stepup_active = await is_stepup_active(session, user_id, "change_webauthn_settings", "instance")

    async for db in get_db_session():
        ctx = await _webauthn_view_context(db, stepup_active=stepup_active)
        break

    return await render_template("admin/webauthn.html", **ctx)


@admin_bp.post("/webauthn")
async def webauthn_update():
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        await assert_stepup(session, user_id, "change_webauthn_settings", target="instance")
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403

    from arborpress.core.site_settings import (
        coerce_webauthn_payload,
        get_webauthn_settings,
        save_section,
    )

    form = await request.form

    # Algorithms come in as alg_<int>=1 checkboxes.
    selected_algs: list[int] = []
    for key in form.keys():
        if key.startswith("alg_"):
            try:
                selected_algs.append(int(key[len("alg_") :]))
            except ValueError:
                continue

    raw: dict = {
        "user_verification": form.get("user_verification"),
        "resident_key": form.get("resident_key"),
        "attestation": form.get("attestation"),
        "authenticator_attachment": form.get("authenticator_attachment"),
        "algorithms": selected_algs or None,
        "timeout_ms": form.get("timeout_ms"),
        "challenge_ttl_seconds": form.get("challenge_ttl_seconds"),
        "webauthn_credential_limit": form.get("webauthn_credential_limit"),
        "conditional_ui_enabled": form.get("conditional_ui_enabled"),
        "signal_api_enabled": form.get("signal_api_enabled"),
        "require_2fa_after_passkey": form.get("require_2fa_after_passkey"),
        "require_mfa_after_sso": form.get("require_mfa_after_sso"),
        "counter_strict": form.get("counter_strict"),
    }
    # Unchecked checkboxes ⇒ explicit False (form omits them).
    for bool_key in (
        "conditional_ui_enabled",
        "signal_api_enabled",
        "require_2fa_after_passkey",
        "require_mfa_after_sso",
        "counter_strict",
    ):
        if raw[bool_key] is None:
            raw[bool_key] = False
    raw = {k: v for k, v in raw.items() if v is not None}

    try:
        cleaned = coerce_webauthn_payload(raw)
    except ValueError as exc:
        async for db in get_db_session():
            ctx = await _webauthn_view_context(db, stepup_active=True, error=str(exc))
            break
        return await render_template("admin/webauthn.html", **ctx), 400

    async for db in get_db_session():
        # Preserve guard fields – never editable through this form.
        existing = await get_webauthn_settings(db)
        cleaned["rp_id_locked"] = existing.get("rp_id_locked", True)
        cleaned["rp_id_last_known"] = existing.get("rp_id_last_known", "")
        await save_section("webauthn", cleaned, db, updated_by=user_id)
        await write_audit_event(
            event_type="auth_policy_changed",
            outcome="success",
            actor_id=user_id,
            target_id="instance",
            detail="webauthn_settings:" + ",".join(sorted(cleaned)),
            db=db,
        )
        await db.commit()
        ctx = await _webauthn_view_context(db, stepup_active=True, saved=True)
        break

    audit.info("WEBAUTHN settings changed | user=%s keys=%s", user_id, ",".join(cleaned))
    return await render_template("admin/webauthn.html", **ctx)


@admin_bp.post("/webauthn/unlock-rp-id")
async def webauthn_unlock_rp_id():
    """Confirm an RP-ID change after the operator typed the new rp.id.

    W3C WebAuthn L3 §5.3 – this irrevocably invalidates every existing
    credential bound to the previous rp.id.
    """
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        await assert_stepup(session, user_id, "unlock_webauthn_rp_id", target="instance")
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403

    from arborpress.auth.webauthn import resolve_rp_id
    from arborpress.core.site_settings import (
        get_webauthn_settings,
        save_section,
    )

    cfg = get_settings()
    resolved = resolve_rp_id(cfg.web.base_url)

    form = await request.form
    confirm = (form.get("confirm_rp_id") or "").strip()
    if confirm != resolved:
        async for db in get_db_session():
            ctx = await _webauthn_view_context(
                db,
                stepup_active=True,
                error=f"Bestätigung stimmt nicht mit aktueller rp.id ({resolved!r}) überein.",
            )
            break
        return await render_template("admin/webauthn.html", **ctx), 400

    async for db in get_db_session():
        wa = await get_webauthn_settings(db)
        old = wa.get("rp_id_last_known", "")
        wa["rp_id_last_known"] = resolved
        wa["rp_id_locked"] = True
        await save_section("webauthn", wa, db, updated_by=user_id)
        await write_audit_event(
            event_type="rp_id_change_confirmed",
            outcome="success",
            actor_id=user_id,
            target_id=resolved,
            detail=f"old={old};new={resolved}",
            db=db,
        )
        await db.commit()
        ctx = await _webauthn_view_context(db, stepup_active=True, saved=True)
        break

    audit.warning(
        "WEBAUTHN rp_id unlocked | user=%s old=%s new=%s",
        user_id,
        old,
        resolved,
    )
    return await render_template("admin/webauthn.html", **ctx)


@admin_bp.post("/webauthn/relock-rp-id")
async def webauthn_relock_rp_id():
    _require_session()
    require_role("admin")
    user_id = session.get("user_id", "")
    try:
        await assert_stepup(session, user_id, "lock_webauthn_rp_id", target="instance")
    except PermissionError:
        return jsonify({"error": "step_up_required"}), 403

    from arborpress.core.site_settings import (
        get_webauthn_settings,
        save_section,
    )

    async for db in get_db_session():
        wa = await get_webauthn_settings(db)
        wa["rp_id_locked"] = True
        await save_section("webauthn", wa, db, updated_by=user_id)
        ctx = await _webauthn_view_context(db, stepup_active=True, saved=True)
        break

    audit.info("WEBAUTHN rp_id relocked | user=%s", user_id)
    return await render_template("admin/webauthn.html", **ctx)


@admin_bp.post("/security/password-tools/generate")
async def security_password_generate():
    require_role("admin")
    payload = await request.get_json() or {}
    mode = str(payload.get("mode") or "random").strip().lower()
    try:
        if mode in {"diceware", "xkcd"}:
            password = generate_diceware_passphrase(
                word_count=int(payload.get("words") or 6),
                delimiter=str(payload.get("delimiter") or "-"),
            )
        elif mode == "random":
            password = generate_random_password(length=int(payload.get("length") or 24))
        else:
            abort(400, "Unknown generator mode")

        from arborpress.core.site_settings import get_security_settings

        async for db in get_db_session():
            sec = await get_security_settings(db)
            break

        assessment = validate_password_policy(
            password,
            min_length=sec["legacy_password_min_length"],
            max_length=sec["legacy_password_max_length"],
            min_score=sec["legacy_password_min_score"],
            user_inputs=[session.get("user_name", ""), "arborpress", "admin"],
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(
        {
            "password": password,
            "assessment": assessment.to_dict(),
            "policy": {
                "min_length": sec["legacy_password_min_length"],
                "max_length": sec["legacy_password_max_length"],
                "min_score": sec["legacy_password_min_score"],
                "accepted": True,
            },
        }
    ), 200


@admin_bp.post("/security/password-tools/evaluate")
async def security_password_evaluate():
    require_role("admin")
    payload = await request.get_json() or {}
    password = str(payload.get("password") or "")
    if not password:
        return jsonify({"error": "Password required"}), 400

    assessment = assess_password_strength(
        password,
        user_inputs=[session.get("user_name", ""), "arborpress", "admin"],
    )
    from arborpress.core.site_settings import get_security_settings

    async for db in get_db_session():
        sec = await get_security_settings(db)
        break

    policy_error = ""
    try:
        validate_password_policy(
            password,
            min_length=sec["legacy_password_min_length"],
            max_length=sec["legacy_password_max_length"],
            min_score=sec["legacy_password_min_score"],
            user_inputs=[session.get("user_name", ""), "arborpress", "admin"],
            # Evaluate endpoint operates on user input; HIBP applies
            check_hibp=sec["hibp_enabled"],
            hibp_max_count=sec["hibp_max_count"],
            hibp_timeout=sec["hibp_timeout"],
            hibp_fail_open=sec["hibp_fail_open"],
        )
        accepted = True
    except ValueError as exc:
        accepted = False
        policy_error = str(exc)

    return jsonify(
        {
            "assessment": assessment.to_dict(),
            "policy": {
                "min_length": sec["legacy_password_min_length"],
                "max_length": sec["legacy_password_max_length"],
                "min_score": sec["legacy_password_min_score"],
                "accepted": accepted,
                "error": policy_error,
            },
        }
    ), 200


# ---------------------------------------------------------------------------
# Step-up Status
# ---------------------------------------------------------------------------


@admin_bp.get("/stepup/status")
async def stepup_status():
    user_id = session.get("user_id", "")
    active = await is_stepup_active(session, user_id) if user_id else False
    return jsonify({"active": active}), 200


# ---------------------------------------------------------------------------
# Kommentar-Moderation
# ---------------------------------------------------------------------------


@admin_bp.get("/comments")
async def comments_list() -> ResponseReturnValue:
    _require_session()
    from datetime import datetime

    from arborpress.auth.permissions import can, content_ids_for_relation
    from arborpress.comments import REASON_CATALOG
    from arborpress.models.authorization import ObjectRelationName
    from arborpress.models.content import (
        Comment,
        CommentModerationAppeal,
        CommentRevision,
        CommentRevisionStatus,
        CommentStatus,
        ModerationDecision,
    )
    from arborpress.models.user import User

    selected = request.args.get("type", "all")
    if selected not in {"all", "comments", "revisions", "appeals"}:
        selected = "all"
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    offset = (page - 1) * 50
    since_raw = (request.args.get("since") or "").strip()
    try:
        since = datetime.fromisoformat(since_raw) if since_raw else None
    except ValueError:
        abort(400)
    async for db in get_db_session():
        actor = await db.get(User, str(session.get("user_id") or ""))
        global_moderator = await can(db, actor, "comments.moderate")
        scoped_content_ids = (
            None
            if global_moderator
            else await content_ids_for_relation(
                db, str(actor.id) if actor else "", ObjectRelationName.COMMENT_MODERATOR
            )
        )
        if scoped_content_ids == []:
            abort(403)
        pending = []
        revisions = []
        appeals: list[
            tuple[CommentModerationAppeal, ModerationDecision, Comment, CommentRevision | None]
        ] = []
        queue_has_more = False
        if selected in {"all", "comments"}:
            pending_result = await db.execute(
                select(Comment)
                .where(
                    Comment.status == CommentStatus.PENDING_MODERATION,
                    *(
                        [Comment.post_id.in_(scoped_content_ids)]
                        if scoped_content_ids is not None
                        else []
                    ),
                    *([Comment.created_at >= since] if since else []),
                )
                .options(selectinload(Comment.post))
                .order_by(Comment.confirmed_at.asc(), Comment.id)
                .offset(offset)
                .limit(51)
            )
            pending = list(pending_result.scalars().all())
            queue_has_more = queue_has_more or len(pending) > 50
            pending = pending[:50]
        if selected in {"all", "revisions"}:
            revision_result = await db.execute(
                select(CommentRevision)
                .join(Comment, Comment.id == CommentRevision.comment_id)
                .where(
                    CommentRevision.status == CommentRevisionStatus.PENDING,
                    Comment.status == CommentStatus.APPROVED,
                    *(
                        [Comment.post_id.in_(scoped_content_ids)]
                        if scoped_content_ids is not None
                        else []
                    ),
                    *([CommentRevision.created_at >= since] if since else []),
                )
                .options(selectinload(CommentRevision.comment).selectinload(Comment.post))
                .order_by(CommentRevision.created_at, CommentRevision.id)
                .offset(offset)
                .limit(51)
            )
            revisions = list(revision_result.scalars().all())
            queue_has_more = queue_has_more or len(revisions) > 50
            revisions = revisions[:50]
        if selected in {"all", "appeals"}:
            appeal_filters = [CommentModerationAppeal.state == "pending"]
            if scoped_content_ids is not None:
                comment_ids = select(Comment.id).where(Comment.post_id.in_(scoped_content_ids))
                revision_ids = (
                    select(CommentRevision.id)
                    .join(Comment, Comment.id == CommentRevision.comment_id)
                    .where(Comment.post_id.in_(scoped_content_ids))
                )
                comment_decision_ids = select(ModerationDecision.id).where(
                    ModerationDecision.target_type == "comment",
                    ModerationDecision.target_id.in_(comment_ids),
                )
                revision_decision_ids = select(ModerationDecision.id).where(
                    ModerationDecision.target_type == "revision",
                    ModerationDecision.target_id.in_(revision_ids),
                )
                appeal_filters.append(
                    CommentModerationAppeal.decision_id.in_(comment_decision_ids)
                    | CommentModerationAppeal.decision_id.in_(revision_decision_ids)
                )
            if since:
                appeal_filters.append(CommentModerationAppeal.created_at >= since)
            appeal_result = await db.execute(
                select(CommentModerationAppeal, ModerationDecision)
                .join(
                    ModerationDecision, ModerationDecision.id == CommentModerationAppeal.decision_id
                )
                .where(*appeal_filters)
                .order_by(CommentModerationAppeal.created_at, CommentModerationAppeal.id)
                .offset(offset)
                .limit(51)
            )
            appeals = []
            for appeal, decision in appeal_result.all():
                if decision.target_type == "comment":
                    target = await db.get(Comment, decision.target_id)
                    target_revision = None
                else:
                    target_revision = await db.get(CommentRevision, decision.target_id)
                    target = (
                        await db.get(Comment, target_revision.comment_id)
                        if target_revision
                        else None
                    )
                if target is not None:
                    appeals.append((appeal, decision, target, target_revision))
            queue_has_more = queue_has_more or len(appeals) > 50
            appeals = appeals[:50]
    return await render_template(
        "admin/comments.html",
        pending=pending,
        revisions=revisions,
        appeals=appeals,
        selected_type=selected,
        page=page,
        has_prev=page > 1,
        has_next=queue_has_more,
        since=since_raw,
        reasons=REASON_CATALOG,
        noindex=True,
    )


@admin_bp.get("/comments/transparency")
async def comments_transparency() -> ResponseReturnValue:
    _require_session()
    from datetime import UTC, date, datetime, timedelta

    from arborpress.auth.permissions import can, content_ids_for_relation
    from arborpress.comments import moderation_transparency
    from arborpress.models.authorization import ObjectRelationName
    from arborpress.models.user import User

    today = datetime.now(UTC).date()
    try:
        end_day = (
            date.fromisoformat(request.args.get("end", "")) if request.args.get("end") else today
        )
        start_day = (
            date.fromisoformat(request.args.get("start", ""))
            if request.args.get("start")
            else end_day - timedelta(days=30)
        )
    except ValueError:
        abort(400)
    if start_day >= end_day or (end_day - start_day).days > 366:
        abort(400)
    async for db in get_db_session():
        actor = await db.get(User, str(session.get("user_id") or ""))
        global_moderator = await can(db, actor, "comments.moderate")
        scoped_content_ids = (
            None
            if global_moderator
            else await content_ids_for_relation(
                db, str(actor.id) if actor else "", ObjectRelationName.COMMENT_MODERATOR
            )
        )
        if scoped_content_ids == []:
            abort(403)
        report = await moderation_transparency(
            db,
            start=datetime.combine(start_day, datetime.min.time()),
            end=datetime.combine(end_day + timedelta(days=1), datetime.min.time()),
            post_ids=scoped_content_ids,
        )
    return await render_template("admin/comment_transparency.html", report=report, noindex=True)


@admin_bp.get("/comments/<comment_id>")
async def comment_detail(comment_id: str) -> ResponseReturnValue:
    _require_session()
    from arborpress.auth.permissions import require_permission
    from arborpress.comments import REASON_CATALOG, decisions_for_target
    from arborpress.models.content import (
        Comment,
        CommentModerationAppeal,
        CommentRevision,
    )
    from arborpress.models.user import User

    async for db in get_db_session():
        comment = await db.get(Comment, comment_id)
        if comment is None:
            abort(404)
        await require_permission(
            db,
            await db.get(User, str(session.get("user_id") or "")),
            "comments.moderate",
            comment.post_id,
        )
        revisions_result = await db.execute(
            select(CommentRevision)
            .where(CommentRevision.comment_id == comment.id)
            .order_by(CommentRevision.revision_number)
        )
        revisions = list(revisions_result.scalars().all())
        decisions = await decisions_for_target(db, target_type="comment", target_ids=[comment.id])
        if revisions:
            decisions += await decisions_for_target(
                db, target_type="revision", target_ids=[revision.id for revision in revisions]
            )
        decisions.sort(key=lambda item: (item.created_at, item.id))
        decision_ids = [item.id for item in decisions]
        appeals_result = await db.execute(
            select(CommentModerationAppeal).where(
                CommentModerationAppeal.decision_id.in_(decision_ids or [""])
            )
        )
        appeals = {str(item.decision_id): item for item in appeals_result.scalars().all()}
    return await render_template(
        "admin/comment_detail.html",
        comment=comment,
        revisions=revisions,
        decisions=decisions,
        appeals=appeals,
        reasons=REASON_CATALOG,
        noindex=True,
    )


async def _apply_comment_decision(
    comment_id: str, outcome: str, default_reason: str
) -> ResponseReturnValue:
    from quart import flash

    from arborpress.auth.permissions import require_permission
    from arborpress.comments import ModerationError, moderate_comment
    from arborpress.models.content import Comment
    from arborpress.models.user import User

    form = await request.form
    actor_id = str(session.get("user_id") or "")
    async for db in get_db_session():
        try:
            comment = await db.get(Comment, comment_id)
            if comment is None:
                abort(404)
            await require_permission(
                db, await db.get(User, actor_id), "comments.moderate", comment.post_id
            )
            decision = await moderate_comment(
                db,
                comment_id=comment_id,
                actor_user_id=actor_id,
                outcome=outcome,
                reason_code=(form.get("reason_code") or default_reason).strip(),
                human_reason=form.get("human_reason"),
                rule_reference=form.get("rule_reference"),
                restriction_type=form.get("restriction_type") or None,
            )
            await db.commit()
        except ModerationError as exc:
            await db.rollback()
            await flash(str(exc), "error")
            return redirect(url_for("admin.comment_detail", comment_id=comment_id), code=303)
        await flash(f"Moderation decision recorded ({decision.reason_code}).", "success")
    return redirect(url_for("admin.comment_detail", comment_id=comment_id), code=303)


@admin_bp.post("/comments/<comment_id>/approve")
async def comment_approve(comment_id: str) -> ResponseReturnValue:
    _require_session()
    return await _apply_comment_decision(comment_id, "approve", "no_violation")


@admin_bp.post("/comments/<comment_id>/reject")
async def comment_reject(comment_id: str) -> ResponseReturnValue:
    _require_session()
    return await _apply_comment_decision(comment_id, "reject", "rule_violation")


@admin_bp.post("/comments/<comment_id>/spam")
async def comment_spam(comment_id: str) -> ResponseReturnValue:
    _require_session()
    return await _apply_comment_decision(comment_id, "spam", "spam")


@admin_bp.post("/comments/<comment_id>/decision")
async def comment_decision(comment_id: str) -> ResponseReturnValue:
    _require_session()
    form = await request.form
    outcome = (form.get("outcome") or "").strip()
    if outcome not in {"approve", "reject", "spam", "delete", "restore"}:
        abort(400)
    return await _apply_comment_decision(comment_id, outcome, "rule_violation")


@admin_bp.post("/comment-revisions/<revision_id>/decision")
async def comment_revision_decision(revision_id: str) -> ResponseReturnValue:
    _require_session()
    from quart import flash

    from arborpress.auth.permissions import require_permission
    from arborpress.comments import ModerationError, moderate_revision
    from arborpress.models.content import Comment, CommentRevision
    from arborpress.models.user import User

    form = await request.form
    outcome = (form.get("outcome") or "").strip()
    if outcome not in {"approve", "reject"}:
        abort(400)
    async for db in get_db_session():
        try:
            revision = await db.get(CommentRevision, revision_id)
            comment = await db.get(Comment, revision.comment_id) if revision else None
            if comment is None:
                abort(404)
            await require_permission(
                db,
                await db.get(User, str(session.get("user_id") or "")),
                "comments.moderate",
                comment.post_id,
            )
            await moderate_revision(
                db,
                revision_id=revision_id,
                actor_user_id=str(session.get("user_id") or ""),
                outcome=cast(Literal["approve", "reject"], outcome),
                reason_code=(form.get("reason_code") or "rule_violation").strip(),
                human_reason=form.get("human_reason"),
                rule_reference=form.get("rule_reference"),
            )
            await db.commit()
        except ModerationError as exc:
            await db.rollback()
            await flash(str(exc), "error")
    return redirect(url_for("admin.comments_list", type="revisions"), code=303)


@admin_bp.post("/comment-appeals/<appeal_id>/review")
async def comment_appeal_review(appeal_id: str) -> ResponseReturnValue:
    _require_session()
    from quart import flash

    from arborpress.auth.permissions import (
        other_comment_reviewer_available,
        require_permission,
    )
    from arborpress.comments import ModerationError, review_comment_appeal
    from arborpress.models.content import (
        Comment,
        CommentModerationAppeal,
        CommentRevision,
        ModerationDecision,
    )
    from arborpress.models.user import User

    form = await request.form
    outcome = (form.get("outcome") or "").strip()
    if outcome not in {"upheld", "overturned"}:
        abort(400)
    async for db in get_db_session():
        try:
            appeal_record = await db.get(CommentModerationAppeal, appeal_id)
            decision_record = (
                await db.get(ModerationDecision, appeal_record.decision_id)
                if appeal_record
                else None
            )
            target_comment = None
            if decision_record and decision_record.target_type == "comment":
                target_comment = await db.get(Comment, decision_record.target_id)
            elif decision_record:
                revision = await db.get(CommentRevision, decision_record.target_id)
                target_comment = await db.get(Comment, revision.comment_id) if revision else None
            if target_comment is None:
                abort(404)
            reviewer_id = str(session.get("user_id") or "")
            await require_permission(
                db, await db.get(User, reviewer_id), "comments.moderate", target_comment.post_id
            )
            other_reviewer = await other_comment_reviewer_available(
                db,
                original_actor_id=decision_record.actor_user_id if decision_record else None,
                post_id=str(target_comment.post_id),
            )
            appeal = await review_comment_appeal(
                db,
                appeal_id=appeal_id,
                reviewer_user_id=reviewer_id,
                outcome=cast(Literal["upheld", "overturned"], outcome),
                reviewer_reason=form.get("reviewer_reason", ""),
                other_reviewer_available=other_reviewer,
            )
            await db.commit()
        except ModerationError as exc:
            await db.rollback()
            await flash(str(exc), "error")
        else:
            await flash(f"Appeal {appeal.state}.", "success")
    return redirect(url_for("admin.comments_list", type="appeals"), code=303)


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

_SETTINGS_SECTIONS = (
    "general",
    "mail",
    "comments",
    "comment_filter",
    "federation",
    "search",
    "theme",
    "demo",
)


_SETTING_SECRET_MARKERS = (
    "password",
    "secret",
    "api_key",
    "private_key",
    "signing_key",
    "token",
)


def _template_safe_settings(value):
    """Copy settings for rendering without exposing stored credentials to themes."""
    if isinstance(value, dict):
        return {
            key: ""
            if any(marker in str(key).lower() for marker in _SETTING_SECRET_MARKERS)
            else _template_safe_settings(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_template_safe_settings(item) for item in value]
    return value


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

    sections = _template_safe_settings(sections)

    # Separate selectors preserve the Public/Admin trust boundary.
    registry = get_theme_registry()
    available_public_themes = [
        {"id": t.theme.id, "name": t.theme.name} for t in registry.all("public")
    ]
    available_admin_themes = [
        {"id": t.theme.id, "name": t.theme.name} for t in registry.all("admin")
    ]

    # Available patterns for pattern picker
    available_patterns = [
        {"id": pid, "label": PATTERN_LABELS.get(pid, pid)} for pid in PATTERN_ORDER
    ]

    return await render_template(
        "admin/settings.html",
        sections=sections,
        available_public_themes=available_public_themes,
        available_admin_themes=available_admin_themes,
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
        current = await (
            _locked_theme_settings(db) if section == "theme" else get_section(section, db)
        )

        if section == "general":
            current.update(
                {
                    "site_title": (
                        (form.get("site_title") or "").strip() or current.get("site_title", "")
                    ),
                    "tagline": (form.get("tagline") or "").strip(),
                    "language": (form.get("language") or "de").strip(),
                    "posts_per_page": int(
                        form.get("posts_per_page") or current.get("posts_per_page", 10)
                    ),
                    "timezone": (form.get("timezone") or "UTC").strip(),
                }
            )

        elif section == "mail":
            current.update(
                {
                    "backend": (form.get("backend") or "none").strip(),
                    "smtp_host": (form.get("smtp_host") or "localhost").strip(),
                    "smtp_port": int(form.get("smtp_port") or 587),
                    "smtp_starttls": form.get("smtp_starttls") == "1",
                    "smtp_tls": form.get("smtp_tls") == "1",
                    "smtp_user": (form.get("smtp_user") or "").strip(),
                    "from_address": (form.get("from_address") or "").strip(),
                    "from_name": (form.get("from_name") or "ArborPress").strip(),
                }
            )
            # Only apply password if filled in (do not delete when empty)
            pw = (form.get("smtp_password") or "").strip()
            if pw:
                current["smtp_password"] = pw

        elif section == "comments":
            current.update(
                {
                    "require_email_confirmation": form.get("require_email_confirmation") == "1",
                    "require_admin_approval": form.get("require_admin_approval") == "1",
                    "moderation_mode": (form.get("moderation_mode") or "").strip(),
                    "first_n_count": max(0, int(form.get("first_n_count") or 1)),
                    "visible_max_depth": max(1, int(form.get("max_depth") or 4)),
                    "edit_window_minutes": max(0, int(form.get("edit_window_minutes") or 30)),
                    "max_user_edits": max(0, int(form.get("max_user_edits") or 2)),
                    "trusted_edit_bypass": form.get("trusted_edit_bypass") == "1",
                    "confirmation_ttl_hours": min(
                        168, max(1, int(form.get("confirmation_ttl_hours") or 24))
                    ),
                    "appeal_window_days": min(
                        90, max(1, int(form.get("appeal_window_days") or 14))
                    ),
                    "allow_anonymous": form.get("allow_anonymous") == "1",
                    "allow_replies": form.get("allow_replies") == "1",
                    "allow_quotes": form.get("allow_quotes") == "1",
                    "rate_limit_per_hour": int(form.get("rate_limit_per_hour") or 10),
                    "notify_admin_email": (form.get("notify_admin_email") or "").strip(),
                    "max_depth": int(form.get("max_depth") or 3),
                    "min_comment_length": int(form.get("min_comment_length") or 1),
                    "max_comment_length": int(form.get("max_comment_length") or 5000),
                }
            )

        elif section == "federation":
            current.update(
                {
                    "mode": (form.get("mode") or "disabled").strip(),
                    "instance_name": (form.get("instance_name") or "").strip(),
                    "instance_description": (form.get("instance_description") or "").strip(),
                    "contact_email": (form.get("contact_email") or "").strip(),
                    "followers_visible": form.get("followers_visible") == "1",
                    "following_visible": form.get("following_visible") == "1",
                    "allow_per_account_federation": form.get("allow_per_account_federation") == "1",
                    "require_approval_to_follow": form.get("require_approval_to_follow") == "1",
                    "federate_tags": form.get("federate_tags") == "1",
                    "federate_media": form.get("federate_media") == "1",
                    "max_note_length": int(form.get("max_note_length") or 500),
                    "require_http_signature": form.get("require_http_signature") == "1",
                    "authorized_fetch": form.get("authorized_fetch") == "1",
                    "allowlist_mode": form.get("allowlist_mode") == "1",
                    "inbox_blocklist_domains": [
                        d.strip()
                        for d in (form.get("inbox_blocklist_domains") or "").splitlines()
                        if d.strip()
                    ],
                }
            )

        elif section == "search":
            current.update(
                {
                    "provider": (form.get("provider") or "fallback").strip(),
                }
            )

        elif section == "theme":
            from arborpress.themes.management import validate_theme
            from arborpress.themes.manifest import get_theme_registry

            registry = get_theme_registry()
            public_id = (form.get("active") or "default").strip()
            admin_id = (form.get("admin_active") or "arbor-admin").strip()
            public_theme = registry.get(public_id)
            admin_theme = registry.get(admin_id)
            if public_theme is None or public_theme.type != "public":
                abort(400, description="Selected public theme is unavailable or invalid.")
            if admin_theme is None or admin_theme.type != "admin":
                abort(400, description="Selected admin theme is unavailable or invalid.")
            for selected_theme in (public_theme, admin_theme):
                if any(
                    issue["level"] == "error"
                    for issue in validate_theme(registry, selected_theme.id)
                ):
                    abort(400, description=f"Theme {selected_theme.id!r} failed validation.")
            current.update(
                {
                    "active": public_id,
                    "admin_active": admin_id,
                    "auto_dark": form.get("auto_dark") == "1",
                    "auto_dark_start": int(form.get("auto_dark_start") or 19),
                    "auto_dark_end": int(form.get("auto_dark_end") or 6),
                    "bg_pattern": (form.get("bg_pattern") or "auto").strip(),
                    "bg_pattern_color": (form.get("bg_pattern_color") or "").strip(),
                    "bg_pattern_opacity": float(form.get("bg_pattern_opacity") or 0.07),
                }
            )

        elif section == "comment_filter":
            current.update(
                {
                    "ip_whitelist": (form.get("ip_whitelist") or ""),
                    "ip_blocklist": (form.get("ip_blocklist") or ""),
                    "country_whitelist": (form.get("country_whitelist") or "").strip().upper(),
                    "country_blocklist": (form.get("country_blocklist") or "").strip().upper(),
                    "country_block_unknown": form.get("country_block_unknown") == "1",
                    "geoip_db_path": (form.get("geoip_db_path") or "").strip(),
                    "rbl_enabled": form.get("rbl_enabled") == "1",
                    "rbl_zones": (form.get("rbl_zones") or ""),
                    "rbl_action": (form.get("rbl_action") or "block").strip(),
                }
            )

        elif section == "demo":
            current.update(
                {
                    "enabled": form.get("enabled") == "1",
                    "show_banner": form.get("show_banner") == "1",
                    "allow_all_themes": form.get("allow_all_themes") == "1",
                }
            )

        await save_section(section, current, db, updated_by=user_id)

    audit.info("SETTINGS updated | section=%s user=%s", section, user_id)
    from quart import flash

    await flash("Einstellungen gespeichert.", "success")
    return redirect(url_for("admin.site_settings_page"))


# ---------------------------------------------------------------------------
# Theme management (§5 – server-rendered; file edits always create local children)
# ---------------------------------------------------------------------------


async def _theme_settings() -> dict[str, Any]:
    from arborpress.core.site_settings import get_section_uncached

    async for db in get_db_session():
        return await get_section_uncached("theme", db)
    return {}


async def _locked_theme_settings(db: AsyncSession) -> dict[str, Any]:
    """Read the persisted theme JSON under a row lock for optimistic edits."""
    from sqlalchemy import select

    from arborpress.core.site_settings import get_defaults
    from arborpress.models.settings import SiteSetting

    row = (
        await db.execute(select(SiteSetting).where(SiteSetting.key == "theme").with_for_update())
    ).scalar_one_or_none()
    merged = get_defaults("theme")
    if row is not None:
        try:
            stored = json.loads(row.value)
        except TypeError, ValueError:
            stored = {}
        if isinstance(stored, dict):
            merged.update(stored)
    return merged


async def _theme_audit(event: str, theme_id: str, detail: str) -> None:
    user_id = str(session.get("user_id", ""))
    async for db in get_db_session():
        await write_audit_event(
            event_type=f"theme_{event}",
            outcome="success",
            actor_id=user_id,
            actor_name=str(session.get("user_name", ""))[:32] or None,
            target_id=theme_id[:36],
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            detail=detail[:500],
            db=db,
        )
        await db.commit()
        break


def _theme_effective_ids(registry: Any, settings: Mapping[str, Any]) -> dict[str, str]:
    return {
        "public": registry.get_or_default(str(settings.get("active", "default")), "public").id,
        "admin": registry.get_or_default(
            str(settings.get("admin_active", "arbor-admin")), "admin"
        ).id,
    }


def _theme_fallback_reasons(registry: Any, settings: Mapping[str, Any]) -> dict[str, str | None]:
    reasons: dict[str, str | None] = {}
    for kind, key, default_id in (
        ("public", "active", "default"),
        ("admin", "admin_active", "arbor-admin"),
    ):
        configured = str(settings.get(key, default_id))
        record = registry.record(configured)
        if record is not None and record.status == "valid" and record.type == kind:
            reasons[kind] = None
        elif record is None:
            reasons[kind] = "Theme ID is not installed."
        elif record.type != kind:
            reasons[kind] = f"Theme has type {record.type or 'unknown'}, expected {kind}."
        else:
            reasons[kind] = "; ".join(record.diagnostics) or record.status
    return reasons


@admin_bp.get("/themes")
async def themes_overview() -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from arborpress.themes.management import parent_children
    from arborpress.themes.manifest import get_theme_registry

    registry = get_theme_registry()
    settings = await _theme_settings()
    configured = {
        "public": str(settings.get("active", "default")),
        "admin": str(settings.get("admin_active", "arbor-admin")),
    }
    effective = _theme_effective_ids(registry, settings)
    fallback_reasons = _theme_fallback_reasons(registry, settings)
    trusted = settings.get("trusted_themes", [])
    trusted_ids = set(trusted) if isinstance(trusted, list) else set()
    rows: dict[str, list[dict[str, Any]]] = {"public": [], "admin": []}
    invalid_themes: list[dict[str, Any]] = []
    for record in registry.records():
        if record.type not in rows:
            if record.status != "valid":
                invalid_themes.append(
                    {
                        "id": record.id,
                        "name": record.name,
                        "source": record.source,
                        "status": record.status,
                        "diagnostics": record.diagnostics,
                    }
                )
            continue
        theme = record.manifest
        kind = record.type
        rows[kind].append(
            {
                "id": record.id,
                "name": theme.name if theme else record.name,
                "version": record.version,
                "author": theme.author if theme else "",
                "license": theme.license if theme else "",
                "requires": theme.requires_arborpress if theme else "",
                "tested_with": theme.tested_with if theme else None,
                "source": record.source,
                "derived": bool(theme and theme.derived),
                "parent": theme.parent if theme else None,
                "status": record.status,
                "diagnostics": record.diagnostics,
                "trusted": record.source == "builtin" or record.id in trusted_ids,
                "trust_source": "package" if record.source == "builtin" else "local",
                "configured": record.id == configured[kind],
                "effective": record.id == effective[kind],
                "children": parent_children(registry, record.id) if theme else [],
            }
        )
    return await render_template(
        "admin/themes.html",
        public_themes=rows["public"],
        admin_themes=rows["admin"],
        configured=configured,
        effective=effective,
        fallback_reasons=fallback_reasons,
        invalid_themes=invalid_themes,
        preview=session.get("_theme_preview"),
        noindex=True,
    )


@admin_bp.get("/themes/<theme_id>")
async def theme_detail(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from arborpress.themes.management import (
        ThemeManagementError,
        derived_manifest_source,
        editable_styles,
        editable_templates,
        list_revisions,
        merged_option_definitions,
        option_values_hash,
        parent_children,
        resolve_option_values,
        validate_theme,
    )
    from arborpress.themes.manifest import get_theme_registry

    registry = get_theme_registry()
    record = registry.record(theme_id)
    if record is None:
        abort(404)
    settings = await _theme_settings()
    manifest = record.manifest
    definitions = {}
    values = {}
    manifest_text = ""
    management_error = None
    if manifest is not None:
        try:
            definitions = merged_option_definitions(registry, theme_id)
            options = settings.get("option_values", {})
            theme_values = options.get(theme_id, {}) if isinstance(options, dict) else {}
            if not isinstance(theme_values, dict):
                theme_values = {}
            values = resolve_option_values(
                registry,
                theme_id,
                options if isinstance(options, dict) else {},
            )
            manifest_text, _ = derived_manifest_source(registry, theme_id)
        except ThemeManagementError as exc:
            management_error = str(exc)
    trusted = settings.get("trusted_themes", [])
    return await render_template(
        "admin/theme_detail.html",
        record=record,
        theme=manifest,
        trusted=theme_id in trusted if isinstance(trusted, list) else False,
        configured=theme_id in (settings.get("active"), settings.get("admin_active")),
        options=[
            {"key": key, "definition": definition, "value": values.get(key)}
            for key, definition in definitions.items()
        ],
        option_hash=option_values_hash(theme_values if manifest is not None else {}),
        templates=editable_templates(manifest) if manifest else [],
        styles=editable_styles(registry, theme_id) if manifest else [],
        children=parent_children(registry, theme_id),
        validation=validate_theme(registry, theme_id),
        revisions=list_revisions(theme_id),
        manifest_text=manifest_text,
        management_error=management_error,
        noindex=True,
    )


@admin_bp.post("/themes/<theme_id>/activate")
async def theme_activate(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.core.site_settings import save_section
    from arborpress.themes.management import validate_theme
    from arborpress.themes.manifest import get_theme_registry

    form = await request.form
    theme_type = form.get("theme_type", "")
    if theme_type not in ("public", "admin"):
        abort(400)
    registry = get_theme_registry()
    theme = registry.get(theme_id)
    if theme is None or theme.type != theme_type:
        await flash("Theme ist ungültig, inkompatibel oder vom falschen Typ.", "error")
        return redirect(url_for("admin.themes_overview"))
    if any(issue["level"] == "error" for issue in validate_theme(registry, theme_id)):
        await flash(
            "Theme-Validierung fehlgeschlagen; die bisherige Auswahl bleibt aktiv.", "error"
        )
        return redirect(url_for("admin.theme_detail", theme_id=theme_id))
    async for db in get_db_session():
        current = await _locked_theme_settings(db)
        key = "active" if theme_type == "public" else "admin_active"
        current[key] = theme_id
        await save_section("theme", current, db, updated_by=str(session.get("user_id", "")))
    await _theme_audit("activated", theme_id, f"type={theme_type}")
    await flash(f"{theme.name} wurde als {theme_type} Theme aktiviert.", "success")
    return redirect(url_for("admin.themes_overview"))


@admin_bp.post("/themes/<theme_id>/trust")
async def theme_trust(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.core.site_settings import save_section
    from arborpress.themes.manifest import get_theme_registry

    theme = get_theme_registry().get(theme_id)
    if theme is None or theme.source != "instance":
        abort(400, description="Only a valid instance theme can receive local trust.")
    actor_id = str(session.get("user_id", ""))
    await assert_stepup(cast(dict[str, Any], session), actor_id, "trust_theme", target=theme_id)
    grant = (await request.form).get("grant") == "1"
    async for db in get_db_session():
        current = await _locked_theme_settings(db)
        trusted = current.get("trusted_themes", [])
        trusted_ids = set(trusted) if isinstance(trusted, list) else set()
        if grant:
            trusted_ids.add(theme_id)
        else:
            trusted_ids.discard(theme_id)
        current["trusted_themes"] = sorted(trusted_ids)
        await save_section("theme", current, db, updated_by=actor_id)
    event = "trust_granted" if grant else "trust_revoked"
    await _theme_audit(event, theme_id, "local administrator decision")
    await flash("Lokaler Theme-Trust aktualisiert.", "success")
    return redirect(url_for("admin.theme_detail", theme_id=theme_id))


@admin_bp.post("/themes/<theme_id>/options")
async def theme_options_save(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.core.site_settings import save_section
    from arborpress.themes.management import (
        ThemeManagementError,
        option_values_hash,
        record_change_revision,
        validate_option_values,
    )
    from arborpress.themes.manifest import get_theme_registry

    registry = get_theme_registry()
    theme = registry.get(theme_id)
    if theme is None:
        abort(404)
    form = await request.form
    submitted = {
        key.removeprefix("option_"): value
        for key, value in form.items()
        if key.startswith("option_")
    }
    try:
        values = validate_option_values(registry, theme_id, submitted)
    except ThemeManagementError as exc:
        await flash(str(exc), "error")
        return redirect(url_for("admin.theme_detail", theme_id=theme_id))
    actor_id = str(session.get("user_id", ""))
    async for db in get_db_session():
        current = await _locked_theme_settings(db)
        all_values = current.get("option_values", {})
        if not isinstance(all_values, dict):
            all_values = {}
        previous = all_values.get(theme_id, {})
        if option_values_hash(previous if isinstance(previous, dict) else {}) != str(
            form.get("expected_hash", "")
        ):
            abort(409, description="Theme options changed while this form was open; reload first.")
        all_values[theme_id] = values
        current["option_values"] = all_values
        await save_section("theme", current, db, updated_by=actor_id)
    record_change_revision(
        theme_id=theme_id,
        kind="options",
        relative="theme.options",
        before=json.dumps(previous, ensure_ascii=False, sort_keys=True),
        after=json.dumps(values, ensure_ascii=False, sort_keys=True),
        actor_id=actor_id,
        actor_name=str(session.get("user_name", "")),
    )
    await _theme_audit("option_changed", theme_id, "validated option values updated")
    await flash("Themeoptionen gespeichert.", "success")
    return redirect(url_for("admin.theme_detail", theme_id=theme_id))


@admin_bp.post("/themes/<theme_id>/options/reset")
async def theme_options_reset(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.core.site_settings import save_section
    from arborpress.themes.management import option_values_hash, record_change_revision
    from arborpress.themes.manifest import get_theme_registry

    if get_theme_registry().get(theme_id) is None:
        abort(404)
    form = await request.form
    actor_id = str(session.get("user_id", ""))
    previous: dict[str, Any] = {}
    async for db in get_db_session():
        current = await _locked_theme_settings(db)
        all_values = current.get("option_values", {})
        if not isinstance(all_values, dict):
            all_values = {}
        raw_previous = all_values.get(theme_id, {})
        previous = raw_previous if isinstance(raw_previous, dict) else {}
        if option_values_hash(previous) != str(form.get("expected_hash", "")):
            abort(409, description="Theme options changed while this form was open; reload first.")
        all_values.pop(theme_id, None)
        current["option_values"] = all_values
        await save_section("theme", current, db, updated_by=actor_id)
    record_change_revision(
        theme_id=theme_id,
        kind="options-reset",
        relative="theme.options",
        before=json.dumps(previous, ensure_ascii=False, sort_keys=True),
        after="{}",
        actor_id=actor_id,
        actor_name=str(session.get("user_name", "")),
    )
    await _theme_audit("option_reset", theme_id, "local option values removed")
    await flash("Lokale Themeoptionen wurden zurückgesetzt.", "success")
    return redirect(url_for("admin.theme_detail", theme_id=theme_id))


@admin_bp.post("/themes/<theme_id>/preview")
async def theme_preview(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from time import time

    from quart import flash

    from arborpress.themes.management import (
        ThemeManagementError,
        theme_preview_fingerprint,
        validate_theme,
    )
    from arborpress.themes.manifest import get_theme_registry

    theme = get_theme_registry().get(theme_id)
    if theme is None:
        abort(400)
    try:
        registry = get_theme_registry()
        if any(issue["level"] == "error" for issue in validate_theme(registry, theme_id)):
            await flash("Theme-Validierung fehlgeschlagen; Vorschau nicht gestartet.", "error")
            return redirect(url_for("admin.theme_detail", theme_id=theme_id))
        fingerprint = theme_preview_fingerprint(registry, theme_id)
    except ThemeManagementError:
        abort(409, description="Theme changed or failed validation before preview.")
    session["_theme_preview"] = {
        "theme_id": theme_id,
        "type": theme.type,
        "expires": time() + 1800,
        "fingerprint": fingerprint,
    }
    await flash("Vorschau ist 30 Minuten nur in dieser Administratorsitzung aktiv.", "info")
    target = "public.index" if theme.type == "public" else "admin.dashboard"
    return redirect(url_for(target))


@admin_bp.post("/themes/preview/stop")
async def theme_preview_stop() -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    session.pop("_theme_preview", None)
    await flash("Themevorschau beendet.", "success")
    return redirect(url_for("admin.themes_overview"))


@admin_bp.get("/themes/<theme_id>/edit/<kind>/<path:relative>")
async def theme_file_edit(theme_id: str, kind: str, relative: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from arborpress.themes.management import (
        ThemeManagementError,
        load_editable_file,
        local_derived_theme,
    )
    from arborpress.themes.manifest import get_theme_registry

    if kind not in ("template", "css"):
        abort(404)
    editable_kind = cast(Literal["template", "css"], kind)
    try:
        content, expected_hash = load_editable_file(
            get_theme_registry(), theme_id, relative, editable_kind
        )
    except ThemeManagementError:
        abort(404)
    derived_theme = local_derived_theme(get_theme_registry(), theme_id)
    has_local_override = False
    if derived_theme is not None:
        has_local_override = relative in (
            derived_theme.templates if kind == "template" else derived_theme.assets.css
        )
    derived_manifest = None
    if derived_theme is not None:
        try:
            derived_manifest = (derived_theme.theme_dir / "theme.toml").read_text(encoding="utf-8")
        except OSError:
            derived_manifest = None
    return await render_template(
        "admin/theme_editor.html",
        theme_id=theme_id,
        kind=kind,
        relative=relative,
        content=content,
        expected_hash=expected_hash,
        derived_theme=derived_theme.id if derived_theme else None,
        has_local_override=has_local_override,
        derived_manifest=derived_manifest,
        noindex=True,
    )


@admin_bp.post("/themes/<theme_id>/edit/<kind>/<path:relative>")
async def theme_file_save(theme_id: str, kind: str, relative: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.themes.management import (
        ThemeConflictError,
        ThemeManagementError,
        local_derived_theme,
        save_override,
    )
    from arborpress.themes.manifest import get_theme_registry

    if kind not in ("template", "css"):
        abort(404)
    editable_kind = cast(Literal["template", "css"], kind)
    registry = get_theme_registry()
    source_theme = registry.get(theme_id)
    had_derived = local_derived_theme(registry, theme_id) is not None
    form = await request.form
    try:
        derived, revision = save_override(
            registry,
            theme_id,
            relative,
            editable_kind,
            str(form.get("content", "")),
            str(form.get("expected_hash", "")),
            actor_id=str(session.get("user_id", "")),
            actor_name=str(session.get("user_name", "")),
        )
    except ThemeConflictError as exc:
        abort(409, description=str(exc))
    except ThemeManagementError as exc:
        await flash(str(exc), "error")
        return redirect(url_for("admin.theme_detail", theme_id=theme_id))
    if source_theme is not None and not source_theme.derived and not had_derived:
        await _theme_audit("derived_created", derived.id, f"parent={source_theme.id}")
    await _theme_audit("override_created", derived.id, f"{kind}:{relative}; revision={revision}")
    await flash("Lokaler Override gespeichert; das Originaltheme blieb unverändert.", "success")
    return redirect(
        url_for("admin.theme_file_edit", theme_id=derived.id, kind=kind, relative=relative)
    )


@admin_bp.post("/themes/<theme_id>/override/reset/<kind>/<path:relative>")
async def theme_override_reset(theme_id: str, kind: str, relative: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.themes.management import ThemeManagementError, reset_override
    from arborpress.themes.manifest import get_theme_registry

    if kind not in ("template", "css"):
        abort(404)
    editable_kind = cast(Literal["template", "css"], kind)
    form = await request.form
    try:
        revision = reset_override(
            get_theme_registry(),
            theme_id,
            relative,
            editable_kind,
            str(form.get("expected_hash", "")),
            actor_id=str(session.get("user_id", "")),
            actor_name=str(session.get("user_name", "")),
        )
    except ThemeManagementError as exc:
        abort(409, description=str(exc))
    await _theme_audit("override_reset", theme_id, f"{kind}:{relative}; revision={revision}")
    await flash("Lokaler Override entfernt; die Parentdatei ist wieder aktiv.", "success")
    return redirect(url_for("admin.theme_detail", theme_id=theme_id))


@admin_bp.get("/themes/<theme_id>/manifest")
async def theme_manifest_edit(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from arborpress.themes.management import ThemeManagementError, derived_manifest_source
    from arborpress.themes.manifest import get_theme_registry

    try:
        content, expected_hash = derived_manifest_source(get_theme_registry(), theme_id)
    except ThemeManagementError:
        abort(404)
    return await render_template(
        "admin/theme_editor.html",
        theme_id=theme_id,
        kind="manifest",
        relative="theme.toml",
        content=content,
        expected_hash=expected_hash,
        derived_theme=None,
        derived_manifest=None,
        noindex=True,
    )


@admin_bp.post("/themes/<theme_id>/manifest")
async def theme_manifest_save(theme_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.themes.management import (
        ThemeConflictError,
        ThemeManagementError,
        local_derived_theme,
        write_manifest_override,
    )
    from arborpress.themes.manifest import get_theme_registry

    registry = get_theme_registry()
    source_theme = registry.get(theme_id)
    had_derived = local_derived_theme(registry, theme_id) is not None
    form = await request.form
    try:
        derived, revision = write_manifest_override(
            registry,
            theme_id,
            str(form.get("content", "")),
            str(form.get("expected_hash", "")),
            actor_id=str(session.get("user_id", "")),
            actor_name=str(session.get("user_name", "")),
        )
    except ThemeConflictError as exc:
        abort(409, description=str(exc))
    except ThemeManagementError as exc:
        await flash(str(exc), "error")
        return redirect(url_for("admin.theme_manifest_edit", theme_id=theme_id))
    if source_theme is not None and not source_theme.derived and not had_derived:
        await _theme_audit("derived_created", derived.id, f"parent={source_theme.id}")
    await _theme_audit("manifest_changed", derived.id, f"revision={revision}")
    await flash("Derived Theme Manifest validiert und gespeichert.", "success")
    return redirect(url_for("admin.theme_detail", theme_id=derived.id))


@admin_bp.post("/themes/<theme_id>/revisions/<revision_id>/restore")
async def theme_revision_restore(theme_id: str, revision_id: str) -> ResponseReturnValue:
    _require_session()
    require_role("admin")
    from quart import flash

    from arborpress.themes.management import (
        ThemeManagementError,
        derived_manifest_source,
        list_revisions,
        load_editable_file,
        record_change_revision,
        save_override,
        validate_option_values,
        write_manifest_override,
    )
    from arborpress.themes.manifest import get_theme_registry

    revision = next(
        (item for item in list_revisions(theme_id) if item.get("id") == revision_id), None
    )
    if revision is None:
        abort(404)
    registry = get_theme_registry()
    kind = revision.get("kind")
    relative = revision.get("path")
    before = revision.get("before")
    try:
        if kind == "manifest":
            _current, expected_hash = derived_manifest_source(registry, theme_id)
            if not isinstance(before, str):
                abort(400)
            write_manifest_override(
                registry,
                theme_id,
                before,
                expected_hash,
                actor_id=str(session.get("user_id", "")),
                actor_name=str(session.get("user_name", "")),
            )
        elif kind in ("template", "css", "template-reset", "css-reset") and isinstance(
            relative, str
        ):
            file_kind = cast(Literal["template", "css"], kind.removesuffix("-reset"))
            _content, expected_hash = load_editable_file(registry, theme_id, relative, file_kind)
            if before is None:
                from arborpress.themes.management import reset_override

                reset_override(
                    registry,
                    theme_id,
                    relative,
                    file_kind,
                    expected_hash,
                    actor_id=str(session.get("user_id", "")),
                    actor_name=str(session.get("user_name", "")),
                )
            else:
                save_override(
                    registry,
                    theme_id,
                    relative,
                    file_kind,
                    str(before),
                    expected_hash,
                    actor_id=str(session.get("user_id", "")),
                    actor_name=str(session.get("user_name", "")),
                )
        elif kind in ("options", "options-reset"):
            before_values = json.loads(before or "{}")
            if not isinstance(before_values, dict):
                abort(400)
            if before_values:
                before_values = validate_option_values(registry, theme_id, before_values)
            current_values: dict[str, Any] = {}
            async for db in get_db_session():
                from arborpress.core.site_settings import get_section, save_section

                current = await get_section("theme", db)
                all_values = current.get("option_values", {})
                if not isinstance(all_values, dict):
                    all_values = {}
                current_values = all_values.get(theme_id, {})
                if before_values:
                    all_values[theme_id] = before_values
                else:
                    all_values.pop(theme_id, None)
                current["option_values"] = all_values
                await save_section("theme", current, db, updated_by=str(session.get("user_id", "")))
                break
            record_change_revision(
                theme_id=theme_id,
                kind="options-restore",
                relative="theme.options",
                before=json.dumps(current_values, ensure_ascii=False, sort_keys=True),
                after=json.dumps(before_values, ensure_ascii=False, sort_keys=True),
                actor_id=str(session.get("user_id", "")),
                actor_name=str(session.get("user_name", "")),
            )
        else:
            abort(400)
    except ThemeManagementError as exc:
        abort(409, description=str(exc))
    await _theme_audit("revision_restored", theme_id, f"revision={revision_id}")
    await flash("Themeänderung aus der Revision wiederhergestellt.", "success")
    return redirect(url_for("admin.theme_detail", theme_id=theme_id))


@admin_bp.post("/themes/<theme_id>/revision-reset/<kind>/<path:relative>")
async def theme_revision_override_reset(
    theme_id: str, kind: str, relative: str
) -> ResponseReturnValue:
    # Kept as a separate HTML action for an explicit, CSRF-protected reset.
    return await theme_override_reset(theme_id, kind, relative)


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
        result = await db.execute(select(UserSession).where(UserSession.id == session_id))
        us = result.scalar_one_or_none()
        if us is None:
            abort(404)
        us.is_valid = False
        await db.commit()

    audit.info("SESSION revoked | session=%s by user=%s", session_id, session.get("user_id", ""))
    return redirect(url_for("admin.sessions_list"))
