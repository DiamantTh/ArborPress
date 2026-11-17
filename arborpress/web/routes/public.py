"""Public content routes (§6 URL schema, §7 I18N, §9 server-rendered).

Canonical URL hierarchy:
  /               – Post list (home page)
  /p/<slug>       – Post
  /o/<short_id>   – Short ID → 301 to canonical slug
  /page/<slug>    – Static page
  /tag/<tag>      – Tag archive
  /search?q=      – Full-text search
  /media/…        – Media files (stable URL, §6)
  /@<handle>      – User profile (PUBLIC accounts, §4)
  /@<handle>/p/<slug>  – Post by a user
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import mimetypes
import os
from email.utils import formatdate as _rfc822
from typing import Any

from quart import (
    Blueprint,
    Response,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from quart.typing import ResponseReturnValue
from slugify import slugify
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.core.validators import is_safe_url, is_valid_email
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.public")

public_bp = Blueprint("public", __name__)

_PER_PAGE = 20


def register_language_routes(app: Any) -> None:
    """Register public-only aliases for configured language-prefix mode.

    Protocol, account, media, API, admin and discovery routes are deliberately
    absent from this map.
    """
    from quart import Quart

    if not isinstance(app, Quart):
        return
    aliases = (
        ("/<lang>", "public_lang.index", index),
        ("/<lang>/p/<slug>", "public_lang.post_detail", post_detail),
        ("/<lang>/page/<slug>", "public_lang.page_detail", page_detail),
        ("/<lang>/tag/<tag>", "public_lang.tag_archive", tag_archive),
        ("/<lang>/search", "public_lang.search", search),
        ("/<lang>/@<handle>", "public_lang.author_profile", author_profile),
        ("/<lang>/@<handle>/p/<slug>", "public_lang.author_post", author_post),
    )

    for rule, endpoint, handler in aliases:

        async def dispatch(
            lang: str,
            _handler: Any = handler,
            **values: str,
        ) -> Any:
            from arborpress.core.config import get_settings
            from arborpress.core.i18n import normalize_language

            normalized = normalize_language(lang)
            if get_settings().web.i18n_mode != "prefix" or normalized is None:
                abort(404)
            g.lang = normalized
            return await _handler(**values)

        app.add_url_rule(rule, endpoint=endpoint, view_func=dispatch, strict_slashes=False)


def _prefix_mode() -> bool:
    return get_settings().web.i18n_mode == "prefix"


def _content_language(value: str | None) -> str | None:
    from arborpress.core.i18n import normalize_language

    return normalize_language(value) or normalize_language(get_settings().web.default_lang)


def _language_content_filter(column: Any, language: str) -> Any:
    """Treat legacy NULL language as the configured default locale only."""
    from arborpress.core.i18n import language_storage_values

    filters = [column.in_(language_storage_values(language))]
    if language == _content_language(get_settings().web.default_lang):
        filters.append(column.is_(None))
    return or_(*filters)


def _canonical_content_path(endpoint: str, *, lang: str | None = None, **values: str) -> str:
    from arborpress.web.public_urls import public_path

    return public_path(endpoint, lang=lang, **values)


async def _old_content_slug(db: Any, kind: str, slug: str, language: str | None) -> Any:
    """Resolve a prior slug without allowing it to point at another locale."""
    from arborpress.models.content import ContentSlugHistory, Page, Post

    model = Post if kind == "post" else Page
    history_stmt = select(ContentSlugHistory.content_id).where(
        ContentSlugHistory.content_kind == kind,
        ContentSlugHistory.slug == slug,
    )
    if language is not None:
        from sqlalchemy.sql.elements import ColumnElement

        from arborpress.core.i18n import language_storage_values

        language_filters: list[ColumnElement[bool]] = [
            ContentSlugHistory.language.in_(language_storage_values(language))
        ]
        if language == _content_language(get_settings().web.default_lang):
            language_filters.append(ContentSlugHistory.language == "")
        history_stmt = history_stmt.where(or_(*language_filters))
    history_ids = (await db.scalars(history_stmt)).all()
    if history_ids:
        candidates = []
        for item_id in history_ids:
            item = await db.get(model, item_id)
            if item is not None:
                candidates.append(item)
        if language is not None:
            return candidates[0] if candidates else None
        default = _content_language(get_settings().web.default_lang)
        preferred = [item for item in candidates if _content_language(item.lang) == default]
        if preferred:
            return preferred[0]
        return candidates[0] if len(candidates) == 1 else None
    slug_column = model.slug_old
    from sqlalchemy.sql.elements import ColumnElement

    filters: list[ColumnElement[bool]] = [slug_column == slug]
    if language is not None:
        filters.append(_language_content_filter(model.lang, language))
    candidates = (await db.scalars(select(model).where(*filters))).all()
    if language is not None:
        return candidates[0] if candidates else None
    default = _content_language(get_settings().web.default_lang)
    preferred = [item for item in candidates if _content_language(item.lang) == default]
    if preferred:
        return preferred[0]
    return candidates[0] if len(candidates) == 1 else None


# ---------------------------------------------------------------------------
# RDAP background task
# ---------------------------------------------------------------------------


async def _rdap_background(comment_id: str, ip_str: str) -> None:
    """Look up RDAP data for *ip_str* and store it on the comment (best-effort)."""
    import json as _json

    from arborpress.core import rdap as _rdap
    from arborpress.core.db import get_session_factory

    try:
        rdap_data = await _rdap.lookup(ip_str)
        if not rdap_data:
            return
        rdap_text = _json.dumps(rdap_data, ensure_ascii=False)
        _factory = get_session_factory()
        async with _factory() as _db:
            from sqlalchemy import select as _select

            from arborpress.models.content import Comment as _Comment

            stmt = _select(_Comment).where(_Comment.id == comment_id)
            row = (await _db.execute(stmt)).scalar_one_or_none()
            if row is None:
                return
            row.rdap_json = rdap_text
            # If country_code is still None (no GeoIP configured), fill from RDAP
            if not row.country_code and rdap_data.get("country"):
                row.country_code = rdap_data["country"].upper()[:2]
            await _db.commit()
    except Exception:  # noqa: BLE001
        log.debug("RDAP background task failed for comment %s", comment_id, exc_info=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_slug(slug: str) -> str:
    """§6 – Slugs immer lowercase, URL-safe."""
    return slugify(slug, lowercase=True, separator="-")


async def _get_footer_pages() -> list:
    """Loads required pages for the footer (§1 imprint/privacy/rules).

    Only pages with visibility=PUBLIC appear in the footer.
    """
    try:
        from arborpress.models.content import Page, PageType, PostVisibility

        async for db in get_db_session():
            stmt = (
                select(Page)
                .where(
                    Page.page_type.in_(
                        [
                            PageType.IMPRESSUM,
                            PageType.PRIVACY,
                            PageType.RULES,
                        ]
                    ),
                    Page.is_published == True,  # noqa: E712
                    Page.visibility == PostVisibility.PUBLIC,
                )
                .order_by(Page.page_type)
            )
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
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        abort(400, "page must be a positive integer")
    if _prefix_mode() and not request.path.strip("/"):
        default_lang = _content_language(get_settings().web.default_lang)
        if default_lang:
            return redirect(f"/{default_lang}/", 302)
    lang = getattr(g, "lang", None) if _prefix_mode() else request.args.get("lang")
    if _prefix_mode() and lang and request.path == f"/{lang}":
        return redirect(f"/{lang}/", 301)

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
                language_filter = (
                    Post.lang == lang
                    if not _prefix_mode()
                    else _language_content_filter(Post.lang, lang)
                )
                stmt = stmt.where(language_filter)

            total_stmt = (
                select(func.count())
                .select_from(Post)
                .where(
                    Post.status == PostStatus.PUBLISHED,
                    Post.visibility == PostVisibility.PUBLIC,
                )
            )
            if lang:
                language_filter = (
                    Post.lang == lang
                    if not _prefix_mode()
                    else _language_content_filter(Post.lang, lang)
                )
                total_stmt = total_stmt.where(language_filter)
            total_result = await db.execute(total_stmt)
            total = total_result.scalar_one()

            stmt = stmt.offset((page - 1) * _PER_PAGE).limit(_PER_PAGE)
            result = await db.execute(stmt)
            posts = result.scalars().all()

            pages = max(1, (total + _PER_PAGE - 1) // _PER_PAGE)
            from types import SimpleNamespace

            pagination = SimpleNamespace(
                page=page,
                pages=pages,
                has_prev=page > 1,
                has_next=page < pages,
                prev_num=page - 1,
                next_num=page + 1,
            )
            return await _render(
                "index.html",
                posts=posts,
                pagination=pagination,
                lang=lang,
                active_lang=lang or get_settings().web.default_lang,
            )
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
        return redirect(
            _canonical_content_path(
                "public.post_detail",
                lang=(request.path.lstrip("/").split("/", 1)[0] if _prefix_mode() else None),
                slug=canonical,
            ),
            301,
        )

    from arborpress.comments import (
        REASON_CATALOG,
        CommentVoteCounts,
        build_comment_thread,
        can_edit_comment,
        resolve_comment_policy,
    )
    from arborpress.content.authors import authors_for_posts
    from arborpress.core.captcha import get_captcha_challenge, get_effective_captcha_type
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import (
        Comment,
        CommentModerationAppeal,
        CommentRevision,
        CommentStatus,
        CommentVote,
        ModerationDecision,
        Post,
        PostStatus,
        PostVisibility,
    )
    from arborpress.models.user import User

    post_activitypub_actor_uri = None

    async for db in get_db_session():
        # Load post (status=published is sufficient; visibility is checked separately)
        from arborpress.core.i18n import normalize_language

        path_lang = (
            normalize_language(request.path.lstrip("/").split("/", 1)[0])
            if _prefix_mode()
            else None
        )
        lookup_lang = path_lang
        stmt = (
            select(Post)
            .where(
                Post.slug == canonical,
                Post.status == PostStatus.PUBLISHED,
            )
            .options(selectinload(Post.author))
        )
        if lookup_lang:
            stmt = stmt.where(_language_content_filter(Post.lang, lookup_lang))
        result = await db.execute(stmt)
        matches = result.scalars().all()
        post: Post | None = None
        if len(matches) == 1:
            post = matches[0]
        else:
            default_lang = _content_language(get_settings().web.default_lang)
            preferred = [item for item in matches if _content_language(item.lang) == default_lang]
            post = preferred[0] if len(preferred) == 1 else None

        if post is None:
            # Versuch: alter Slug → 301
            old_post = await _old_content_slug(db, "post", canonical, lookup_lang)
            if (
                old_post
                and old_post.status == PostStatus.PUBLISHED
                and old_post.visibility == PostVisibility.PUBLIC
            ):
                return redirect(
                    _canonical_content_path(
                        "public.post_detail",
                        lang=_content_language(old_post.lang),
                        slug=old_post.slug,
                    ),
                    301,
                )
            abort(404)

        content_lang = _content_language(post.lang)
        if _prefix_mode():
            from arborpress.core.i18n import normalize_language

            if path_lang is None:
                return redirect(
                    _canonical_content_path(
                        "public.post_detail", lang=content_lang, slug=post.slug
                    ),
                    301,
                )
            if path_lang != content_lang:
                abort(404)
            expected_path = _canonical_content_path(
                "public.post_detail", lang=content_lang, slug=post.slug
            )
            if request.path != expected_path:
                return redirect(expected_path, 301)
        translation_alternates: list[tuple[str, str]] = []
        if (
            post.translation_group_id
            and not post.noindex
            and post.visibility == PostVisibility.PUBLIC
        ):
            from arborpress.core.i18n import normalize_language

            variant_rows = await db.execute(
                select(Post.lang, Post.slug).where(
                    Post.translation_group_id == post.translation_group_id,
                    Post.id != post.id,
                    Post.status == PostStatus.PUBLISHED,
                    Post.visibility == PostVisibility.PUBLIC,
                    Post.noindex.is_(False),
                )
            )
            translation_alternates = [
                (normalized, variant_slug)
                for variant_lang, variant_slug in variant_rows.all()
                if (normalized := normalize_language(variant_lang)) is not None
            ]

        authors_by_post = await authors_for_posts(db, [str(post.id)])
        post_authors: list[Any] = authors_by_post.get(str(post.id), [])
        if not post_authors and post.author is not None:
            # Compatibility for pre-migration fixtures and legacy null-edge data.
            post_authors = [(post.author, "primary", 0)]
        from arborpress.federation.policy import canonical_origin, federation_is_enabled
        from arborpress.federation.security import FederationFetchError
        from arborpress.models.federation import FederationInstanceIdentity, LocalFederationActor

        federation_settings = await get_section("federation", db)
        if post_authors and federation_is_enabled(federation_settings):
            try:
                configured_origin = canonical_origin()
            except FederationFetchError:
                configured_origin = ""
            identity = await db.get(FederationInstanceIdentity, 1)
            if not identity or identity.canonical_origin == configured_origin:
                primary_relation = post_authors[0]
                primary_user = (
                    primary_relation.user
                    if hasattr(primary_relation, "user")
                    else primary_relation[0]
                )
                post_activitypub_actor_uri = (
                    await db.execute(
                        select(LocalFederationActor.actor_uri).where(
                            LocalFederationActor.user_id == str(primary_user.id),
                            LocalFederationActor.enabled.is_(True),
                        )
                    )
                ).scalar_one_or_none()
        comment_author_ids = {
            str(item.user_id) for item in post_authors if hasattr(item, "user_id")
        }
        if not comment_author_ids and post.author_id:
            comment_author_ids.add(str(post.author_id))

        # private: Artikel ist komplett gesperrt
        if post.visibility == PostVisibility.PRIVATE:
            abort(404)
        # hidden: Artikel ist erreichbar, aber nicht verlinkt – kein abort

        captcha_section = await get_section("captcha", db)
        captcha_type = get_effective_captcha_type(post.captcha_type, captcha_section)
        captcha_ctx = get_captcha_challenge(captcha_type, captcha_section)
        comment_settings = await get_section("comments", db)
        comment_policy = resolve_comment_policy(post, comment_settings)
        comments_result = await db.execute(
            select(Comment)
            .where(
                Comment.post_id == post.id,
                Comment.status.in_([CommentStatus.APPROVED, CommentStatus.DELETED]),
            )
            .options(
                selectinload(Comment.quoted),
                selectinload(Comment.author_user),
                selectinload(Comment.remote_actor),
            )
            .order_by(Comment.created_at, Comment.id)
        )
        visible_comments = list(comments_result.scalars().all())
        comment_threads = build_comment_thread(visible_comments)
        comment_ids = [str(comment.id) for comment in visible_comments]
        vote_counts: dict[str, CommentVoteCounts] = {
            comment_id: CommentVoteCounts(upvotes=0, downvotes=0) for comment_id in comment_ids
        }
        if comment_ids:
            vote_rows = await db.execute(
                select(CommentVote.comment_id, CommentVote.value, func.count(CommentVote.id))
                .join(Comment, Comment.id == CommentVote.comment_id)
                .where(
                    CommentVote.comment_id.in_(comment_ids),
                    Comment.status == CommentStatus.APPROVED,
                )
                .group_by(CommentVote.comment_id, CommentVote.value)
            )
            mutable_counts = {comment_id: {1: 0, -1: 0} for comment_id in comment_ids}
            for comment_id, vote_value, total in vote_rows.all():
                mutable_counts[str(comment_id)][int(vote_value)] = int(total)
            vote_counts = {
                comment_id: CommentVoteCounts(upvotes=counts[1], downvotes=counts[-1])
                for comment_id, counts in mutable_counts.items()
            }
        active_user_id = str(session.get("user_id") or "") or None
        active_user = await db.get(User, active_user_id) if active_user_id else None
        own_votes: dict[str, int] = {}
        if active_user_id and comment_ids:
            votes_result = await db.execute(
                select(CommentVote.comment_id, CommentVote.value).where(
                    CommentVote.user_id == active_user_id,
                    CommentVote.comment_id.in_(comment_ids),
                )
            )
            own_votes = {str(comment_id): int(value) for comment_id, value in votes_result.all()}

        editable_comments: set[str] = set()
        if active_user is not None:
            for visible_comment in visible_comments:
                if str(visible_comment.author_user_id or "") != active_user_id:
                    continue
                editable, _ = await can_edit_comment(
                    db,
                    comment=visible_comment,
                    actor_user=active_user,
                    policy=comment_policy,
                )
                if editable:
                    editable_comments.add(str(visible_comment.id))

        # Appeal and decision details are visible only to the signed-in author.
        author_decisions: dict[
            str,
            list[tuple[ModerationDecision, CommentModerationAppeal | None, dt.datetime]],
        ] = {}
        own_pending_comments: list[Comment] = []
        own_hidden_comments: list[Comment] = []
        appeal_days = max(1, min(90, int(comment_settings.get("appeal_window_days", 14))))
        if active_user_id:
            own_pending_result = await db.execute(
                select(Comment)
                .where(
                    Comment.post_id == post.id,
                    Comment.author_user_id == active_user_id,
                    Comment.status.in_(
                        [CommentStatus.PENDING_CONFIRMATION, CommentStatus.PENDING_MODERATION]
                    ),
                )
                .order_by(Comment.created_at.desc())
            )
            own_pending_comments = list(own_pending_result.scalars().all())
            own_hidden_result = await db.execute(
                select(Comment)
                .where(
                    Comment.post_id == post.id,
                    Comment.author_user_id == active_user_id,
                    Comment.status.in_([CommentStatus.REJECTED, CommentStatus.SPAM]),
                )
                .order_by(Comment.created_at.desc())
            )
            own_hidden_comments = list(own_hidden_result.scalars().all())
            own_comment_ids = list(
                {
                    str(item.id)
                    for item in [*visible_comments, *own_pending_comments, *own_hidden_comments]
                }
            )
            if own_comment_ids:
                own_revisions_result = await db.execute(
                    select(CommentRevision)
                    .join(Comment, Comment.id == CommentRevision.comment_id)
                    .where(
                        Comment.post_id == post.id,
                        Comment.author_user_id == active_user_id,
                    )
                )
                own_revisions = list(own_revisions_result.scalars().all())
                revision_to_comment = {
                    str(revision.id): str(revision.comment_id) for revision in own_revisions
                }
                decision_result = await db.execute(
                    select(ModerationDecision)
                    .where(
                        (
                            (ModerationDecision.target_type == "comment")
                            & ModerationDecision.target_id.in_(own_comment_ids)
                        )
                        | (
                            (ModerationDecision.target_type == "revision")
                            & ModerationDecision.target_id.in_(revision_to_comment or [""])
                        ),
                    )
                    .order_by(ModerationDecision.created_at.desc())
                )
                decisions = list(decision_result.scalars().all())
                decision_ids = [item.id for item in decisions]
                appeals_by_decision: dict[str, CommentModerationAppeal] = {}
                if decision_ids:
                    appeals_result = await db.execute(
                        select(CommentModerationAppeal).where(
                            CommentModerationAppeal.decision_id.in_(decision_ids)
                        )
                    )
                    appeals_by_decision = {
                        str(item.decision_id): item for item in appeals_result.scalars().all()
                    }
                for item in decisions:
                    comment_id = (
                        item.target_id
                        if item.target_type == "comment"
                        else revision_to_comment.get(item.target_id)
                    )
                    if comment_id is None:
                        continue
                    author_decisions.setdefault(comment_id, []).append(
                        (
                            item,
                            appeals_by_decision.get(item.id),
                            item.created_at + dt.timedelta(days=appeal_days),
                        )
                    )
        requested_parent = request.args.get("reply_to", "")
        requested_quote = request.args.get("quote", "")
        requested_edit = request.args.get("edit", "")
        target_by_id = {str(comment.id): comment for comment in visible_comments}
        reply_target = target_by_id.get(requested_parent)
        quote_target = target_by_id.get(requested_quote)
        edit_target = target_by_id.get(requested_edit)
        if reply_target and reply_target.status != CommentStatus.APPROVED:
            reply_target = None
        if quote_target and quote_target.status != CommentStatus.APPROVED:
            quote_target = None
        if (
            edit_target is None
            or active_user_id is None
            or str(edit_target.author_user_id or "") != active_user_id
            or str(edit_target.id) not in editable_comments
        ):
            edit_target = None

        # --- Related articles (tag overlap, max. 3) ---
        related_posts: list = []
        post_tag_ids = [t.id for t in (post.tags or [])]
        if post_tag_ids:
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
                    Post.status == PostStatus.PUBLISHED,
                    Post.visibility == PostVisibility.PUBLIC,
                )
                .order_by(overlap_subq.c.overlap.desc(), Post.published_at.desc())
                .limit(3)
            )
            rel_result = await db.execute(rel_stmt)
            related_posts = [row[0] for row in rel_result.all()]

    assert post is not None
    from arborpress.web.http_cache import conditional_response

    response = Response(
        await _render(
            "post.html",
            post=post,
            captcha=captcha_ctx,
            related_posts=related_posts,
            comment_threads=comment_threads,
            comment_count=len(visible_comments),
            comment_policy=comment_policy,
            comment_vote_counts=vote_counts,
            comment_own_votes=own_votes,
            comment_editable_ids=editable_comments,
            comment_author_decisions=author_decisions,
            comment_pending_own=own_pending_comments,
            comment_hidden_own=own_hidden_comments,
            comment_appeal_days=appeal_days,
            comment_active_user=active_user,
            post_authors=post_authors,
            comment_author_ids=comment_author_ids,
            comment_reply_target=reply_target,
            comment_quote_target=quote_target,
            comment_edit_target=edit_target,
            comment_reason_catalog=REASON_CATALOG,
            post_activitypub_actor_uri=post_activitypub_actor_uri,
            active_lang=content_lang,
            canonical_endpoint="public.post_detail",
            canonical_values={"slug": post.slug},
            translation_alternates=translation_alternates,
        ),
        mimetype="text/html",
    )
    # The representation includes comment/thread state and session-specific
    # controls, so use a body ETag instead of a Post timestamp as its validator.
    return await conditional_response(response, private=True)


# ---------------------------------------------------------------------------
# Short-ID /o/{short_id}
# ---------------------------------------------------------------------------


@public_bp.get("/o/<short_id>")
async def shortlink(short_id: str):
    """ActivityPub / Kurz-Link → 301 zum kanonischen Slug (§6)."""
    from arborpress.models.content import Post, PostStatus, PostVisibility

    async for db in get_db_session():
        stmt = select(Post).where(Post.short_id == short_id)
        result = await db.execute(stmt)
        post = result.scalar_one_or_none()

    if post is None:
        abort(404)
    # private posts are not reachable via short link either
    if post.status != PostStatus.PUBLISHED or post.visibility != PostVisibility.PUBLIC:
        abort(404)
    return redirect(
        _canonical_content_path(
            "public.post_detail", lang=_content_language(post.lang), slug=post.slug
        ),
        301,
    )


# ---------------------------------------------------------------------------
# Statische Seiten
# ---------------------------------------------------------------------------


@public_bp.get("/page/<slug>")
async def page_detail(slug: str):
    """Statische Seite – Impressum, Datenschutz, Regeln (§1, §6)."""
    canonical = _canonical_slug(slug)
    if canonical != slug:
        return redirect(
            _canonical_content_path(
                "public.page_detail",
                lang=(request.path.lstrip("/").split("/", 1)[0] if _prefix_mode() else None),
                slug=canonical,
            ),
            301,
        )

    from arborpress.models.content import Page, PostVisibility

    async for db in get_db_session():
        # check is_published; handle visibility separately
        from arborpress.core.i18n import normalize_language

        path_lang = (
            normalize_language(request.path.lstrip("/").split("/", 1)[0])
            if _prefix_mode()
            else None
        )
        lookup_lang = path_lang
        stmt = select(Page).where(
            Page.slug == canonical,
            Page.is_published == True,  # noqa: E712
        )
        if lookup_lang:
            stmt = stmt.where(_language_content_filter(Page.lang, lookup_lang))
        result = await db.execute(stmt)
        matches = result.scalars().all()
        page: Page | None = None
        if len(matches) == 1:
            page = matches[0]
        else:
            default_lang = _content_language(get_settings().web.default_lang)
            preferred = [item for item in matches if _content_language(item.lang) == default_lang]
            page = preferred[0] if len(preferred) == 1 else None

        if page is None:
            old_page = await _old_content_slug(db, "page", canonical, lookup_lang)
            if (
                old_page is not None
                and old_page.is_published
                and old_page.visibility == PostVisibility.PUBLIC
            ):
                return redirect(
                    _canonical_content_path(
                        "public.page_detail",
                        lang=_content_language(old_page.lang),
                        slug=old_page.slug,
                    ),
                    301,
                )

        if page is not None and _prefix_mode():
            from arborpress.core.i18n import normalize_language

            page_lang = _content_language(page.lang)
            path_lang = normalize_language(request.path.lstrip("/").split("/", 1)[0])
            if path_lang is None:
                return redirect(
                    _canonical_content_path("public.page_detail", lang=page_lang, slug=page.slug),
                    301,
                )
            if path_lang != page_lang:
                abort(404)
            expected_path = _canonical_content_path(
                "public.page_detail", lang=page_lang, slug=page.slug
            )
            if request.path != expected_path:
                return redirect(expected_path, 301)

        translation_alternates: list[tuple[str, str]] = []
        if (
            page is not None
            and page.translation_group_id
            and page.noindex is False
            and page.visibility == PostVisibility.PUBLIC
        ):
            from arborpress.core.i18n import normalize_language

            variants = await db.execute(
                select(Page.lang, Page.slug).where(
                    Page.translation_group_id == page.translation_group_id,
                    Page.id != page.id,
                    Page.is_published.is_(True),
                    Page.visibility == PostVisibility.PUBLIC,
                    Page.noindex.is_(False),
                )
            )
            translation_alternates = [
                (normalized, variant_slug)
                for variant_lang, variant_slug in variants.all()
                if (normalized := normalize_language(variant_lang)) is not None
            ]

    if page is None:
        abort(404)
    # private: Seite komplett gesperrt
    if page.visibility == PostVisibility.PRIVATE:
        abort(404)
    # hidden: reachable but not linked in navigation/footer
    from arborpress.web.http_cache import conditional_response

    response = Response(
        await _render(
            "page.html",
            page=page,
            active_lang=_content_language(page.lang),
            canonical_endpoint="public.page_detail",
            canonical_values={"slug": page.slug},
            translation_alternates=translation_alternates,
        ),
        mimetype="text/html",
    )
    # Theme/template changes also affect the rendered representation; its ETag
    # is a more accurate validator than the Page row timestamp.
    return await conditional_response(response, private=True)


# ---------------------------------------------------------------------------
# Tag archive
# ---------------------------------------------------------------------------


@public_bp.get("/tag/<tag>")
async def tag_archive(tag: str):
    """Posts eines Tags (§6)."""
    canonical = _canonical_slug(tag)
    if canonical != tag:
        return redirect(
            _canonical_content_path(
                "public.tag_archive",
                lang=(request.path.lstrip("/").split("/", 1)[0] if _prefix_mode() else None),
                tag=canonical,
            ),
            301,
        )

    from arborpress.models.content import Post, PostStatus, Tag

    if _prefix_mode():
        from arborpress.core.i18n import normalize_language

        path_lang = normalize_language(request.path.lstrip("/").split("/", 1)[0])
        if path_lang is None:
            default_lang = _content_language(get_settings().web.default_lang)
            return redirect(
                _canonical_content_path("public.tag_archive", lang=default_lang, tag=canonical),
                301,
            )

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
        if _prefix_mode():
            active_language = _content_language(getattr(g, "lang", None))
            if active_language:
                posts_stmt = posts_stmt.where(
                    _language_content_filter(Post.lang, active_language)
                )
        posts_result = await db.execute(posts_stmt)
        posts = posts_result.scalars().all()

    if _prefix_mode() and not normalize_language(request.path.lstrip("/").split("/", 1)[0]):
        return redirect(
            _canonical_content_path(
                "public.tag_archive",
                lang=_content_language(get_settings().web.default_lang),
                tag=canonical,
            ),
            301,
        )
    return await _render(
        "tag.html",
        tag=tag_obj.label,
        tag_slug=canonical,
        posts=posts,
        active_lang=getattr(g, "lang", None),
    )


# ---------------------------------------------------------------------------
# Suche
# ---------------------------------------------------------------------------


@public_bp.get("/search")
async def search():
    """Public search through the same visibility-aware service as API v1."""
    q = request.args.get("q", "").strip()
    results = []

    if _prefix_mode():
        from arborpress.core.i18n import normalize_language

        path_lang = normalize_language(request.path.lstrip("/").split("/", 1)[0])
        if path_lang is None:
            default_lang = _content_language(get_settings().web.default_lang)
            from urllib.parse import urlencode

            query = (
                "?" + urlencode({"q": request.args.get("q", "")}) if request.args.get("q") else ""
            )
            return redirect(
                _canonical_content_path("public.search", lang=default_lang) + query, 301
            )

    if q:
        try:
            from arborpress.core.search import search_public_content
            from arborpress.core.site_settings import get_section

            async for db in get_db_session():
                search_settings = await get_section("search", db)
                search_result = await search_public_content(
                    db,
                    q,
                    per_page=50,
                    configured_provider=search_settings.get("provider", "auto"),
                    language=getattr(g, "lang", None)
                    if _prefix_mode()
                    else request.args.get("lang"),
                    default_language=get_settings().web.default_lang,
                )
                results = [
                    {
                        "title": item.title,
                        "url": _canonical_content_path(
                            "public.post_detail" if item.kind == "post" else "public.page_detail",
                            lang=getattr(g, "lang", None) if _prefix_mode() else None,
                            slug=item.slug,
                        ),
                        "excerpt": item.excerpt,
                    }
                    for item in search_result.items
                ]
        except Exception as exc:
            if isinstance(exc, ValueError):
                abort(400, "Search query is invalid")
            log.warning("Public search failed (%s)", type(exc).__name__)
            abort(503, "Search is temporarily unavailable")

    from arborpress.web.http_cache import conditional_response

    response = Response(
        await _render("search.html", q=q, results=results, active_lang=getattr(g, "lang", None)),
        mimetype="text/html",
    )
    return await conditional_response(response, private=True)


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

    stat = media_path.stat()
    validator = hashlib.sha256(
        f"{stat.st_ino}:{stat.st_size}:{stat.st_mtime_ns}".encode()
    ).hexdigest()
    resp = Response(stream_file(), mimetype=mime)
    from arborpress.web.http_cache import conditional_response

    await conditional_response(
        resp,
        etag=validator,
        last_modified=stat.st_mtime,
        weak_etag=True,
        cache_control="public, max-age=31536000, immutable",
    )

    # §10 SVG-XSS-Schutz: SVGs können JavaScript enthalten und werden auf
    # derselben Origin ausgeliefert → restriktive CSP aufzwingen, sodass
    # kein Script-Kontext entsteht, selbst wenn eine SVG-Datei in den
    # Media-Ordner gelangt ist.
    if mime == "image/svg+xml":
        resp.headers["Content-Security-Policy"] = "default-src 'none'"
        resp.headers["Content-Disposition"] = "attachment"

    return resp


# ---------------------------------------------------------------------------
# Nutzerprofil /@{handle} (§4 PUBLIC-Konten, §6)
# ---------------------------------------------------------------------------


@public_bp.get("/@<handle>")
async def author_profile(handle: str):
    """Public profile – PUBLIC accounts only (§4 security separation)."""
    from arborpress.models.user import AccountType, User

    actor = None
    federation_active = False
    async for db in get_db_session():
        stmt = select(User).where(
            func.lower(User.username) == handle.lower(),
            User.account_type == AccountType.PUBLIC,
            User.is_active == True,  # noqa: E712
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if user is not None:
            from arborpress.core.site_settings import get_section
            from arborpress.federation.policy import federation_is_enabled
            from arborpress.models.federation import LocalFederationActor

            federation_active = federation_is_enabled(await get_section("federation", db))
            if federation_active and not user.federation_opt_out:
                actor = (
                    await db.execute(
                        select(LocalFederationActor).where(
                            LocalFederationActor.user_id == str(user.id),
                            LocalFederationActor.enabled.is_(True),
                        )
                    )
                ).scalar_one_or_none()

    if user is None:
        abort(404)

    active_lang = getattr(g, "lang", None) if _prefix_mode() else None
    if _prefix_mode():
        from arborpress.core.i18n import normalize_language

        path_lang = normalize_language(request.path.lstrip("/").split("/", 1)[0])
        if path_lang is None:
            path_lang = _content_language(get_settings().web.default_lang)
            return redirect(
                _canonical_content_path(
                    "public.author_profile", lang=path_lang, handle=user.username
                ),
                301,
            )
        active_lang = path_lang

    # Publicly published posts where the user is primary or coauthor.
    from arborpress.models.content import Post, PostAuthorRelation, PostStatus, PostVisibility

    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        abort(400)
    per_page = 20

    async for db in get_db_session():
        authored = or_(
            PostAuthorRelation.user_id == str(user.id),
            Post.author_id == str(user.id),
        )
        posts_stmt = (
            select(Post)
            .distinct()
            .outerjoin(PostAuthorRelation, PostAuthorRelation.post_id == Post.id)
            .where(
                authored,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
                Post.noindex.is_(False),
            )
            .order_by(Post.published_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page + 1)
        )
        if active_lang:
            posts_stmt = posts_stmt.where(_language_content_filter(Post.lang, active_lang))
        posts_result = await db.execute(posts_stmt)
        rows = list(posts_result.scalars().all())
        has_next = len(rows) > per_page
        posts = rows[:per_page]

    return await _render(
        "author_profile.html",
        posts=posts,
        author=user,
        federation_actor=actor,
        federation_active=federation_active,
        page=page,
        has_next=has_next,
        active_lang=active_lang,
        noindex=False,
    )


@public_bp.get("/@<handle>/p/<slug>")
async def author_post(handle: str, slug: str):
    """Post eines bestimmten Autors /@{handle}/p/{slug} (§6)."""
    canonical = _canonical_slug(slug)
    if canonical != slug:
        return redirect(
            _canonical_content_path(
                "public.author_post",
                lang=(request.path.lstrip("/").split("/", 1)[0] if _prefix_mode() else None),
                handle=handle,
                slug=canonical,
            ),
            301,
        )

    from arborpress.models.content import Post, PostAuthorRelation, PostStatus, PostVisibility
    from arborpress.models.user import AccountType, User

    async for db in get_db_session():
        author_stmt = select(User).where(
            func.lower(User.username) == handle.lower(),
            User.account_type == AccountType.PUBLIC,
        )
        author_result = await db.execute(author_stmt)
        author = author_result.scalar_one_or_none()
        if author is None:
            abort(404)

        post_stmt = select(Post).where(
            Post.slug == canonical,
            Post.status == PostStatus.PUBLISHED,
            or_(
                Post.author_id == author.id,
                Post.id.in_(
                    select(PostAuthorRelation.post_id).where(
                        PostAuthorRelation.user_id == str(author.id)
                    )
                ),
            ),
        )
        if _prefix_mode():
            from arborpress.core.i18n import normalize_language

            language = normalize_language(request.path.lstrip("/").split("/", 1)[0])
            if language is not None:
                post_stmt = post_stmt.where(Post.lang == language)
        post_result = await db.execute(post_stmt)
        matches = post_result.scalars().all()
        post: Post | None = None
        if len(matches) == 1:
            post = matches[0]
        else:
            default_lang = _content_language(get_settings().web.default_lang)
            preferred = [item for item in matches if _content_language(item.lang) == default_lang]
            post = preferred[0] if len(preferred) == 1 else None

        if post is None:
            if _prefix_mode():
                from arborpress.core.i18n import normalize_language

                language = normalize_language(request.path.lstrip("/").split("/", 1)[0])
                language = language or _content_language(get_settings().web.default_lang)
            else:
                language = None
            historic = await _old_content_slug(db, "post", canonical, language)
            if (
                historic is not None
                and historic.status == PostStatus.PUBLISHED
                and historic.visibility == PostVisibility.PUBLIC
                and (
                    historic.author_id == author.id
                    or (
                        await db.execute(
                            select(PostAuthorRelation.id).where(
                                PostAuthorRelation.post_id == historic.id,
                                PostAuthorRelation.user_id == author.id,
                            )
                        )
                    ).scalar_one_or_none()
                    is not None
                )
            ):
                return redirect(
                    _canonical_content_path(
                        "public.post_detail",
                        lang=_content_language(historic.lang),
                        slug=historic.slug,
                    ),
                    301,
                )

    if post is None:
        abort(404)
    # private: also blocked via author URL
    if post.visibility == PostVisibility.PRIVATE:
        abort(404)
    return await post_detail(post.slug)


# ---------------------------------------------------------------------------
# Kommentar-Routen (zweistufige Moderation: E-Mail + Admin)
# ---------------------------------------------------------------------------


@public_bp.post("/p/<slug>/comment")
async def post_comment_submit(slug: str):
    """Kommentar einreichen.

    Ablauf: validate CSRF/CAPTCHA, delegate policy and persistence to the
    comment domain service, then mail a one-time guest token when applicable.
    """
    await validate_csrf()
    from datetime import UTC
    from datetime import datetime as dt

    from quart import flash

    from arborpress.comments import CommentPolicyError, create_comment, resolve_comment_policy
    from arborpress.core.captcha import get_effective_captcha_type, verify_captcha
    from arborpress.core.mail import send_comment_confirmation
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus
    from arborpress.models.user import User

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
        captcha_section = await get_section("captcha", db)
        comments_section = await get_section("comments", db)
        policy = resolve_comment_policy(post, comments_section)
        if not policy.enabled:
            await flash("Comments are closed for this article.", "error")
            return redirect(url_for("public.post_detail", slug=canonical))

        # --- Captcha validation ---
        captcha_type = get_effective_captcha_type(post.captcha_type, captcha_section)
        ok, err = await verify_captcha(captcha_type, form, captcha_section)
        if not ok:
            await flash(err or "Please solve the captcha correctly.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        user_id = session.get("user_id")
        author_user = await db.get(User, str(user_id)) if user_id else None
        author_name = (form.get("author_name", "") or "").strip()[:128]
        author_email = (form.get("author_email", "") or "").strip()
        if author_user is not None:
            author_name = author_user.display_name
            author_email = author_user.email or ""
        author_url = (form.get("author_url", "") or "").strip() or None
        body = (form.get("body", "") or "").strip()[:10_000]
        # Parent and quote are deliberately independent references.
        parent_raw = (form.get("parent_id", "") or "").strip() or None
        quote_of_raw = (form.get("quote_of_id", "") or "").strip() or None

        if not author_name or not body or (author_user is None and not author_email):
            await flash("Please fill in all required fields.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        # Check GDPR consent
        if not form.get("consent"):
            await flash("Please agree to the privacy policy.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        # Grobes E-Mail-Format-Check
        if author_email and not is_valid_email(author_email):
            await flash("Please enter a valid e-mail address.", "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        # author_url: nur http/https erlaubt, sonst lautlos verwerfen
        if author_url and not is_safe_url(author_url):
            author_url = None

        # --- Netzfilter (IP whitelist/blocklist, RBL, Country) ---
        from arborpress.core.comment_filter import check_comment_ip
        from arborpress.core.site_settings import get_section as _get_section

        net_filter_section = await _get_section("comment_filter", db)
        net_action, net_reason, country_code = await check_comment_ip(
            request.remote_addr or "", net_filter_section
        )
        if net_action == "block":
            # Hard block: reject without feedback (same UX as SPAM silent-accept)
            import logging as _log

            _log.getLogger("arborpress.comment_filter").info(
                "Comment blocked | ip=%s reason=%s", request.remote_addr, net_reason
            )
            await flash("Thank you for your comment!", "success")
            return redirect(url_for("public.post_detail", slug=canonical))

        # Rate limit (simple IP check)
        rate_limit = comments_section.get("rate_limit_per_hour", 10)
        if rate_limit > 0:
            from datetime import timedelta

            from sqlalchemy import and_

            one_hour_ago = dt.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
            ip = request.remote_addr or ""
            rl_stmt = select(Comment).where(
                and_(
                    Comment.ip_address == ip,
                    Comment.created_at >= one_hour_ago,
                )
            )
            rl_result = await db.execute(rl_stmt)
            if len(rl_result.scalars().all()) >= rate_limit:
                await flash("Too many comments – please try again later.", "error")
                return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")

        # --- Check blocklist (soft-block: immediately mark as SPAM) ---
        blocklist_raw = comments_section.get("blocklist", "") or ""
        blocklist = [term.strip().lower() for term in blocklist_raw.splitlines() if term.strip()]
        _check_fields = " ".join(
            [
                author_name.lower(),
                author_email.lower(),
                (author_url or "").lower(),
                body.lower(),
                (request.remote_addr or "").lower(),
            ]
        )
        blocked = any(term in _check_fields for term in blocklist)
        # RBL "flag"-Aktion: ebenfalls als SPAM einstufen (stilles Akzeptieren)
        if net_action == "flag":
            blocked = True

        try:
            creation = await create_comment(
                db,
                post=post,
                policy=policy,
                author_name=author_name,
                author_email=author_email or None,
                body=body,
                author_url=author_url,
                author_user=author_user,
                parent_id=parent_raw,
                quote_of_id=quote_of_raw,
                spam=blocked,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                country_code=country_code,
            )
        except CommentPolicyError as exc:
            await flash(str(exc), "error")
            return redirect(url_for("public.post_detail", slug=canonical) + "#comment-form")
        comment = creation.comment
        # Persist the confirmation delivery in the same transaction as its
        # comment and token evidence; a crash cannot commit one without the other.
        if not blocked and creation.confirmation_token:
            await send_comment_confirmation(comment, post, creation.confirmation_token, session=db)
        await db.commit()
        await db.refresh(comment)

        # Fire RDAP lookup in background (stores result on comment.rdap_json)
        import asyncio as _asyncio

        _asyncio.ensure_future(_rdap_background(str(comment.id), request.remote_addr or ""))

        # Send confirmation mail (if backend != none and not blocked)
        if blocked:
            # Silent accept – do not give the sender any feedback
            await flash(
                "Thank you for your comment!",
                "success",
            )
        elif creation.confirmation_token:
            await flash(
                "Thank you for your comment! Please confirm it via the link "
                "in the e-mail we sent you.",
                "success",
            )
        elif comment.status == CommentStatus.PENDING_MODERATION:
            await flash(
                "Thank you for your comment! It will be published after review.",
                "success",
            )
        else:
            await flash("Thank you for your comment!", "success")

    return redirect(url_for("public.post_detail", slug=canonical))


@public_bp.get("/comment/confirm/<token>")
async def comment_confirm(token: str):
    """E-mail confirmation of the comment.

    Consumes one guest confirmation and applies the current moderation policy.
    """
    from quart import make_response

    from arborpress.comments import CommentTokenError, confirm_guest_comment
    from arborpress.core.mail import send_comment_notification
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import CommentStatus

    result = "invalid"
    async for db in get_db_session():
        try:
            settings = await get_section("comments", db)
            comment = await confirm_guest_comment(db, token=token, settings=settings)
            if comment.status == CommentStatus.PENDING_MODERATION:
                await send_comment_notification(comment, comment.post, session=db)
            await db.commit()
        except CommentTokenError:
            await db.rollback()
        else:
            result = "published" if comment.status == CommentStatus.APPROVED else "moderation"
    response = await make_response(
        redirect(url_for("public.comment_confirmation_result", state=result))
    )
    if result != "invalid":
        session.pop("_flashes", None)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@public_bp.get("/comment/confirmation-result")
async def comment_confirmation_result() -> ResponseReturnValue:
    from quart import make_response

    state = request.args.get("state", "invalid")
    if state not in {"invalid", "published", "moderation", "resent"}:
        state = "invalid"
    response = await make_response(await _render("comment_confirmation_result.html", state=state))
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@public_bp.post("/comment/confirmation/resend")
async def comment_confirmation_resend() -> ResponseReturnValue:
    await validate_csrf()
    from datetime import timedelta

    from quart import flash, make_response

    from arborpress.comments import CommentTokenError, issue_guest_confirmation
    from arborpress.core.mail import send_comment_confirmation
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import Comment, CommentStatus, Post

    form = await request.form
    raw_slug = (form.get("slug") or "").strip()
    canonical = _canonical_slug(raw_slug) if raw_slug else ""
    email = (form.get("author_email") or "").strip().lower()
    try:
        async for db in get_db_session():
            settings = await get_section("comments", db)
            # Generic UX: never disclose whether an address has a pending comment.
            if is_valid_email(email):
                recent = await db.execute(
                    select(Comment)
                    .where(
                        Comment.author_email == email,
                        Comment.status == CommentStatus.PENDING_CONFIRMATION,
                        Comment.confirmation_sent_at
                        >= dt.datetime.now(dt.UTC).replace(tzinfo=None) - timedelta(seconds=60),
                    )
                    .with_for_update()
                )
                if not recent.scalars().first():
                    pending = await db.execute(
                        select(Comment)
                        .join(Post, Post.id == Comment.post_id)
                        .where(
                            Post.slug == canonical,
                            Comment.author_email == email,
                            Comment.status == CommentStatus.PENDING_CONFIRMATION,
                        )
                        .order_by(Comment.created_at.desc())
                        .limit(1)
                        .with_for_update()
                    )
                    comment = pending.scalar_one_or_none()
                    if comment is not None:
                        token = await issue_guest_confirmation(
                            db,
                            comment=comment,
                            ttl_hours=int(settings.get("confirmation_ttl_hours", 24)),
                        )
                        await send_comment_confirmation(comment, comment.post, token, session=db)
                        await db.commit()
                    else:
                        await db.rollback()
                else:
                    await db.rollback()
            else:
                await db.rollback()
    except CommentTokenError:
        # Cooldown, stale state and unknown address are intentionally indistinguishable.
        pass
    await flash(
        "Falls für diese Adresse eine Bestätigung aussteht, wurde eine Nachricht versendet.",
        "success",
    )
    response = await make_response(
        redirect(url_for("public.comment_confirmation_result", state="resent"))
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@public_bp.post("/comment/<comment_id>/edit")
async def comment_edit(comment_id: str) -> ResponseReturnValue:
    await validate_csrf()
    from quart import flash

    from arborpress.comments import (
        CommentPolicyError,
        create_comment_revision,
        resolve_comment_policy,
    )
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import Comment, Post
    from arborpress.models.user import User

    actor_id = str(session.get("user_id") or "")
    if not actor_id:
        abort(403)
    form = await request.form
    body = (form.get("body") or "").strip()
    async for db in get_db_session():
        comment = await db.get(Comment, comment_id)
        actor = await db.get(User, actor_id)
        if comment is None or actor is None:
            abort(404)
        post = await db.get(Post, comment.post_id)
        if post is None:
            abort(404)
        settings = await get_section("comments", db)
        policy = resolve_comment_policy(post, settings)
        try:
            revision = await create_comment_revision(
                db,
                comment_id=comment.id,
                actor_user=actor,
                body=body,
                policy=policy,
            )
            await db.commit()
        except CommentPolicyError as exc:
            await db.rollback()
            await flash(str(exc), "error")
            return redirect(
                url_for("public.post_detail", slug=post.slug) + f"?edit={comment.id}#comment-form"
            )
        await flash(
            "Deine Änderung wurde veröffentlicht."
            if revision.status.value == "approved"
            else "Deine Änderung wartet auf Prüfung; die bisherige Fassung bleibt sichtbar.",
            "success",
        )
    return redirect(url_for("public.post_detail", slug=post.slug) + f"#comment-{comment_id}")


@public_bp.post("/comment/<comment_id>/vote")
async def comment_vote(comment_id: str) -> ResponseReturnValue:
    await validate_csrf()
    from quart import flash

    from arborpress.comments import CommentVoteError, cast_comment_vote

    actor_id = str(session.get("user_id") or "")
    if not actor_id:
        abort(403)
    form = await request.form
    try:
        value = int(form.get("value", "2"))
    except ValueError:
        value = 2
    async for db in get_db_session():
        from arborpress.models.content import Comment

        comment = await db.get(Comment, comment_id)
        if comment is None:
            abort(404)
        try:
            await cast_comment_vote(db, user_id=actor_id, comment_id=comment_id, value=value)
            await db.commit()
        except CommentVoteError as exc:
            await db.rollback()
            await flash(str(exc), "error")
        post_slug = comment.post.slug
    return redirect(url_for("public.post_detail", slug=post_slug) + f"#comment-{comment_id}")


@public_bp.post("/comment/appeals/<decision_id>")
async def comment_appeal(decision_id: str) -> ResponseReturnValue:
    await validate_csrf()
    from quart import flash

    from arborpress.comments import ModerationError, submit_comment_appeal
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import Comment, ModerationDecision

    actor_id = str(session.get("user_id") or "")
    if not actor_id:
        abort(403)
    form = await request.form
    async for db in get_db_session():
        decision = await db.get(ModerationDecision, decision_id)
        if decision is None:
            abort(404)
        if decision.target_type == "comment":
            comment_id = decision.target_id
        else:
            from arborpress.models.content import CommentRevision

            revision = await db.get(CommentRevision, decision.target_id)
            if revision is None:
                abort(404)
            comment_id = revision.comment_id
        comment = await db.get(Comment, comment_id)
        if comment is None:
            abort(404)
        settings = await get_section("comments", db)
        try:
            await submit_comment_appeal(
                db,
                decision_id=decision_id,
                appellant_user_id=actor_id,
                statement=form.get("statement", ""),
                appeal_window_days=int(settings.get("appeal_window_days", 14)),
            )
            await db.commit()
        except ModerationError:
            await db.rollback()
            await flash(
                "Die Berufung konnte nicht eingereicht werden. "
                "Prüfe Frist, Berechtigung und Status.",
                "error",
            )
        else:
            await flash("Deine Berufung wurde eingereicht.", "success")
    return redirect(
        url_for("public.post_detail", slug=comment.post.slug) + f"#comment-{comment_id}"
    )


# ---------------------------------------------------------------------------
# RSS- und Atom-Feeds
# ---------------------------------------------------------------------------

_FEED_LIMIT = 20
_RSS_MIME = "application/rss+xml; charset=utf-8"
_ATOM_MIME = "application/atom+xml; charset=utf-8"


def _post_url(base: str, post) -> str:
    """Absolute URL zu einem Post-Objekt."""
    from arborpress.web.public_urls import canonical_url

    return canonical_url("public.post_detail", lang=post.lang, slug=post.slug)


def _rfc3339(d: dt.datetime | None) -> str:
    """ISO-8601 / RFC 3339 date for Atom. Always UTC + Z suffix."""
    if d is None:
        return "1970-01-01T00:00:00Z"
    if d.tzinfo is not None:
        d = d.astimezone(dt.UTC).replace(tzinfo=None)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rfc822_ts(d: dt.datetime | None) -> str:
    """RFC-822 date for RSS 2.0."""
    if d is None:
        return "Thu, 01 Jan 1970 00:00:00 GMT"
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.UTC)
    return _rfc822(d.timestamp(), usegmt=True)


def _xml_esc(s: str) -> str:
    """Minimal XML escaping for CDATA attributes."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


async def _feed_posts():
    """Returns the last _FEED_LIMIT published, public posts."""
    from arborpress.models.content import Post, PostStatus, PostVisibility

    async for db in get_db_session():
        stmt = (
            select(Post)
            .where(
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
                Post.noindex.is_(False),
            )
            .order_by(Post.published_at.desc())
            .limit(_FEED_LIMIT)
        )
        result = await db.execute(stmt)
        return result.scalars().all()
    return []


@public_bp.get("/feed.xml")
async def rss_feed():
    """RSS 2.0 feed of all public posts (max. 20).

    URL: /feed.xml
    Auto-Discovery: <link rel="alternate" type="application/rss+xml" …>
    """
    from arborpress.core.site_settings import get_section

    cfg = get_settings()
    base_url = cfg.web.base_url.rstrip("/")

    async for db in get_db_session():
        general = await get_section("general", db)
        break
    else:
        general = {}

    title = _xml_esc(general.get("site_title", "ArborPress"))
    description = _xml_esc(general.get("site_description", ""))
    language = general.get("site_language", "de")
    posts = await _feed_posts()

    last_build = _rfc822_ts(posts[0].published_at if posts else None)

    items = []
    for p in posts:
        link = _post_url(base_url, p)
        excerpt = _xml_esc((p.excerpt or "").strip())
        desc_elem = f"<description>{excerpt}</description>" if excerpt else "<description/>"
        items.append(
            f"    <item>\n"
            f"      <title>{_xml_esc(p.title)}</title>\n"
            f"      <link>{link}</link>\n"
            f'      <guid isPermaLink="true">{link}</guid>\n'
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
        f"    <pubDate>{last_build}</pubDate>\n"
        f'    <atom:link href="{base_url}/feed.xml" rel="self" '
        f'type="application/rss+xml"/>\n' + "\n".join(items) + "\n"
        "  </channel>\n"
        "</rss>"
    )
    from arborpress.web.http_cache import conditional_response

    return await conditional_response(Response(xml, content_type=_RSS_MIME), max_age=300)


@public_bp.get("/feed/atom.xml")
async def atom_feed():
    """Atom 1.0 feed of all public posts (max. 20).

    URL: /feed/atom.xml
    Auto-Discovery: <link rel="alternate" type="application/atom+xml" …>
    """
    from arborpress.core.site_settings import get_section

    cfg = get_settings()
    base_url = cfg.web.base_url.rstrip("/")

    async for db in get_db_session():
        general = await get_section("general", db)
        break
    else:
        general = {}

    title = _xml_esc(general.get("site_title", "ArborPress"))
    posts = await _feed_posts()
    updated = _rfc3339(posts[0].published_at if posts else None)

    entries = []
    for p in posts:
        link = _post_url(base_url, p)
        excerpt = _xml_esc((p.excerpt or "").strip())
        entries.append(
            f"  <entry>\n"
            f"    <id>{link}</id>\n"
            f"    <title>{_xml_esc(p.title)}</title>\n"
            f'    <link href="{link}"/>\n'
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
        f'  <link href="{base_url}/feed/atom.xml" rel="self"/>\n' + "\n".join(entries) + "\n"
        "</feed>"
    )
    from arborpress.web.http_cache import conditional_response

    return await conditional_response(Response(xml, content_type=_ATOM_MIME), max_age=300)
