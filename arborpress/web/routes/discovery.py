"""Bounded public crawler discovery using configured canonical URLs."""

from __future__ import annotations

from html import escape
from typing import Any

from quart import Blueprint, Response, abort
from sqlalchemy import func, literal, select, union_all

from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.models.content import Page, Post, PostStatus, PostVisibility
from arborpress.web.public_urls import canonical_url

discovery_bp = Blueprint("discovery", __name__)
SITEMAP_LIMIT = 10_000


def _xml_response(xml: str) -> Response:
    response = Response(xml, content_type="application/xml; charset=utf-8")
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


@discovery_bp.get("/robots.txt")
async def robots() -> Response:
    origin = get_settings().web.base_url.rstrip("/")
    response = Response(
        f"User-agent: *\nAllow: /\nSitemap: {origin}/sitemap.xml\n",
        content_type="text/plain; charset=utf-8",
    )
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


def _sitemap_source() -> Any:
    posts = select(
        Post.id.label("object_id"),
        Post.slug,
        Post.lang,
        Post.translation_group_id,
        Post.updated_at,
        literal("post").label("kind"),
    ).where(
        Post.status == PostStatus.PUBLISHED,
        Post.visibility == PostVisibility.PUBLIC,
        Post.noindex.is_(False),
    )
    pages = select(
        Page.id.label("object_id"),
        Page.slug,
        Page.lang,
        Page.translation_group_id,
        Page.updated_at,
        literal("page").label("kind"),
    ).where(
        Page.is_published.is_(True),
        Page.visibility == PostVisibility.PUBLIC,
        Page.noindex.is_(False),
    )
    return union_all(posts, pages).subquery("public_sitemap_content")


async def _sitemap_document(part: int) -> Response:
    if part < 0:
        abort(404)
    source = _sitemap_source()
    async for db in get_db_session():
        total = int((await db.execute(select(func.count()).select_from(source))).scalar_one())
        page_count = max(1, (total + SITEMAP_LIMIT - 1) // SITEMAP_LIMIT)
        if part >= page_count:
            abort(404)
        rows = (
            await db.execute(
                select(source)
                .order_by(source.c.kind, source.c.object_id)
                .offset(part * SITEMAP_LIMIT)
                .limit(SITEMAP_LIMIT)
            )
        ).all()
        group_ids = {row.translation_group_id for row in rows if row.translation_group_id}
        alternates: dict[tuple[str, str], list[tuple[str, str]]] = {}
        if group_ids and get_settings().web.i18n_mode == "prefix":
            from arborpress.core.i18n import normalize_language

            post_groups = {
                row.translation_group_id
                for row in rows
                if row.kind == "post" and row.translation_group_id
            }
            page_groups = {
                row.translation_group_id
                for row in rows
                if row.kind == "page" and row.translation_group_id
            }
            if post_groups:
                for group_id, lang, slug in (
                    await db.execute(
                        select(Post.translation_group_id, Post.lang, Post.slug).where(
                            Post.translation_group_id.in_(post_groups),
                            Post.status == PostStatus.PUBLISHED,
                            Post.visibility == PostVisibility.PUBLIC,
                            Post.noindex.is_(False),
                        )
                    )
                ).all():
                    normalized = normalize_language(lang)
                    if normalized:
                        alternates[("post", str(group_id))] = alternates.get(
                            ("post", str(group_id)), []
                        ) + [(normalized, str(slug))]
            if page_groups:
                for group_id, lang, slug in (
                    await db.execute(
                        select(Page.translation_group_id, Page.lang, Page.slug).where(
                            Page.translation_group_id.in_(page_groups),
                            Page.is_published.is_(True),
                            Page.visibility == PostVisibility.PUBLIC,
                            Page.noindex.is_(False),
                        )
                    )
                ).all():
                    normalized = normalize_language(lang)
                    if normalized:
                        alternates[("page", str(group_id))] = alternates.get(
                            ("page", str(group_id)), []
                        ) + [(normalized, str(slug))]
        break

    cfg = get_settings()
    urls: list[str] = []
    if part == 0 and cfg.web.i18n_mode == "single":
        urls.append(cfg.web.base_url.rstrip("/") + "/")
    elif part == 0:
        from arborpress.core.i18n import normalize_language

        default_lang = normalize_language(cfg.web.default_lang)
        if default_lang:
            urls.append(canonical_url("public.index", lang=default_lang))
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">'
    if urls:
        xml += f"<url><loc>{escape(urls[0])}</loc></url>"
    for row in rows:
        language_key = str(row.lang or "")
        if cfg.web.i18n_mode == "prefix":
            from arborpress.core.i18n import normalize_language

            normalized_language = normalize_language(row.lang) or (
                normalize_language(cfg.web.default_lang) if row.lang is None else None
            )
            if normalized_language is None:
                continue
            language_key = normalized_language
        endpoint = "public.post_detail" if row.kind == "post" else "public.page_detail"
        loc = canonical_url(endpoint, lang=language_key or None, slug=row.slug)
        xml += f"<url><loc>{escape(loc)}</loc>"
        if row.translation_group_id and cfg.web.i18n_mode == "prefix":
            for lang, slug in alternates.get((str(row.kind), str(row.translation_group_id)), []):
                alternate_url = canonical_url(endpoint, lang=lang, slug=slug)
                xml += (
                    '<xhtml:link rel="alternate" hreflang="'
                    + escape(lang)
                    + '" href="'
                    + escape(alternate_url)
                    + '" />'
                )
        if row.updated_at is not None:
            xml += f"<lastmod>{escape(row.updated_at.date().isoformat())}</lastmod>"
        xml += "</url>"
    return _xml_response(xml + "</urlset>\n")


@discovery_bp.get("/sitemap.xml")
async def sitemap() -> Response:
    source = _sitemap_source()
    async for db in get_db_session():
        total = int((await db.execute(select(func.count()).select_from(source))).scalar_one())
        page_count = max(1, (total + SITEMAP_LIMIT - 1) // SITEMAP_LIMIT)
        break
    if page_count == 1:
        return await _sitemap_document(0)
    origin = get_settings().web.base_url.rstrip("/")
    entries = "".join(
        f"<sitemap><loc>{escape(origin)}/sitemap/{part}.xml</loc></sitemap>"
        for part in range(page_count)
    )
    return _xml_response(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        + entries
        + "</sitemapindex>\n"
    )


@discovery_bp.get("/sitemap/<int:part>.xml")
async def sitemap_part(part: int) -> Response:
    return await _sitemap_document(part)
