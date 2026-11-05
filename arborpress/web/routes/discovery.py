"""Bounded public crawler discovery using the configured canonical origin."""
from __future__ import annotations

from html import escape
from urllib.parse import quote

from quart import Blueprint, Response
from sqlalchemy import select

from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.models.content import Page, Post, PostStatus, PostVisibility

discovery_bp = Blueprint('discovery', __name__)
SITEMAP_LIMIT = 10_000


@discovery_bp.get('/robots.txt')
async def robots() -> Response:
    origin = get_settings().web.base_url.rstrip('/')
    return Response(
        f'User-agent: *\nAllow: /\nSitemap: {origin}/sitemap.xml\n',
        content_type='text/plain; charset=utf-8',
    )


@discovery_bp.get('/sitemap.xml')
async def sitemap() -> Response:
    origin = get_settings().web.base_url.rstrip('/')
    urls: list[str] = [origin + '/']
    async for db in get_db_session():
        posts = await db.scalars(select(Post.slug).where(
            Post.status == PostStatus.PUBLISHED,
            Post.visibility == PostVisibility.PUBLIC,
            Post.noindex.is_(False),
        ).order_by(Post.id).limit(SITEMAP_LIMIT))
        pages = await db.scalars(select(Page.slug).where(
            Page.is_published.is_(True), Page.visibility == PostVisibility.PUBLIC,
            Page.noindex.is_(False),
        ).order_by(Page.id).limit(SITEMAP_LIMIT))
        urls.extend(origin + '/p/' + quote(slug, safe='') for slug in posts)
        urls.extend(origin + '/page/' + quote(slug, safe='') for slug in pages)
        break
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    xml += ''.join(f'<url><loc>{escape(url)}</loc></url>' for url in urls)
    xml += '</urlset>\n'
    response = Response(xml, content_type='application/xml; charset=utf-8')
    response.headers['Cache-Control'] = 'public, max-age=60'
    return response
