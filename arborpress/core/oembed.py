"""oEmbed fetch with database cache for external post embeds.

Architecture (Mastodon approach)
--------------------------------
The author writes in Markdown::

    {{embed:https://twitter.com/user/status/123}}

``render_md_async()`` detects the pattern and queries ``get_embed_html()``:

1. DB cache present and not expired → return immediately (no network).
2. Cache miss → httpx request to the provider's oEmbed endpoint.
3. ``<script>``, ``<noscript>`` and ``<iframe>`` tags are **removed**.
4. Persist sanitised HTML in the DB (default TTL: 24 h).

GDPR Compliance
---------------
No browser request reaches Twitter / Meta / Google.
The ArborPress server fetches the embed HTML once server-side.
Without ``<script src="platform.twitter.com/...">`` the visitor sees
a static ``<blockquote>`` element – no tracking, no cookie.
Facebook/Instagram ``<iframe>`` embeds are removed entirely;
the fallback in ``render_md_async`` provides a text link.

Supported Providers
-------------------
- Twitter / X   (twitter.com, x.com)
- YouTube       (youtube.com, youtu.be)
- Vimeo         (vimeo.com)
- Instagram     (instagram.com – public posts, no token required)
- Mastodon      (any instance via /api/oembed)
- Bluesky       (bsky.app)

Custom providers can be added via ``register_provider()``.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import NamedTuple
from urllib.parse import urlencode, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.models.content import OEmbedCache

log = logging.getLogger("arborpress.oembed")

# ─── Types ────────────────────────────────────────────────────────────────────


class OEmbedProvider(NamedTuple):
    """Describes an oEmbed provider."""
    name: str
    # Regex for the post URL (not the oEmbed endpoint)
    url_pattern: re.Pattern
    # Base URL of the oEmbed endpoint
    endpoint: str
    # Additional query params (e.g. omit_script=1 for Twitter)
    extra_params: dict[str, str] = {}


# ─── Known Providers ─────────────────────────────────────────────────────────

_PROVIDERS: list[OEmbedProvider] = [
    OEmbedProvider(
        name="Twitter/X",
        url_pattern=re.compile(
            r"https?://(www\.)?(twitter\.com|x\.com)/\S+/status/\d+"
        ),
        endpoint="https://publish.twitter.com/oembed",
        extra_params={"omit_script": "1", "dnt": "1"},
    ),
    OEmbedProvider(
        name="YouTube",
        url_pattern=re.compile(
            r"https?://(www\.)?(youtube\.com/watch|youtu\.be/)\S+"
        ),
        endpoint="https://www.youtube.com/oembed",
        extra_params={"format": "json"},
    ),
    OEmbedProvider(
        name="Vimeo",
        url_pattern=re.compile(r"https?://(www\.)?vimeo\.com/\S+"),
        endpoint="https://vimeo.com/api/oembed.json",
        extra_params={},
    ),
    OEmbedProvider(
        name="Instagram",
        url_pattern=re.compile(r"https?://(www\.)?instagram\.com/p/\S+"),
        endpoint="https://graph.facebook.com/v21.0/instagram_oembed",
        extra_params={"omitscript": "1"},
    ),
    OEmbedProvider(
        name="Bluesky",
        url_pattern=re.compile(r"https?://bsky\.app/profile/\S+/post/\S+"),
        endpoint="https://embed.bsky.app/oembed",
        extra_params={},
    ),
]


def register_provider(provider: OEmbedProvider) -> None:
    """Registers an additional oEmbed provider (plugin hook)."""
    _PROVIDERS.append(provider)


def _match_provider(url: str) -> OEmbedProvider | None:
    """Returns the matching provider for *url*, or None."""
    for p in _PROVIDERS:
        if p.url_pattern.match(url):
            return p

    # Mastodon: generic fallback for arbitrary instances
    parsed = urlparse(url)
    if parsed.path.startswith("/@") or "/objects/" in parsed.path:
        return OEmbedProvider(
            name=f"Mastodon ({parsed.netloc})",
            url_pattern=re.compile(re.escape(url)),
            endpoint=f"https://{parsed.netloc}/api/oembed",
            extra_params={},
        )
    return None


# ─── HTML Sanitisation ─────────────────────────────────────────────────────────

_SCRIPT_RE = re.compile(
    r"<(script|noscript|iframe)[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE
)


def _strip_scripts(html: str) -> str:
    """Removes all <script>, <noscript>, and <iframe> tags (including content)."""
    return _SCRIPT_RE.sub("", html).strip()


# ─── Core Logic (DB Cache) ────────────────────────────────────────────────────

_DEFAULT_TTL: timedelta = timedelta(hours=24)
_TIMEOUT: float = 8.0


async def get_embed_html(
    url: str,
    db: AsyncSession,
    ttl: timedelta = _DEFAULT_TTL,
) -> str | None:
    """Returns sanitised oEmbed HTML for *url*.

    The fetch is performed once server-side; the result is stored in the
    DB (``oembed_cache`` table).  No browser request to third parties.

    Args:
        url: Public post URL (Twitter, YouTube, …).
        db:  Active AsyncSession – used for both reading **and** writing.
             The caller must commit (or use autocommit).
        ttl: Cache lifetime (default: 24 h).

    Returns:
        HTML fragment as string, or ``None`` if no provider matches
        or the fetch fails.
    """
    now = datetime.now(UTC)

    # ── DB-Cache-Lookup ────────────────────────────────────────────────────
    stmt = select(OEmbedCache).where(OEmbedCache.url == url)
    result = await db.execute(stmt)
    cached: OEmbedCache | None = result.scalar_one_or_none()

    if cached is not None and cached.expires_at.replace(tzinfo=UTC) > now:
        log.debug("oEmbed DB-Cache-Hit: %s", url)
        return cached.html

    # ── Determine provider ──────────────────────────────────────────────────────────────
    provider = _match_provider(url)
    if provider is None:
        log.debug("oEmbed: no provider for %s", url)
        return None

    # ── HTTP-Fetch ────────────────────────────────────────────────────────
    params = {**provider.extra_params, "url": url}
    endpoint_url = f"{provider.endpoint}?{urlencode(params)}"

    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            headers={"User-Agent": "ArborPress-oEmbed/1.0"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(endpoint_url)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        log.warning("oEmbed fetch failed for %s: %s", url, exc)
        return None

    raw_html: str = data.get("html", "")
    if not raw_html:
        log.debug("oEmbed: no 'html' in response for %s", url)
        return None

    clean_html = _strip_scripts(raw_html)
    expires = now + ttl

    # ── DB upsert ─────────────────────────────────────────────────────────
    if cached is not None:
        cached.html = clean_html
        cached.provider_name = provider.name
        cached.fetched_at = now
        cached.expires_at = expires
    else:
        db.add(OEmbedCache(
            id=str(uuid.uuid4()),
            url=url,
            provider_name=provider.name,
            html=clean_html,
            fetched_at=now,
            expires_at=expires,
        ))

    log.info("oEmbed gespeichert: %s (%s)", url, provider.name)
    return clean_html
