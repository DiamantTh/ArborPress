"""oEmbed-Fetch mit Datenbank-Cache für externe Post-Einbettungen.

Architektur (Mastodon-Ansatz)
-----------------------------
Der Autor schreibt im Markdown::

    {{embed:https://twitter.com/user/status/123}}

``render_md_async()`` erkennt das Muster und fragt ``get_embed_html()`` ab:

1. DB-Cache vorhanden und nicht abgelaufen → sofort zurückgeben (kein Netz).
2. Cache-Miss → httpx-Request an oEmbed-Endpoint des Anbieters.
3. ``<script>``, ``<noscript>`` und ``<iframe>``-Tags werden **entfernt**.
4. Sanitisiertes HTML in der DB persistieren (Standard-TTL: 24 h).

DSGVO-Konformität
-----------------
Kein Browser-Request landet bei Twitter / Meta / Google.
Der ArborPress-Server holt das Embed-HTML einmalig serverseitig.
Ohne ``<script src="platform.twitter.com/...">`` sieht der Besucher
ein statisches ``<blockquote>``-Element – kein Tracking, kein Cookie.
Facebook-/Instagram-``<iframe>``-Embeds werden vollständig entfernt;
der Fallback in ``render_md_async`` liefert einen Textlink.

Unterstützte Anbieter
---------------------
- Twitter / X   (twitter.com, x.com)
- YouTube       (youtube.com, youtu.be)
- Vimeo         (vimeo.com)
- Instagram     (instagram.com – öffentliche Posts, kein Token erforderlich)
- Mastodon      (beliebige Instanz via /api/oembed)
- Bluesky       (bsky.app)

Eigene Provider via ``register_provider()`` hinzufügbar.
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

# ─── Typen ────────────────────────────────────────────────────────────────────


class OEmbedProvider(NamedTuple):
    """Beschreibt einen oEmbed-Anbieter."""
    name: str
    # Regex auf die Post-URL (nicht den oEmbed-Endpoint)
    url_pattern: re.Pattern
    # Basis-URL des oEmbed-Endpoints
    endpoint: str
    # Zusätzliche Query-Params (z.B. omit_script=1 bei Twitter)
    extra_params: dict[str, str] = {}


# ─── Bekannte Anbieter ─────────────────────────────────────────────────────────

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
    """Registriert einen zusätzlichen oEmbed-Anbieter (Plugin-Hook)."""
    _PROVIDERS.append(provider)


def _match_provider(url: str) -> OEmbedProvider | None:
    """Gibt den passenden Anbieter für *url* zurück, oder None."""
    for p in _PROVIDERS:
        if p.url_pattern.match(url):
            return p

    # Mastodon: generischer Fallback für beliebige Instanzen
    parsed = urlparse(url)
    if parsed.path.startswith("/@") or "/objects/" in parsed.path:
        return OEmbedProvider(
            name=f"Mastodon ({parsed.netloc})",
            url_pattern=re.compile(re.escape(url)),
            endpoint=f"https://{parsed.netloc}/api/oembed",
            extra_params={},
        )
    return None


# ─── HTML-Bereinigung ─────────────────────────────────────────────────────────

_SCRIPT_RE = re.compile(
    r"<(script|noscript|iframe)[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE
)


def _strip_scripts(html: str) -> str:
    """Entfernt alle <script>-, <noscript>- und <iframe>-Tags (inkl. Inhalt)."""
    return _SCRIPT_RE.sub("", html).strip()


# ─── Kern-Logik (DB-Cache) ────────────────────────────────────────────────────

_DEFAULT_TTL: timedelta = timedelta(hours=24)
_TIMEOUT: float = 8.0


async def get_embed_html(
    url: str,
    db: AsyncSession,
    ttl: timedelta = _DEFAULT_TTL,
) -> str | None:
    """Gibt sanitisiertes oEmbed-HTML für *url* zurück.

    Der Abruf erfolgt einmalig serverseitig; das Ergebnis wird in der DB
    gespeichert (``oembed_cache``-Tabelle).  Kein Browser-Request an Dritte.

    Args:
        url: Öffentliche Post-URL (Twitter, YouTube, …).
        db:  Aktive AsyncSession – wird für Lesen **und** Schreiben genutzt.
             Der Aufrufer muss committen (oder autocommit verwenden).
        ttl: Cache-Lebensdauer (Standard: 24 h).

    Returns:
        HTML-Fragment als String, oder ``None`` wenn kein Anbieter passt
        oder der Fetch fehlschlägt.
    """
    now = datetime.now(UTC)

    # ── DB-Cache-Lookup ────────────────────────────────────────────────────
    stmt = select(OEmbedCache).where(OEmbedCache.url == url)
    result = await db.execute(stmt)
    cached: OEmbedCache | None = result.scalar_one_or_none()

    if cached is not None and cached.expires_at.replace(tzinfo=UTC) > now:
        log.debug("oEmbed DB-Cache-Hit: %s", url)
        return cached.html

    # ── Anbieter bestimmen ────────────────────────────────────────────────
    provider = _match_provider(url)
    if provider is None:
        log.debug("oEmbed: kein Anbieter für %s", url)
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
        log.warning("oEmbed-Fetch fehlgeschlagen für %s: %s", url, exc)
        return None

    raw_html: str = data.get("html", "")
    if not raw_html:
        log.debug("oEmbed: kein 'html' in Antwort für %s", url)
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
