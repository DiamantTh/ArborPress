"""oEmbed-Proxy und Disk-Cache für externe Post-Einbettungen.

Architektur
-----------
Der Autor schreibt im Markdown::

    {{embed:https://twitter.com/user/status/123}}

``render_md_async()`` erkennt das Muster, fragt ``get_embed_html()`` ab:

1. Disk-Cache vorhanden und nicht abgelaufen → sofort zurückgeben.
2. Cache-Miss → httpx-Request an oEmbed-Endpoint des Anbieters.
3. ``<script>``-Tags werden aus der Antwort **entfernt**.
4. Sanitisiertes HTML auf Disk cachen (Standard-TTL: 24 h).

DSGVO-Konformität
-----------------
Kein Browser-Request landet bei Twitter / Meta / Google.
Der ArborPress-Server holt die Embed-HTML einmalig serverseitig.
Das entfernte ``<script src="platform.twitter.com/widgets.js">`` bedeutet:
Der Besucher sieht ein statisches ``<blockquote>``-Element (Text + ggf. Bild)
ohne interaktives Widget – kein Tracking, kein First-/Third-Party-Cookie.

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

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from datetime import timedelta
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlencode, urlparse

import httpx

log = logging.getLogger("arborpress.oembed")

# ─── Typen ────────────────────────────────────────────────────────────────────


class OEmbedProvider(NamedTuple):
    """Beschreibt einen oEmbed-Anbieter."""
    name: str
    # Regex auf die Post-URL (nicht den oEmbed-Endpoint)
    url_pattern: re.Pattern
    # Format-String; {url} wird durch die encoded URL ersetzt
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
    # (Mastodon-Instanzen servieren /api/oembed?url=...)
    parsed = urlparse(url)
    if parsed.path.startswith("/@") or "/objects/" in parsed.path:
        return OEmbedProvider(
            name=f"Mastodon ({parsed.netloc})",
            url_pattern=re.compile(re.escape(url)),
            endpoint=f"https://{parsed.netloc}/api/oembed",
            extra_params={},
        )
    return None


# ─── Cache ────────────────────────────────────────────────────────────────────

_DEFAULT_TTL: timedelta = timedelta(hours=24)
_TIMEOUT: float = 8.0


def _cache_paths(cache_dir: Path, url: str) -> tuple[Path, Path]:
    """Gibt (html_path, meta_path) für *url* zurück."""
    digest = hashlib.sha256(url.encode()).hexdigest()
    base = cache_dir / "oembed" / digest[:2] / digest
    return base.with_suffix(".html"), base.with_suffix(".meta.json")


def _cache_valid(meta_path: Path, ttl: timedelta = _DEFAULT_TTL) -> bool:
    """True wenn die Cache-Datei existiert und nicht abgelaufen ist."""
    if not meta_path.exists():
        return False
    try:
        meta = json.loads(meta_path.read_text())
        return time.time() < meta.get("expires_at", 0)
    except (json.JSONDecodeError, OSError):
        return False


def _write_cache(html_path: Path, meta_path: Path, html: str, ttl: timedelta) -> None:
    """Schreibt HTML + Meta-JSON atomar (sync, für asyncio.to_thread)."""
    html_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_html = html_path.with_suffix(".tmp")
    tmp_html.write_text(html, encoding="utf-8")
    os.replace(tmp_html, html_path)

    meta = {"expires_at": time.time() + ttl.total_seconds()}
    tmp_meta = meta_path.with_suffix(".tmp")
    tmp_meta.write_text(json.dumps(meta), encoding="utf-8")
    os.replace(tmp_meta, meta_path)


# ─── HTML-Bereinigung ─────────────────────────────────────────────────────────

_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script\s*>", re.DOTALL | re.IGNORECASE)
_NOSCRIPT_RE = re.compile(r"<noscript[^>]*>.*?</noscript\s*>", re.DOTALL | re.IGNORECASE)


def _strip_scripts(html: str) -> str:
    """Entfernt alle <script>- und <noscript>-Tags aus dem HTML-String."""
    html = _SCRIPT_RE.sub("", html)
    html = _NOSCRIPT_RE.sub("", html)
    return html.strip()


# ─── Kern-Logik ───────────────────────────────────────────────────────────────


async def get_embed_html(
    url: str,
    cache_dir: Path,
    ttl: timedelta = _DEFAULT_TTL,
) -> str | None:
    """Gibt sanitisiertes oEmbed-HTML für *url* zurück.

    Args:
        url:       Öffentlich zugänglicher Post-URL (Twitter, YouTube, …).
        cache_dir: Verzeichnis für den Disk-Cache.
        ttl:       Cache-Lebensdauer (Standard: 24 h).

    Returns:
        HTML-Fragment als String, oder ``None`` wenn kein Anbieter passt
        oder der Fetch fehlschlägt.
    """
    provider = _match_provider(url)
    if provider is None:
        log.debug("oEmbed: kein Anbieter für %s", url)
        return None

    html_path, meta_path = _cache_paths(cache_dir, url)

    # Cache-Hit
    if _cache_valid(meta_path, ttl):
        try:
            return html_path.read_text(encoding="utf-8")
        except OSError:
            pass  # Datei fehlt → neu holen

    # Cache-Miss → Fetch
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
    log.info("oEmbed gecacht: %s (%s)", url, provider.name)

    await asyncio.to_thread(_write_cache, html_path, meta_path, clean_html, ttl)
    return clean_html
