"""Markdown → HTML Rendering (§1).

Verwendet markdown-it-py (MIT) mit bleach-Sanitization (§10).

Aktivierte Plugins:
  - table          – GFM-Tabellen
  - strikethrough  – ~~Text~~
  - tasklist       – [ ] / [x] Checklisten

Oeffentliche API
  render_md(text)         – sync, Markdown → sanitisiertes HTML.
                            Externe <img>-URLs → /proxy/img (wenn proxy_secret gesetzt).
  render_md_async(text)   – async, wie render_md + oEmbed-Shortcodes aufloesen.

Embed-Shortcode im Markdown::

    {{embed:https://twitter.com/user/status/123}}
    {{embed:https://www.youtube.com/watch?v=xyz}}

  ArborPress holt oEmbed-HTML serverseitig, entfernt <script>-Tags,
  cached Ergebnis auf Disk (TTL: 24 h). Kein JS-Request des Besuchers.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
from urllib.parse import urlencode

import bleach
from markdown_it import MarkdownIt

log = logging.getLogger("arborpress.markdown")

# ---------------------------------------------------------------------------
# Erlaubte HTML-Elemente nach dem Rendering (§10 XSS-Prävention)
# ---------------------------------------------------------------------------

_ALLOWED_TAGS: list[str] = [
    # Struktur & Text
    "p", "br", "hr",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "strong", "em", "del", "ins", "s",
    "blockquote", "pre", "code",
    # Listen
    "ul", "ol", "li",
    # Tabellen
    "table", "thead", "tbody", "tfoot", "tr", "th", "td",
    # Links & Medien
    "a", "img",
    # Code
    "kbd", "samp",
    # Tasklists
    "input",
    # Sonstiges
    "div", "span",
    "sup", "sub",
    "details", "summary",
]

_ALLOWED_ATTRS: dict[str, list[str]] = {
    "a":     ["href", "title", "rel", "target"],
    "img":   ["src", "alt", "title", "width", "height", "loading"],
    "code":  ["class"],
    "pre":   ["class"],
    "div":   ["class"],
    "span":  ["class"],
    "th":    ["align", "scope"],
    "td":    ["align"],
    "input": ["type", "checked", "disabled"],
}

_ALLOWED_PROTOCOLS: list[str] = ["http", "https", "mailto", "tel"]

# ---------------------------------------------------------------------------
# Markdown-it Instanz
# ---------------------------------------------------------------------------

_md = (
    MarkdownIt("gfm-like", {"html": False, "linkify": True, "typographer": True})
    .enable("table")
    .enable("strikethrough")
)

# Tasklists ([ ] / [x]) – mdit-py-plugins wenn vorhanden
try:
    from mdit_py_plugins.tasklists import tasklists_plugin
    _md = tasklists_plugin(_md)
except ImportError:
    pass  # optionale Dependency, kein Pflicht-Feature


# ---------------------------------------------------------------------------
# Öffentliche API
# ---------------------------------------------------------------------------


def render_md(text: str) -> str:
    """Rendert Markdown zu sanitisiertem HTML.

    Schritte:
      1. markdown-it-py wandelt MD → rohes HTML
      2. bleach entfernt nicht-erlaubte Tags/Attribute (§10)
      3. Links zu externen Domains erhalten rel="noopener noreferrer"

    Args:
        text: Markdown-Text.

    Returns:
        Sanitisiertes HTML als String.
    """
    if not text:
        return ""
    try:
        raw_html = _md.render(text)
    except Exception:
        log.exception("Markdown-Renderfehler")
        raw_html = f"<p>{bleach.clean(text)}</p>"

    clean_html = bleach.clean(
        raw_html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
    )

    # Externe Links sichern: rel="noopener noreferrer"
    clean_html = _add_link_rel(clean_html)

    # Externe Bilder durch lokalen Proxy routen
    try:
        from arborpress.core.config import get_settings
        _cfg = get_settings()
        clean_html = _rewrite_external_imgs(
            clean_html,
            _cfg.web.base_url,
            _cfg.web.proxy_secret.get_secret_value(),
        )
    except Exception:
        pass  # Proxy-Rewrite ist optional – nie den Render-Prozess abbrechen

    return clean_html


async def render_md_async(text: str) -> str:
    """Async-Variante von render_md mit oEmbed-Shortcode-Aufloesung.

    Ablauf:
      1. ``{{embed:url}}``-Muster aus Text extrahieren, Platzhalter einfuegen.
      2. Synchrones render_md() auf den verbleibenden Text anwenden.
      3. Alle Platzhalter durch gecachtes oEmbed-HTML ersetzen.

    Der Schritt 1+3 stellt sicher, dass oEmbed-HTML nicht durch markdown-it
    prozessiert oder durch bleach sanitisiert wird.

    Args:
        text: Markdown-Text, kann ``{{embed:url}}``-Shortcodes enthalten.

    Returns:
        Vollstaendig gerendertes, sanitisiertes HTML.
    """
    if not text:
        return ""

    # Schritt 1: Shortcodes extrahieren, Platzhalter einsetzen
    embed_urls: list[str] = []
    placeholder_map: dict[str, str] = {}

    def _extract(m: re.Match) -> str:
        url = m.group(1).strip()
        key = f"__EMBED_{len(embed_urls)}__"
        embed_urls.append(url)
        placeholder_map[key] = url
        return key  # Wird in Markdown als normaler Text durch render_md gerendert

    text_with_placeholders = _EMBED_RE.sub(_extract, text)

    # Schritt 2: Normales Markdown-Rendering
    rendered = render_md(text_with_placeholders)

    if not embed_urls:
        return rendered  # Kein Embed → fertig

    # Schritt 3: Embeds holen (parallel) und einsetzen
    try:
        from arborpress.core.config import get_settings
        from arborpress.core.oembed import get_embed_html
        _cfg = get_settings()
        cache_dir = _cfg.web.oembed_cache_dir
    except Exception:
        return rendered  # Fallback: Platzhalter im Text belassen

    # Alle Fetches parallel starten
    fetch_tasks = [
        get_embed_html(url, cache_dir)
        for url in embed_urls
    ]
    results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

    for key, result in zip(placeholder_map, results):
        url = placeholder_map[key]
        if isinstance(result, str) and result:
            embed_block = (
                f'<div class="ap-embed" data-provider-url="{url}">'
                f'{result}'
                f'</div>'
            )
        else:
            # Fallback: Link zur Original-URL
            embed_block = (
                f'<p class="ap-embed-fallback">'
                f'<a href="{url}" rel="noopener noreferrer" target="_blank">{url}</a>'
                f'</p>'
            )
        # Platzhalter kann als <p>__EMBED_0__</p> im gerenderten HTML stehen
        rendered = rendered.replace(f"<p>{key}</p>", embed_block)
        rendered = rendered.replace(key, embed_block)

    return rendered


def _add_link_rel(html: str) -> str:
    """Fügt rel="noopener noreferrer" und target="_blank" zu externen Links."""
    def _replace(m: re.Match) -> str:
        tag = m.group(0)
        href = re.search(r'href="([^"]*)"', tag)
        if href:
            url = href.group(1)
            if url.startswith(("http://", "https://")) and "noopener" not in tag:
                tag = tag.rstrip(">")
                tag += ' rel="noopener noreferrer" target="_blank">'
        return tag
    return re.sub(r'<a [^>]+>', _replace, html)


# ---------------------------------------------------------------------------
# Externer Bild-Proxy: automatisches Umschreiben von <img src="https://...">
# ---------------------------------------------------------------------------

_IMG_RE = re.compile(r'<img\b([^>]*)\bsrc="(https?://[^"]*)"([^>]*)>', re.IGNORECASE)


def _rewrite_external_imgs(html: str, base_url: str, secret: str) -> str:
    """Schreibt externe img-src-Attribute auf /proxy/img um.

    Signiert jeden URL mit HMAC-SHA256 (gleiche Logik wie image_proxy.py).
    Wenn kein ``secret`` gesetzt ist, wird nichts veraendert.
    """
    if not secret:
        return html

    def _replace(m: re.Match) -> str:
        before, ext_url, after = m.group(1), m.group(2), m.group(3)
        sig = hmac.new(secret.encode(), ext_url.encode(), hashlib.sha256).hexdigest()
        proxy = (
            f"{base_url.rstrip('/')}/proxy/img?"
            + urlencode({"url": ext_url, "sig": sig})
        )
        return f'<img{before}src="{proxy}"{after}>'

    return _IMG_RE.sub(_replace, html)


# ---------------------------------------------------------------------------
# oEmbed-Shortcode  {{embed:https://...}}
# ---------------------------------------------------------------------------

_EMBED_RE = re.compile(r"\{\{embed:(https?://[^}]+)\}\}", re.IGNORECASE)
