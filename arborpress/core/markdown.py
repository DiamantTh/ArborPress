"""Markdown → HTML Rendering (§1).

Verwendet markdown-it-py (MIT) mit bleach-Sanitization (§10).

Aktivierte Plugins:
  - table          – GFM-Tabellen
  - strikethrough  – ~~Text~~
  - tasklist       – [ ] / [x] Checklisten

Oeffentliche API
  render_md(text)         – sync, Markdown → sanitisiertes HTML.
  render_md_async(text, db=None) – async, render_md + oEmbed-Shortcodes aufloesen
                               + externe Bilder lokal speichern (wenn db übergeben).

Embed-Shortcode im Markdown::

    {{embed:https://twitter.com/user/status/123}}
    {{embed:https://www.youtube.com/watch?v=xyz}}

  ArborPress holt oEmbed-HTML serverseitig, entfernt <script>-Tags,
  cached Ergebnis auf Disk (TTL: 24 h). Kein JS-Request des Besuchers.
"""

from __future__ import annotations

import asyncio
import logging
import re

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

    return clean_html


async def render_md_async(text: str, db=None) -> str:
    """Async-Variante von render_md mit oEmbed-Shortcode-Aufloesung.

    Ablauf:
      1. ``{{embed:url}}``-Muster aus Text extrahieren, Platzhalter einfuegen.
      2. Synchrones render_md() auf den verbleibenden Text anwenden.
      2b. Externe <img>-URLs herunterladen und lokal speichern (wenn db übergeben).
      3. Alle Platzhalter durch gecachtes oEmbed-HTML ersetzen.

    Der Schritt 1+3 stellt sicher, dass oEmbed-HTML nicht durch markdown-it
    prozessiert oder durch bleach sanitisiert wird.

    Args:
        text: Markdown-Text, kann ``{{embed:url}}``-Shortcodes enthalten.
        db:   Aktive AsyncSession für Bild-Download + oEmbed-DB-Cache.
              ``None`` = Preview-Modus (kein Download, Embeds als Fallback-Link).

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

    # Schritt 2b: Externe Bilder herunterladen (Mastodon-Ansatz)
    if db is not None:
        rendered = await _fetch_and_replace_imgs(rendered, db)

    if not embed_urls:
        return rendered  # Kein Embed → fertig

    if db is None:
        # Preview-Modus: Platzhalter durch Fallback-Link ersetzen
        for key, url in placeholder_map.items():
            fallback = (
                f'<p class="ap-embed-fallback">'
                f'<a href="{url}" rel="noopener noreferrer" target="_blank">{url}</a>'
                f'</p>'
            )
            rendered = rendered.replace(f"<p>{key}</p>", fallback)
            rendered = rendered.replace(key, fallback)
        return rendered

    # Schritt 3: Embeds holen (parallel) und einsetzen
    try:
        from arborpress.core.oembed import get_embed_html
    except Exception:
        return rendered  # Fallback: Platzhalter im Text belassen

    # Alle Fetches parallel starten
    fetch_tasks = [
        get_embed_html(url, db)
        for url in embed_urls
    ]
    results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

    for key, result in zip(placeholder_map, results, strict=False):
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
# Externe Bilder herunterladen (Mastodon-Ansatz)
# ---------------------------------------------------------------------------

_EXT_IMG_RE = re.compile(
    r'<img\b([^>]*)\bsrc="(https?://[^"]*)"([^>]*)>', re.IGNORECASE
)


async def _fetch_and_replace_imgs(html: str, db) -> str:
    """Lädt externe <img>-URLs herunter und ersetzt src durch lokale URL.

    Verwendet ``download_and_store`` aus ``image_fetch`` – gleiche Logik
    wie Mastodon: einmaliger Server-Download, Besucher bekommt nur die
    lokale ``/media/``-URL.
    """
    from arborpress.core.image_fetch import download_and_store

    matches = list(_EXT_IMG_RE.finditer(html))
    if not matches:
        return html

    for m in matches:
        before, ext_url, after = m.group(1), m.group(2), m.group(3)
        try:
            local_url = await download_and_store(ext_url, db)
        except Exception:
            local_url = None
        if local_url:
            html = html.replace(
                m.group(0),
                f'<img{before}src="{local_url}"{after}>',
                1,
            )

    return html


# ---------------------------------------------------------------------------
# oEmbed-Shortcode  {{embed:https://...}}
# ---------------------------------------------------------------------------

_EMBED_RE = re.compile(r"\{\{embed:(https?://[^}]+)\}\}", re.IGNORECASE)
