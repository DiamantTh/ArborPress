"""Markdown → HTML Rendering (§1).

Verwendet markdown-it-py (MIT) mit bleach-Sanitization (§10).

Aktivierte Plugins:
  - table          – GFM-Tabellen
  - strikethrough  – ~~Text~~
  - tasklist       – [ ] / [x] Checklisten

Öffentliche API:
  render_md(text: str) -> str   – Markdown → sanitisiertes HTML
"""

from __future__ import annotations

import logging

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


def _add_link_rel(html: str) -> str:
    """Fügt rel="noopener noreferrer" und target="_blank" zu externen Links."""
    import re
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
