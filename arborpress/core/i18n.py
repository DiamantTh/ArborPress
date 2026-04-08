"""I18N / localization (§7 Internationalization).

Supported routing modes (§7 / config [web].i18n_mode):
  - "single"  – no language prefix, language from Accept-Language header
  - "prefix"  – /de/…, /en/…  (full language routes)

Translations are stored as GNU gettext .po/.mo files under
  arborpress/translations/<lang>/LC_MESSAGES/arborpress.mo

To extract:
  pybabel extract -F babel.cfg -o translations/messages.pot .
  pybabel init -l de -i translations/messages.pot -d translations
  pybabel compile -d translations
"""

from __future__ import annotations

import logging
from pathlib import Path

from quart import g, request

log = logging.getLogger("arborpress.i18n")

# Supported languages – extended via plugin capability (§15)
_SUPPORTED: set[str] = {"de", "en"}

# Root directory for .mo files
_TRANSLATIONS_DIR = Path(__file__).parent.parent / "translations"


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def detect_language(default: str = "de") -> str:
    """Determine the active language for the current request.

    Order (§7):
    1. URL prefix (when i18n_mode="prefix"):  /de/page  → "de"
    2. _lang cookie (user preference)
    3. Accept-Language header (browser)
    4. Configured default
    """
    from arborpress.core.config import get_settings
    cfg = get_settings()

    # 1. URL-Prefix
    if cfg.web.i18n_mode == "prefix":
        path = request.path
        parts = path.lstrip("/").split("/", 1)
        if parts and parts[0] in _SUPPORTED:
            return parts[0]

    # 2. Cookie
    lang_cookie = request.cookies.get("_lang", "")
    if lang_cookie in _SUPPORTED:
        return lang_cookie

    # 3. Accept-Language
    best = request.accept_languages.best_match(list(_SUPPORTED))
    if best:
        # Primary code only (de-AT → de)
        code = best.split("-")[0].lower()
        if code in _SUPPORTED:
            return code

    return default


def get_lang() -> str:
    """Return the language of the current request (from `g`)."""
    return getattr(g, "lang", "de")


# ---------------------------------------------------------------------------
# Quart before-request hook
# ---------------------------------------------------------------------------


async def i18n_before_request() -> None:
    """Set g.lang for every request."""
    from arborpress.core.config import get_settings
    g.lang = detect_language(get_settings().web.default_lang)


# ---------------------------------------------------------------------------
# Simple translation function (gettext-compatible)
# ---------------------------------------------------------------------------

_cache: dict[str, dict[str, str]] = {}  # lang → {msgid: msgstr}


def _load_translations(lang: str) -> dict[str, str]:
    """Load .po file as a simple dict (fallback when no .mo is compiled)."""
    if lang in _cache:
        return _cache[lang]

    po_path = _TRANSLATIONS_DIR / lang / "LC_MESSAGES" / "arborpress.po"
    translations: dict[str, str] = {}

    if po_path.exists():
        # Minimal parser for .po files (msgid + msgstr pairs only)
        msgid = ""
        in_msgstr = False
        for line in po_path.read_text("utf-8").splitlines():
            line = line.strip()
            if line.startswith("msgid "):
                msgid = line[7:].strip('"')
                in_msgstr = False
            elif line.startswith("msgstr "):
                val = line[8:].strip('"')
                if msgid:
                    translations[msgid] = val or msgid
                in_msgstr = True
            elif line.startswith('"') and in_msgstr:
                if msgid in translations:
                    translations[msgid] += line.strip('"')

    _cache[lang] = translations
    return translations


def gettext(msgid: str, lang: str | None = None) -> str:
    """Translate msgid into the given or current language."""
    if lang is None:
        lang = get_lang()
    t = _load_translations(lang)
    return t.get(msgid, msgid)


# Short alias for templates
_ = gettext


# ---------------------------------------------------------------------------
# Helper functions for URL prefix mode
# ---------------------------------------------------------------------------


def url_for_lang(lang: str, endpoint: str, **values: object) -> str:
    """Build a URL in prefix mode (§7)."""
    from quart import url_for as _url_for
    url = _url_for(endpoint, **values)
    return f"/{lang}{url}"


def register_i18n(app: object) -> None:
    """Register the before-request hook on the Quart app (§7)."""
    import quart
    assert isinstance(app, quart.Quart)
    app.before_request(i18n_before_request)
    # Make translation function available as Jinja2 global
    app.jinja_env.globals["_"] = gettext
    app.jinja_env.globals["get_lang"] = get_lang
    log.debug("I18N registered (§7)")
