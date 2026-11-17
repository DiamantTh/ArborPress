"""I18N / localization (§7 Internationalization).

Supported routing modes (§7 / config [web].i18n_mode):
  - "single"  – no language prefix, language from Accept-Language header
  - "prefix"  – /de/…, /en/…  (full language routes)

Translations are stored as GNU gettext .po/.mo files under
  arborpress/translations/<lang_underscore>/LC_MESSAGES/arborpress.mo
  (BCP 47 hyphen is converted to underscore for the filesystem path,
   e.g. de-DE → de_DE)

To extract:
  pybabel extract -F babel.cfg -o translations/messages.pot .
  pybabel init -l de_DE -i translations/messages.pot -d translations
  pybabel compile -d translations
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from babel.support import NullTranslations, Translations
from quart import g, request

log = logging.getLogger("arborpress.i18n")

# Supported languages as BCP 47 tags (language-REGION) – extended via plugin capability (§15)
_SUPPORTED: set[str] = {
    "de-DE",  # Deutsch
    "en-GB",  # English
    "fr-FR",  # Français
    "es-ES",  # Español
    "it-IT",  # Italiano
    "nl-NL",  # Nederlands
    "pl-PL",  # Polski
}


def normalize_language(value: str | None) -> str | None:
    """Return the configured BCP-47 tag for a supported language spelling."""
    if not value:
        return None
    folded = value.replace("_", "-").casefold()
    exact = next((item for item in _SUPPORTED if item.casefold() == folded), None)
    if exact:
        return exact
    if "-" not in folded:
        base_matches = [item for item in _SUPPORTED if item.split("-", 1)[0].casefold() == folded]
        if len(base_matches) == 1:
            return base_matches[0]
    return None


def supported_languages() -> tuple[str, ...]:
    """Stable, sorted list of languages accepted by public prefix routes."""
    return tuple(sorted(_SUPPORTED))


def language_storage_values(value: str) -> tuple[str, ...]:
    """Return canonical locale plus unambiguous legacy base-language values."""
    normalized = normalize_language(value)
    if normalized is None:
        return ()
    aliases = tuple(
        item.split("-", 1)[0]
        for item in supported_languages()
        if item.split("-", 1)[0] != item and normalize_language(item.split("-", 1)[0]) == normalized
    )
    return (normalized, *aliases)


# Root directory for .mo files
_TRANSLATIONS_DIR = Path(__file__).parent.parent / "translations"


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def detect_language(default: str = "de-DE") -> str:
    """Determine the active language for the current request.

    Returns a BCP 47 tag (e.g. "de-DE", "en-GB").

    Order (§7):
    1. URL prefix (when i18n_mode="prefix"):  /de-DE/page  → "de-DE"
    2. _lang cookie (user preference)
    3. Accept-Language header (browser, Werkzeug handles BCP 47 natively)
    4. Configured default
    """
    from arborpress.core.config import get_settings

    cfg = get_settings()

    # 1. URL-Prefix
    if cfg.web.i18n_mode == "prefix":
        path = request.path
        parts = path.lstrip("/").split("/", 1)
        if parts:
            language = normalize_language(parts[0])
            if language:
                return language

    # 2. Cookie
    lang_cookie = request.cookies.get("_lang", "")
    normalized_cookie = normalize_language(lang_cookie)
    if normalized_cookie:
        return normalized_cookie

    # 3. Accept-Language – Werkzeug best_match vergleicht BCP 47 nativ
    best = request.accept_languages.best_match(list(_SUPPORTED))
    if best:
        return normalize_language(best) or best

    return normalize_language(default) or "de-DE"


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
# Translation runtime (babel.support.Translations)
# ---------------------------------------------------------------------------

_cache: dict[str, NullTranslations] = {}  # lang → Translations object


def _load_translations(lang: str) -> NullTranslations:
    """Load compiled .mo (or fall back to .po) for *lang* via Babel."""
    if lang in _cache:
        return _cache[lang]

    # pybabel uses underscores for locale dirs: de-DE → de_DE
    fs_lang = lang.replace("-", "_")
    t = Translations.load(_TRANSLATIONS_DIR, [fs_lang], domain="arborpress")
    _cache[lang] = t
    return t


def gettext(msgid: str, lang: str | None = None) -> str:
    """Translate *msgid* into the given or current language."""
    if lang is None:
        lang = get_lang()
    return _load_translations(lang).gettext(msgid)


# Short alias for templates / web
_ = gettext


# ---------------------------------------------------------------------------
# CLI translation helper (no request context required)
# ---------------------------------------------------------------------------


def _cli_lang() -> str:
    """Determine language for CLI output.

    Priority:
    1. ARBORPRESS_LANG environment variable  (e.g. ``export ARBORPRESS_LANG=de-DE``)
    2. configured default_lang from config.toml
    3. hard-coded fallback "de-DE"
    """
    env = os.environ.get("ARBORPRESS_LANG", "").strip()
    if env in _SUPPORTED:
        return env
    try:
        from arborpress.core.config import get_settings

        lang = get_settings().web.default_lang
        if lang in _SUPPORTED:
            return lang
    except OSError, ValueError:
        return "de-DE"
    return "de-DE"


def cli_gettext(msgid: str) -> str:
    """Translate *msgid* for CLI output (no Quart request context needed)."""
    return _load_translations(_cli_lang()).gettext(msgid)


# Short alias for CLI modules
__ = cli_gettext


# ---------------------------------------------------------------------------
# Helper functions for URL prefix mode
# ---------------------------------------------------------------------------


def url_for_lang(lang: str, endpoint: str, **values: object) -> str:
    """Build a language-aware public route without prefixing protocols."""
    from arborpress.web.public_urls import public_path

    return public_path(endpoint, lang=lang, **values)


def register_i18n(app: object) -> None:
    """Register the before-request hook on the Quart app (§7)."""
    import quart

    assert isinstance(app, quart.Quart)
    app.before_request(i18n_before_request)
    # Make translation function available as Jinja2 global
    app.jinja_env.globals["_"] = gettext
    app.jinja_env.globals["get_lang"] = get_lang
    log.debug("I18N registered (§7)")
