"""I18N / Lokalisierung (§7 Internationalization).

Unterstützte Routing-Modes (§7 / config [web].i18n_mode):
  - "single"  – keine Sprach-Prefix, Sprache aus Accept-Language-Header
  - "prefix"  – /de/…, /en/…  (vollständige Sprach-Routes)

Übersetzungen liegen als GNU-gettext-.po/.mo-Dateien unter
  arborpress/translations/<lang>/LC_MESSAGES/arborpress.mo

Zum Extrahieren:
  pybabel extract -F babel.cfg -o translations/messages.pot .
  pybabel init -l de -i translations/messages.pot -d translations
  pybabel compile -d translations
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from quart import request, g

log = logging.getLogger("arborpress.i18n")

# Unterstützte Sprachen – erweitert via Plugin-Capability (§15)
_SUPPORTED: set[str] = {"de", "en"}

# Root für .mo-Dateien
_TRANSLATIONS_DIR = Path(__file__).parent.parent / "translations"


# ---------------------------------------------------------------------------
# Spracherkennung
# ---------------------------------------------------------------------------


def detect_language(default: str = "de") -> str:
    """Bestimmt die aktive Sprache für den aktuellen Request.

    Reihenfolge (§7):
    1. URL-Prefix (wenn i18n_mode="prefix"):  /de/seite  → "de"
    2. _lang-Cookie (User-Präferenz)
    3. Accept-Language-Header (Browser)
    4. Konfigurierter Default
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
        # Nur Primärcode (de-AT → de)
        code = best.split("-")[0].lower()
        if code in _SUPPORTED:
            return code

    return default


def get_lang() -> str:
    """Gibt die Sprache des aktuellen Requests zurück (aus `g`)."""
    return getattr(g, "lang", "de")


# ---------------------------------------------------------------------------
# Quart Before-Request-Hook
# ---------------------------------------------------------------------------


async def i18n_before_request() -> None:
    """Setzt g.lang für jeden Request."""
    from arborpress.core.config import get_settings
    g.lang = detect_language(get_settings().web.default_lang)


# ---------------------------------------------------------------------------
# Einfache Übersetzungs-Funktion (Gettext-kompatibel)
# ---------------------------------------------------------------------------

_cache: dict[str, dict[str, str]] = {}  # lang → {msgid: msgstr}


def _load_translations(lang: str) -> dict[str, str]:
    """Lädt .po-Datei als simples Dict (Fallback wenn kein .mo kompiliert)."""
    if lang in _cache:
        return _cache[lang]

    po_path = _TRANSLATIONS_DIR / lang / "LC_MESSAGES" / "arborpress.po"
    translations: dict[str, str] = {}

    if po_path.exists():
        # Minimalparser für .po-Dateien (nur msgid + msgstr Paare)
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
    """Übersetzt msgid in die angegebene oder aktuelle Sprache."""
    if lang is None:
        lang = get_lang()
    t = _load_translations(lang)
    return t.get(msgid, msgid)


# Kurz-Alias für Templates
_ = gettext


# ---------------------------------------------------------------------------
# Hilfsfunktionen für URL-Prefix-Mode
# ---------------------------------------------------------------------------


def url_for_lang(lang: str, endpoint: str, **values: object) -> str:
    """Baut eine URL im Prefix-Mode (§7)."""
    from quart import url_for as _url_for
    url = _url_for(endpoint, **values)
    return f"/{lang}{url}"


def register_i18n(app: object) -> None:
    """Registriert den Before-Request-Hook an der Quart-App (§7)."""
    import quart
    assert isinstance(app, quart.Quart)
    app.before_request(i18n_before_request)
    # Übersetzungsfunktion als Jinja2-Global bereitstellen
    app.jinja_env.globals["_"] = gettext
    app.jinja_env.globals["get_lang"] = get_lang
    log.debug("I18N registriert (§7)")
