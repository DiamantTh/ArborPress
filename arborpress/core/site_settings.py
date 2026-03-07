"""Zugriff auf DB-gespeicherte Site-Einstellungen.

Alle nicht-infrastrukturellen Konfigurationswerte werden hier verwaltet.
config.toml enthält nur noch: [db], [web] (host/port/secret), [auth], [logging], [plugins].

Sektionen und ihre Defaults:
  general    – Blog-Titel, Beschreibung, Sprache, Posts/Seite
  theme      – Aktives Theme, externer Themes-Ordner
  mail       – SMTP-Backend, Host, Port, Credentials, From-Adresse
  comments   – Moderation, E-Mail-Bestätigung, Rate-Limit
  captcha    – Typ, eigene Fragen, Provider-Keys
  federation – ActivityPub-Modus, Instanzname
  search     – FTS-Provider

Öffentliche API (async):
  get_section(section, db)                → dict (Defaults + DB merged)
  save_section(section, data, db, by="") → None
  invalidate_cache(section=None)         → None

Sync-Hilfsfunktionen:
  get_defaults(section)  → dict  (nur Defaults, ohne DB)
  get_cached(section)    → dict | None  (nur Cache, None wenn nicht befüllt)
"""

from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger("arborpress.site_settings")

# ---------------------------------------------------------------------------
# Defaults – werden mit DB-Werten gemergt (DB überschreibt Defaults)
# ---------------------------------------------------------------------------

_DEFAULTS: dict[str, dict[str, Any]] = {
    "general": {
        "site_title":       "ArborPress Blog",
        "site_description": "",
        "site_language":    "de",
        "posts_per_page":   10,
    },
    "theme": {
        "active":          "default",
        "themes_dir":      "themes",      # relativ zum Arbeitsverzeichnis
        "auto_dark":       False,          # automatisch Dark-Companion ab/bis Uhrzeit aktivieren
        "auto_dark_start": 19,             # Stunde (0–23), ab der das Dark-Theme gilt
        "auto_dark_end":   6,              # Stunde (0–23), bis zu der das Dark-Theme gilt
        # Hintergrundmuster-Override ("auto" = Theme-eigene --bg-pattern-Variable)
        "bg_pattern":       "auto",        # none | auto | hexagon | diamond | triangle | ...
        "bg_pattern_color": "",            # Hex-Farbe, leer = Theme-Akzentfarbe
        "bg_pattern_opacity": 0.07,        # 0–1
    },
    "mail": {
        "backend":          "none",   # smtp | console | none
        "smtp_host":        "localhost",
        "smtp_port":        587,
        "smtp_user":        "",
        "smtp_password":    "",       # wird NICHT im Browser angezeigt
        "smtp_tls":         False,    # echte TLS (Port 465)
        "smtp_starttls":    True,     # STARTTLS-Upgrade (Port 587)
        "from_address":     "noreply@example.com",
        "from_name":        "ArborPress",
        "pgp_sign_enabled": False,
        "pgp_signing_key_id": "",
        "max_retries":      5,
        "retry_backoff_base": 60,
    },
    "comments": {
        "enabled":                   True,
        "require_email_confirmation": True,
        "require_admin_approval":     True,
        "notify_admin_email":         "",
        "rate_limit_per_hour":        10,
        "blocklist":                  "",   # Zeilengetrennte Schlüsselwörter / E-Mails / IPs
    },
    "captcha": {
        "default_type": "custom",   # none|math|custom|hcaptcha|friendly_captcha|…
        "custom_questions": [
            {"q": "Wie heißt dieses CMS?",             "a": "arborpress"},
            {"q": "Welche Farbe hat Gras?",             "a": "grün"},
            {"q": "Wie viele Beine hat eine Katze?",   "a": "4"},
            {"q": "Was ist das Gegenteil von schwarz?","a": "weiß"},
            {"q": "Wie viele Tage hat eine Woche?",    "a": "7"},
        ],
        # hCaptcha
        "hcaptcha_site_key":   "",
        "hcaptcha_secret":     "",
        "hcaptcha_verify_url": "https://api.hcaptcha.com/siteverify",
        # Friendly Captcha
        "friendly_sitekey":   "",
        "friendly_api_key":   "",
        "friendly_verify_url": "https://global.frcapi.com/api/v2/captcha/siteverify",
        # ALTCHA (selbstgehostet, kein externer Dienst)
        "altcha_hmac_key":    "",
        "altcha_max_number":  1_000_000,
        "altcha_algorithm":   "SHA-256",
        # mCaptcha
        "mcaptcha_site_key":  "",
        "mcaptcha_secret":    "",
        "mcaptcha_url":       "",
        # mosparo
        "mosparo_url":         "",
        "mosparo_public_key":  "",
        "mosparo_private_key": "",
        # Cloudflare Turnstile
        "turnstile_site_key":  "",
        "turnstile_secret":    "",
        "turnstile_verify_url": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    },
    "federation": {
        "mode":                 "disabled",   # full|outgoing_only|inbox_only|disabled
        "instance_name":        "ArborPress",
        "instance_description": "",
        "contact_email":        "",
        "allowlist_mode":       False,
    },
    "search": {
        "provider": "auto",   # auto|pg_fts|mariadb_fulltext|fallback
    },
    "demo": {
        "enabled":        False,   # Demo-Modus: Besucher können Theme wechseln
        "show_banner":    True,    # Hinweis-Banner oben anzeigen
        "allow_all_themes": True,  # Alle Themes zeigen (auch Dark-Only)
    },
}

# ---------------------------------------------------------------------------
# In-Memory-Cache (section → merged dict)
# ---------------------------------------------------------------------------

_cache: dict[str, dict[str, Any]] = {}


def get_defaults(section: str) -> dict[str, Any]:
    """Gibt die Hard-coded Defaults einer Sektion zurück (synchron, ohne DB)."""
    return dict(_DEFAULTS.get(section, {}))


def get_cached(section: str) -> dict[str, Any] | None:
    """Gibt die gecachte Version zurück, oder None wenn nicht im Cache."""
    return _cache.get(section)


def invalidate_cache(section: str | None = None) -> None:
    """Cache leeren – nach einem Speichern oder Anwendungsstart."""
    if section:
        _cache.pop(section, None)
    else:
        _cache.clear()


# ---------------------------------------------------------------------------
# Async DB-Operationen
# ---------------------------------------------------------------------------

async def get_section(section: str, db: Any) -> dict[str, Any]:
    """Liest eine Einstellungssektion aus der DB.

    Merged DB-Werte mit Defaults (DB überschreibt). Cached in Memory.
    Wirft keine Exception bei DB-Fehler – fällt auf Defaults zurück.
    """
    if section in _cache:
        return dict(_cache[section])

    merged = dict(_DEFAULTS.get(section, {}))

    try:
        from sqlalchemy import select
        from arborpress.models.settings import SiteSetting

        result = await db.execute(
            select(SiteSetting).where(SiteSetting.key == section)
        )
        row = result.scalar_one_or_none()
        if row and row.value:
            stored = json.loads(row.value)
            merged.update(stored)
    except Exception as exc:
        log.warning("SiteSettings.get_section(%r) DB-Fehler (nutze Defaults): %s", section, exc)

    _cache[section] = merged
    return dict(merged)


async def save_section(
    section: str,
    data: dict[str, Any],
    db: Any,
    updated_by: str = "",
) -> None:
    """Speichert eine Einstellungssektion in der DB.

    Mergt mit Defaults (DB enthält nur explizit gesetzte Werte).
    Leert den Cache für diese Sektion nach dem Speichern.
    """
    from sqlalchemy import select
    from arborpress.models.settings import SiteSetting

    try:
        result = await db.execute(
            select(SiteSetting).where(SiteSetting.key == section)
        )
        row = result.scalar_one_or_none()
        payload = json.dumps(data, ensure_ascii=False, indent=None)

        if row:
            row.value      = payload
            row.updated_by = updated_by or None
        else:
            db.add(SiteSetting(key=section, value=payload, updated_by=updated_by or None))

        await db.commit()

        # Cache aktualisieren
        merged = dict(_DEFAULTS.get(section, {}))
        merged.update(data)
        _cache[section] = merged

        log.info("SiteSettings gespeichert | section=%s by=%s", section, updated_by)
    except Exception as exc:
        log.error("SiteSettings.save_section(%r) Fehler: %s", section, exc)
        raise
