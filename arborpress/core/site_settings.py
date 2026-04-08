"""Access to database-stored site settings.

All non-infrastructure configuration values are managed here.
config.toml only retains: [db], [web] (host/port/secret), [auth], [logging], [plugins].

Sections and their defaults:
  general    – blog title, description, language, posts per page
  theme      – active theme, external themes folder
  mail       – SMTP backend, host, port, credentials, from address
  comments   – moderation, e-mail confirmation, rate limit
  captcha    – type, custom questions, provider keys
  federation – ActivityPub mode, instance name
  search     – FTS provider

Public API (async):
  get_section(section, db)                → dict (defaults + DB merged)
  save_section(section, data, db, by="") → None
  invalidate_cache(section=None)         → None

Sync helpers:
  get_defaults(section)  → dict  (defaults only, without DB)
  get_cached(section)    → dict | None  (cache only, None if not populated)
"""

from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger("arborpress.site_settings")

# ---------------------------------------------------------------------------
# Defaults – merged with DB values (DB overrides defaults)
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
        "themes_dir":      "content/themes",      # relative to working directory
        "auto_dark":       False,          # automatically activate dark companion between hours
        "auto_dark_start": 19,             # hour (0–23) from which dark theme applies
        "auto_dark_end":   6,              # hour (0–23) until which dark theme applies
        # Background pattern override ("auto" = theme's own --bg-pattern variable)
        "bg_pattern":       "auto",        # none | auto | hexagon | diamond | triangle | ...
        "bg_pattern_color": "",            # hex color, empty = theme accent color
        "bg_pattern_opacity": 0.07,        # 0–1
    },
    "mail": {
        "backend":          "none",   # smtp | console | none
        "smtp_host":        "localhost",
        "smtp_port":        587,
        "smtp_user":        "",
        "smtp_password":    "",       # NOT displayed in the browser
        "smtp_tls":         False,    # real TLS (port 465)
        "smtp_starttls":    True,     # STARTTLS upgrade (port 587)
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
        "blocklist":                  "",   # newline-separated keywords / emails / IPs
    },
    "captcha": {
        "default_type": "custom",   # none|math|custom|hcaptcha|friendly_captcha|…
        "custom_questions": [
            {"q": "What is this CMS called?",        "a": "arborpress"},
            {"q": "What color is grass?",             "a": "green"},
            {"q": "How many legs does a cat have?",   "a": "4"},
            {"q": "What is the opposite of black?",   "a": "white"},
            {"q": "How many days does a week have?",  "a": "7"},
        ],
        # hCaptcha
        "hcaptcha_site_key":   "",
        "hcaptcha_secret":     "",
        "hcaptcha_verify_url": "https://api.hcaptcha.com/siteverify",
        # Friendly Captcha
        "friendly_sitekey":   "",
        "friendly_api_key":   "",
        "friendly_verify_url": "https://global.frcapi.com/api/v2/captcha/siteverify",
        # ALTCHA (self-hosted, no external service)
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
        # Visibility
        "followers_visible":           True,   # followers list publicly visible
        "following_visible":           True,   # following list publicly visible
        "allow_per_account_federation": True,  # accounts can opt out of fediverse
        # Follow control
        "require_approval_to_follow":  False,  # confirm follow requests manually
        # Content
        "federate_tags":               True,   # federate hashtag activities
        "federate_media":              False,  # send media attachments in AP objects
        "max_note_length":             500,    # character limit for AP notes/replies
        # Security
        "require_http_signature":      True,   # reject unsigned inbox requests
        "authorized_fetch":            False,  # outbox/actor only retrievable with signature
        "inbox_blocklist_domains":     [],     # domains from which no inbox is accepted
        "allowlist_mode":              False,  # only allowlisted domains accepted
    },
    "search": {
        # Provider: auto|pg_fts|mariadb_fulltext|sqlite_fts5
        #   |meilisearch|typesense|elasticsearch|manticore|fallback
        "provider": "auto",
        # Meilisearch
        "meilisearch_url":     "http://localhost:7700",
        "meilisearch_api_key": "",
        # Typesense
        "typesense_host":    "localhost",
        "typesense_port":    8108,
        "typesense_api_key": "",
        # Elasticsearch / OpenSearch
        "elasticsearch_url": "http://localhost:9200",
        # ManticoreSearch (MySQL-Protokoll)
        "manticore_url":     "mysql://localhost:9306",
    },
    "demo": {
        "enabled":        False,   # demo mode: visitors can switch themes
        "show_banner":    True,    # show info banner at the top
        "allow_all_themes": True,  # show all themes (including dark-only)
    },
}

# ---------------------------------------------------------------------------
# In-memory cache (section → merged dict)
# ---------------------------------------------------------------------------

_cache: dict[str, dict[str, Any]] = {}


def get_defaults(section: str) -> dict[str, Any]:
    """Return the hard-coded defaults for a section (synchronous, no DB)."""
    return dict(_DEFAULTS.get(section, {}))


def get_cached(section: str) -> dict[str, Any] | None:
    """Return the cached version, or None if not in cache."""
    return _cache.get(section)


def invalidate_cache(section: str | None = None) -> None:
    """Clear cache – after a save or on application start."""
    if section:
        _cache.pop(section, None)
    else:
        _cache.clear()


# ---------------------------------------------------------------------------
# Async DB operations
# ---------------------------------------------------------------------------

async def get_section(section: str, db: Any) -> dict[str, Any]:
    """Read a settings section from the DB.

    Merges DB values with defaults (DB overrides). Cached in memory.
    Does not raise on DB error – falls back to defaults.
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
        log.warning("SiteSettings.get_section(%r) DB error (using defaults): %s", section, exc)

    _cache[section] = merged
    return dict(merged)


async def save_section(
    section: str,
    data: dict[str, Any],
    db: Any,
    updated_by: str = "",
) -> None:
    """Save a settings section to the DB.

    Merges with defaults (DB stores only explicitly set values).
    Clears the cache for this section after saving.
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

        # Update cache
        merged = dict(_DEFAULTS.get(section, {}))
        merged.update(data)
        _cache[section] = merged

        log.info("SiteSettings saved | section=%s by=%s", section, updated_by)
    except Exception as exc:
        log.error("SiteSettings.save_section(%r) error: %s", section, exc)
        raise
