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
    "comment_filter": {
        # IP whitelist / blocklist (CIDR or exact IP, one per line)
        # Whitelist takes priority over blocklist.
        "ip_whitelist":         "",
        "ip_blocklist":         "",
        # Country filter – ISO 3166-1 alpha-2 codes, comma-separated.
        # country_whitelist: only listed countries allowed (empty = all)
        # country_blocklist: listed countries blocked (empty = none)
        "country_whitelist":    "",
        "country_blocklist":    "",
        # Block when GeoIP returns no result (e.g. private IPs → no geo data)
        "country_block_unknown": False,
        # Path to MaxMind GeoLite2-Country.mmdb (leave empty to disable)
        "geoip_db_path":        "",
        # RBL / DNSBL
        "rbl_enabled":          False,
        "rbl_zones":            "zen.spamhaus.org\nbl.spamcop.net",
        # rbl_action: block = reject comment; flag = mark as SPAM silently
        "rbl_action":           "block",
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
    # ---------------------------------------------------------------------
    # security – Break-Glass password policy + HIBP (Have I Been Pwned)
    # Mirrors the old [auth] entries in config.toml so operators can manage
    # them via the admin UI instead of editing files. The TOML values are
    # used only as bootstrap defaults if the DB row is missing.
    # ---------------------------------------------------------------------
    "security": {
        # Break-Glass policy
        "legacy_password_min_length": 16,
        "legacy_password_max_length": 128,
        "legacy_password_min_score":  3,    # zxcvbn 0–4
        # HIBP k-Anonymity check
        "hibp_enabled":   False,
        "hibp_max_count": 0,    # 0 = reject any breach hit
        "hibp_timeout":   3.0,  # seconds
        "hibp_fail_open": True, # do not block on network errors
    },
    # ---------------------------------------------------------------------
    # webauthn – Passkey / FIDO2 policy.
    #
    # Default values follow the W3C Web Authentication Level 3 specification
    # and the joint W3C/FIDO Alliance "passkeys.dev" guidance:
    #
    #   user_verification  = "preferred"
    #     W3C WebAuthn L3 §5.4.6 (UserVerificationRequirement) – "preferred"
    #     is the IDL default; passkeys.dev "A note about user verification"
    #     warns that "required" causes painful UX on desktops without
    #     biometric sensors. Source: https://passkeys.dev/docs/use-cases/bootstrapping/
    #   resident_key       = "preferred"
    #     W3C WebAuthn L3 §5.4.7 (ResidentKeyRequirement). "preferred"
    #     enables discoverable credentials (passkeys) when the authenticator
    #     supports them, without forcing failure on legacy security keys.
    #   attestation        = "none"
    #     W3C WebAuthn L3 §5.4 (AttestationConveyancePreference) – "none"
    #     is the IDL default. passkeys.dev: "We recommend that most relying
    #     parties not specify the attestation conveyance parameter (thus
    #     defaulting to none)" for streamlined UX.
    #   algorithms         = [-7, -257]
    #     COSE algorithm identifiers ES256 and RS256, the only algorithms
    #     all WebAuthn Level 2/3 clients MUST support (W3C WebAuthn L3 §5.4
    #     and IANA COSE registry, RFC 9053). Ed25519 (-8) is opt-in because
    #     of historical Firefox/Node interop issues (SimpleWebAuthn docs).
    #   timeout_ms         = 60000
    #     W3C WebAuthn L3 §5.4 / §5.5 RECOMMENDED range for both
    #     PublicKeyCredentialCreationOptions and …RequestOptions is
    #     30 000 – 600 000 ms; 60 000 is the widely adopted middle ground
    #     (Yubico Developer Guide, MDN).
    #   challenge_ttl_seconds = 300
    #     W3C WebAuthn L3 §13.4.3 requires fresh, single-use challenges;
    #     OWASP Authentication Cheat Sheet recommends short TTLs.
    #   conditional_ui_enabled = True
    #     W3C WebAuthn L3 §5.5 (mediation: "conditional") – the documented
    #     bootstrapping pattern for autofill UI.
    #   signal_api_enabled = True
    #     W3C WebAuthn L3 §5.1.7+ Signal methods
    #     (PublicKeyCredential.signalUnknownCredential etc.) keep
    #     credential providers in sync with the RP's database.
    #   require_2fa_after_passkey = False
    #     A successful passkey assertion already provides phishing-resistant
    #     multi-factor authentication (W3C WebAuthn L3 §1.2). Demanding an
    #     additional factor on top is explicitly discouraged by web.dev /
    #     FIDO Alliance passkey UX guidance.
    #   counter_strict     = False
    #     W3C WebAuthn L3 §6.1.1 ("Signature Counter") states the counter
    #     is OPTIONAL for authenticators and many synced passkeys always
    #     return 0. Strict enforcement causes false positives, so we log
    #     anomalies but do not block by default (SimpleWebAuthn note).
    #
    # rp.id, rp.name and origin are NOT stored here – they are derived
    # from [web].base_url and the general/site_title setting via the
    # resolver in arborpress.auth.webauthn. Changing the deployment domain
    # invalidates every existing passkey (W3C WebAuthn L3 §5.3 RP ID), so
    # the change must pass through the rp_id_locked guard below.
    # ---------------------------------------------------------------------
    "webauthn": {
        "user_verification":         "preferred",
        "resident_key":              "preferred",
        "attestation":               "none",
        "authenticator_attachment":  "",       # "" | "platform" | "cross-platform"
        "algorithms":                [-7, -257],
        "timeout_ms":                60_000,
        "challenge_ttl_seconds":     300,
        "conditional_ui_enabled":    True,
        "signal_api_enabled":        True,
        "require_2fa_after_passkey": False,
        "counter_strict":            False,
        # Domain-change guard
        "rp_id_locked":              True,
        "rp_id_last_known":          "",       # empty until first successful resolve
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


# ---------------------------------------------------------------------------
# Security section helper
# ---------------------------------------------------------------------------

# Whitelist of fields the admin UI may set; protects against arbitrary keys.
_SECURITY_FIELDS: dict[str, type] = {
    "legacy_password_min_length": int,
    "legacy_password_max_length": int,
    "legacy_password_min_score":  int,
    "hibp_enabled":   bool,
    "hibp_max_count": int,
    "hibp_timeout":   float,
    "hibp_fail_open": bool,
}

_SECURITY_BOUNDS: dict[str, tuple[float, float]] = {
    "legacy_password_min_length": (8, 256),
    "legacy_password_max_length": (16, 1024),
    "legacy_password_min_score":  (0, 4),
    "hibp_max_count": (0, 10_000_000),
    "hibp_timeout":   (0.5, 30.0),
}


async def get_security_settings(db: Any) -> dict[str, Any]:
    """Return the merged security settings, using config.toml as bootstrap.

    Order of precedence: DB > [auth] in config.toml > built-in defaults.
    The result always carries the full set of keys defined in _SECURITY_FIELDS.
    """
    from arborpress.core.config import get_settings

    cfg = get_settings()
    bootstrap = {
        "legacy_password_min_length": cfg.auth.legacy_password_min_length,
        "legacy_password_max_length": cfg.auth.legacy_password_max_length,
        "legacy_password_min_score":  cfg.auth.legacy_password_min_score,
        "hibp_enabled":   cfg.auth.hibp_enabled,
        "hibp_max_count": cfg.auth.hibp_max_count,
        "hibp_timeout":   cfg.auth.hibp_timeout,
        "hibp_fail_open": cfg.auth.hibp_fail_open,
    }

    db_values = await get_section("security", db)
    # Drop unknown keys from cache/DB so the caller never sees stale fields.
    merged = bootstrap.copy()
    for key, value in db_values.items():
        if key in _SECURITY_FIELDS:
            merged[key] = value
    return merged


def coerce_security_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and coerce an admin-form payload to the security schema.

    Raises ``ValueError`` on invalid input. Unknown keys are dropped silently.
    """
    cleaned: dict[str, Any] = {}
    for key, expected_type in _SECURITY_FIELDS.items():
        if key not in payload:
            continue
        raw = payload[key]
        try:
            if expected_type is bool:
                if isinstance(raw, str):
                    value: Any = raw.strip().lower() in {"1", "true", "on", "yes"}
                else:
                    value = bool(raw)
            elif expected_type is int:
                value = int(raw)
            elif expected_type is float:
                value = float(raw)
            else:
                value = raw
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid value for {key!r}: {raw!r}") from exc

        if key in _SECURITY_BOUNDS:
            lo, hi = _SECURITY_BOUNDS[key]
            if value < lo or value > hi:
                raise ValueError(
                    f"{key!r} must be between {lo} and {hi} (got {value})"
                )
        cleaned[key] = value

    # Cross-field invariant
    if (
        "legacy_password_min_length" in cleaned
        and "legacy_password_max_length" in cleaned
        and cleaned["legacy_password_max_length"] < cleaned["legacy_password_min_length"]
    ):
        raise ValueError(
            "legacy_password_max_length must be greater than or equal to "
            "legacy_password_min_length"
        )
    return cleaned


# ---------------------------------------------------------------------------
# WebAuthn section helper
#
# Whitelist + value bounds for the admin UI.  Sources for the allowed
# values are the W3C Web Authentication Level 3 spec and IANA COSE
# registry (RFC 9053):
#   user_verification         §5.4.6 UserVerificationRequirement
#   resident_key              §5.4.7 ResidentKeyRequirement
#   attestation               §5.4   AttestationConveyancePreference
#   authenticator_attachment  §5.4.5 AuthenticatorAttachment
#   algorithms                §5.4   pubKeyCredParams + IANA COSE
#   timeout_ms                §5.4 / §5.5 RECOMMENDED 30 000–600 000 ms
# ---------------------------------------------------------------------------

_WEBAUTHN_FIELDS: dict[str, type] = {
    "user_verification":         str,
    "resident_key":              str,
    "attestation":               str,
    "authenticator_attachment":  str,
    "algorithms":                list,
    "timeout_ms":                int,
    "challenge_ttl_seconds":     int,
    "conditional_ui_enabled":    bool,
    "signal_api_enabled":        bool,
    "require_2fa_after_passkey": bool,
    "counter_strict":            bool,
    "rp_id_locked":              bool,
    "rp_id_last_known":          str,
}

_WEBAUTHN_ENUMS: dict[str, set[str]] = {
    # W3C WebAuthn L3 §5.4.6
    "user_verification":        {"required", "preferred", "discouraged"},
    # W3C WebAuthn L3 §5.4.7
    "resident_key":             {"required", "preferred", "discouraged"},
    # W3C WebAuthn L3 §5.4
    "attestation":              {"none", "indirect", "direct", "enterprise"},
    # W3C WebAuthn L3 §5.4.5 ("" = unset)
    "authenticator_attachment": {"", "platform", "cross-platform"},
}

_WEBAUTHN_BOUNDS: dict[str, tuple[float, float]] = {
    # W3C WebAuthn L3 §5.4 / §5.5 RECOMMENDED upper bound 600 000 ms
    "timeout_ms":            (30_000, 600_000),
    "challenge_ttl_seconds": (60, 900),
}

# IANA COSE algorithm registry (RFC 9053). ArborPress whitelists the
# values WebAuthn clients are most likely to support.
_WEBAUTHN_ALGORITHMS_ALLOWED: set[int] = {-7, -8, -35, -36, -37, -38, -39, -257, -258, -259}


async def get_webauthn_settings(db: Any) -> dict[str, Any]:
    """Return merged WebAuthn settings (defaults + DB)."""
    merged = dict(_DEFAULTS["webauthn"])
    db_values = await get_section("webauthn", db)
    for key, value in db_values.items():
        if key in _WEBAUTHN_FIELDS:
            merged[key] = value
    return merged


def coerce_webauthn_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate an admin-form payload against the WebAuthn schema.

    Drops unknown keys silently. Raises ``ValueError`` on invalid values.
    """
    cleaned: dict[str, Any] = {}
    for key, expected_type in _WEBAUTHN_FIELDS.items():
        if key not in payload:
            continue
        raw = payload[key]
        try:
            if expected_type is bool:
                if isinstance(raw, str):
                    value: Any = raw.strip().lower() in {"1", "true", "on", "yes"}
                else:
                    value = bool(raw)
            elif expected_type is int:
                value = int(raw)
            elif expected_type is list:
                if isinstance(raw, str):
                    parts = [p.strip() for p in raw.split(",") if p.strip()]
                else:
                    parts = list(raw)
                value = [int(p) for p in parts]
            else:
                value = str(raw).strip()
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid value for {key!r}: {raw!r}") from exc

        if key in _WEBAUTHN_ENUMS and value not in _WEBAUTHN_ENUMS[key]:
            raise ValueError(
                f"{key!r} must be one of {sorted(_WEBAUTHN_ENUMS[key])} (got {value!r})"
            )
        if key in _WEBAUTHN_BOUNDS:
            lo, hi = _WEBAUTHN_BOUNDS[key]
            if value < lo or value > hi:
                raise ValueError(f"{key!r} must be between {lo} and {hi} (got {value})")
        if key == "algorithms":
            if not value:
                raise ValueError("algorithms must contain at least one COSE identifier")
            for alg in value:
                if alg not in _WEBAUTHN_ALGORITHMS_ALLOWED:
                    raise ValueError(
                        f"unsupported COSE algorithm {alg!r}; allowed: "
                        f"{sorted(_WEBAUTHN_ALGORITHMS_ALLOWED)}"
                    )
        cleaned[key] = value

    return cleaned
