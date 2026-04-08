"""Captcha module – supports multiple providers (§ comment system).

Supported types (CaptchaType):
  none             – no captcha
  math             – built-in arithmetic challenge (a + b)
  custom           – custom questions from admin interface (fallback → math)
  hcaptcha         – hCaptcha (GDPR-friendly, EU usage possible)
  friendly_captcha – Friendly Captcha (Germany, EU-hosted, PoW, no interaction)
  altcha           – ALTCHA (open source, self-hosted, PoW, MIT)
  mcaptcha         – mCaptcha (self-hosted, open source, AGPL)
  mosparo          – mosparo (Switzerland, EFTA, open source, MIT)
  turnstile        – Cloudflare Turnstile

All verification functions are async so external API calls do not block.

Public API:
  get_effective_captcha_type(post_captcha_type, captcha_section) -> CaptchaType
  verify_captcha(captcha_type, form, captcha_section) -> (ok: bool, error: str)
  get_captcha_challenge(captcha_type, captcha_section) -> dict   # template context
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
import logging
import secrets

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CaptchaType – hierher verschoben (war in config.py)
# ---------------------------------------------------------------------------

class CaptchaType(enum.StrEnum):
    NONE             = "none"
    MATH             = "math"
    CUSTOM           = "custom"
    HCAPTCHA         = "hcaptcha"
    FRIENDLY_CAPTCHA = "friendly_captcha"
    ALTCHA           = "altcha"
    MCAPTCHA         = "mcaptcha"
    MOSPARO          = "mosparo"
    TURNSTILE        = "turnstile"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_effective_captcha_type(
    post_captcha_type: str | None,
    captcha_section: dict,
) -> CaptchaType:
    """Return the effective CaptchaType.

    Per-post override takes precedence over the global default.
    Falls back to math if type=custom but custom_questions is empty.
    """
    default = captcha_section.get("default_type", CaptchaType.CUSTOM.value)
    if post_captcha_type:
        try:
            t = CaptchaType(post_captcha_type)
        except ValueError:
            t = CaptchaType(default)
    else:
        t = CaptchaType(default)

    # Fallback: custom ohne Fragen → math
    if t == CaptchaType.CUSTOM and not captcha_section.get("custom_questions", []):
        return CaptchaType.MATH

    return t


def _random_question(captcha_section: dict) -> tuple[int, dict]:
    """Pick a random custom question.

    Returns (index, {"q": ..., "a": ...}).
    """
    questions = captcha_section.get("custom_questions", [])
    if not questions:
        raise ValueError("No custom questions configured.")
    idx = secrets.randbelow(len(questions))
    return idx, questions[idx]


# ---------------------------------------------------------------------------
# Challenge creation (for template rendering)
# ---------------------------------------------------------------------------

def get_captcha_challenge(captcha_type: CaptchaType, captcha_section: dict) -> dict:
    """Build template context for the chosen captcha type.

    Returned keys (depending on type):
      type, site_key, question, question_index, math_a, math_b
    """
    ctx: dict = {"type": captcha_type.value}

    if captcha_type == CaptchaType.MATH:
        a = secrets.randbelow(9) + 1
        b = secrets.randbelow(9) + 1
        ctx.update({"math_a": a, "math_b": b})

    elif captcha_type == CaptchaType.CUSTOM:
        idx, entry = _random_question(captcha_section)
        ctx.update({"question": entry["q"], "question_index": idx})

    elif captcha_type == CaptchaType.HCAPTCHA:
        ctx["site_key"] = captcha_section.get("hcaptcha_site_key", "")

    elif captcha_type == CaptchaType.FRIENDLY_CAPTCHA:
        ctx["site_key"] = captcha_section.get("friendly_sitekey", "")

    elif captcha_type == CaptchaType.ALTCHA:
        challenge = _altcha_create_challenge(captcha_section)
        ctx["altcha_challenge"] = json.dumps(challenge)

    elif captcha_type == CaptchaType.MCAPTCHA:
        ctx["site_key"] = captcha_section.get("mcaptcha_site_key", "")
        ctx["mcaptcha_url"] = captcha_section.get("mcaptcha_url", "")

    elif captcha_type == CaptchaType.MOSPARO:
        ctx["mosparo_url"] = captcha_section.get("mosparo_url", "")
        ctx["mosparo_public_key"] = captcha_section.get("mosparo_public_key", "")

    elif captcha_type == CaptchaType.TURNSTILE:
        ctx["site_key"] = captcha_section.get("turnstile_site_key", "")

    return ctx


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

async def verify_captcha(
    captcha_type: CaptchaType,
    form: dict,
    captcha_section: dict,
) -> tuple[bool, str]:
    """Verify the submitted captcha.

    Returns (True, "") on success,
    (False, "error message") on failure.
    """
    if captcha_type == CaptchaType.NONE:
        return True, ""

    if captcha_type == CaptchaType.MATH:
        return _verify_math(form)

    if captcha_type == CaptchaType.CUSTOM:
        return _verify_custom(form, captcha_section)

    if captcha_type == CaptchaType.HCAPTCHA:
        return await _verify_hcaptcha(form, captcha_section)

    if captcha_type == CaptchaType.FRIENDLY_CAPTCHA:
        return await _verify_friendly(form, captcha_section)

    if captcha_type == CaptchaType.ALTCHA:
        return _verify_altcha(form, captcha_section)

    if captcha_type == CaptchaType.MCAPTCHA:
        return await _verify_mcaptcha(form, captcha_section)

    if captcha_type == CaptchaType.MOSPARO:
        return await _verify_mosparo(form, captcha_section)

    if captcha_type == CaptchaType.TURNSTILE:
        return await _verify_turnstile(form, captcha_section)

    return True, ""


# ---------------------------------------------------------------------------
# Built-in verifiers
# ---------------------------------------------------------------------------

def _verify_math(form: dict) -> tuple[bool, str]:
    """Verify a + b = answer."""
    try:
        a = int(form.get("captcha_a", ""))
        b = int(form.get("captcha_b", ""))
        answer = int(form.get("captcha_answer", ""))
    except (ValueError, TypeError):
        return False, "Please solve the arithmetic challenge."
    if a + b != answer:
        return False, "The answer to the arithmetic challenge is incorrect."
    return True, ""


def _verify_custom(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """Verify a custom question using the stored index."""
    questions = captcha_section.get("custom_questions", [])
    if not questions:
        return _verify_math(form)  # fallback

    try:
        idx = int(form.get("captcha_qi", ""))
        if idx < 0 or idx >= len(questions):
            raise ValueError("Index out of range")
        expected = questions[idx]["a"].strip().lower()
    except (ValueError, TypeError, KeyError, IndexError):
        return False, "Invalid question – please reload the page."

    given = (form.get("captcha_answer") or "").strip().lower()
    if not given or given != expected:
        return False, "The answer to the security question is incorrect."
    return True, ""


# ---------------------------------------------------------------------------
# ALTCHA (self-hosted PoW, server-side HMAC) – kein externer Dienst
# ---------------------------------------------------------------------------

def _altcha_create_challenge(captcha_section: dict) -> dict:
    """Create an ALTCHA challenge (SHA-256, HMAC-signed)."""
    max_number = captcha_section.get("altcha_max_number", 1_000_000)
    algorithm  = captcha_section.get("altcha_algorithm", "SHA-256")
    hmac_key   = captcha_section.get("altcha_hmac_key", "")
    salt      = secrets.token_hex(12)
    number    = secrets.randbelow(max_number) + 1
    challenge = hashlib.sha256(f"{salt}{number}".encode()).hexdigest()
    key       = hmac_key.encode()
    signature = hmac.new(
        key,
        f"{algorithm}:{challenge}:{salt}:{max_number}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return {
        "algorithm": algorithm,
        "challenge": challenge,
        "salt":      salt,
        "maxnumber": max_number,
        "signature": signature,
    }


def _verify_altcha(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """Verify an ALTCHA solution (base64 JSON payload in field 'altcha')."""
    import base64

    max_number = captcha_section.get("altcha_max_number", 1_000_000)
    hmac_key   = captcha_section.get("altcha_hmac_key", "")

    raw = form.get("altcha", "")
    if not raw:
        return False, "Please solve the captcha."

    try:
        payload   = json.loads(base64.b64decode(raw))
        algorithm = payload.get("algorithm", "SHA-256")
        challenge = payload["challenge"]
        salt      = payload["salt"]
        number    = int(payload["number"])
        sig       = payload["signature"]
    except Exception:
        return False, "Invalid captcha solution."

    # Recompute and compare challenge
    computed = hashlib.sha256(f"{salt}{number}".encode()).hexdigest()
    if computed != challenge:
        return False, "Captcha verification failed (challenge)."

    # Verify signature
    key = hmac_key.encode()
    expected_sig = hmac.new(
        key,
        f"{algorithm}:{challenge}:{salt}:{max_number}".encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, "Captcha signature invalid."

    return True, ""


# ---------------------------------------------------------------------------
# External providers (HTTP calls)
# ---------------------------------------------------------------------------

async def _http_post_form(url: str, data: dict) -> dict:
    """Helper: POST x-www-form-urlencoded → JSON."""
    try:
        import aiohttp
    except ImportError:
        log.warning("aiohttp not installed – captcha verification skipped.")
        return {"success": True}  # fail-open when no network library available

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            return await resp.json()


async def _verify_hcaptcha(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """hCaptcha server-side verification."""
    token = form.get("h-captcha-response", "")
    if not token:
        return False, "Please solve the hCaptcha."
    resp = await _http_post_form(
        captcha_section.get("hcaptcha_verify_url", "https://hcaptcha.com/siteverify"),
        {
            "secret":   captcha_section.get("hcaptcha_secret", ""),
            "response": token,
        },
    )
    if resp.get("success"):
        return True, ""
    errors = ", ".join(resp.get("error-codes", ["unknown"]))
    return False, f"hCaptcha error: {errors}."


async def _verify_friendly(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """Friendly Captcha v2 server-side verification."""
    token = form.get("frc-captcha-response", "")
    if not token:
        return False, "Please solve the Friendly Captcha."
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                captcha_section.get("friendly_verify_url", "https://global.frcapi.com/api/v2/captcha/siteverify"),
                json={"response": token, "sitekey": captcha_section.get("friendly_sitekey", "")},
                headers={
                    "X-API-Key": captcha_section.get("friendly_api_key", ""),
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                data = await resp.json()
    except ImportError:
        return True, ""  # fail-open
    except Exception as exc:
        log.warning("Friendly Captcha error: %s", exc)
        return False, "Captcha verification failed."
    if data.get("success"):
        return True, ""
    return False, "Friendly Captcha not solved."


async def _verify_mcaptcha(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """mCaptcha server-side verification (self-hosted instance)."""
    token = form.get("mcaptcha__token", "")
    if not token:
        return False, "Please solve the mCaptcha."
    verify_url = captcha_section.get("mcaptcha_url", "").rstrip("/") + "/api/v1/pow/siteverify"
    resp = await _http_post_form(verify_url, {
        "token":  token,
        "key":    captcha_section.get("mcaptcha_site_key", ""),
        "secret": captcha_section.get("mcaptcha_secret", ""),
    })
    if resp.get("valid"):
        return True, ""
    return False, "mCaptcha not solved."


async def _verify_mosparo(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """mosparo server-side verification."""
    submit_token     = form.get("_mosparo_submitToken", "")
    validation_token = form.get("_mosparo_validationToken", "")
    if not submit_token or not validation_token:
        return False, "Please fill in the mosparo form correctly."
    try:
        import aiohttp
        # Build signature (HMAC-SHA256 over submitToken:validationToken)
        private_key = captcha_section.get("mosparo_private_key", "")
        sig = hmac.new(
            private_key.encode(),
            f"{submit_token}:{validation_token}".encode(),
            hashlib.sha256,
        ).hexdigest()
        mosparo_base = captcha_section.get("mosparo_url", "").rstrip("/")
        verify_url = mosparo_base + f"/api/v1/verification/verify/{submit_token}"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                verify_url,
                params={"validationToken": validation_token, "hmacHash": sig},
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                data = await resp.json()
    except ImportError:
        return True, ""
    except Exception as exc:
        log.warning("mosparo error: %s", exc)
        return False, "Captcha verification failed."
    if data.get("valid"):
        return True, ""
    return False, "mosparo verification failed."


async def _verify_turnstile(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """Cloudflare Turnstile server-side verification."""
    token = form.get("cf-turnstile-response", "")
    if not token:
        return False, "Please solve the captcha."
    resp = await _http_post_form(
        captcha_section.get("turnstile_verify_url", "https://challenges.cloudflare.com/turnstile/v0/siteverify"),
        {
            "secret":   captcha_section.get("turnstile_secret", ""),
            "response": token,
        },
    )
    if resp.get("success"):
        return True, ""
    errors = ", ".join(resp.get("error-codes", ["unknown"]))
    return False, f"Turnstile error: {errors}."
