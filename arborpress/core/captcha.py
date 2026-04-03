"""Captcha-Modul – unterstützt mehrere Anbieter (§-Kommentar-System).

Unterstützte Typen (CaptchaType):
  none             – kein Captcha
  math             – eingebaute Rechenaufgabe (a + b)
  custom           – eigene Fragen aus Admin-Interface (Fallback → math)
  hcaptcha         – hCaptcha (GDPR-freundlich, EU-Nutzung möglich)
  friendly_captcha – Friendly Captcha (Deutschland, EU-hosted, PoW, keine Interaktion)
  altcha           – ALTCHA (Open Source, selbstgehostet, PoW, MIT)
  mcaptcha         – mCaptcha (selbstgehostet, Open Source, AGPL)
  mosparo          – mosparo (Schweiz, EFTA, Open Source, MIT)
  turnstile        – Cloudflare Turnstile

Alle Verifikationsfunktionen sind async, damit externe API-Aufrufe nicht blocken.

Öffentliche API:
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
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def get_effective_captcha_type(
    post_captcha_type: str | None,
    captcha_section: dict,
) -> CaptchaType:
    """Gibt den effektiven CaptchaType zurück.

    Per-Post-Override hat Vorrang vor dem globalen Standard.
    Falls custom_questions leer ist und Typ=custom, fällt das System auf math zurück.
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
    """Wählt eine zufällige eigene Frage aus.

    Gibt (index, {"q": ..., "a": ...}) zurück.
    """
    questions = captcha_section.get("custom_questions", [])
    if not questions:
        raise ValueError("Keine Custom-Fragen konfiguriert.")
    idx = secrets.randbelow(len(questions))
    return idx, questions[idx]


# ---------------------------------------------------------------------------
# Challenge erzeugen (für Template-Rendering)
# ---------------------------------------------------------------------------

def get_captcha_challenge(captcha_type: CaptchaType, captcha_section: dict) -> dict:
    """Erzeugt Template-Kontext für den gewählten Captcha-Typ.

    Rückgabe-Keys (je nach Typ):
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
# Verifikation
# ---------------------------------------------------------------------------

async def verify_captcha(
    captcha_type: CaptchaType,
    form: dict,
    captcha_section: dict,
) -> tuple[bool, str]:
    """Prüft das eingereichte Captcha.

    Gibt (True, "") bei Erfolg zurück,
    (False, "Fehlermeldung") bei Fehler.
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
# Eingebaute Verifizierer
# ---------------------------------------------------------------------------

def _verify_math(form: dict) -> tuple[bool, str]:
    """Prüft a + b = answer."""
    try:
        a = int(form.get("captcha_a", ""))
        b = int(form.get("captcha_b", ""))
        answer = int(form.get("captcha_answer", ""))
    except (ValueError, TypeError):
        return False, "Bitte löse die Rechenaufgabe."
    if a + b != answer:
        return False, "Die Antwort auf die Rechenaufgabe ist leider falsch."
    return True, ""


def _verify_custom(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """Prüft eine eigene Frage anhand des gespeicherten Index."""
    questions = captcha_section.get("custom_questions", [])
    if not questions:
        return _verify_math(form)  # Fallback

    try:
        idx = int(form.get("captcha_qi", ""))
        if idx < 0 or idx >= len(questions):
            raise ValueError("Index out of range")
        expected = questions[idx]["a"].strip().lower()
    except (ValueError, TypeError, KeyError, IndexError):
        return False, "Ungültige Frage – bitte Seite neu laden."

    given = (form.get("captcha_answer") or "").strip().lower()
    if not given or given != expected:
        return False, "Die Antwort auf die Sicherheitsfrage ist leider falsch."
    return True, ""


# ---------------------------------------------------------------------------
# ALTCHA (self-hosted PoW, server-side HMAC) – kein externer Dienst
# ---------------------------------------------------------------------------

def _altcha_create_challenge(captcha_section: dict) -> dict:
    """Erstellt eine ALTCHA-Herausforderung (SHA-256, HMAC-signiert)."""
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
    """Prüft eine ALTCHA-Lösung (base64-JSON-Payload im field 'altcha')."""
    import base64

    max_number = captcha_section.get("altcha_max_number", 1_000_000)
    hmac_key   = captcha_section.get("altcha_hmac_key", "")

    raw = form.get("altcha", "")
    if not raw:
        return False, "Bitte das Captcha lösen."

    try:
        payload   = json.loads(base64.b64decode(raw))
        algorithm = payload.get("algorithm", "SHA-256")
        challenge = payload["challenge"]
        salt      = payload["salt"]
        number    = int(payload["number"])
        sig       = payload["signature"]
    except Exception:
        return False, "Ungültige Captcha-Lösung."

    # Challenge neu berechnen und vergleichen
    computed = hashlib.sha256(f"{salt}{number}".encode()).hexdigest()
    if computed != challenge:
        return False, "Captcha-Prüfung fehlgeschlagen (challenge)."

    # Signatur prüfen
    key = hmac_key.encode()
    expected_sig = hmac.new(
        key,
        f"{algorithm}:{challenge}:{salt}:{max_number}".encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, "Captcha-Signatur ungültig."

    return True, ""


# ---------------------------------------------------------------------------
# Externe Anbieter (HTTP-Calls)
# ---------------------------------------------------------------------------

async def _http_post_form(url: str, data: dict) -> dict:
    """Hilfsfunktion: POST x-www-form-urlencoded → JSON."""
    try:
        import aiohttp
    except ImportError:
        log.warning("aiohttp nicht installiert – Captcha-Verifikation übersprungen.")
        return {"success": True}  # fail-open wenn keine Netzwerk-Library

    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            return await resp.json()


async def _verify_hcaptcha(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """hCaptcha-Serververifikation."""
    token = form.get("h-captcha-response", "")
    if not token:
        return False, "Bitte das hCaptcha lösen."
    resp = await _http_post_form(
        captcha_section.get("hcaptcha_verify_url", "https://hcaptcha.com/siteverify"),
        {
            "secret":   captcha_section.get("hcaptcha_secret", ""),
            "response": token,
        },
    )
    if resp.get("success"):
        return True, ""
    errors = ", ".join(resp.get("error-codes", ["unbekannt"]))
    return False, f"hCaptcha-Fehler: {errors}."


async def _verify_friendly(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """Friendly Captcha v2 Serververifikation."""
    token = form.get("frc-captcha-response", "")
    if not token:
        return False, "Bitte das Friendly Captcha lösen."
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
        log.warning("Friendly Captcha Fehler: %s", exc)
        return False, "Captcha-Prüfung fehlgeschlagen."
    if data.get("success"):
        return True, ""
    return False, "Friendly Captcha nicht gelöst."


async def _verify_mcaptcha(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """mCaptcha Serververifikation (selbstgehostete Instanz)."""
    token = form.get("mcaptcha__token", "")
    if not token:
        return False, "Bitte das mCaptcha lösen."
    verify_url = captcha_section.get("mcaptcha_url", "").rstrip("/") + "/api/v1/pow/siteverify"
    resp = await _http_post_form(verify_url, {
        "token":  token,
        "key":    captcha_section.get("mcaptcha_site_key", ""),
        "secret": captcha_section.get("mcaptcha_secret", ""),
    })
    if resp.get("valid"):
        return True, ""
    return False, "mCaptcha nicht gelöst."


async def _verify_mosparo(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """mosparo Serververifikation."""
    submit_token     = form.get("_mosparo_submitToken", "")
    validation_token = form.get("_mosparo_validationToken", "")
    if not submit_token or not validation_token:
        return False, "Bitte das mosparo-Formular korrekt ausfüllen."
    try:
        import aiohttp
        # Signatur erstellen (HMAC-SHA256 über submitToken:validationToken)
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
        log.warning("mosparo Fehler: %s", exc)
        return False, "Captcha-Prüfung fehlgeschlagen."
    if data.get("valid"):
        return True, ""
    return False, "mosparo-Prüfung fehlgeschlagen."


async def _verify_turnstile(form: dict, captcha_section: dict) -> tuple[bool, str]:
    """Cloudflare Turnstile Serververifikation."""
    token = form.get("cf-turnstile-response", "")
    if not token:
        return False, "Bitte das Captcha lösen."
    resp = await _http_post_form(
        captcha_section.get("turnstile_verify_url", "https://challenges.cloudflare.com/turnstile/v0/siteverify"),
        {
            "secret":   captcha_section.get("turnstile_secret", ""),
            "response": token,
        },
    )
    if resp.get("success"):
        return True, ""
    errors = ", ".join(resp.get("error-codes", ["unbekannt"]))
    return False, f"Turnstile-Fehler: {errors}."
