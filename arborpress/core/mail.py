"""E-Mail-Versand (aiosmtplib, TLS/STARTTLS).

Unterstützte Backends (config.toml → [mail]):
  backend = "none"   – kein Versand, nur Logging (Standard bei Neuinstallation)
  backend = "smtp"   – echter SMTP-Versand via aiosmtplib

SMTP-Konfiguration (Beispiele für config.toml):
  # --- STARTTLS (Port 587, empfohlen) ---
  [mail]
  backend        = "smtp"
  smtp_host      = "mail.example.com"
  smtp_port      = 587
  smtp_starttls  = true
  smtp_tls       = false
  smtp_user      = "user@example.com"
  smtp_password  = "geheim"
  from_address   = "blog@example.com"
  from_name      = "Mein Blog"

  # --- Implizites TLS (Port 465) ---
  [mail]
  backend   = "smtp"
  smtp_port = 465
  smtp_tls  = true
  smtp_starttls = false
"""

from __future__ import annotations

import logging
from email.headerregistry import Address
from email.message import EmailMessage
from typing import TYPE_CHECKING

log = logging.getLogger("arborpress.mail")

if TYPE_CHECKING:
    from arborpress.models.content import Comment, Post


def _mail_s() -> dict:
    """Liefert Mail-Settings (Cache oder Defaults)."""
    from arborpress.core.site_settings import get_cached, get_defaults
    return get_cached("mail") or get_defaults("mail")


def _comments_s() -> dict:
    """Liefert Comments-Settings (Cache oder Defaults)."""
    from arborpress.core.site_settings import get_cached, get_defaults
    return get_cached("comments") or get_defaults("comments")


# ---------------------------------------------------------------------------
# Basis-Senderfunktion
# ---------------------------------------------------------------------------

async def _send(
    to_address: str,
    to_name: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
) -> bool:
    """Sendet eine E-Mail gemäß aktueller Konfiguration.

    Gibt True zurück bei Erfolg, False bei Fehler oder Backend=none.
    STARTTLS hat Vorrang vor smtp_tls, wenn beide gesetzt sind.
    """
    mc = _mail_s()

    if mc.get("backend", "none") == "none":
        log.info(
            "[mail:none] An=%s | Betreff=%s | Text=%s",
            to_address, subject, body_text[:120],
        )
        return False

    try:
        import aiosmtplib  # optional dependency
    except ImportError:
        log.error(
            "aiosmtplib nicht installiert – bitte 'pip install aiosmtplib' ausführen."
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"]    = str(Address(mc.get("from_name", ""), addr_spec=mc.get("from_address", "")))
    msg["To"]      = str(Address(to_name, addr_spec=to_address))
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    kwargs: dict = {
        "hostname": mc.get("smtp_host", "localhost"),
        "port":     mc.get("smtp_port", 587),
        "username": mc.get("smtp_user") or None,
        "password": mc.get("smtp_password", "") or None,
    }

    # Verbindungsmodus: explizites TLS (465) oder STARTTLS (587)
    if mc.get("smtp_tls") and not mc.get("smtp_starttls"):
        kwargs["use_tls"] = True
    elif mc.get("smtp_starttls"):
        kwargs["start_tls"] = True

    try:
        await aiosmtplib.send(msg, **kwargs)
        log.info("Mail gesendet an %s (Betreff: %s)", to_address, subject)
        return True
    except Exception as exc:
        log.error("Mail-Fehler an %s: %s", to_address, exc)
        return False


# ---------------------------------------------------------------------------
# Kommentar-Bestätigungs-E-Mail (an Autor)
# ---------------------------------------------------------------------------

async def send_comment_confirmation(comment: Comment, post: Post) -> bool:
    """Sendet den Bestätigungs-Link an den Kommentar-Autor.

    Der Nutzer muss auf diesen Link klicken, damit der Kommentar
    zur Admin-Freischaltung weitergereicht wird (zweistufige Moderation).
    """
    from arborpress.core.config import get_settings

    base_url    = get_settings().web.base_url.rstrip("/")
    from_name   = _mail_s().get("from_name", "ArborPress")
    confirm_url = f"{base_url}/comment/confirm/{comment.confirmation_token}"

    subject = f"Kommentar bestätigen – {post.title}"

    body_text = (
        f"Hallo {comment.author_name},\n\n"
        f"vielen Dank für deinen Kommentar zum Artikel »{post.title}«.\n\n"
        f"Bitte bestätige deinen Kommentar durch einen Klick auf folgenden Link:\n"
        f"{confirm_url}\n\n"
        f"Nach deiner Bestätigung wird der Kommentar von uns geprüft und\n"
        f"anschließend freigeschaltet.\n\n"
        f"Falls du keinen Kommentar hinterlassen hast, ignoriere diese E-Mail einfach.\n\n"
        f"Viele Grüße,\n{from_name}"
    )

    body_html = f"""\
<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;color:#1a202c;max-width:520px;margin:0 auto">
  <h2 style="color:#2563eb">Kommentar bestätigen</h2>
  <p>Hallo <strong>{comment.author_name}</strong>,</p>
  <p>vielen Dank für deinen Kommentar zum Artikel
     <em>&raquo;{post.title}&laquo;</em>.</p>
  <p>Bitte bestätige deinen Kommentar:</p>
  <p style="text-align:center;margin:1.5rem 0">
    <a href="{confirm_url}"
       style="background:#2563eb;color:#fff;padding:.65rem 1.5rem;
              border-radius:6px;text-decoration:none;font-weight:700">
      Kommentar bestätigen
    </a>
  </p>
  <p style="font-size:.85rem;color:#6b7280">
    Nach der Bestätigung wird dein Kommentar vom Betreiber geprüft
    und anschließend freigeschaltet.<br>
    Falls du keinen Kommentar hinterlassen hast, ignoriere diese E-Mail.
  </p>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0">
  <p style="font-size:.8rem;color:#9ca3af">
    Direkt-Link: <a href="{confirm_url}">{confirm_url}</a>
  </p>
</body>
</html>"""

    return await _send(
        to_address=comment.author_email,
        to_name=comment.author_name,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
    )


# ---------------------------------------------------------------------------
# Admin-Benachrichtigung (neuer bestätigter Kommentar)
# ---------------------------------------------------------------------------

async def send_comment_notification(comment: Comment, post: Post) -> bool:
    """Benachrichtigt den Admin über einen neuen (bestätigten) Kommentar.

    Wird versandt, nachdem der Autor per E-Mail bestätigt hat.
    Nur aktiv, wenn comments.notify_admin_email in den Einstellungen gesetzt ist.
    """
    from arborpress.core.config import get_settings

    admin_email = _comments_s().get("notify_admin_email", "")
    if not admin_email:
        return False

    base_url = get_settings().web.base_url.rstrip("/")
    approve_url = f"{base_url}/admin/comments/{comment.id}/approve"
    reject_url  = f"{base_url}/admin/comments/{comment.id}/reject"

    subject = f"Neuer Kommentar zur Freischaltung – {post.title}"

    body_text = (
        f"Neuer Kommentar von {comment.author_name} <{comment.author_email}>\n"
        f"Artikel: {post.title}\n\n"
        f"---\n{comment.body}\n---\n\n"
        f"Freischalten:  {approve_url}\n"
        f"Ablehnen:      {reject_url}\n\n"
        f"Oder direkt im Admin-Bereich: {base_url}/admin/comments"
    )

    body_html = f"""\
<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;color:#1a202c;max-width:560px;margin:0 auto">
  <h2>Neuer Kommentar zur Freischaltung</h2>
  <table style="width:100%;border-collapse:collapse;font-size:.9rem;margin-bottom:1rem">
    <tr><td style="color:#6b7280;padding:.3rem .5rem">Artikel</td>
        <td><strong>{post.title}</strong></td></tr>
    <tr><td style="color:#6b7280;padding:.3rem .5rem">Autor</td>
        <td>{comment.author_name} &lt;{comment.author_email}&gt;</td></tr>
  </table>
  <blockquote style="border-left:3px solid #2563eb;padding:.5rem 1rem;
                     background:#f8f9fa;border-radius:0 6px 6px 0">
    {comment.body}
  </blockquote>
  <p style="display:flex;gap:.75rem;margin-top:1.25rem">
    <a href="{approve_url}"
       style="background:#16a34a;color:#fff;padding:.55rem 1.25rem;
              border-radius:6px;text-decoration:none;font-weight:700">
      ✓ Freischalten
    </a>
    <a href="{reject_url}"
       style="background:#dc2626;color:#fff;padding:.55rem 1.25rem;
              border-radius:6px;text-decoration:none;font-weight:700">
      ✗ Ablehnen
    </a>
  </p>
  <p style="font-size:.8rem;color:#9ca3af;margin-top:1rem">
    <a href="{base_url}/admin/comments">Alle Kommentare im Admin-Bereich</a>
  </p>
</body>
</html>"""

    return await _send(
        to_address=admin_email,
        to_name="Admin",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
    )
