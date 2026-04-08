"""E-mail sending (aiosmtplib, TLS/STARTTLS).

Supported backends (config.toml → [mail]):
  backend = "none"   – no sending, logging only (default on first install)
  backend = "smtp"   – real SMTP via aiosmtplib

SMTP configuration (examples for config.toml):
  # --- STARTTLS (port 587, recommended) ---
  [mail]
  backend        = "smtp"
  smtp_host      = "mail.example.com"
  smtp_port      = 587
  smtp_starttls  = true
  smtp_tls       = false
  smtp_user      = "user@example.com"
  smtp_password  = "secret"
  from_address   = "blog@example.com"
  from_name      = "My Blog"

  # --- Implicit TLS (port 465) ---
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
    """Return mail settings (cached or defaults)."""
    from arborpress.core.site_settings import get_cached, get_defaults
    return get_cached("mail") or get_defaults("mail")


def _comments_s() -> dict:
    """Return comment settings (cached or defaults)."""
    from arborpress.core.site_settings import get_cached, get_defaults
    return get_cached("comments") or get_defaults("comments")


# ---------------------------------------------------------------------------
# Base send function
# ---------------------------------------------------------------------------

async def _send(
    to_address: str,
    to_name: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
) -> bool:
    """Send an e-mail according to the current configuration.

    Returns True on success, False on error or backend=none.
    STARTTLS takes precedence over smtp_tls when both are set.
    """
    mc = _mail_s()

    if mc.get("backend", "none") == "none":
        log.info(
            "[mail:none] to=%s | subject=%s | text=%s",
            to_address, subject, body_text[:120],
        )
        return False

    try:
        import aiosmtplib  # optional dependency
    except ImportError:
        log.error(
            "aiosmtplib not installed – please run 'pip install aiosmtplib'."
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

    # Connection mode: explicit TLS (465) or STARTTLS (587)
    if mc.get("smtp_tls") and not mc.get("smtp_starttls"):
        kwargs["use_tls"] = True
    elif mc.get("smtp_starttls"):
        kwargs["start_tls"] = True

    try:
        await aiosmtplib.send(msg, **kwargs)
        log.info("Mail sent to %s (subject: %s)", to_address, subject)
        return True
    except Exception as exc:
        log.error("Mail error for %s: %s", to_address, exc)
        return False


# ---------------------------------------------------------------------------
# Comment confirmation e-mail (to author)
# ---------------------------------------------------------------------------

async def send_comment_confirmation(comment: Comment, post: Post) -> bool:
    """Send the confirmation link to the comment author.

    The user must click this link so that the comment is forwarded
    for admin approval (two-step moderation).
    """
    from arborpress.core.config import get_settings

    base_url    = get_settings().web.base_url.rstrip("/")
    from_name   = _mail_s().get("from_name", "ArborPress")
    confirm_url = f"{base_url}/comment/confirm/{comment.confirmation_token}"

    subject = f"Please confirm your comment – {post.title}"

    body_text = (
        f"Hello {comment.author_name},\n\n"
        f"thank you for your comment on the post \u00bb{post.title}\u00ab.\n\n"
        f"Please confirm your comment by clicking the following link:\n"
        f"{confirm_url}\n\n"
        f"After confirmation your comment will be reviewed by us and\n"
        f"then published.\n\n"
        f"If you did not leave a comment, simply ignore this e-mail.\n\n"
        f"Best regards,\n{from_name}"
    )

    body_html = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;color:#1a202c;max-width:520px;margin:0 auto">
  <h2 style="color:#2563eb">Confirm your comment</h2>
  <p>Hello <strong>{comment.author_name}</strong>,</p>
  <p>thank you for your comment on the post
     <em>&raquo;{post.title}&laquo;</em>.</p>
  <p>Please confirm your comment:</p>
  <p style="text-align:center;margin:1.5rem 0">
    <a href="{confirm_url}"
       style="background:#2563eb;color:#fff;padding:.65rem 1.5rem;
              border-radius:6px;text-decoration:none;font-weight:700">
      Confirm comment
    </a>
  </p>
  <p style="font-size:.85rem;color:#6b7280">
    After confirmation your comment will be reviewed by the site owner
    and then published.<br>
    If you did not leave a comment, please ignore this e-mail.
  </p>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0">
  <p style="font-size:.8rem;color:#9ca3af">
    Direct link: <a href="{confirm_url}">{confirm_url}</a>
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
# Admin notification (new confirmed comment)
# ---------------------------------------------------------------------------

async def send_comment_notification(comment: Comment, post: Post) -> bool:
    """Notify the admin about a new (confirmed) comment.

    Sent after the author has confirmed via e-mail.
    Only active when comments.notify_admin_email is set in the settings.
    """
    from arborpress.core.config import get_settings

    admin_email = _comments_s().get("notify_admin_email", "")
    if not admin_email:
        return False

    base_url = get_settings().web.base_url.rstrip("/")
    approve_url = f"{base_url}/admin/comments/{comment.id}/approve"
    reject_url  = f"{base_url}/admin/comments/{comment.id}/reject"

    subject = f"New comment awaiting approval – {post.title}"

    body_text = (
        f"New comment from {comment.author_name} <{comment.author_email}>\n"
        f"Post: {post.title}\n\n"
        f"---\n{comment.body}\n---\n\n"
        f"Approve:  {approve_url}\n"
        f"Reject:   {reject_url}\n\n"
        f"Or directly in the admin area: {base_url}/admin/comments"
    )

    body_html = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;color:#1a202c;max-width:560px;margin:0 auto">
  <h2>New comment awaiting approval</h2>
  <table style="width:100%;border-collapse:collapse;font-size:.9rem;margin-bottom:1rem">
    <tr><td style="color:#6b7280;padding:.3rem .5rem">Post</td>
        <td><strong>{post.title}</strong></td></tr>
    <tr><td style="color:#6b7280;padding:.3rem .5rem">Author</td>
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
      ✓ Approve
    </a>
    <a href="{reject_url}"
       style="background:#dc2626;color:#fff;padding:.55rem 1.25rem;
              border-radius:6px;text-decoration:none;font-weight:700">
      ✗ Reject
    </a>
  </p>
  <p style="font-size:.8rem;color:#9ca3af;margin-top:1rem">
    <a href="{base_url}/admin/comments">All comments in the admin area</a>
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
