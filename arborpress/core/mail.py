"""Core mail producers. Delivery is persisted to the SMTP-profile DB outbox."""

from __future__ import annotations

import logging
from html import escape
from typing import TYPE_CHECKING, Any

log = logging.getLogger("arborpress.mail")

if TYPE_CHECKING:
    from arborpress.models.content import Comment, Post


def _mail_s() -> dict[str, Any]:
    """Return mail settings (cached or defaults)."""
    from arborpress.core.site_settings import get_cached, get_defaults

    return get_cached("mail") or get_defaults("mail")


def _comments_s() -> dict[str, Any]:
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
    *,
    session: Any | None = None,
    purpose: str = "transactional",
) -> bool:
    """Enqueue an e-mail for delivery via the async mail queue.

    Returns True when the mail was successfully enqueued.
    Returns False when backend=none (logging only).
    Actual SMTP delivery is handled by the queue worker (run_queue_worker).
    """
    mc = _mail_s()

    if mc.get("backend", "none") == "none":
        log.info("[mail:none] message suppressed (mail transport not configured)")
        return False

    from arborpress.mail.queue import enqueue_mail

    try:
        await enqueue_mail(
            to=to_address,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            purpose=purpose,
            session=session,
        )
        log.debug("Mail enqueued for recipient domain=%s", to_address.rpartition("@")[2])
        return True
    except Exception as exc:
        if session is not None:
            raise
        log.error("Failed to enqueue mail (error_type=%s)", type(exc).__name__)
        return False


# ---------------------------------------------------------------------------
# Comment confirmation e-mail (to author)
# ---------------------------------------------------------------------------


async def send_comment_confirmation(
    comment: Comment, post: Post, token: str, *, session: Any | None = None
) -> bool:
    """Send the confirmation link to the comment author.

    The user must click this link so that the comment is forwarded
    for admin approval (two-step moderation).
    """
    from arborpress.core.config import get_settings

    if not comment.author_email:
        return False
    base_url = get_settings().web.base_url.rstrip("/")
    from_name = _mail_s().get("from_name", "ArborPress")
    confirm_url = f"{base_url}/comment/confirm/{token}"
    confirm_href = escape(confirm_url, quote=True)
    author_name = escape(comment.author_name)
    post_title = escape(post.title)

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
  <p>Hello <strong>{author_name}</strong>,</p>
  <p>thank you for your comment on the post
     <em>&raquo;{post_title}&laquo;</em>.</p>
  <p>Please confirm your comment:</p>
  <p style="text-align:center;margin:1.5rem 0">
    <a href="{confirm_href}"
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
    Direct link: <a href="{confirm_href}">{escape(confirm_url)}</a>
  </p>
</body>
</html>"""

    return await _send(
        to_address=comment.author_email,
        to_name=comment.author_name,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        session=session,
        purpose="comment-confirmation",
    )


# ---------------------------------------------------------------------------
# Admin notification (new confirmed comment)
# ---------------------------------------------------------------------------


async def send_comment_notification(
    comment: Comment, post: Post, *, session: Any | None = None
) -> bool:
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
    reject_url = f"{base_url}/admin/comments/{comment.id}/reject"

    subject = f"New comment awaiting approval – {post.title}"
    html_author = escape(comment.author_name)
    html_email = escape(comment.author_email or "")
    html_title = escape(post.title)
    html_body = escape(comment.body)
    approve_href = escape(approve_url, quote=True)
    reject_href = escape(reject_url, quote=True)
    author_text = (
        f"New comment from {comment.author_name} <{comment.author_email}>"
        if comment.author_email
        else f"New comment from registered author {comment.author_name}"
    )
    author_email_html = f" &lt;{html_email}&gt;" if html_email else ""

    body_text = (
        f"{author_text}\n"
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
        <td><strong>{html_title}</strong></td></tr>
    <tr><td style="color:#6b7280;padding:.3rem .5rem">Author</td>
        <td>{html_author}{author_email_html}</td></tr>
  </table>
  <blockquote style="border-left:3px solid #2563eb;padding:.5rem 1rem;
                     background:#f8f9fa;border-radius:0 6px 6px 0">
    {html_body}
  </blockquote>
  <p style="display:flex;gap:.75rem;margin-top:1.25rem">
    <a href="{approve_href}"
       style="background:#16a34a;color:#fff;padding:.55rem 1.25rem;
              border-radius:6px;text-decoration:none;font-weight:700">
      ✓ Approve
    </a>
    <a href="{reject_href}"
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
        session=session,
        purpose="comment-notification",
    )
