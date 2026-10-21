"""Core mail producers. Delivery is persisted to the SMTP-profile DB outbox."""

from __future__ import annotations

import logging
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
    confirm_url = f"{base_url}/comment/confirm/{token}"
    if _mail_s().get("backend", "none") == "none":
        log.info("[mail:none] message suppressed (mail transport not configured)")
        return False
    from arborpress.mail.template_engine import enqueue_template_mail

    try:
        await enqueue_template_mail(
            session,
            template_id="comment.guest_confirmation",
            to=comment.author_email,
            context={
                "display_name": comment.author_name,
                "post_title": post.title,
                "confirmation_url": confirm_url,
                "site_name": _mail_s().get("from_name", "ArborPress"),
            },
            site_locale=get_settings().web.default_lang,
            idempotency_key=f"comment-confirmation:{comment.id}:{token}",
            purpose="transactional",
        )
        return True
    except Exception as exc:
        if session is not None:
            raise
        log.error("Failed to enqueue comment confirmation (error_type=%s)", type(exc).__name__)
        return False


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
    if _mail_s().get("backend", "none") == "none":
        log.info("[mail:none] message suppressed (mail transport not configured)")
        return False
    from arborpress.mail.template_engine import enqueue_template_mail

    try:
        await enqueue_template_mail(
            session,
            template_id="comment.admin_notice",
            to=admin_email,
            context={
                "display_name": comment.author_name,
                "author_email": comment.author_email or "",
                "post_title": post.title,
                "comment_body": comment.body,
                "admin_url": f"{base_url}/admin/comments",
                "site_name": _mail_s().get("from_name", "ArborPress"),
            },
            site_locale=get_settings().web.default_lang,
            idempotency_key=f"comment-admin-notice:{comment.id}",
            purpose="transactional",
        )
        return True
    except Exception as exc:
        if session is not None:
            raise
        log.error("Failed to enqueue comment notice (error_type=%s)", type(exc).__name__)
        return False
