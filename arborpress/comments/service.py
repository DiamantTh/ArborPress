"""Transactional comment creation, guest confirmation and revision services."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from arborpress.comments.policy import CommentPolicy, resolve_comment_policy
from arborpress.models.content import (
    Comment,
    CommentRevision,
    CommentRevisionStatus,
    CommentStatus,
    Post,
)


class CommentPolicyError(ValueError):
    """A comment operation violates the effective site/content policy."""


class CommentTokenError(ValueError):
    """A guest confirmation token is invalid, expired, consumed or ineligible."""


@dataclass(frozen=True, slots=True)
class CommentCreation:
    comment: Comment
    confirmation_token: str | None


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _token_pair() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return token, digest


def _publication_state(
    policy: CommentPolicy, *, author: Any | None, approved_author_count: int
) -> CommentStatus:
    mode = policy.moderation_mode
    if mode == "none":
        return CommentStatus.APPROVED
    if mode == "first_n":
        if author is not None and approved_author_count >= policy.first_n_count:
            return CommentStatus.APPROVED
        return CommentStatus.PENDING_MODERATION
    if mode == "trusted_bypass" and author is not None and bool(author.comment_trusted):
        return CommentStatus.APPROVED
    return CommentStatus.PENDING_MODERATION


async def _approved_count(db: Any, author_user_id: str | None) -> int:
    if author_user_id is None:
        return 0
    return int(
        await db.scalar(
            select(func.count(Comment.id)).where(
                Comment.author_user_id == author_user_id,
                Comment.status == CommentStatus.APPROVED,
            )
        )
        or 0
    )


async def create_comment(
    db: Any,
    *,
    post: Post,
    policy: CommentPolicy,
    author_name: str,
    author_email: str | None,
    body: str,
    author_url: str | None = None,
    author_user: Any | None = None,
    parent_id: str | None = None,
    quote_of_id: str | None = None,
    spam: bool = False,
    ip_address: str | None = None,
    user_agent: str | None = None,
    country_code: str | None = None,
) -> CommentCreation:
    """Validate relations and persist one comment; plaintext token is returned once."""
    if not policy.enabled:
        raise CommentPolicyError("Comments are disabled for this content.")
    if author_user is None and not policy.allow_guests:
        raise CommentPolicyError("Guest comments are disabled.")
    if not author_name.strip() or not body.strip():
        raise CommentPolicyError("Author name and comment body are required.")
    if len(body) > policy.max_comment_length:
        raise CommentPolicyError("Comment exceeds the configured maximum length.")
    if parent_id and not policy.allow_replies:
        raise CommentPolicyError("Replies are disabled by comment policy.")
    if quote_of_id and not policy.allow_quotes:
        raise CommentPolicyError("Quoting is disabled by comment policy.")

    parent = await _same_post_comment(db, post.id, parent_id) if parent_id else None
    quoted = await _same_post_comment(db, post.id, quote_of_id) if quote_of_id else None
    if parent_id and (parent is None or parent.status != CommentStatus.APPROVED):
        raise CommentPolicyError("Reply target is unavailable.")
    if quote_of_id and (quoted is None or quoted.status != CommentStatus.APPROVED):
        raise CommentPolicyError("Quote target is unavailable.")
    if parent is not None and await _parent_chain_contains(db, parent, ""):
        raise CommentPolicyError("Reply would create a parent cycle.")

    confirmation_token: str | None = None
    digest: str | None = None
    now = _now()
    if spam:
        status = CommentStatus.SPAM
    elif author_user is None and policy.guest_confirmation_required:
        if not author_email:
            raise CommentPolicyError("Guest e-mail is required for confirmation.")
        confirmation_token, digest = _token_pair()
        status = CommentStatus.PENDING_CONFIRMATION
    else:
        digest = None
        status = _publication_state(
            policy,
            author=author_user,
            approved_author_count=await _approved_count(
                db, str(author_user.id) if author_user else None
            ),
        )

    comment = Comment(
        id=str(uuid.uuid4()),
        post_id=str(post.id),
        author_user_id=str(author_user.id) if author_user else None,
        author_name=author_name.strip()[:128],
        author_email=author_email,
        author_url=author_url,
        body=body.strip(),
        status=status,
        confirmation_token_hash=digest,
        confirmation_expires_at=(now + timedelta(hours=policy.confirmation_ttl_hours))
        if digest
        else None,
        confirmation_sent_at=now if digest else None,
        confirmed_at=now if digest is None and not spam else None,
        approved_at=now if status == CommentStatus.APPROVED else None,
        published_at=now if status == CommentStatus.APPROVED else None,
        parent_id=str(parent.id) if parent else None,
        quote_of_id=str(quoted.id) if quoted else None,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:512] or None,
        country_code=country_code,
    )
    db.add(comment)
    await db.flush()
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="comment_created",
        outcome="success",
        target_id=comment.id,
        actor_id=comment.author_user_id,
        ip=ip_address,
        db=db,
        detail=f"state={comment.status.value}",
    )
    if status == CommentStatus.APPROVED:
        await write_audit_event(
            event_type="comment_auto_approved_by_policy",
            outcome="success",
            target_id=comment.id,
            actor_id=comment.author_user_id,
            db=db,
        )
    return CommentCreation(comment, confirmation_token)


async def _same_post_comment(db: Any, post_id: str, comment_id: str | None) -> Comment | None:
    if not comment_id:
        return None
    value = (
        await db.execute(
            select(Comment).where(Comment.id == comment_id, Comment.post_id == post_id)
        )
    ).scalar_one_or_none()
    return cast(Comment | None, value)


async def _parent_chain_contains(db: Any, parent: Comment, target_id: str) -> bool:
    seen: set[str] = set()
    current: Comment | None = parent
    while current is not None:
        current_id = str(current.id)
        if current_id == target_id or current_id in seen:
            return True
        seen.add(current_id)
        current = await db.get(Comment, current.parent_id) if current.parent_id else None
    return False


async def confirm_guest_comment(
    db: Any,
    *,
    token: str,
    settings: dict[str, object],
) -> Comment:
    """Consume a purpose-bound, expiring token with a conditional one-shot update."""
    if not token or len(token) > 128:
        raise CommentTokenError("Confirmation link is invalid or expired.")
    try:
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    except UnicodeEncodeError as exc:
        raise CommentTokenError("Confirmation link is invalid or expired.") from exc
    now = _now()
    comment = cast(
        Comment | None,
        (
            await db.execute(
                select(Comment).where(
                    Comment.confirmation_token_hash == digest,
                    Comment.status == CommentStatus.PENDING_CONFIRMATION,
                    Comment.confirmation_expires_at > now,
                )
            )
        ).scalar_one_or_none(),
    )
    if comment is None:
        raise CommentTokenError("Confirmation link is invalid or expired.")
    post = await db.get(Post, comment.post_id)
    if post is None:
        raise CommentTokenError("Confirmation link is invalid or expired.")
    policy = resolve_comment_policy(post, settings)
    next_state = _publication_state(policy, author=None, approved_author_count=0)
    result = await db.execute(
        update(Comment)
        .where(
            Comment.id == comment.id,
            Comment.status == CommentStatus.PENDING_CONFIRMATION,
            Comment.confirmation_token_hash == digest,
            Comment.confirmation_expires_at > now,
        )
        .values(
            status=next_state,
            confirmation_token_hash=None,
            confirmation_expires_at=None,
            confirmed_at=now,
            approved_at=now if next_state == CommentStatus.APPROVED else None,
            published_at=now if next_state == CommentStatus.APPROVED else None,
        )
    )
    if result.rowcount != 1:
        raise CommentTokenError("Confirmation link is invalid or expired.")
    await db.flush()
    await db.refresh(comment)
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="comment_guest_confirmation_consumed",
        outcome="success",
        target_id=comment.id,
        db=db,
        detail=f"state={comment.status.value}",
    )
    if next_state == CommentStatus.APPROVED:
        await write_audit_event(
            event_type="comment_auto_approved_by_policy",
            outcome="success",
            target_id=comment.id,
            db=db,
        )
    return comment


async def issue_guest_confirmation(
    db: Any,
    *,
    comment: Comment,
    ttl_hours: int = 24,
    minimum_interval_seconds: int = 60,
) -> str:
    """Rotate a pending comment's token; old links become invalid immediately."""
    if comment.status != CommentStatus.PENDING_CONFIRMATION:
        raise CommentTokenError("Only pending guest comments can be confirmed.")
    now = _now()
    if comment.confirmation_sent_at and now < comment.confirmation_sent_at + timedelta(
        seconds=max(1, minimum_interval_seconds)
    ):
        raise CommentTokenError("A new confirmation message cannot be sent yet.")
    token, digest = _token_pair()
    result = await db.execute(
        update(Comment)
        .where(
            Comment.id == comment.id,
            Comment.status == CommentStatus.PENDING_CONFIRMATION,
            Comment.confirmation_token_hash == comment.confirmation_token_hash,
            Comment.confirmation_sent_at == comment.confirmation_sent_at,
        )
        .values(
            confirmation_token_hash=digest,
            confirmation_expires_at=now + timedelta(hours=min(168, max(1, ttl_hours))),
            confirmation_sent_at=now,
        )
    )
    if result.rowcount != 1:
        raise CommentTokenError("Confirmation state changed; request a new message again.")
    await db.flush()
    await db.refresh(comment)
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="comment_guest_confirmation_resent",
        outcome="success",
        target_id=comment.id,
        db=db,
    )
    return token


async def can_edit_comment(
    db: Any,
    *,
    comment: Comment,
    actor_user: Any,
    policy: CommentPolicy,
    moderator: bool = False,
    now: datetime | None = None,
) -> tuple[bool, str | None]:
    if comment.status != CommentStatus.APPROVED:
        return False, "Only published comments can be edited."
    if moderator:
        return True, None
    if comment.author_user_id is None or str(comment.author_user_id) != str(actor_user.id):
        return False, "Only the registered comment author may edit this comment."
    now = now or _now()
    published = comment.published_at or comment.approved_at or comment.created_at
    if policy.edit_window_minutes <= 0 or now > published + timedelta(
        minutes=policy.edit_window_minutes
    ):
        return False, "The comment edit window has expired."
    count = int(
        await db.scalar(
            select(func.count(CommentRevision.id)).where(
                CommentRevision.comment_id == comment.id,
                CommentRevision.editor_user_id == str(actor_user.id),
                CommentRevision.is_author_edit.is_(True),
            )
        )
        or 0
    )
    if count >= policy.max_user_edits:
        return False, "The maximum number of author edits has been reached."
    return True, None


async def create_comment_revision(
    db: Any,
    *,
    comment_id: str,
    actor_user: Any,
    body: str,
    policy: CommentPolicy,
    moderator: bool = False,
) -> CommentRevision:
    """Save a revision while keeping the currently published body public."""
    comment = (
        await db.execute(select(Comment).where(Comment.id == comment_id).with_for_update())
    ).scalar_one_or_none()
    if comment is None:
        raise CommentPolicyError("Comment not found.")
    allowed, reason = await can_edit_comment(
        db, comment=comment, actor_user=actor_user, policy=policy, moderator=moderator
    )
    if not allowed:
        raise CommentPolicyError(reason or "Comment cannot be edited.")
    if not body.strip() or len(body) > policy.max_comment_length:
        raise CommentPolicyError("Edited comment is empty or exceeds the maximum length.")
    current_count = int(
        await db.scalar(
            select(func.max(CommentRevision.revision_number)).where(
                CommentRevision.comment_id == comment.id
            )
        )
        or 0
    )
    author_edit = not moderator
    immediate = moderator or (
        policy.trusted_edit_bypass and bool(getattr(actor_user, "comment_trusted", False))
    )
    if not immediate:
        pending = await db.scalar(
            select(func.count(CommentRevision.id)).where(
                CommentRevision.comment_id == comment.id,
                CommentRevision.status == CommentRevisionStatus.PENDING,
            )
        )
        if pending:
            raise CommentPolicyError("A comment revision is already awaiting moderation.")
    revision = CommentRevision(
        id=str(uuid.uuid4()),
        comment_id=comment.id,
        editor_user_id=str(actor_user.id) if actor_user else None,
        revision_number=current_count + 1,
        previous_body=comment.body,
        body=body.strip(),
        status=CommentRevisionStatus.APPROVED if immediate else CommentRevisionStatus.PENDING,
        pending_key=None if immediate else comment.id,
        is_author_edit=author_edit,
    )
    try:
        async with db.begin_nested():
            db.add(revision)
            if immediate:
                comment.body = revision.body
                comment.edited_at = _now()
            await db.flush()
    except IntegrityError as exc:
        raise CommentPolicyError("A concurrent comment edit conflicted; reload and retry.") from exc
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="comment_revision_created",
        outcome="success",
        actor_id=revision.editor_user_id,
        target_id=comment.id,
        db=db,
        detail=f"revision={revision.revision_number};state={revision.status.value}",
    )
    return revision


async def review_comment_revision(
    db: Any,
    *,
    revision_id: str,
    approve: bool,
) -> CommentRevision:
    revision = cast(
        CommentRevision | None,
        (
            await db.execute(
                select(CommentRevision).where(CommentRevision.id == revision_id).with_for_update()
            )
        ).scalar_one_or_none(),
    )
    if revision is None or revision.status != CommentRevisionStatus.PENDING:
        raise CommentPolicyError("Pending comment revision not found.")
    comment = await db.get(Comment, revision.comment_id)
    if comment is None or comment.status != CommentStatus.APPROVED:
        raise CommentPolicyError("The published comment is no longer editable.")
    revision.status = CommentRevisionStatus.APPROVED if approve else CommentRevisionStatus.REJECTED
    revision.pending_key = None
    if approve:
        comment.body = revision.body
        comment.edited_at = _now()
    await db.flush()
    return revision
