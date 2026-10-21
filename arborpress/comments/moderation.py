"""Structured, immutable comment moderation decisions and author appeals."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from arborpress.models.content import (
    Comment,
    CommentModerationAppeal,
    CommentRevision,
    CommentRevisionStatus,
    CommentStatus,
    ModerationDecision,
)
from arborpress.models.user import User, UserRole

TargetType = Literal["comment", "revision"]
DecisionSource = Literal["human", "automated", "assisted"]


@dataclass(frozen=True, slots=True)
class ReasonCode:
    code: str
    label: str
    description: str
    human_reason_recommended: bool
    default_restriction: str


REASON_CATALOG: dict[str, ReasonCode] = {
    item.code: item
    for item in (
        ReasonCode(
            "spam", "Spam", "Unsolicited or deceptive promotional content.", False, "marked_spam"
        ),
        ReasonCode(
            "harassment",
            "Harassment",
            "Targeted intimidation or harassment.",
            True,
            "publication_denied",
        ),
        ReasonCode(
            "hate_or_abuse",
            "Hate or abuse",
            "Hateful or abusive content.",
            True,
            "publication_denied",
        ),
        ReasonCode(
            "illegal_content",
            "Illegal content",
            "Content that appears to violate applicable law.",
            True,
            "content_removed",
        ),
        ReasonCode(
            "personal_data",
            "Personal data",
            "Unnecessary exposure of personal information.",
            True,
            "content_removed",
        ),
        ReasonCode(
            "off_topic",
            "Off topic",
            "Content is unrelated to the discussion.",
            False,
            "publication_denied",
        ),
        ReasonCode("duplicate", "Duplicate", "Duplicate submission.", False, "publication_denied"),
        ReasonCode(
            "misinformation_or_deceptive",
            "Misleading content",
            "Deceptive or materially misleading content.",
            True,
            "publication_denied",
        ),
        ReasonCode(
            "rule_violation",
            "Rule violation",
            "The content does not follow the site rules.",
            True,
            "publication_denied",
        ),
        ReasonCode(
            "automated_policy",
            "Automatic policy",
            "The active site policy determined this outcome.",
            False,
            "none",
        ),
        ReasonCode(
            "appeal_overturned",
            "Appeal outcome",
            "A reviewed appeal changed the effective result.",
            True,
            "none",
        ),
        ReasonCode(
            "no_violation",
            "No violation",
            "The content is suitable for publication.",
            False,
            "none",
        ),
        ReasonCode(
            "other", "Other", "Another reason not represented by a specific code.", True, "other"
        ),
    )
}

COMMENT_OUTCOMES = {"approve", "reject", "spam", "delete", "restore"}
REVISION_OUTCOMES = {"approve", "reject", "restore"}
RESTRICTIONS = {
    "none",
    "publication_denied",
    "content_removed",
    "marked_spam",
    "edit_rejected",
    "other",
}
MAX_REASON_LENGTH = 2000
MAX_APPEAL_LENGTH = 5000


class ModerationError(ValueError):
    """A moderation or appeal operation is invalid or stale."""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def validate_reason(
    *, reason_code: str, human_reason: str | None, restriction_type: str | None
) -> tuple[ReasonCode, str | None, str]:
    reason = REASON_CATALOG.get(reason_code)
    if reason is None:
        raise ModerationError("Choose a supported moderation reason.")
    text = (human_reason or "").strip() or None
    if len(text or "") > MAX_REASON_LENGTH:
        raise ModerationError("The explanation is too long.")
    if reason.code == "other" and not text:
        raise ModerationError("An explanation is required when the reason is Other.")
    restriction = restriction_type or reason.default_restriction
    if restriction not in RESTRICTIONS:
        raise ModerationError("Choose a supported restriction type.")
    return reason, text, restriction


async def _audit(
    db: Any, *, event_type: str, actor_id: str | None, target_id: str, detail: str
) -> None:
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type=event_type,
        outcome="success",
        actor_id=actor_id,
        target_id=target_id,
        detail=detail,
        db=db,
    )


async def _new_decision(
    db: Any,
    *,
    target_type: TargetType,
    target_id: str,
    actor_id: str | None,
    outcome: str,
    reason_code: str,
    human_reason: str | None = None,
    rule_reference: str | None = None,
    restriction_type: str = "none",
    decision_source: DecisionSource = "human",
    supersedes_decision_id: str | None = None,
) -> ModerationDecision:
    if decision_source not in {"human", "automated", "assisted"}:
        raise ModerationError("Unsupported decision source.")
    if not reason_code or len(reason_code) > 48:
        raise ModerationError("Invalid moderation reason code.")
    if restriction_type not in RESTRICTIONS:
        raise ModerationError("Invalid restriction type.")
    if human_reason and len(human_reason) > MAX_REASON_LENGTH:
        raise ModerationError("The explanation is too long.")
    reference = (rule_reference or "").strip() or None
    if len(reference or "") > 256:
        raise ModerationError("The rule reference is too long.")
    record = ModerationDecision(
        id=str(uuid.uuid4()),
        target_type=target_type,
        target_id=target_id,
        actor_user_id=actor_id,
        outcome=outcome,
        reason_code=reason_code,
        human_reason=human_reason,
        rule_reference=reference,
        restriction_type=restriction_type,
        decision_source=decision_source,
        supersedes_decision_id=supersedes_decision_id,
    )
    db.add(record)
    await db.flush()
    return record


async def record_automatic_decision(
    db: Any, *, target_id: str, outcome: str, reason_code: str
) -> ModerationDecision:
    """Record a deterministic core-policy result without labeling it as AI."""
    reason = REASON_CATALOG.get(reason_code)
    if reason is None:
        raise ModerationError("Unsupported automatic decision reason.")
    restriction = "marked_spam" if outcome == "spam" else "none"
    decision = await _new_decision(
        db,
        target_type="comment",
        target_id=target_id,
        actor_id=None,
        outcome=outcome,
        reason_code=reason.code,
        restriction_type=restriction,
        decision_source="automated",
    )
    return decision


async def moderate_comment(
    db: Any,
    *,
    comment_id: str,
    actor_user_id: str,
    outcome: str,
    reason_code: str,
    human_reason: str | None = None,
    rule_reference: str | None = None,
    restriction_type: str | None = None,
    decision_source: DecisionSource = "human",
    supersedes_decision_id: str | None = None,
) -> ModerationDecision:
    """Apply one allowed comment state transition and record it atomically."""
    comment = (
        await db.execute(select(Comment).where(Comment.id == comment_id).with_for_update())
    ).scalar_one_or_none()
    if comment is None:
        raise ModerationError("Comment not found.")
    if outcome not in COMMENT_OUTCOMES:
        raise ModerationError("Unsupported comment decision.")
    next_status = {
        "approve": CommentStatus.APPROVED,
        "restore": CommentStatus.APPROVED,
        "reject": CommentStatus.REJECTED,
        "spam": CommentStatus.SPAM,
        "delete": CommentStatus.DELETED,
    }[outcome]
    allowed = {
        CommentStatus.PENDING_MODERATION: {"approve", "reject", "spam"},
        CommentStatus.APPROVED: {"delete", "spam"},
        CommentStatus.REJECTED: {"restore"},
        CommentStatus.SPAM: {"restore"},
        CommentStatus.DELETED: {"restore"},
    }
    if outcome not in allowed.get(comment.status, set()):
        raise ModerationError("The comment has already changed or this transition is not allowed.")
    reason, text, restriction = validate_reason(
        reason_code=reason_code, human_reason=human_reason, restriction_type=restriction_type
    )
    result = await db.execute(
        update(Comment)
        .where(Comment.id == comment_id, Comment.status == comment.status)
        .values(
            status=next_status,
            approved_at=_now() if next_status == CommentStatus.APPROVED else comment.approved_at,
            published_at=(
                comment.published_at or _now()
                if next_status == CommentStatus.APPROVED
                else comment.published_at
            ),
        )
    )
    if result.rowcount != 1:
        raise ModerationError("The comment changed concurrently; reload and retry.")
    decision = await _new_decision(
        db,
        target_type="comment",
        target_id=comment.id,
        actor_id=actor_user_id,
        outcome=outcome,
        reason_code=reason.code,
        human_reason=text,
        rule_reference=rule_reference,
        restriction_type=restriction,
        decision_source=decision_source,
        supersedes_decision_id=supersedes_decision_id,
    )
    event_types = {
        "approve": "comment_approved",
        "reject": "comment_rejected",
        "spam": "comment_spam",
        "delete": "comment_deleted",
        "restore": "comment_restored",
    }
    await _audit(
        db,
        event_type=event_types[outcome],
        actor_id=actor_user_id,
        target_id=comment.id,
        detail=f"decision={decision.id};reason={reason.code}",
    )
    if comment.author_user_id:
        from arborpress.notifications.service import create_notification

        await create_notification(
            db,
            user_id=str(comment.author_user_id),
            notification_type="comment.moderation_decision",
            payload={"outcome": outcome},
            target_path="/notifications",
            dedupe_key=f"decision:{decision.id}",
            source_type="comment",
            source_id=comment.id,
        )
    return decision


async def moderate_revision(
    db: Any,
    *,
    revision_id: str,
    actor_user_id: str,
    outcome: Literal["approve", "reject"],
    reason_code: str,
    human_reason: str | None = None,
    rule_reference: str | None = None,
    decision_source: DecisionSource = "human",
) -> ModerationDecision:
    revision = (
        await db.execute(
            select(CommentRevision).where(CommentRevision.id == revision_id).with_for_update()
        )
    ).scalar_one_or_none()
    if revision is None or revision.status != CommentRevisionStatus.PENDING:
        raise ModerationError("The revision is no longer awaiting review.")
    comment = (
        await db.execute(select(Comment).where(Comment.id == revision.comment_id).with_for_update())
    ).scalar_one_or_none()
    if comment is None or comment.status != CommentStatus.APPROVED:
        raise ModerationError("The published comment is no longer available for revision review.")
    reason, text, _ = validate_reason(
        reason_code=reason_code,
        human_reason=human_reason,
        restriction_type="edit_rejected" if outcome == "reject" else "none",
    )
    expected = CommentRevisionStatus.PENDING
    result = await db.execute(
        update(CommentRevision)
        .where(CommentRevision.id == revision.id, CommentRevision.status == expected)
        .values(
            status=CommentRevisionStatus.APPROVED
            if outcome == "approve"
            else CommentRevisionStatus.REJECTED,
            pending_key=None,
        )
    )
    if result.rowcount != 1:
        raise ModerationError("The revision changed concurrently; reload and retry.")
    if outcome == "approve":
        comment.body = revision.body
        comment.edited_at = _now()
    decision = await _new_decision(
        db,
        target_type="revision",
        target_id=revision.id,
        actor_id=actor_user_id,
        outcome=outcome,
        reason_code=reason.code,
        human_reason=text,
        rule_reference=rule_reference,
        restriction_type="none" if outcome == "approve" else "edit_rejected",
        decision_source=decision_source,
    )
    await _audit(
        db,
        event_type=f"comment_revision_{outcome}d"
        if outcome == "approve"
        else "comment_revision_rejected",
        actor_id=actor_user_id,
        target_id=revision.id,
        detail=f"decision={decision.id};comment={comment.id};reason={reason.code}",
    )
    if comment.author_user_id:
        from arborpress.notifications.service import create_notification

        await create_notification(
            db,
            user_id=str(comment.author_user_id),
            notification_type="comment.revision_decision",
            payload={"outcome": outcome},
            target_path="/notifications",
            dedupe_key=f"decision:{decision.id}",
            source_type="comment",
            source_id=str(comment.id),
        )
    return decision


async def _decision_comment(
    db: Any, decision: ModerationDecision
) -> tuple[Comment, CommentRevision | None]:
    if decision.target_type == "comment":
        comment = await db.get(Comment, decision.target_id)
        revision = None
    elif decision.target_type == "revision":
        revision = await db.get(CommentRevision, decision.target_id)
        comment = await db.get(Comment, revision.comment_id) if revision else None
    else:
        comment, revision = None, None
    if comment is None:
        raise ModerationError("The appealed comment is no longer available.")
    return comment, revision


async def submit_comment_appeal(
    db: Any,
    *,
    decision_id: str,
    appellant_user_id: str,
    statement: str,
    appeal_window_days: int = 14,
) -> CommentModerationAppeal:
    """Submit one appeal from the registered author affected by a decision."""
    decision = await db.get(ModerationDecision, decision_id)
    if decision is None:
        raise ModerationError("Appealable decision not found.")
    if decision.outcome not in {"reject", "spam", "delete"}:
        # Revision rejection uses the same outcome and target_type.
        raise ModerationError("This decision cannot be appealed.")
    superseded = await db.scalar(
        select(func.count(ModerationDecision.id)).where(
            ModerationDecision.supersedes_decision_id == decision.id
        )
    )
    if superseded:
        raise ModerationError("This decision has already been replaced.")
    comment, revision = await _decision_comment(db, decision)
    if comment.author_user_id is None or str(comment.author_user_id) != str(appellant_user_id):
        raise ModerationError("Only the registered author may appeal this decision.")
    window_days = min(90, max(1, int(appeal_window_days)))
    decided = decision.created_at or _now()
    if _now() > decided + timedelta(days=window_days):
        raise ModerationError("The appeal period has expired.")
    if decision.target_type == "revision" and (
        revision is None
        or revision.editor_user_id is None
        or str(revision.editor_user_id) != str(appellant_user_id)
    ):
        raise ModerationError("Only the author of this revision may appeal its decision.")
    text = statement.strip()
    if not text or len(text) > MAX_APPEAL_LENGTH:
        raise ModerationError("An appeal statement is required (maximum 5,000 characters).")
    appeal = CommentModerationAppeal(
        id=str(uuid.uuid4()),
        decision_id=decision.id,
        appellant_user_id=str(appellant_user_id),
        statement=text,
        state="pending",
    )
    try:
        async with db.begin_nested():
            db.add(appeal)
            await db.flush()
    except IntegrityError as exc:
        raise ModerationError("An appeal for this decision has already been submitted.") from exc
    await _audit(
        db,
        event_type="comment_appeal_submitted",
        actor_id=str(appellant_user_id),
        target_id=appeal.id,
        detail=(
            f"decision={decision.id};comment={comment.id};"
            f"revision={revision.id if revision else ''}"
        ),
    )
    return appeal


async def review_comment_appeal(
    db: Any,
    *,
    appeal_id: str,
    reviewer_user_id: str,
    outcome: Literal["upheld", "overturned"],
    reviewer_reason: str,
    other_reviewer_available: bool | None = None,
) -> CommentModerationAppeal:
    appeal = (
        await db.execute(
            select(CommentModerationAppeal)
            .where(CommentModerationAppeal.id == appeal_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if appeal is None or appeal.state != "pending":
        raise ModerationError("The appeal is no longer pending review.")
    reason = reviewer_reason.strip()
    if not reason or len(reason) > MAX_REASON_LENGTH:
        raise ModerationError("A review reason is required (maximum 2,000 characters).")
    decision = await db.get(ModerationDecision, appeal.decision_id)
    if decision is None:
        raise ModerationError("The original decision is unavailable.")
    other_reviewers = other_reviewer_available
    if other_reviewers is None:
        other_reviewers = bool(
            await db.scalar(
                select(func.count(User.id)).where(
                    User.is_active.is_(True),
                    User.role.in_([UserRole.ADMIN, UserRole.EDITOR, UserRole.MODERATOR]),
                    User.id != decision.actor_user_id,
                )
            )
        )
    self_exception = bool(
        decision.actor_user_id
        and str(decision.actor_user_id) == str(reviewer_user_id)
        and not other_reviewers
    )
    if (
        decision.actor_user_id
        and str(decision.actor_user_id) == str(reviewer_user_id)
        and other_reviewers
    ):
        raise ModerationError("A different moderator must review this appeal.")
    replacement = None
    if outcome == "overturned":
        if decision.target_type == "revision":
            revision = await db.get(CommentRevision, decision.target_id)
            comment = await db.get(Comment, revision.comment_id) if revision else None
            if revision is None or comment is None:
                raise ModerationError("The appealed revision is unavailable.")
            revision.status = CommentRevisionStatus.APPROVED
            revision.pending_key = None
            comment.body = revision.body
            comment.edited_at = _now()
            replacement = await _new_decision(
                db,
                target_type="revision",
                target_id=revision.id,
                actor_id=reviewer_user_id,
                outcome="restore",
                reason_code=decision.reason_code,
                human_reason=reason,
                restriction_type="none",
                supersedes_decision_id=decision.id,
            )
        else:
            comment, _ = await _decision_comment(db, decision)
            if comment.status not in {
                CommentStatus.REJECTED,
                CommentStatus.SPAM,
                CommentStatus.DELETED,
            }:
                raise ModerationError("The comment state changed before the appeal was reviewed.")
            result = await db.execute(
                update(Comment)
                .where(Comment.id == comment.id, Comment.status == comment.status)
                .values(
                    status=CommentStatus.APPROVED,
                    approved_at=_now(),
                    published_at=comment.published_at or _now(),
                )
            )
            if result.rowcount != 1:
                raise ModerationError("The comment changed concurrently; reload and retry.")
            replacement = await _new_decision(
                db,
                target_type="comment",
                target_id=comment.id,
                actor_id=reviewer_user_id,
                outcome="restore",
                reason_code=decision.reason_code,
                human_reason=reason,
                restriction_type="none",
                supersedes_decision_id=decision.id,
            )
    result = await db.execute(
        update(CommentModerationAppeal)
        .where(
            CommentModerationAppeal.id == appeal.id,
            CommentModerationAppeal.state == "pending",
        )
        .values(
            state=outcome,
            reviewer_user_id=reviewer_user_id,
            reviewed_at=_now(),
            outcome=outcome,
            reviewer_reason=reason,
            replacement_decision_id=replacement.id if replacement else None,
            self_review_exception=self_exception,
        )
    )
    if result.rowcount != 1:
        raise ModerationError("The appeal changed concurrently; reload and retry.")
    await _audit(
        db,
        event_type="comment_appeal_reviewed",
        actor_id=reviewer_user_id,
        target_id=appeal.id,
        detail=(
            f"decision={decision.id};outcome={outcome};"
            f"replacement={replacement.id if replacement else ''};"
            f"self_review={self_exception}"
        ),
    )
    if appeal.appellant_user_id:
        from arborpress.notifications.service import create_notification

        await create_notification(
            db,
            user_id=str(appeal.appellant_user_id),
            notification_type="comment.appeal_reviewed",
            payload={"outcome": outcome},
            target_path="/notifications",
            dedupe_key=f"appeal:{appeal.id}:reviewed",
            source_type="appeal",
            source_id=appeal.id,
        )
    return cast(CommentModerationAppeal, appeal)


async def moderation_transparency(
    db: Any, *, start: datetime, end: datetime, post_ids: Sequence[str] | None = None
) -> dict[str, Any]:
    """Return anonymized, grouped decision and appeal counts for a time range."""
    decision_filters = [
        ModerationDecision.created_at >= start,
        ModerationDecision.created_at < end,
    ]
    appeal_filters = [
        CommentModerationAppeal.created_at >= start,
        CommentModerationAppeal.created_at < end,
    ]
    if post_ids is not None:
        comment_ids = select(Comment.id).where(Comment.post_id.in_(post_ids))
        revision_ids = (
            select(CommentRevision.id)
            .join(Comment, Comment.id == CommentRevision.comment_id)
            .where(Comment.post_id.in_(post_ids))
        )
        decision_filters.append(
            or_(
                and_(
                    ModerationDecision.target_type == "comment",
                    ModerationDecision.target_id.in_(comment_ids),
                ),
                and_(
                    ModerationDecision.target_type == "revision",
                    ModerationDecision.target_id.in_(revision_ids),
                ),
            )
        )
        decision_ids = select(ModerationDecision.id).where(*decision_filters)
        appeal_filters.append(CommentModerationAppeal.decision_id.in_(decision_ids))
    decision_rows = await db.execute(
        select(
            ModerationDecision.reason_code,
            ModerationDecision.restriction_type,
            ModerationDecision.decision_source,
            ModerationDecision.outcome,
            func.count(ModerationDecision.id),
        )
        .where(*decision_filters)
        .group_by(
            ModerationDecision.reason_code,
            ModerationDecision.restriction_type,
            ModerationDecision.decision_source,
            ModerationDecision.outcome,
        )
        .order_by(ModerationDecision.reason_code, ModerationDecision.restriction_type)
    )
    appeal_rows = await db.execute(
        select(CommentModerationAppeal.state, func.count(CommentModerationAppeal.id))
        .where(*appeal_filters)
        .group_by(CommentModerationAppeal.state)
    )
    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "decisions": [
            {
                "reason_code": reason,
                "restriction_type": restriction,
                "decision_source": source,
                "outcome": outcome,
                "count": int(count),
            }
            for reason, restriction, source, outcome, count in decision_rows.all()
        ],
        "appeals": {state: int(count) for state, count in appeal_rows.all()},
    }


async def decisions_for_target(
    db: Any, *, target_type: TargetType, target_ids: Sequence[str]
) -> list[ModerationDecision]:
    if not target_ids:
        return []
    result = await db.execute(
        select(ModerationDecision)
        .where(
            ModerationDecision.target_type == target_type,
            ModerationDecision.target_id.in_(target_ids),
        )
        .order_by(ModerationDecision.created_at, ModerationDecision.id)
    )
    return list(result.scalars().all())
