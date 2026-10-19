"""Registered-account comment votes with a unique row as the source of truth."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from arborpress.models.content import Comment, CommentStatus, CommentVote
from arborpress.models.user import User


class CommentVoteError(ValueError):
    """A vote is not allowed for the requested actor/comment/value."""


@dataclass(frozen=True, slots=True)
class CommentVoteCounts:
    upvotes: int
    downvotes: int

    @property
    def score(self) -> int:
        return self.upvotes - self.downvotes


async def cast_comment_vote(
    db: Any, *, user_id: str | None, comment_id: str, value: int
) -> int | None:
    """Set one vote to +/-1, or remove it with 0; guests cannot vote."""
    if not user_id:
        raise CommentVoteError("Sign in to vote on comments.")
    if value not in {-1, 0, 1}:
        raise CommentVoteError("Vote must be -1, 0 or 1.")
    actor = await db.get(User, str(user_id))
    if actor is None or not actor.is_active:
        raise CommentVoteError("An active registered account is required to vote.")
    comment = (
        await db.execute(select(Comment).where(Comment.id == comment_id).with_for_update())
    ).scalar_one_or_none()
    if comment is None or comment.status != CommentStatus.APPROVED:
        raise CommentVoteError("Only published comments can be voted on.")
    if comment.author_user_id is not None and str(comment.author_user_id) == str(user_id):
        raise CommentVoteError("Authors cannot vote on their own comments.")

    vote = (
        await db.execute(
            select(CommentVote)
            .where(CommentVote.comment_id == comment_id, CommentVote.user_id == str(user_id))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if value == 0:
        if vote is not None:
            await db.delete(vote)
        await db.flush()
        await _audit_vote(db, user_id=str(user_id), comment_id=comment_id, detail="removed")
        return None
    if vote is not None:
        vote.value = value
        await db.flush()
        await _audit_vote(db, user_id=str(user_id), comment_id=comment_id, detail=f"value={value}")
        return int(vote.value)

    vote = CommentVote(
        id=str(uuid.uuid4()), user_id=str(user_id), comment_id=comment_id, value=value
    )
    try:
        async with db.begin_nested():
            db.add(vote)
            await db.flush()
    except IntegrityError as exc:
        # A concurrent insert won the unique (user_id, comment_id) race.
        current = (
            await db.execute(
                select(CommentVote)
                .where(CommentVote.comment_id == comment_id, CommentVote.user_id == str(user_id))
                .with_for_update()
            )
        ).scalar_one_or_none()
        if current is None:
            raise CommentVoteError("Vote conflicted with another update; retry.") from exc
        current.value = value
        await db.flush()
    await _audit_vote(db, user_id=str(user_id), comment_id=comment_id, detail=f"value={value}")
    return value


async def _audit_vote(db: Any, *, user_id: str, comment_id: str, detail: str) -> None:
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="comment_vote_changed",
        outcome="success",
        actor_id=user_id,
        target_id=comment_id,
        db=db,
        detail=detail,
    )


async def get_comment_vote_counts(db: Any, comment_id: str) -> CommentVoteCounts:
    rows = await db.execute(
        select(CommentVote.value, func.count(CommentVote.id))
        .join(Comment, Comment.id == CommentVote.comment_id)
        .where(CommentVote.comment_id == comment_id, Comment.status == CommentStatus.APPROVED)
        .group_by(CommentVote.value)
    )
    counts = {int(value): int(count) for value, count in rows.all()}
    return CommentVoteCounts(upvotes=counts.get(1, 0), downvotes=counts.get(-1, 0))
