"""Structured decision, appeal and aggregation contracts for comment moderation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from arborpress.comments import (
    REASON_CATALOG,
    ModerationError,
    moderate_comment,
    moderate_revision,
    moderation_transparency,
    review_comment_appeal,
    submit_comment_appeal,
)
from arborpress.models.content import (
    Comment,
    CommentRevision,
    CommentRevisionStatus,
    CommentStatus,
    ModerationDecision,
    Post,
    PostStatus,
)
from arborpress.models.user import AccountType, User, UserRole


def _user(role: UserRole = UserRole.AUTHOR) -> User:
    suffix = uuid.uuid4().hex[:10]
    return User(
        username=f"mod-{suffix}",
        display_name=f"User {suffix}",
        account_type=AccountType.PUBLIC,
        role=role,
        is_active=True,
    )


async def _comment(db, author: User, *, status: CommentStatus = CommentStatus.PENDING_MODERATION):
    post = Post(
        short_id=uuid.uuid4().hex[:8],
        slug=f"moderation-{uuid.uuid4().hex[:10]}",
        title="Moderation post",
        body_md="",
        body_html="",
    )
    db.add(post)
    await db.flush()
    comment = Comment(
        post_id=post.id,
        author_user_id=str(author.id),
        author_name=author.display_name,
        body="Original published text",
        status=status,
        created_at=datetime.now(UTC).replace(tzinfo=None),
        published_at=datetime.now(UTC).replace(tzinfo=None)
        if status == CommentStatus.APPROVED
        else None,
    )
    db.add(comment)
    await db.flush()
    return comment


@pytest.mark.asyncio
async def test_reason_catalog_and_decisions_are_structured_and_state_checked(db_session):
    author = _user()
    moderator = _user(UserRole.MODERATOR)
    db_session.add_all([author, moderator])
    await db_session.flush()
    comment = await _comment(db_session, author)

    with pytest.raises(ModerationError, match="required"):
        await moderate_comment(
            db_session,
            comment_id=comment.id,
            actor_user_id=str(moderator.id),
            outcome="reject",
            reason_code="other",
        )
    decision = await moderate_comment(
        db_session,
        comment_id=comment.id,
        actor_user_id=str(moderator.id),
        outcome="reject",
        reason_code="harassment",
        human_reason="Targeted abuse in the submission.",
        rule_reference="Community rule 4",
    )
    assert decision.target_type == "comment"
    assert decision.reason_code == "harassment"
    assert decision.decision_source == "human"
    assert decision.restriction_type == "publication_denied"
    assert comment.status == CommentStatus.REJECTED
    with pytest.raises(ModerationError, match="already changed"):
        await moderate_comment(
            db_session,
            comment_id=comment.id,
            actor_user_id=str(moderator.id),
            outcome="reject",
            reason_code="harassment",
        )
    assert "other" in REASON_CATALOG
    assert decision.human_reason != comment.body


@pytest.mark.asyncio
async def test_revision_moderation_keeps_published_timestamp_and_records_decision(db_session):
    author = _user()
    moderator = _user(UserRole.MODERATOR)
    db_session.add_all([author, moderator])
    await db_session.flush()
    comment = await _comment(db_session, author, status=CommentStatus.APPROVED)
    original_published_at = comment.published_at
    revision = CommentRevision(
        comment_id=comment.id,
        editor_user_id=str(author.id),
        revision_number=1,
        previous_body=comment.body,
        body="Revised and approved text",
        status=CommentRevisionStatus.PENDING,
        pending_key=comment.id,
        is_author_edit=True,
    )
    db_session.add(revision)
    await db_session.flush()
    decision = await moderate_revision(
        db_session,
        revision_id=revision.id,
        actor_user_id=str(moderator.id),
        outcome="approve",
        reason_code="no_violation",
        decision_source="assisted",
    )
    await db_session.refresh(comment)
    assert decision.target_type == "revision"
    assert decision.decision_source == "assisted"
    assert revision.status == CommentRevisionStatus.APPROVED
    assert comment.body == "Revised and approved text"
    assert comment.published_at == original_published_at
    assert comment.is_edited


@pytest.mark.asyncio
async def test_author_appeal_overturns_without_rewriting_original_decision(db_session):
    author = _user()
    moderator = _user(UserRole.MODERATOR)
    reviewer = _user(UserRole.EDITOR)
    db_session.add_all([author, moderator, reviewer])
    await db_session.flush()
    comment = await _comment(db_session, author)
    original = await moderate_comment(
        db_session,
        comment_id=comment.id,
        actor_user_id=str(moderator.id),
        outcome="reject",
        reason_code="rule_violation",
        human_reason="Review required.",
    )
    appeal = await submit_comment_appeal(
        db_session,
        decision_id=original.id,
        appellant_user_id=str(author.id),
        statement="The cited rule does not apply here.",
    )
    with pytest.raises(ModerationError, match="already been submitted"):
        await submit_comment_appeal(
            db_session,
            decision_id=original.id,
            appellant_user_id=str(author.id),
            statement="Another appeal",
        )
    reviewed = await review_comment_appeal(
        db_session,
        appeal_id=appeal.id,
        reviewer_user_id=str(reviewer.id),
        outcome="overturned",
        reviewer_reason="The content is within the discussion scope.",
    )
    await db_session.refresh(comment)
    assert reviewed.state == "overturned"
    assert comment.status == CommentStatus.APPROVED
    assert original.outcome == "reject"
    assert reviewed.replacement_decision_id
    replacement = await db_session.get(ModerationDecision, reviewed.replacement_decision_id)
    assert replacement is not None
    assert replacement.supersedes_decision_id == original.id
    with pytest.raises(ModerationError, match="already been replaced"):
        await submit_comment_appeal(
            db_session,
            decision_id=original.id,
            appellant_user_id=str(author.id),
            statement="Late duplicate appeal",
        )


@pytest.mark.asyncio
async def test_appeal_window_and_reviewer_separation_with_single_moderator_exception(db_session):
    author = _user()
    moderator = _user(UserRole.MODERATOR)
    other = _user(UserRole.EDITOR)
    db_session.add_all([author, moderator, other])
    await db_session.flush()
    comment = await _comment(db_session, author)
    decision = await moderate_comment(
        db_session,
        comment_id=comment.id,
        actor_user_id=str(moderator.id),
        outcome="reject",
        reason_code="rule_violation",
    )
    with pytest.raises(ModerationError, match="different moderator"):
        appeal = await submit_comment_appeal(
            db_session,
            decision_id=decision.id,
            appellant_user_id=str(author.id),
            statement="Please review.",
        )
        await review_comment_appeal(
            db_session,
            appeal_id=appeal.id,
            reviewer_user_id=str(moderator.id),
            outcome="upheld",
            reviewer_reason="The decision stands.",
        )
    decision.created_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=20)
    with pytest.raises(ModerationError, match="expired"):
        await submit_comment_appeal(
            db_session,
            decision_id=decision.id,
            appellant_user_id=str(author.id),
            statement="Too late.",
        )


@pytest.mark.asyncio
async def test_automated_decisions_and_transparency_are_aggregated_without_rows(db_session):
    from arborpress.comments import record_automatic_decision

    author = _user()
    db_session.add(author)
    await db_session.flush()
    comment = await _comment(db_session, author, status=CommentStatus.SPAM)
    decision = await record_automatic_decision(
        db_session, target_id=comment.id, outcome="spam", reason_code="spam"
    )
    start = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1)
    end = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1)
    report = await moderation_transparency(db_session, start=start, end=end)
    assert decision.decision_source == "automated"
    assert {
        "reason_code": "spam",
        "restriction_type": "marked_spam",
        "decision_source": "automated",
        "outcome": "spam",
        "count": 1,
    } in report["decisions"]
    assert all("target_id" not in item for item in report["decisions"])
    assert report["appeals"] == {}


@pytest.mark.asyncio
async def test_public_thread_is_ssr_escaped_nested_and_contains_deleted_placeholder(
    test_engine, client, monkeypatch
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    suffix = uuid.uuid4().hex[:10]
    async with factory() as db:
        author = _user()
        post = Post(
            short_id=uuid.uuid4().hex[:8],
            slug=f"thread-{suffix}",
            title="Thread rendering",
            body_md="",
            body_html="<p>Post</p>",
            status=PostStatus.PUBLISHED,
            published_at=datetime.now(UTC).replace(tzinfo=None),
            author_id=str(author.id),
        )
        db.add_all([author, post])
        await db.flush()
        # SQLAlchemy assigns the UUID primary key on INSERT, so bind the post
        # author only after the user has been flushed.
        post.author_id = str(author.id)
        await db.flush()
        root = Comment(
            post_id=post.id,
            author_user_id=str(author.id),
            author_name="<script>alert(1)</script>",
            body="<script>comment-xss()</script>",
            status=CommentStatus.APPROVED,
            published_at=datetime.now(UTC).replace(tzinfo=None),
        )
        db.add(root)
        await db.flush()
        child = Comment(
            post_id=post.id,
            author_name="Guest",
            author_email="guest@example.test",
            body="A reply",
            status=CommentStatus.APPROVED,
            parent_id=root.id,
            quote_of_id=root.id,
            published_at=datetime.now(UTC).replace(tzinfo=None),
        )
        deleted = Comment(
            post_id=post.id,
            author_name="Former guest",
            body="not public",
            status=CommentStatus.DELETED,
            parent_id=root.id,
        )
        db.add_all([child, deleted])
        await db.flush()
        await db.commit()
        root_id, child_id, author_id = root.id, child.id, str(author.id)

    response = await client.get(f"/p/thread-{suffix}")
    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert f'id="comment-{root_id}"' in html
    assert f'id="comment-{child_id}"' in html
    assert "A reply" in html
    assert "Dieser Kommentar wurde moderiert." in html
    assert "<script>comment-xss()" not in html
    assert "&lt;script&gt;comment-xss()&lt;/script&gt;" in html
    assert "guest@example.test" not in html
    assert "comment__vote-form" not in html

    async with client.session_transaction() as browser_session:
        browser_session["user_id"] = author_id
    signed_in = await client.get(f"/p/thread-{suffix}")
    signed_in_html = await signed_in.get_data(as_text=True)
    assert 'class="comment__author-marker">Autor</span>' in signed_in_html
    assert "comment__vote-form" in signed_in_html
    assert 'aria-pressed="false"' in signed_in_html
