"""Core comment policy, threading, guest confirmation, revision and vote behavior."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from arborpress.comments import (
    CommentPolicyError,
    CommentTokenError,
    build_comment_thread,
    can_edit_comment,
    cast_comment_vote,
    confirm_guest_comment,
    create_comment,
    create_comment_revision,
    get_comment_vote_counts,
    issue_guest_confirmation,
    resolve_comment_policy,
    review_comment_revision,
)
from arborpress.comments.voting import CommentVoteError
from arborpress.models.content import (
    Comment,
    CommentRevisionStatus,
    CommentStatus,
    CommentVote,
    Post,
)
from arborpress.models.user import AccountType, User, UserRole


def _post(slug: str | None = None) -> Post:
    suffix = uuid.uuid4().hex[:10]
    return Post(
        short_id=uuid.uuid4().hex[:8],
        slug=slug or f"comment-{suffix}",
        title="Comment test",
        body_md="",
        body_html="",
    )


def _user(*, trusted: bool = False) -> User:
    suffix = uuid.uuid4().hex[:10]
    return User(
        username=f"comment-{suffix}",
        display_name="Comment Author",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
        comment_trusted=trusted,
    )


@pytest.mark.asyncio
async def test_guest_confirmation_hash_ttl_one_shot_and_policy_transition(db_session):
    post = _post()
    db_session.add(post)
    await db_session.flush()
    policy = resolve_comment_policy(post, {"require_email_confirmation": True})
    created = await create_comment(
        db_session,
        post=post,
        policy=policy,
        author_name="Guest",
        author_email="guest@example.test",
        body="A comment",
    )
    assert created.comment.status == CommentStatus.PENDING_CONFIRMATION
    assert created.confirmation_token
    assert created.confirmation_token not in (created.comment.confirmation_token_hash or "")
    assert created.comment.confirmation_expires_at is not None
    assert created.comment.confirmation_expires_at <= datetime.now(UTC).replace(
        tzinfo=None
    ) + timedelta(hours=25)
    with pytest.raises(CommentTokenError):
        await confirm_guest_comment(
            db_session,
            token=f"{created.confirmation_token}é",
            settings={"moderation_mode": "always"},
        )

    confirmed = await confirm_guest_comment(
        db_session,
        token=created.confirmation_token,
        settings={"moderation_mode": "always"},
    )
    assert confirmed.status == CommentStatus.PENDING_MODERATION
    assert confirmed.confirmation_token_hash is None
    assert confirmed.confirmation_expires_at is None
    with pytest.raises(CommentTokenError):
        await confirm_guest_comment(
            db_session,
            token=created.confirmation_token,
            settings={"moderation_mode": "always"},
        )


@pytest.mark.asyncio
async def test_expired_guest_confirmation_is_rejected_and_spam_cannot_be_reactivated(db_session):
    post = _post()
    db_session.add(post)
    await db_session.flush()
    created = await create_comment(
        db_session,
        post=post,
        policy=resolve_comment_policy(post, {"require_email_confirmation": True}),
        author_name="Guest",
        author_email="guest@example.test",
        body="Expired",
    )
    created.comment.confirmation_expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
        seconds=1
    )
    await db_session.flush()
    with pytest.raises(CommentTokenError):
        await confirm_guest_comment(
            db_session,
            token=created.confirmation_token or "",
            settings={"moderation_mode": "always"},
        )
    assert created.comment.status == CommentStatus.PENDING_CONFIRMATION


@pytest.mark.asyncio
async def test_resend_rotates_token_and_enforces_cooldown(db_session):
    post = _post()
    db_session.add(post)
    await db_session.flush()
    created = await create_comment(
        db_session,
        post=post,
        policy=resolve_comment_policy(post, {"require_email_confirmation": True}),
        author_name="Guest",
        author_email="guest@example.test",
        body="Resend",
    )
    with pytest.raises(CommentTokenError):
        await issue_guest_confirmation(db_session, comment=created.comment)
    created.comment.confirmation_sent_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
        minutes=2
    )
    old_token = created.confirmation_token
    new_token = await issue_guest_confirmation(db_session, comment=created.comment)
    assert old_token is not None and new_token != old_token
    with pytest.raises(CommentTokenError):
        await confirm_guest_comment(
            db_session, token=old_token, settings={"moderation_mode": "always"}
        )
    assert (
        await confirm_guest_comment(
            db_session, token=new_token, settings={"moderation_mode": "always"}
        )
    ).status == CommentStatus.PENDING_MODERATION


@pytest.mark.asyncio
async def test_policy_modes_and_per_post_overrides(db_session):
    post = _post()
    db_session.add(post)
    await db_session.flush()
    guest_policy = resolve_comment_policy(post, {"enabled": True, "moderation_mode": "always"})
    assert guest_policy.moderation_mode == "always"
    assert guest_policy.visible_max_depth == 4
    post.comments_enabled = False
    post.guest_confirmation_required = False
    post.comment_moderation_mode = "none"
    override = resolve_comment_policy(post, {"enabled": True, "require_email_confirmation": True})
    assert not override.enabled
    assert not override.guest_confirmation_required
    assert override.moderation_mode == "none"
    restricted = resolve_comment_policy(post, {"allow_replies": False, "allow_quotes": False})
    assert not restricted.allow_replies
    assert not restricted.allow_quotes


@pytest.mark.asyncio
async def test_first_n_and_trusted_bypass_only_apply_to_registered_accounts(db_session):
    post, author = _post(), _user()
    trusted = _user(trusted=True)
    db_session.add_all([post, author, trusted])
    await db_session.flush()
    first_n = resolve_comment_policy(
        post,
        {
            "require_email_confirmation": True,
            "moderation_mode": "first_n",
            "first_n_count": 1,
        },
    )
    first = await create_comment(
        db_session,
        post=post,
        policy=first_n,
        author_name="Author",
        author_email=None,
        author_user=author,
        body="first",
    )
    assert first.confirmation_token is None
    assert first.comment.status == CommentStatus.PENDING_MODERATION
    first.comment.status = CommentStatus.APPROVED
    await db_session.flush()
    next_comment = await create_comment(
        db_session,
        post=post,
        policy=first_n,
        author_name="Author",
        author_email=None,
        author_user=author,
        body="next",
    )
    assert next_comment.comment.status == CommentStatus.APPROVED
    trusted_policy = resolve_comment_policy(post, {"moderation_mode": "trusted_bypass"})
    trusted_comment = await create_comment(
        db_session,
        post=post,
        policy=trusted_policy,
        author_name="Trusted",
        author_email=None,
        author_user=trusted,
        body="trusted",
    )
    assert trusted_comment.comment.status == CommentStatus.APPROVED


@pytest.mark.asyncio
async def test_parent_and_quote_are_separate_same_post_relations(db_session):
    post, other = _post(), _post()
    db_session.add_all([post, other])
    await db_session.flush()
    policy = resolve_comment_policy(
        post, {"require_email_confirmation": False, "require_admin_approval": False}
    )
    root = await create_comment(
        db_session, post=post, policy=policy, author_name="A", author_email=None, body="root"
    )
    first_reply = await create_comment(
        db_session,
        post=post,
        policy=policy,
        author_name="B",
        author_email=None,
        body="reply",
        parent_id=root.comment.id,
    )
    second_reply = await create_comment(
        db_session,
        post=post,
        policy=policy,
        author_name="C",
        author_email=None,
        body="reply to B",
        parent_id=first_reply.comment.id,
        quote_of_id=root.comment.id,
    )
    assert second_reply.comment.parent_id == first_reply.comment.id
    assert second_reply.comment.quote_of_id == root.comment.id
    with pytest.raises(CommentPolicyError):
        await create_comment(
            db_session,
            post=post,
            policy=policy,
            author_name="D",
            author_email=None,
            body="foreign parent",
            parent_id=str(uuid.uuid4()),
        )
    other_comment = await create_comment(
        db_session,
        post=other,
        policy=resolve_comment_policy(
            other, {"require_admin_approval": False, "require_email_confirmation": False}
        ),
        author_name="E",
        author_email=None,
        body="other post",
    )
    with pytest.raises(CommentPolicyError):
        await create_comment(
            db_session,
            post=post,
            policy=policy,
            author_name="F",
            author_email=None,
            body="foreign quote",
            quote_of_id=other_comment.comment.id,
        )
    tree = build_comment_thread([second_reply.comment, root.comment, first_reply.comment])
    assert [node.comment.id for node in tree] == [root.comment.id]
    assert tree[0].replies[0].comment.id == first_reply.comment.id
    assert tree[0].replies[0].replies[0].comment.id == second_reply.comment.id


@pytest.mark.asyncio
async def test_thread_builder_uses_timestamp_and_id_and_retains_logical_depth(db_session):
    post = _post()
    db_session.add(post)
    await db_session.flush()
    now = datetime.now(UTC).replace(tzinfo=None)
    nodes = [
        Comment(
            post_id=post.id,
            author_name="N",
            author_email=None,
            body=str(i),
            status=CommentStatus.APPROVED,
            created_at=now,
            parent_id=parent,
        )
        for i, parent in enumerate((None, None))
    ]
    db_session.add_all(nodes)
    await db_session.flush()
    tree = build_comment_thread(nodes)
    assert len(tree) == 2
    assert [node.comment.id for node in tree] == sorted(node.comment.id for node in tree)


@pytest.mark.asyncio
async def test_reply_to_cyclic_or_self_parent_chain_is_rejected(db_session):
    post = _post()
    db_session.add(post)
    await db_session.flush()
    first, second = (
        Comment(
            post_id=post.id,
            author_name="N",
            author_email=None,
            body="legacy",
            status=CommentStatus.APPROVED,
        )
        for _ in range(2)
    )
    db_session.add_all([first, second])
    await db_session.flush()
    first.parent_id = second.id
    second.parent_id = first.id
    await db_session.flush()
    with pytest.raises(CommentPolicyError, match="cycle"):
        await create_comment(
            db_session,
            post=post,
            policy=resolve_comment_policy(
                post, {"require_email_confirmation": False, "require_admin_approval": False}
            ),
            author_name="New",
            author_email=None,
            body="reply",
            parent_id=first.id,
        )


@pytest.mark.asyncio
async def test_author_edits_create_pending_revision_and_approval_switches_public_body(db_session):
    post, user = _post(), _user()
    db_session.add_all([post, user])
    await db_session.flush()
    now = datetime.now(UTC).replace(tzinfo=None)
    comment = Comment(
        post_id=post.id,
        author_user_id=str(user.id),
        author_name=user.display_name,
        author_email=user.email,
        body="published",
        status=CommentStatus.APPROVED,
        created_at=now,
        published_at=now,
    )
    db_session.add(comment)
    await db_session.flush()
    policy = resolve_comment_policy(post, {"edit_window_minutes": 30, "max_user_edits": 2})
    allowed, _ = await can_edit_comment(
        db_session,
        comment=comment,
        actor_user=user,
        policy=policy,
        now=now + timedelta(minutes=31),
    )
    assert not allowed
    moderator_allowed, _ = await can_edit_comment(
        db_session,
        comment=comment,
        actor_user=user,
        policy=policy,
        moderator=True,
        now=now + timedelta(days=10),
    )
    assert moderator_allowed
    revision = await create_comment_revision(
        db_session,
        comment_id=comment.id,
        actor_user=user,
        body="proposed",
        policy=policy,
    )
    assert revision.status == CommentRevisionStatus.PENDING
    assert comment.body == "published"
    await review_comment_revision(db_session, revision_id=revision.id, approve=True)
    assert comment.body == "proposed"
    assert comment.is_edited


@pytest.mark.asyncio
async def test_author_edit_window_limit_and_trusted_bypass(db_session):
    post, user = _post(), _user(trusted=True)
    db_session.add_all([post, user])
    await db_session.flush()
    now = datetime.now(UTC).replace(tzinfo=None)
    comment = Comment(
        post_id=post.id,
        author_user_id=str(user.id),
        author_name=user.display_name,
        body="original",
        status=CommentStatus.APPROVED,
        created_at=now,
        published_at=now,
    )
    db_session.add(comment)
    await db_session.flush()
    policy = resolve_comment_policy(post, {"edit_window_minutes": 30, "max_user_edits": 2})
    first = await create_comment_revision(
        db_session, comment_id=comment.id, actor_user=user, body="one", policy=policy
    )
    assert first.status == CommentRevisionStatus.PENDING
    with pytest.raises(CommentPolicyError):
        await create_comment_revision(
            db_session, comment_id=comment.id, actor_user=user, body="parallel", policy=policy
        )
    await review_comment_revision(db_session, revision_id=first.id, approve=True)
    second = await create_comment_revision(
        db_session, comment_id=comment.id, actor_user=user, body="two", policy=policy
    )
    assert second.status == CommentRevisionStatus.PENDING
    with pytest.raises(CommentPolicyError, match="maximum"):
        await create_comment_revision(
            db_session, comment_id=comment.id, actor_user=user, body="three", policy=policy
        )
    trusted_policy = resolve_comment_policy(
        post, {"edit_window_minutes": 30, "max_user_edits": 2, "trusted_edit_bypass": True}
    )
    moderator = _user()
    db_session.add(moderator)
    await db_session.flush()
    direct = await create_comment_revision(
        db_session,
        comment_id=comment.id,
        actor_user=moderator,
        body="moderator edit",
        policy=trusted_policy,
        moderator=True,
    )
    assert direct.status == CommentRevisionStatus.APPROVED
    assert comment.body == "moderator edit"


@pytest.mark.asyncio
async def test_votes_are_registered_unique_self_vote_protected_and_not_ranked(db_session):
    post, author, voter = _post(), _user(), _user()
    db_session.add_all([post, author, voter])
    await db_session.flush()
    comment = Comment(
        post_id=post.id,
        author_user_id=str(author.id),
        author_name=author.display_name,
        body="approved",
        status=CommentStatus.APPROVED,
    )
    db_session.add(comment)
    await db_session.flush()
    assert (
        await cast_comment_vote(db_session, user_id=str(voter.id), comment_id=comment.id, value=1)
        == 1
    )
    assert (
        await cast_comment_vote(db_session, user_id=str(voter.id), comment_id=comment.id, value=-1)
        == -1
    )
    assert await db_session.scalar(select(func.count(CommentVote.id))) == 1
    counts = await get_comment_vote_counts(db_session, comment.id)
    assert (counts.upvotes, counts.downvotes, counts.score) == (0, 1, -1)
    await cast_comment_vote(db_session, user_id=str(voter.id), comment_id=comment.id, value=0)
    assert (await get_comment_vote_counts(db_session, comment.id)).downvotes == 0
    with pytest.raises(CommentVoteError):
        await cast_comment_vote(db_session, user_id=str(author.id), comment_id=comment.id, value=1)
    with pytest.raises(CommentVoteError):
        await cast_comment_vote(db_session, user_id=None, comment_id=comment.id, value=1)


@pytest.mark.asyncio
async def test_nonapproved_comments_cannot_be_voted_on(db_session):
    post, voter = _post(), _user()
    db_session.add_all([post, voter])
    await db_session.flush()
    comment = Comment(
        post_id=post.id,
        author_name="Guest",
        body="pending",
        status=CommentStatus.PENDING_MODERATION,
    )
    db_session.add(comment)
    await db_session.flush()
    with pytest.raises(CommentVoteError):
        await cast_comment_vote(db_session, user_id=str(voter.id), comment_id=comment.id, value=1)


@pytest.mark.asyncio
async def test_comment_confirmation_email_escapes_untrusted_html(monkeypatch):
    import arborpress.core.mail as mail
    from arborpress.mail.template_engine import TEMPLATE_REGISTRY, _packaged_source, render_sources

    captured: dict[str, object] = {}

    async def capture(*args, **kwargs):
        captured["template_id"] = kwargs["template_id"]
        captured["context"] = kwargs["context"]
        captured.update(kwargs)
        return "job-id"

    monkeypatch.setattr("arborpress.mail.template_engine.enqueue_template_mail", capture)
    monkeypatch.setattr(mail, "_mail_s", lambda: {"backend": "profiles", "from_name": "ArborPress"})
    comment = SimpleNamespace(
        id="comment-test-id", author_email="guest@example.com", author_name="<script>x</script>"
    )
    post = SimpleNamespace(title="<img src=x onerror=alert(1)>")
    result = await mail.send_comment_confirmation(comment, post, "safe-token")
    assert result is True
    assert captured["template_id"] == "comment.guest_confirmation"
    context = captured["context"]
    assert isinstance(context, dict)
    definition = TEMPLATE_REGISTRY["comment.guest_confirmation"]
    html = render_sources(
        definition,
        {
            kind: _packaged_source(definition.id, "en-GB", kind)
            for kind in ("subject", "plain", "html")
        },
        context,
    )[2]
    assert html is not None
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "/comment/confirm/safe-token" in html
