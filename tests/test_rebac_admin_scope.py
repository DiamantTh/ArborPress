"""Object moderators receive only the moderation scope they were granted."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker


@pytest.mark.asyncio
async def test_object_comment_moderator_queue_and_detail_are_server_scoped(
    client, test_engine, monkeypatch
):
    from arborpress.models.authorization import ObjectRelation, ObjectRelationName
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus
    from arborpress.models.user import AccountType, User, UserRole, UserSession

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    actor = User(
        username=f"object-mod-{uuid.uuid4().hex[:10]}",
        display_name="Object Moderator",
        account_type=AccountType.OPERATIONAL,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    post_x = Post(
        short_id=uuid.uuid4().hex[:8],
        slug=f"moderator-x-{uuid.uuid4().hex[:8]}",
        title="Scoped moderation target",
        body_md="",
        body_html="",
        status=PostStatus.PUBLISHED,
    )
    post_y = Post(
        short_id=uuid.uuid4().hex[:8],
        slug=f"moderator-y-{uuid.uuid4().hex[:8]}",
        title="Unrelated moderation target",
        body_md="",
        body_html="",
        status=PostStatus.PUBLISHED,
    )
    async with factory() as db:
        db.add_all([actor, post_x, post_y])
        await db.flush()
        user_session = UserSession(
            user_id=str(actor.id),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC),
            is_valid=True,
            is_tls=False,
            is_cli=False,
        )
        comment_x = Comment(
            post_id=str(post_x.id),
            author_name="Visible pending comment",
            body="Scoped body x",
            status=CommentStatus.PENDING_MODERATION,
        )
        comment_y = Comment(
            post_id=str(post_y.id),
            author_name="Hidden pending comment",
            body="Scoped body y",
            status=CommentStatus.PENDING_MODERATION,
        )
        db.add_all(
            [
                user_session,
                comment_x,
                comment_y,
                ObjectRelation(
                    subject_user_id=str(actor.id),
                    object_type="content",
                    object_id=str(post_x.id),
                    relation=ObjectRelationName.COMMENT_MODERATOR,
                ),
            ]
        )
        await db.commit()
        comment_y_id = str(comment_y.id)

    async with client.session_transaction() as browser_session:
        browser_session["user_id"] = str(actor.id)
        browser_session["user_name"] = actor.username
        browser_session["user_role"] = "author"
        browser_session["account_type"] = "operational"
        browser_session["session_id"] = user_session.id

    queue = await client.get("/admin/comments?type=comments")
    queue_html = await queue.get_data(as_text=True)
    assert queue.status_code == 200
    assert "Visible pending comment" in queue_html
    assert "Hidden pending comment" not in queue_html

    hidden_detail = await client.get(f"/admin/comments/{comment_y_id}")
    assert hidden_detail.status_code == 403
