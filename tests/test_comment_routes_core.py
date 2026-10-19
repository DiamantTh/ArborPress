"""Thin public route integration checks for the service-owned comment flow."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker


@pytest.mark.asyncio
async def test_public_guest_submission_stores_only_hash_and_confirmation_consumes_it(
    test_engine, client, monkeypatch
):
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus

    suffix = uuid.uuid4().hex[:10]
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        post = Post(
            short_id=uuid.uuid4().hex[:8],
            slug=f"comment-route-{suffix}",
            title="Comment route",
            body_md="",
            body_html="",
            status=PostStatus.PUBLISHED,
        )
        db.add(post)
        await db.commit()
        post_id = post.id

    async def no_csrf():
        return None

    async def captcha_ok(*args, **kwargs):
        return True, None

    async def network_ok(*args, **kwargs):
        return "allow", "", None

    async def no_rdap(*args, **kwargs):
        return None

    sent: dict[str, str] = {}

    async def capture_confirmation(comment, post, token):
        sent["token"] = token
        return True

    monkeypatch.setattr("arborpress.web.routes.public.validate_csrf", no_csrf)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setattr("arborpress.core.captcha.get_effective_captcha_type", lambda *_: "none")
    monkeypatch.setattr("arborpress.core.captcha.verify_captcha", captcha_ok)
    monkeypatch.setattr("arborpress.core.comment_filter.check_comment_ip", network_ok)
    monkeypatch.setattr("arborpress.web.routes.public._rdap_background", no_rdap)
    monkeypatch.setattr("arborpress.core.mail.send_comment_confirmation", capture_confirmation)

    response = await client.post(
        f"/p/comment-route-{suffix}/comment",
        form={
            "author_name": "Guest <script>",
            "author_email": "guest@example.com",
            "body": "Hello",
            "consent": "1",
        },
    )
    assert response.status_code == 302
    assert response.headers.get("Location", "").startswith(f"/p/comment-route-{suffix}"), (
        response.headers.get("Location")
    )
    assert sent.get("token"), response.headers.get("Location")
    async with factory() as db:
        comment = (await db.execute(select(Comment).where(Comment.post_id == post_id))).scalar_one()
        assert comment.status == CommentStatus.PENDING_CONFIRMATION
        assert comment.confirmation_token_hash
        assert sent["token"] not in comment.confirmation_token_hash
        assert not hasattr(comment, "confirmation_token")

    confirm = await client.get(f"/comment/confirm/{sent['token']}")
    assert confirm.status_code == 302
    assert sent["token"] not in confirm.headers.get("Location", "")
    assert confirm.headers.get("Cache-Control") == "no-store"
    result_page = await client.get(confirm.headers["Location"])
    assert result_page.status_code == 200
    assert b"wartet jetzt auf Moderation" in await result_page.get_data()
    async with factory() as db:
        comment = (await db.execute(select(Comment).where(Comment.post_id == post_id))).scalar_one()
        assert comment.status == CommentStatus.PENDING_MODERATION
        assert comment.confirmation_token_hash is None
