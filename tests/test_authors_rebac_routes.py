"""Public SSR profile and post-author rendering safety tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker


@pytest.mark.asyncio
async def test_public_author_profile_and_post_box_include_coauthors_without_private_data(
    client, app, test_engine, monkeypatch
):
    from arborpress.content.authors import replace_post_authors
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus, PostVisibility
    from arborpress.models.user import AccountType, User, UserRole
    from arborpress.web.assets import AssetBundle

    suffix = uuid.uuid4().hex[:12]
    primary = User(
        username=f"primary-{suffix}",
        display_name="Primary Person",
        email=f"primary-{suffix}@example.test",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
        bio="<script>alert('bio')</script>Safe bio",
    )
    coauthor = User(
        username=f"coauthor-{suffix}",
        display_name="Coauthor Person",
        email=f"coauthor-{suffix}@example.test",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
        bio="<script>alert('coauthor')</script>Coauthor bio",
    )
    post = Post(
        short_id=uuid.uuid4().hex[:8],
        slug=f"authors-{suffix}",
        title="Shared article",
        body_md="",
        body_html="",
        status=PostStatus.PUBLISHED,
        visibility=PostVisibility.PUBLIC,
        published_at=datetime.now(UTC).replace(tzinfo=None),
    )
    primary_comment = Comment(
        post_id="pending-post-id",
        author_user_id="pending-primary-id",
        author_name="Primary Person",
        body="Primary comment",
        status=CommentStatus.APPROVED,
    )
    coauthor_comment = Comment(
        post_id="pending-post-id",
        author_user_id="pending-coauthor-id",
        author_name="Coauthor Person",
        body="Coauthor comment",
        status=CommentStatus.APPROVED,
    )
    guest_comment = Comment(
        post_id="pending-post-id",
        author_name="Coauthor Person",
        body="Guest comment",
        status=CommentStatus.APPROVED,
    )
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        db.add_all([primary, coauthor, post])
        await db.flush()
        primary_comment.post_id = str(post.id)
        primary_comment.author_user_id = str(primary.id)
        coauthor_comment.post_id = str(post.id)
        coauthor_comment.author_user_id = str(coauthor.id)
        guest_comment.post_id = str(post.id)
        db.add_all([primary_comment, coauthor_comment, guest_comment])
        await replace_post_authors(
            db,
            post_id=str(post.id),
            primary_user_id=str(primary.id),
            coauthor_user_ids=[str(coauthor.id)],
            actor_user_id=str(primary.id),
        )
        await db.commit()

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(javascript=f"dist/assets/{entry}-1234.js", stylesheets=()),
    )

    profile = await client.get(f"/@{coauthor.username}")
    profile_html = await profile.get_data(as_text=True)
    assert profile.status_code == 200
    assert "Shared article" in profile_html
    assert "coauthor-" not in profile_html.replace(coauthor.username, "")
    assert coauthor.email not in profile_html
    assert "&lt;script&gt;" in profile_html
    assert "<script>alert('coauthor')</script>" not in profile_html

    detail = await client.get(f"/p/{post.slug}")
    detail_html = await detail.get_data(as_text=True)
    assert detail.status_code == 200
    assert "Primary Person" in detail_html
    assert "Coauthor Person" in detail_html
    assert "coauthor-" not in detail_html.replace(coauthor.username, "")
    assert primary.email not in detail_html
    assert coauthor.email not in detail_html
    assert "&lt;script&gt;" in detail_html
    assert detail_html.count('class="comment__author-marker">Autor</span>') == 2
