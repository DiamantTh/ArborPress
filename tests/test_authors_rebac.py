"""Post authorship and object-scoped permission regression tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from werkzeug.exceptions import Forbidden

from arborpress.auth.permissions import (
    can,
    grant_object_relation,
    object_relations_for_post,
    revoke_object_relation,
)
from arborpress.content.authors import AuthorRelationError, post_authors, replace_post_authors
from arborpress.models.authorization import ObjectRelation, ObjectRelationName
from arborpress.models.content import (
    Post,
    PostAuthorRelation,
    PostAuthorRole,
    PostStatus,
    PostVisibility,
)
from arborpress.models.user import AccountType, User, UserRole


def _account(role: UserRole = UserRole.AUTHOR) -> User:
    handle = f"author-{uuid.uuid4().hex[:12]}"
    return User(
        username=handle,
        display_name=f"Display {handle}",
        account_type=AccountType.PUBLIC,
        role=role,
        is_active=True,
        bio="<script>alert(1)</script>Bio",
    )


def _post() -> Post:
    return Post(
        short_id=uuid.uuid4().hex[:8],
        slug=f"authors-{uuid.uuid4().hex[:12]}",
        title="Author relation test",
        body_md="",
        body_html="",
    )


@pytest.mark.asyncio
async def test_author_links_are_canonical_ordered_and_maintain_legacy_primary(db_session):
    primary, first, second = _account(), _account(), _account()
    post = _post()
    db_session.add_all([primary, first, second, post])
    await db_session.flush()

    rows = await replace_post_authors(
        db_session,
        post_id=str(post.id),
        primary_user_id=str(primary.id),
        coauthor_user_ids=[str(first.id), str(second.id)],
        actor_user_id=str(primary.id),
    )
    assert [(row.role, row.position) for row in rows] == [
        (PostAuthorRole.PRIMARY, 0),
        (PostAuthorRole.COAUTHOR, 1),
        (PostAuthorRole.COAUTHOR, 2),
    ]
    assert post.author_id == primary.id
    assert await can(db_session, second, "content.edit", post)
    assert not await can(db_session, second, "comments.moderate", post)

    with pytest.raises(AuthorRelationError, match="unique"):
        await replace_post_authors(
            db_session,
            post_id=str(post.id),
            primary_user_id=str(primary.id),
            coauthor_user_ids=[str(first.id), str(first.id)],
            actor_user_id=str(primary.id),
        )

    changed = await replace_post_authors(
        db_session,
        post_id=str(post.id),
        primary_user_id=str(first.id),
        coauthor_user_ids=[str(second.id)],
        actor_user_id=str(primary.id),
    )
    assert changed[0].user_id == first.id
    assert changed[0].role == PostAuthorRole.PRIMARY
    assert post.author_id == first.id
    assert len(await post_authors(db_session, str(post.id))) == 2


@pytest.mark.asyncio
async def test_object_relations_are_scoped_and_require_global_relation_management(db_session):
    admin = _account(UserRole.ADMIN)
    subject = _account()
    post_x, post_y = _post(), _post()
    db_session.add_all([admin, subject, post_x, post_y])
    await db_session.flush()

    assert await can(db_session, admin, "comments.moderate", post_x)
    assert not await can(db_session, subject, "content.edit", post_x)
    assert not await can(db_session, subject, "object_relations.manage", post_x)
    with pytest.raises(Forbidden):
        await grant_object_relation(
            db_session,
            actor=subject,
            subject_user_id=str(subject.id),
            post=post_x,
            relation=ObjectRelationName.COMMENT_MODERATOR.value,
        )

    relation = await grant_object_relation(
        db_session,
        actor=admin,
        subject_user_id=str(subject.id),
        post=post_x,
        relation=ObjectRelationName.EDITOR.value,
    )
    moderator_relation = await grant_object_relation(
        db_session,
        actor=admin,
        subject_user_id=str(subject.id),
        post=post_x,
        relation=ObjectRelationName.COMMENT_MODERATOR.value,
    )
    assert await can(db_session, subject, "content.edit", post_x)
    assert not await can(db_session, subject, "content.edit", post_y)
    assert await can(db_session, subject, "comments.moderate", post_x)
    assert not await can(db_session, subject, "comments.moderate", post_y)
    assert len(await object_relations_for_post(db_session, str(post_x.id))) == 2
    with pytest.raises(ValueError, match="already exists"):
        await grant_object_relation(
            db_session,
            actor=admin,
            subject_user_id=str(subject.id),
            post=post_x,
            relation=ObjectRelationName.EDITOR.value,
        )
    with pytest.raises(ValueError, match="Unknown"):
        await grant_object_relation(
            db_session,
            actor=admin,
            subject_user_id=str(subject.id),
            post=post_x,
            relation="unknown_relation",
        )

    await revoke_object_relation(
        db_session,
        actor=admin,
        relation_id=str(moderator_relation.id),
        post=post_x,
    )
    await db_session.flush()
    assert not await can(db_session, subject, "comments.moderate", post_x)
    assert await db_session.get(ObjectRelation, str(moderator_relation.id)) is None
    assert await db_session.get(ObjectRelation, str(relation.id)) is not None


@pytest.mark.asyncio
async def test_author_relation_does_not_leak_drafts_into_public_eligibility(db_session):
    author = _account()
    published, draft = _post(), _post()
    published.status = PostStatus.PUBLISHED
    published.visibility = PostVisibility.PUBLIC
    draft.status = PostStatus.DRAFT
    db_session.add_all([author, published, draft])
    await db_session.flush()
    await replace_post_authors(
        db_session,
        post_id=str(published.id),
        primary_user_id=str(author.id),
        coauthor_user_ids=[],
        actor_user_id=str(author.id),
    )
    await replace_post_authors(
        db_session,
        post_id=str(draft.id),
        primary_user_id=str(author.id),
        coauthor_user_ids=[],
        actor_user_id=str(author.id),
    )

    public_posts = (
        (
            await db_session.execute(
                select(Post)
                .join(PostAuthorRelation)
                .where(
                    PostAuthorRelation.user_id == author.id,
                    Post.status == PostStatus.PUBLISHED,
                    Post.visibility == PostVisibility.PUBLIC,
                )
            )
        )
        .scalars()
        .all()
    )
    assert [row.id for row in public_posts] == [published.id]


@pytest.mark.asyncio
async def test_disabled_existing_author_is_preserved_but_cannot_be_added_anew(db_session):
    disabled_author = _account()
    other_author = _account()
    existing_post, new_post = _post(), _post()
    db_session.add_all([disabled_author, other_author, existing_post, new_post])
    await db_session.flush()
    await replace_post_authors(
        db_session,
        post_id=str(existing_post.id),
        primary_user_id=str(disabled_author.id),
        coauthor_user_ids=[],
        actor_user_id=str(other_author.id),
    )
    disabled_author.is_active = False
    await db_session.flush()

    preserved = await replace_post_authors(
        db_session,
        post_id=str(existing_post.id),
        primary_user_id=str(disabled_author.id),
        coauthor_user_ids=[str(other_author.id)],
        actor_user_id=str(other_author.id),
    )
    assert [row.user_id for row in preserved] == [
        str(disabled_author.id),
        str(other_author.id),
    ]
    with pytest.raises(AuthorRelationError, match="active"):
        await replace_post_authors(
            db_session,
            post_id=str(new_post.id),
            primary_user_id=str(other_author.id),
            coauthor_user_ids=[str(disabled_author.id)],
            actor_user_id=str(other_author.id),
        )
