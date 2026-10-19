"""Canonical primary-author and ordered coauthor relations for posts."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.models.content import Post, PostAuthorRelation, PostAuthorRole
from arborpress.models.user import User


class AuthorRelationError(ValueError):
    """An author relationship is invalid or stale."""


async def post_authors(db: AsyncSession, post_id: str) -> list[PostAuthorRelation]:
    result = await db.execute(
        select(PostAuthorRelation)
        .where(PostAuthorRelation.post_id == post_id)
        .order_by(PostAuthorRelation.position, PostAuthorRelation.user_id)
    )
    return list(result.scalars().all())


async def has_primary_author(db: AsyncSession, post_id: str) -> bool:
    return bool(
        await db.scalar(
            select(PostAuthorRelation.id)
            .where(
                PostAuthorRelation.post_id == post_id,
                PostAuthorRelation.role == PostAuthorRole.PRIMARY,
            )
            .limit(1)
        )
    )


async def authors_for_posts(
    db: AsyncSession, post_ids: Sequence[str]
) -> dict[str, list[PostAuthorRelation]]:
    if not post_ids:
        return {}
    result = await db.execute(
        select(PostAuthorRelation)
        .where(PostAuthorRelation.post_id.in_(list(post_ids)))
        .order_by(PostAuthorRelation.position, PostAuthorRelation.user_id)
    )
    grouped: dict[str, list[PostAuthorRelation]] = {}
    for relation in result.scalars().all():
        grouped.setdefault(str(relation.post_id), []).append(relation)
    return grouped


async def replace_post_authors(
    db: AsyncSession,
    *,
    post_id: str,
    primary_user_id: str,
    coauthor_user_ids: Sequence[str],
    actor_user_id: str,
) -> list[PostAuthorRelation]:
    """Replace all author links atomically and maintain legacy author_id projection."""
    post = (
        await db.execute(select(Post).where(Post.id == post_id).with_for_update())
    ).scalar_one_or_none()
    if post is None:
        raise AuthorRelationError("Content was not found.")
    primary_id = str(primary_user_id).strip()
    coauthor_ids = [str(value).strip() for value in coauthor_user_ids if str(value).strip()]
    if not primary_id:
        raise AuthorRelationError("A primary author is required.")
    if len(set(coauthor_ids)) != len(coauthor_ids) or primary_id in coauthor_ids:
        raise AuthorRelationError("Authors must be unique; the primary author cannot be repeated.")
    user_ids = [primary_id, *coauthor_ids]
    users_result = await db.execute(
        select(User.id).where(User.id.in_(user_ids), User.is_active.is_(True))
    )
    found = {str(value) for value in users_result.scalars().all()}
    if found != set(user_ids):
        raise AuthorRelationError("Every author must be an active ArborPress account.")

    previous = await post_authors(db, post_id)
    before = {row.user_id: (row.role.value, row.position) for row in previous}
    await db.execute(delete(PostAuthorRelation).where(PostAuthorRelation.post_id == post_id))
    await db.flush()
    rows = [
        PostAuthorRelation(
            id=str(uuid.uuid4()),
            post_id=post_id,
            user_id=primary_id,
            role=PostAuthorRole.PRIMARY,
            position=0,
            added_by_user_id=actor_user_id,
        ),
        *[
            PostAuthorRelation(
                id=str(uuid.uuid4()),
                post_id=post_id,
                user_id=user_id,
                role=PostAuthorRole.COAUTHOR,
                position=position,
                added_by_user_id=actor_user_id,
            )
            for position, user_id in enumerate(coauthor_ids, start=1)
        ],
    ]
    db.add_all(rows)
    # Transitional read-compatibility for federation and older integrations.
    post.author_id = primary_id
    try:
        await db.flush()
    except IntegrityError as exc:
        raise AuthorRelationError("The author assignment conflicts with another update.") from exc
    after = {row.user_id: (row.role.value, row.position) for row in rows}
    if before != after:
        from arborpress.core.audit import write_audit_event

        for user_id in sorted(set(before) | set(after)):
            old, new = before.get(user_id), after.get(user_id)
            if old == new:
                continue
            if old is None:
                event = (
                    "coauthor_added" if new and new[0] == "coauthor" else "primary_author_changed"
                )
            elif new is None:
                event = "coauthor_removed" if old[0] == "coauthor" else "primary_author_changed"
            elif old[1] != new[1] and old[0] == new[0] == "coauthor":
                event = "coauthor_reordered"
            else:
                event = "primary_author_changed"
            role_value = new[0] if new is not None else old[0] if old is not None else "removed"
            position_value = new[1] if new is not None else "removed"
            await write_audit_event(
                event_type=event,
                outcome="success",
                actor_id=actor_user_id,
                target_id=post_id,
                detail=f"subject={user_id};role={role_value};position={position_value}",
                db=db,
            )
    return rows


async def ensure_primary_author(
    db: AsyncSession, *, post: Post, user_id: str, actor_user_id: str
) -> list[PostAuthorRelation]:
    return await replace_post_authors(
        db,
        post_id=str(post.id),
        primary_user_id=user_id,
        coauthor_user_ids=[],
        actor_user_id=actor_user_id,
    )


async def author_account_choices(db: AsyncSession) -> list[User]:
    result = await db.execute(
        select(User).where(User.is_active.is_(True)).order_by(User.display_name, User.username)
    )
    return list(result.scalars().all())
