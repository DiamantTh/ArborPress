"""Central effective permission resolver combining global RBAC and local ReBAC."""

from __future__ import annotations

from quart import abort
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.models.authorization import ObjectRelation, ObjectRelationName
from arborpress.models.content import Post, PostAuthorRelation, PostAuthorRole
from arborpress.models.user import User, UserRole

SUPPORTED_ACTIONS = {
    "content.edit",
    "content.manage_authors",
    "comments.moderate",
    "object_relations.manage",
}


def _global_permission(role: UserRole, action: str) -> bool:
    if role in {UserRole.ADMIN, UserRole.EDITOR}:
        return True
    if action == "comments.moderate":
        return role == UserRole.MODERATOR
    return False


async def can(
    db: AsyncSession,
    actor: User | None,
    action: str,
    object: Post | str | None = None,
) -> bool:
    """Check a bounded action against global roles, authorship, then object relations."""
    if action not in SUPPORTED_ACTIONS or actor is None or not actor.is_active:
        return False
    if _global_permission(actor.role, action):
        return True
    if object is None or action in {"content.manage_authors", "object_relations.manage"}:
        return False
    post_id = str(object.id) if isinstance(object, Post) else str(object)
    if action == "content.edit":
        authored = await db.scalar(
            select(Post.id)
            .join(PostAuthorRelation, PostAuthorRelation.post_id == Post.id)
            .where(
                Post.id == post_id,
                PostAuthorRelation.user_id == str(actor.id),
                PostAuthorRelation.role.in_([PostAuthorRole.PRIMARY, PostAuthorRole.COAUTHOR]),
            )
            .limit(1)
        )
        if authored is not None:
            return True
        legacy_author = await db.scalar(
            select(Post.id).where(Post.id == post_id, Post.author_id == str(actor.id)).limit(1)
        )
        if legacy_author is not None:
            return True
    relation = (
        ObjectRelationName.EDITOR
        if action == "content.edit"
        else ObjectRelationName.COMMENT_MODERATOR
        if action == "comments.moderate"
        else None
    )
    if relation is None:
        return False
    return bool(
        await db.scalar(
            select(ObjectRelation.id)
            .where(
                ObjectRelation.subject_user_id == str(actor.id),
                ObjectRelation.object_type == "content",
                ObjectRelation.object_id == post_id,
                ObjectRelation.relation == relation.value,
            )
            .limit(1)
        )
    )


async def require_permission(
    db: AsyncSession,
    actor: User | None,
    action: str,
    object: Post | str | None = None,
) -> None:
    if not await can(db, actor, action, object):
        abort(403)


async def grant_object_relation(
    db: AsyncSession,
    *,
    actor: User,
    subject_user_id: str,
    post: Post,
    relation: str,
) -> ObjectRelation:
    if relation not in {item.value for item in ObjectRelationName}:
        raise ValueError("Unknown object relation.")
    if not await can(db, actor, "object_relations.manage", post):
        abort(403)
    if str(subject_user_id) == str(actor.id) and not await can(
        db, actor, "object_relations.manage", post
    ):
        abort(403)
    subject = await db.get(User, str(subject_user_id))
    if subject is None or not subject.is_active:
        raise ValueError("The selected subject account is unavailable.")
    model_relation = ObjectRelationName(relation)
    existing = await db.scalar(
        select(ObjectRelation).where(
            ObjectRelation.subject_user_id == str(subject.id),
            ObjectRelation.object_type == "content",
            ObjectRelation.object_id == str(post.id),
            ObjectRelation.relation == relation,
        )
    )
    if existing:
        raise ValueError("That relation already exists.")
    item = ObjectRelation(
        subject_user_id=str(subject.id),
        object_type="content",
        object_id=str(post.id),
        relation=model_relation,
        granted_by_user_id=str(actor.id),
    )
    db.add(item)
    await db.flush()
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="object_relation_granted",
        outcome="success",
        actor_id=str(actor.id),
        target_id=str(post.id),
        detail=f"subject={subject.id};object_type=content;relation={relation}",
        db=db,
    )
    return item


async def revoke_object_relation(
    db: AsyncSession, *, actor: User, relation_id: str, post: Post
) -> None:
    if not await can(db, actor, "object_relations.manage", post):
        abort(403)
    item = await db.get(ObjectRelation, relation_id)
    if item is None or item.object_type != "content" or item.object_id != str(post.id):
        raise ValueError("The object relation was not found.")
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="object_relation_revoked",
        outcome="success",
        actor_id=str(actor.id),
        target_id=str(post.id),
        detail=(f"subject={item.subject_user_id};object_type=content;relation={item.relation}"),
        db=db,
    )
    await db.delete(item)


async def object_relations_for_post(db: AsyncSession, post_id: str) -> list[ObjectRelation]:
    result = await db.execute(
        select(ObjectRelation)
        .where(ObjectRelation.object_type == "content", ObjectRelation.object_id == post_id)
        .order_by(ObjectRelation.relation, ObjectRelation.subject_user_id)
    )
    return list(result.scalars().all())


async def content_ids_for_relation(
    db: AsyncSession, user_id: str, relation: ObjectRelationName
) -> list[str]:
    result = await db.execute(
        select(ObjectRelation.object_id).where(
            ObjectRelation.subject_user_id == user_id,
            ObjectRelation.object_type == "content",
            ObjectRelation.relation == relation.value,
        )
    )
    return [str(value) for value in result.scalars().all()]


async def other_comment_reviewer_available(
    db: AsyncSession, *, original_actor_id: str | None, post_id: str
) -> bool:
    global_reviewer = await db.scalar(
        select(User.id)
        .where(
            User.is_active.is_(True),
            User.role.in_([UserRole.ADMIN, UserRole.EDITOR, UserRole.MODERATOR]),
            User.id != str(original_actor_id or ""),
        )
        .limit(1)
    )
    if global_reviewer is not None:
        return True
    object_reviewer = await db.scalar(
        select(ObjectRelation.id)
        .join(User, User.id == ObjectRelation.subject_user_id)
        .where(
            ObjectRelation.object_type == "content",
            ObjectRelation.object_id == post_id,
            ObjectRelation.relation == ObjectRelationName.COMMENT_MODERATOR.value,
            ObjectRelation.subject_user_id != str(original_actor_id or ""),
            User.is_active.is_(True),
        )
        .limit(1)
    )
    return object_reviewer is not None
