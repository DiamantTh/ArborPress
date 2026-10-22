"""Durable ActivityPub inbox processing over the existing 10A intake records."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from arborpress.federation.policy import domain_allowed, federation_is_enabled
from arborpress.federation.services import queue_follow_accept
from arborpress.models.federation import FederationInboxActivity, LocalFederationActor, RemoteActor
from arborpress.models.user import Follower, FollowerDirection, FollowerState

log = logging.getLogger("arborpress.federation.inbox")


class InboxProcessingError(ValueError):
    """An authenticated inbox activity failed safe semantic validation."""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


async def claim_inbox(db: AsyncSession, *, worker_id: str, lease_seconds: int = 90) -> str | None:
    now = _now()
    eligible = or_(
        (FederationInboxActivity.processing_state == "received")
        & (FederationInboxActivity.received_at <= now),
        (FederationInboxActivity.processing_state == "processing")
        & (FederationInboxActivity.lease_until <= now),
    )
    candidate = await db.scalar(
        select(FederationInboxActivity.id)
        .where(eligible)
        .order_by(FederationInboxActivity.received_at, FederationInboxActivity.id)
        .limit(1)
    )
    if candidate is None:
        return None
    result = await db.execute(
        update(FederationInboxActivity)
        .where(FederationInboxActivity.id == candidate, eligible)
        .values(
            processing_state="processing",
            lease_owner=worker_id,
            lease_until=now + timedelta(seconds=lease_seconds),
            attempt_count=FederationInboxActivity.attempt_count + 1,
        )
    )
    return str(candidate) if getattr(result, "rowcount", 0) == 1 else None


async def process_claimed(db: AsyncSession, intake_id: str, *, worker_id: str) -> str:
    intake = await db.get(FederationInboxActivity, intake_id)
    if intake is None or intake.processing_state != "processing" or intake.lease_owner != worker_id:
        return "unavailable"
    try:
        settings = await _settings(db)
        if not federation_is_enabled(settings) or not await domain_allowed(
            db, intake.source_domain, settings
        ):
            raise InboxProcessingError("domain_not_allowed")
        payload = json.loads(intake.payload_json)
        if not isinstance(payload, dict) or payload.get("actor") != intake.actor_uri:
            raise InboxProcessingError("actor_binding_mismatch")
        actor = (
            await db.execute(select(RemoteActor).where(RemoteActor.actor_uri == intake.actor_uri))
        ).scalar_one_or_none()
        if actor is None:
            raise InboxProcessingError("verified_actor_cache_missing")
        handler = {
            "Follow": _follow,
            "Accept": _follow_response,
            "Reject": _follow_response,
            "Undo": _undo,
            "Create": _create,
            "Update": _update,
            "Delete": _delete,
        }.get(intake.activity_type)
        if handler is None:
            intake.processing_state = "ignored"
        else:
            async with db.begin_nested():
                await handler(db, intake, payload, actor, settings)
            intake.processing_state = "processed"
        intake.last_error = None
        intake.processed_at = _now()
    except InboxProcessingError as exc:
        intake.processing_state = "rejected"
        intake.last_error = str(exc)[:512]
        intake.processed_at = _now()
    except Exception:
        log.exception("Federation inbox processing failed intake_id=%s", intake_id)
        intake.last_error = "internal_processing_error"
        if intake.attempt_count < 5:
            intake.processing_state = "received"
            intake.received_at = _now() + timedelta(seconds=min(300, 2**intake.attempt_count))
        else:
            intake.processing_state = "failed"
    intake.lease_owner = None
    intake.lease_until = None
    await db.flush()
    return intake.processing_state


async def process_inbox_batch(
    factory: async_sessionmaker[AsyncSession], *, batch_size: int = 20, worker_id: str | None = None
) -> int:
    worker = worker_id or f"federation-inbox-{uuid.uuid4()}"
    processed = 0
    for _ in range(max(1, min(batch_size, 100))):
        async with factory() as db:
            if not federation_is_enabled(await _settings(db)):
                break
            intake_id = await claim_inbox(db, worker_id=worker)
            await db.commit()
        if intake_id is None:
            break
        async with factory() as db:
            await process_claimed(db, intake_id, worker_id=worker)
            await db.commit()
        processed += 1
    return processed


async def _settings(db: AsyncSession) -> dict[str, Any]:
    from arborpress.core.site_settings import get_section

    return await get_section("federation", db)


async def _target_actor(
    db: AsyncSession, intake: FederationInboxActivity, obj: Any
) -> LocalFederationActor:
    target = (
        await db.get(LocalFederationActor, intake.target_actor_id)
        if intake.target_actor_id
        else None
    )
    if target is None and isinstance(obj, str):
        target = (
            await db.execute(
                select(LocalFederationActor).where(
                    LocalFederationActor.actor_uri == obj,
                    LocalFederationActor.enabled.is_(True),
                )
            )
        ).scalar_one_or_none()
    if target is None or not target.enabled:
        raise InboxProcessingError("local_actor_unavailable")
    return target


async def _follow(
    db: AsyncSession,
    intake: FederationInboxActivity,
    payload: dict[str, Any],
    remote: RemoteActor,
    settings: dict[str, Any],
) -> None:
    target_uri = payload.get("object")
    if not isinstance(target_uri, str):
        raise InboxProcessingError("follow_object_invalid")
    local = await _target_actor(db, intake, target_uri)
    if local.actor_uri != target_uri:
        raise InboxProcessingError("follow_target_mismatch")
    from arborpress.models.user import User

    user = await db.get(User, local.user_id)
    if user is None:
        raise InboxProcessingError("local_actor_unavailable")
    result = await db.execute(
        select(Follower).where(
            Follower.local_user_id == str(user.id),
            Follower.remote_actor_uri == remote.actor_uri,
            Follower.direction == FollowerDirection.INBOUND,
        )
    )
    relation = result.scalar_one_or_none()
    if relation is None:
        relation = Follower(
            local_user_id=str(user.id),
            remote_actor_uri=remote.actor_uri,
            remote_display_name=remote.display_name,
            remote_inbox_uri=remote.shared_inbox_uri or remote.inbox_uri,
            direction=FollowerDirection.INBOUND,
            state=FollowerState.PENDING,
            activity_id=intake.activity_uri,
        )
        db.add(relation)
    else:
        relation.remote_display_name = remote.display_name
        relation.remote_inbox_uri = remote.shared_inbox_uri or remote.inbox_uri
        relation.activity_id = intake.activity_uri
    if bool(settings.get("require_approval_to_follow", False)):
        relation.state = FollowerState.PENDING
    else:
        relation.state = FollowerState.ACCEPTED
        await queue_follow_accept(
            db, local_actor=local, remote_actor=remote, follow_id=intake.activity_uri
        )
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="federation.follow_received",
        outcome="success",
        actor_id=None,
        target_id=local.id,
        db=db,
        detail=f"remote_domain={remote.domain};state={relation.state.value}",
    )


async def _follow_response(
    db: AsyncSession,
    intake: FederationInboxActivity,
    payload: dict[str, Any],
    remote: RemoteActor,
    _settings: dict[str, Any],
) -> None:
    follow = payload.get("object")
    follow_id = follow.get("id") if isinstance(follow, dict) else follow
    if not isinstance(follow_id, str):
        raise InboxProcessingError("follow_response_object_invalid")
    result = await db.execute(
        select(Follower).where(
            Follower.remote_actor_uri == remote.actor_uri,
            Follower.activity_id == follow_id,
            Follower.direction == FollowerDirection.OUTBOUND,
        )
    )
    relation = result.scalar_one_or_none()
    if relation is None:
        raise InboxProcessingError("follow_relation_not_found")
    follow = payload.get("object")
    from arborpress.models.federation import LocalFederationActor

    local_actor = (
        await db.execute(
            select(LocalFederationActor).where(
                LocalFederationActor.user_id == relation.local_user_id
            )
        )
    ).scalar_one_or_none()
    follow_matches = follow == relation.activity_id or (
        isinstance(follow, dict)
        and follow.get("type") == "Follow"
        and follow.get("id") == relation.activity_id
        and follow.get("actor") == (local_actor.actor_uri if local_actor else None)
        and follow.get("object") == remote.actor_uri
    )
    if not follow_matches:
        raise InboxProcessingError("follow_response_binding_mismatch")
    outcome = FollowerState.ACCEPTED if payload.get("type") == "Accept" else FollowerState.REJECTED
    if relation.state == FollowerState.PENDING:
        relation.state = outcome
    elif relation.state != outcome:
        raise InboxProcessingError("conflicting_follow_response")


async def unfollow_remote_actor(
    db: AsyncSession, *, local_actor: LocalFederationActor, remote_actor: RemoteActor
) -> Follower:
    """Queue an idempotent Undo for a local-to-remote Follow."""
    from arborpress.federation.services import enqueue_activity
    from arborpress.models.user import User

    settings = await _settings(db)
    if not federation_is_enabled(settings) or not await domain_allowed(
        db, remote_actor.domain, settings
    ):
        raise InboxProcessingError("federation_or_remote_domain_unavailable")
    if not local_actor.enabled:
        raise InboxProcessingError("local_actor_unavailable")
    user = await db.get(User, local_actor.user_id)
    if user is None:
        raise InboxProcessingError("local_actor_unavailable")
    relation = (
        await db.execute(
            select(Follower)
            .where(
                Follower.local_user_id == str(user.id),
                Follower.remote_actor_uri == remote_actor.actor_uri,
                Follower.direction == FollowerDirection.OUTBOUND,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if relation is None or not relation.activity_id:
        raise InboxProcessingError("outbound_follow_not_found")
    if relation.state == FollowerState.UNDONE:
        return relation
    follow_id = relation.activity_id
    relation.state = FollowerState.UNDONE
    await enqueue_activity(
        db,
        actor=local_actor,
        activity_type="Undo",
        obj={
            "id": follow_id,
            "type": "Follow",
            "actor": local_actor.actor_uri,
            "object": remote_actor.actor_uri,
        },
        source_type="follow-undo",
        source_id=str(relation.id),
        source_revision=follow_id,
        recipients=[(remote_actor.shared_inbox_uri or remote_actor.inbox_uri, remote_actor.domain)],
        public=False,
    )
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="federation.follow_removed",
        outcome="success",
        actor_id=str(user.id),
        target_id=relation.id,
        db=db,
        detail=f"remote_domain={remote_actor.domain}",
    )
    return relation


async def respond_inbound_follow(db: AsyncSession, *, follower_id: str, accept: bool) -> Follower:
    """Approve or reject one pending inbound Follow and queue its response."""
    from arborpress.federation.services import queue_follow_accept

    relation = (
        await db.execute(select(Follower).where(Follower.id == follower_id).with_for_update())
    ).scalar_one_or_none()
    if (
        relation is None
        or relation.direction != FollowerDirection.INBOUND
        or relation.state != FollowerState.PENDING
    ):
        raise InboxProcessingError("pending_inbound_follow_not_found")
    local = (
        await db.execute(
            select(LocalFederationActor).where(
                LocalFederationActor.user_id == relation.local_user_id,
                LocalFederationActor.enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    remote = (
        await db.execute(
            select(RemoteActor).where(RemoteActor.actor_uri == relation.remote_actor_uri)
        )
    ).scalar_one_or_none()
    if local is None or remote is None or not relation.activity_id:
        raise InboxProcessingError("follow_actor_unavailable")
    relation.state = FollowerState.ACCEPTED if accept else FollowerState.REJECTED
    await queue_follow_accept(
        db,
        local_actor=local,
        remote_actor=remote,
        follow_id=relation.activity_id,
        reject=not accept,
    )
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="federation.follow_accepted" if accept else "federation.follow_rejected",
        outcome="success",
        target_id=relation.id,
        db=db,
        detail=f"remote_domain={remote.domain}",
    )
    return relation


async def _undo(
    db: AsyncSession,
    intake: FederationInboxActivity,
    payload: dict[str, Any],
    remote: RemoteActor,
    _settings: dict[str, Any],
) -> None:
    item = payload.get("object")
    if (
        not isinstance(item, dict)
        or item.get("type") != "Follow"
        or item.get("actor") != remote.actor_uri
    ):
        raise InboxProcessingError("undo_follow_owner_mismatch")
    follow_id = item.get("id")
    target_uri = item.get("object")
    if not isinstance(follow_id, str) or not isinstance(target_uri, str):
        raise InboxProcessingError("undo_follow_invalid")
    target = await _target_actor(db, intake, target_uri)
    from arborpress.models.user import User

    user = await db.get(User, target.user_id)
    if user is None:
        raise InboxProcessingError("local_actor_unavailable")
    result = await db.execute(
        select(Follower).where(
            Follower.local_user_id == str(user.id),
            Follower.remote_actor_uri == remote.actor_uri,
            Follower.activity_id == follow_id,
            Follower.direction == FollowerDirection.INBOUND,
        )
    )
    relation = result.scalar_one_or_none()
    if relation is not None and relation.state != FollowerState.UNDONE:
        relation.state = FollowerState.UNDONE


async def _create(
    db: AsyncSession,
    intake: FederationInboxActivity,
    payload: dict[str, Any],
    remote: RemoteActor,
    settings: dict[str, Any],
) -> None:
    obj = payload.get("object")
    if not isinstance(obj, dict) or obj.get("type") != "Note":
        raise InboxProcessingError("unsupported_create_object")
    await _create_remote_comment(db, intake, obj, remote, settings)


async def _update(
    db: AsyncSession,
    intake: FederationInboxActivity,
    payload: dict[str, Any],
    remote: RemoteActor,
    settings: dict[str, Any],
) -> None:
    obj = payload.get("object")
    if not isinstance(obj, dict) or obj.get("type") != "Note":
        raise InboxProcessingError("unsupported_update_object")
    uri = obj.get("id")
    if not isinstance(uri, str):
        raise InboxProcessingError("remote_comment_object_id_invalid")
    from arborpress.models.content import Comment

    comment = (
        (
            await db.execute(select(Comment).where(Comment.remote_object_uri == uri))
        ).scalar_one_or_none()
        if isinstance(uri, str)
        else None
    )
    if comment is None or comment.remote_actor_id != remote.id:
        raise InboxProcessingError("remote_comment_owner_mismatch")
    if obj.get("attributedTo") != remote.actor_uri:
        raise InboxProcessingError("remote_comment_attribution_mismatch")
    from arborpress.federation.security import FederationFetchError, validate_remote_url_syntax

    try:
        object_domain, _path = validate_remote_url_syntax(uri)
    except FederationFetchError as exc:
        raise InboxProcessingError("remote_comment_object_id_invalid") from exc
    if object_domain != remote.domain:
        raise InboxProcessingError("remote_comment_object_id_invalid")
    in_reply_to = obj.get("inReplyTo")
    if in_reply_to != await _comment_parent_uri(db, comment):
        raise InboxProcessingError("remote_comment_thread_changed")
    from arborpress.comments import create_remote_comment_revision

    policy = await _comment_policy(db, comment.post_id)
    content = _comment_text(obj.get("content"), policy.max_comment_length)
    try:
        await create_remote_comment_revision(
            db, comment=comment, remote_actor_id=remote.id, body=content, policy=policy
        )
    except ValueError as exc:
        raise InboxProcessingError("remote_comment_revision_rejected") from exc


async def _delete(
    db: AsyncSession,
    intake: FederationInboxActivity,
    payload: dict[str, Any],
    remote: RemoteActor,
    _settings: dict[str, Any],
) -> None:
    item = payload.get("object")
    uri = item.get("id") if isinstance(item, dict) else item
    if not isinstance(uri, str):
        raise InboxProcessingError("remote_comment_object_id_invalid")
    from arborpress.models.content import Comment, CommentStatus

    comment = (
        (
            await db.execute(select(Comment).where(Comment.remote_object_uri == uri))
        ).scalar_one_or_none()
        if isinstance(uri, str)
        else None
    )
    if comment is None or comment.remote_actor_id != remote.id:
        raise InboxProcessingError("remote_comment_owner_mismatch")
    from arborpress.federation.security import FederationFetchError, validate_remote_url_syntax

    try:
        object_domain, _path = validate_remote_url_syntax(uri)
    except FederationFetchError as exc:
        raise InboxProcessingError("remote_comment_object_id_invalid") from exc
    if object_domain != remote.domain:
        raise InboxProcessingError("remote_comment_object_id_invalid")
    if comment.status == CommentStatus.DELETED:
        return
    comment.status = CommentStatus.DELETED
    comment.confirmation_token_hash = None
    comment.confirmation_expires_at = None
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type="federation_comment_remote_deleted",
        outcome="success",
        actor_id=None,
        target_id=comment.id,
        db=db,
        detail="source=remote_actor",
    )


async def _create_remote_comment(
    db: AsyncSession,
    intake: FederationInboxActivity,
    obj: dict[str, Any],
    remote: RemoteActor,
    settings: dict[str, Any],
) -> None:
    uri = obj.get("id")
    attributed = obj.get("attributedTo", intake.actor_uri)
    in_reply_to = obj.get("inReplyTo")
    if (
        not isinstance(uri, str)
        or attributed != intake.actor_uri
        or not isinstance(in_reply_to, str)
    ):
        raise InboxProcessingError("remote_note_identity_invalid")
    from arborpress.federation.security import FederationFetchError, validate_remote_url_syntax

    try:
        object_domain, _ = validate_remote_url_syntax(uri)
    except FederationFetchError as exc:
        raise InboxProcessingError("remote_object_uri_invalid") from exc
    if object_domain != remote.domain:
        raise InboxProcessingError("remote_object_owner_mismatch")
    from arborpress.models.content import Comment, Post, PostStatus, PostVisibility

    existing = (
        await db.execute(select(Comment).where(Comment.remote_object_uri == uri))
    ).scalar_one_or_none()
    if existing is not None:
        if existing.remote_actor_id != remote.id:
            raise InboxProcessingError("remote_object_owner_conflict")
        return
    post = (
        await db.execute(
            select(Post).where(
                (
                    (Post.ap_object_id == in_reply_to)
                    | (Post.short_id == _object_short_id(in_reply_to))
                ),
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
        )
    ).scalar_one_or_none()
    parent_id = None
    if post is None:
        parent = (
            await db.execute(select(Comment).where(Comment.remote_object_uri == in_reply_to))
        ).scalar_one_or_none()
        if parent is None:
            local_id = _comment_id_from_uri(in_reply_to)
            parent = await db.get(Comment, local_id) if local_id else None
        if parent is None or parent.status.value != "approved":
            raise InboxProcessingError("remote_reply_target_unavailable")
        post = await db.get(Post, parent.post_id)
        if (
            post is None
            or post.status != PostStatus.PUBLISHED
            or post.visibility != PostVisibility.PUBLIC
        ):
            raise InboxProcessingError("remote_reply_target_unavailable")
        parent_id = parent.id
    from arborpress.comments import create_comment

    policy = await _comment_policy(db, str(post.id))
    content = _comment_text(obj.get("content"), policy.max_comment_length)
    display = remote.display_name or remote.preferred_username or remote.domain
    if len(display) > 128:
        display = display[:128]
    try:
        await create_comment(
            db,
            post=post,
            policy=policy,
            author_name=display,
            author_email=None,
            author_url=None,
            body=content,
            parent_id=parent_id,
            remote_actor=remote,
            remote_object_uri=uri,
        )
    except ValueError as exc:
        raise InboxProcessingError("remote_comment_rejected_by_policy") from exc


async def _comment_policy(db: AsyncSession, post_id: str) -> Any:
    from arborpress.comments import resolve_comment_policy
    from arborpress.core.site_settings import get_section
    from arborpress.models.content import Post

    post = await db.get(Post, post_id)
    if post is None:
        raise InboxProcessingError("comment_post_missing")
    return resolve_comment_policy(post, await get_section("comments", db))


async def _comment_parent_uri(db: AsyncSession, comment: Any) -> str:
    from arborpress.federation.policy import canonical_origin
    from arborpress.models.content import Comment, Post

    if comment.parent_id:
        parent = await db.get(Comment, comment.parent_id)
        if parent is not None:
            return parent.remote_object_uri or f"{canonical_origin()}/ap/comment/{parent.id}"
    post = await db.get(Post, comment.post_id)
    if post is None:
        return ""
    return post.ap_object_id or f"{canonical_origin()}/ap/object/{post.short_id}"


def _comment_text(value: Any, max_length: int) -> str:
    import bleach  # type: ignore[import-untyped]

    if not isinstance(value, str) or len(value) > 20_000:
        raise InboxProcessingError("remote_comment_too_large")
    # Local comments are escaped by the SSR nl2br filter, so retain only text.
    text = str(bleach.clean(value, tags=[], strip=True))
    if not text.strip() or len(text) > min(max_length, 20_000):
        raise InboxProcessingError("remote_comment_length_invalid")
    return text


def _object_short_id(uri: str) -> str:
    marker = "/ap/object/"
    return uri.rsplit(marker, 1)[1].split("/", 1)[0] if marker in uri else ""


def _comment_id_from_uri(uri: str) -> str | None:
    marker = "/ap/comment/"
    if marker not in uri:
        return None
    candidate = uri.rsplit(marker, 1)[1].split("/", 1)[0]
    try:
        return str(uuid.UUID(candidate))
    except ValueError:
        return None


async def run_worker(
    factory: async_sessionmaker[AsyncSession], *, stop_event: asyncio.Event, interval: float = 2.0
) -> None:
    while not stop_event.is_set():
        try:
            count = await process_inbox_batch(factory)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Federation inbox worker iteration failed")
            count = 0
        if not count:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except TimeoutError:
                pass
