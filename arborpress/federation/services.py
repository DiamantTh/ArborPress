"""Federation follow, activity outbox and durable delivery services.

This layer extends the 10A inbox/fetch/signature foundation. It deliberately
uses the existing ``Follower`` domain model and comment services; plugin,
browser and remote ActivityPub payloads never receive ORM access.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import bleach  # type: ignore[import-untyped]
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from arborpress.federation.policy import canonical_origin, domain_allowed, federation_is_enabled
from arborpress.federation.security import (
    FederationFetchError,
    normalize_domain,
    post_remote,
    validate_remote_url,
    validate_remote_url_syntax,
)
from arborpress.models.federation import (
    FederationDelivery,
    FederationOutboxActivity,
    LocalFederationActor,
    RemoteActor,
)
from arborpress.models.user import Follower, FollowerDirection, FollowerState

log = logging.getLogger("arborpress.federation.delivery")
PUBLIC = "https://www.w3.org/ns/activitystreams#Public"
_HTML_TAGS = ["p", "br", "strong", "em", "a", "ul", "ol", "li", "blockquote", "span"]


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _activity_id() -> str:
    return f"{canonical_origin()}/ap/activities/{uuid.uuid4()}"


async def enqueue_activity(
    db: AsyncSession,
    *,
    actor: LocalFederationActor,
    activity_type: str,
    obj: dict[str, Any] | str,
    source_type: str,
    source_id: str,
    source_revision: str,
    recipients: list[tuple[str, str]],
    public: bool = True,
) -> FederationOutboxActivity:
    """Persist an immutable activity plus deduplicated, policy-checked inbox jobs."""
    if activity_type not in {"Create", "Update", "Delete", "Accept", "Reject", "Follow", "Undo"}:
        raise ValueError("unsupported_outbound_activity")
    normalized_revision = source_revision[:64]
    if isinstance(obj, str):
        private_recipient = obj
    elif activity_type in {"Accept", "Reject"}:
        private_recipient = str(obj.get("actor") or "")
    elif activity_type == "Undo" and isinstance(obj.get("object"), dict):
        private_recipient = str(obj["object"].get("object") or "")
    else:
        private_recipient = str(obj.get("object") or obj.get("actor") or "")
    existing = (
        await db.execute(
            select(FederationOutboxActivity).where(
                FederationOutboxActivity.source_type == source_type,
                FederationOutboxActivity.source_id == source_id,
                FederationOutboxActivity.source_revision == normalized_revision,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    activity_uri = _activity_id()
    payload = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": activity_uri,
        "type": activity_type,
        "actor": actor.actor_uri,
        "object": obj,
        "to": [PUBLIC] if public else [private_recipient],
    }
    activity = FederationOutboxActivity(
        activity_uri=activity_uri,
        actor_uri=actor.actor_uri,
        activity_type=activity_type,
        object_uri=(
            obj[:2048]
            if isinstance(obj, str)
            else str(obj.get("id") or obj.get("actor") or "")[:2048]
        ),
        payload_json=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        source_type=source_type,
        source_id=source_id,
        source_revision=normalized_revision,
        audience_public=public,
    )
    try:
        async with db.begin_nested():
            db.add(activity)
            await db.flush()
    except IntegrityError:
        concurrent = (
            await db.execute(
                select(FederationOutboxActivity).where(
                    FederationOutboxActivity.source_type == source_type,
                    FederationOutboxActivity.source_id == source_id,
                    FederationOutboxActivity.source_revision == normalized_revision,
                )
            )
        ).scalar_one_or_none()
        if concurrent is not None:
            return concurrent
        raise
    settings = await _federation_settings(db)
    seen: set[str] = set()
    for inbox, domain in recipients[:1000]:
        if inbox in seen:
            continue
        seen.add(inbox)
        try:
            parsed_domain, _ = validate_remote_url_syntax(inbox)
            normalized = normalize_domain(domain or parsed_domain)
        except FederationFetchError:
            continue
        if parsed_domain != normalized or not await domain_allowed(db, normalized, settings):
            continue
        db.add(
            FederationDelivery(
                activity_id=activity.id,
                target_inbox=inbox[:2048],
                domain=normalized,
                status="pending",
                next_attempt_at=_now(),
            )
        )
    await db.flush()
    return activity


async def _federation_settings(db: AsyncSession) -> dict[str, Any]:
    from arborpress.core.site_settings import get_section

    return await get_section("federation", db)


async def _actor_followers(db: AsyncSession, actor: LocalFederationActor) -> list[tuple[str, str]]:
    from arborpress.models.user import User

    user = await db.get(User, actor.user_id)
    if user is None:
        return []
    result = await db.execute(
        select(Follower.remote_actor_uri, Follower.remote_inbox_uri)
        .where(
            Follower.local_user_id == str(user.id),
            Follower.direction == FollowerDirection.INBOUND,
            Follower.state == FollowerState.ACCEPTED,
            Follower.remote_inbox_uri.is_not(None),
        )
        .limit(1000)
    )
    recipients: list[tuple[str, str]] = []
    for _actor_uri, inbox in result.all():
        if not inbox:
            continue
        try:
            domain, _ = validate_remote_url_syntax(inbox)
        except FederationFetchError:
            continue
        recipients.append((inbox, domain))
    return recipients


async def enqueue_post_activity(
    db: AsyncSession,
    *,
    post_id: str,
    activity_type: str = "Create",
    source_revision: str | None = None,
) -> FederationOutboxActivity | None:
    """Federate a public post only as its explicitly federated primary author."""
    from arborpress.models.content import (
        Post,
        PostAuthorRelation,
        PostAuthorRole,
        PostStatus,
        PostVisibility,
    )
    from arborpress.models.user import AccountType, User

    settings = await _federation_settings(db)
    if not federation_is_enabled(settings):
        return None
    row = (
        await db.execute(
            select(Post, User, LocalFederationActor)
            .join(PostAuthorRelation, PostAuthorRelation.post_id == Post.id)
            .join(User, User.id == PostAuthorRelation.user_id)
            .join(LocalFederationActor, LocalFederationActor.user_id == User.id)
            .where(
                Post.id == post_id,
                PostAuthorRelation.role == PostAuthorRole.PRIMARY,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
                User.account_type == AccountType.PUBLIC,
                User.is_active.is_(True),
                User.federation_opt_out.is_(False),
                LocalFederationActor.enabled.is_(True),
            )
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    post, _user, actor = row
    origin = canonical_origin()
    object_uri = post.ap_object_id or f"{origin}/ap/object/{post.short_id}"
    post.ap_object_id = object_uri
    updated = post.updated_at or post.published_at or post.created_at
    published = post.published_at or post.created_at
    safe_content = bleach.clean(
        post.body_html or "",
        tags=_HTML_TAGS,
        attributes={"a": ["href", "title"]},
        protocols=["https", "http", "mailto"],
        strip=True,
    )
    article = {
        "id": object_uri,
        "type": "Article",
        "attributedTo": actor.actor_uri,
        "name": post.title[:512],
        "summary": bleach.clean(post.excerpt or "", tags=[], strip=True)[:4000],
        "content": safe_content[:100_000],
        "published": published.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z"),
        "updated": updated.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z"),
        "url": f"{origin}/@{actor.preferred_username}/p/{post.slug}",
        "to": [PUBLIC],
        "cc": [f"{actor.actor_uri}/followers"],
    }
    recipients = await _actor_followers(db, actor)
    revision = source_revision or str(post.updated_at or post.published_at or post.id)
    return await enqueue_activity(
        db,
        actor=actor,
        activity_type=activity_type,
        obj=article,
        source_type="post",
        source_id=str(post.id),
        source_revision=revision,
        recipients=recipients,
    )


async def enqueue_post_delete(db: AsyncSession, *, post: Any) -> FederationOutboxActivity | None:
    """Queue a minimal Tombstone to the set of followers known at deletion time."""
    from arborpress.models.content import PostAuthorRelation, PostAuthorRole

    settings = await _federation_settings(db)
    if not federation_is_enabled(settings):
        return None
    row = (
        await db.execute(
            select(LocalFederationActor)
            .join(PostAuthorRelation, PostAuthorRelation.user_id == LocalFederationActor.user_id)
            .where(
                PostAuthorRelation.post_id == str(post.id),
                PostAuthorRelation.role == PostAuthorRole.PRIMARY,
                LocalFederationActor.enabled.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None or not post.ap_object_id:
        return None
    previous_targets = (
        await db.execute(
            select(FederationDelivery.target_inbox, FederationDelivery.domain)
            .join(
                FederationOutboxActivity,
                FederationOutboxActivity.id == FederationDelivery.activity_id,
            )
            .where(
                FederationOutboxActivity.source_type == "post",
                FederationOutboxActivity.source_id == str(post.id),
                FederationOutboxActivity.activity_type.in_(["Create", "Update"]),
            )
            .limit(1000)
        )
    ).all()
    return await enqueue_activity(
        db,
        actor=row,
        activity_type="Delete",
        obj={"id": post.ap_object_id, "type": "Tombstone", "formerType": "Article"},
        source_type="post",
        source_id=str(post.id),
        source_revision=f"delete:{post.updated_at or post.id}",
        recipients=[(target, domain) for target, domain in previous_targets],
    )


async def enqueue_comment_activity(
    db: AsyncSession, *, comment_id: str, activity_type: str = "Create", revision: str = "1"
) -> FederationOutboxActivity | None:
    """Queue an approved local registered author's public Note; never guest/remote."""
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus, PostVisibility
    from arborpress.models.user import User

    settings = await _federation_settings(db)
    if not federation_is_enabled(settings):
        return None
    row = (
        await db.execute(
            select(Comment, Post, User, LocalFederationActor)
            .join(Post, Post.id == Comment.post_id)
            .join(User, User.id == Comment.author_user_id)
            .join(LocalFederationActor, LocalFederationActor.user_id == User.id)
            .where(
                Comment.id == comment_id,
                Comment.status.in_(
                    [CommentStatus.APPROVED, CommentStatus.DELETED]
                    if activity_type == "Delete"
                    else [CommentStatus.APPROVED]
                ),
                Comment.author_email.is_(None),
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
                LocalFederationActor.enabled.is_(True),
            )
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    comment, post, _user, actor = row
    post_activity = await db.scalar(
        select(FederationOutboxActivity)
        .where(
            FederationOutboxActivity.source_type == "post",
            FederationOutboxActivity.source_id == str(post.id),
            FederationOutboxActivity.audience_public.is_(True),
            FederationOutboxActivity.activity_type.in_(["Create", "Update"]),
        )
        .order_by(FederationOutboxActivity.created_at)
        .limit(1)
    )
    if post_activity is None:
        post_activity = await enqueue_post_activity(db, post_id=str(post.id))
    if post_activity is None:
        return None
    post_actor = (
        await db.execute(
            select(LocalFederationActor).where(
                LocalFederationActor.actor_uri == post_activity.actor_uri,
                LocalFederationActor.enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if post_actor is None:
        return None
    origin = canonical_origin()
    object_uri = comment.remote_object_uri or f"{origin}/ap/comment/{comment.id}"
    comment.remote_object_uri = object_uri
    parent_uri = post.ap_object_id or f"{origin}/ap/object/{post.short_id}"
    if comment.parent_id:
        parent = await db.get(Comment, comment.parent_id)
        if parent is not None:
            parent_uri = parent.remote_object_uri or f"{origin}/ap/comment/{parent.id}"
    note = {
        "id": object_uri,
        "type": "Note",
        "attributedTo": actor.actor_uri,
        "content": bleach.clean(
            comment.body,
            tags=_HTML_TAGS,
            attributes={"a": ["href", "title"]},
            protocols=["https", "http"],
            strip=True,
        )[:20_000],
        "inReplyTo": parent_uri,
        "published": (comment.published_at or comment.created_at)
        .replace(tzinfo=UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "to": [PUBLIC],
        "cc": [f"{actor.actor_uri}/followers"],
    }
    if activity_type == "Delete":
        note = {"id": object_uri, "type": "Tombstone", "formerType": "Note"}
    return await enqueue_activity(
        db,
        actor=actor,
        activity_type=activity_type,
        obj=note,
        source_type="comment",
        source_id=str(comment.id),
        source_revision=revision,
        recipients=list(
            {*await _actor_followers(db, actor), *await _actor_followers(db, post_actor)}
        ),
    )


async def queue_follow_accept(
    db: AsyncSession,
    *,
    local_actor: LocalFederationActor,
    remote_actor: RemoteActor,
    follow_id: str,
    reject: bool = False,
) -> FederationOutboxActivity:
    follow = {
        "id": follow_id,
        "type": "Follow",
        "actor": remote_actor.actor_uri,
        "object": local_actor.actor_uri,
    }
    return await enqueue_activity(
        db,
        actor=local_actor,
        activity_type="Reject" if reject else "Accept",
        obj=follow,
        source_type="follow-response",
        source_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{local_actor.id}:{follow_id}")),
        source_revision="reject" if reject else "accept",
        recipients=[(remote_actor.shared_inbox_uri or remote_actor.inbox_uri, remote_actor.domain)],
        public=False,
    )


async def follow_remote_actor(
    db: AsyncSession, *, local_actor: LocalFederationActor, remote_actor: RemoteActor
) -> Follower:
    """Create/reuse a local-to-remote Follow and enqueue it without network I/O."""
    from arborpress.models.user import User

    settings = await _federation_settings(db)
    if not federation_is_enabled(settings) or not await domain_allowed(
        db, remote_actor.domain, settings
    ):
        raise ValueError("federation_or_remote_domain_unavailable")
    user = await db.get(User, local_actor.user_id)
    if user is None or not local_actor.enabled:
        raise ValueError("local_actor_unavailable")
    result = await db.execute(
        select(Follower).where(
            Follower.local_user_id == str(user.id),
            Follower.remote_actor_uri == remote_actor.actor_uri,
            Follower.direction == FollowerDirection.OUTBOUND,
        )
    )
    relation = result.scalar_one_or_none()
    if relation is not None and relation.state in {FollowerState.PENDING, FollowerState.ACCEPTED}:
        return relation
    follow_id = _activity_id()
    if relation is None:
        relation = Follower(
            id=str(uuid.uuid4()),
            local_user_id=str(user.id),
            remote_actor_uri=remote_actor.actor_uri,
            remote_display_name=remote_actor.display_name,
            remote_inbox_uri=remote_actor.shared_inbox_uri or remote_actor.inbox_uri,
            direction=FollowerDirection.OUTBOUND,
            state=FollowerState.PENDING,
            activity_id=None,
        )
        db.add(relation)
    else:
        relation.state = FollowerState.PENDING
        relation.remote_inbox_uri = remote_actor.shared_inbox_uri or remote_actor.inbox_uri
    activity = await enqueue_activity(
        db,
        actor=local_actor,
        activity_type="Follow",
        obj=remote_actor.actor_uri,
        source_type="follow-request",
        source_id=str(relation.id),
        source_revision=follow_id.rsplit("/", 1)[-1],
        recipients=[(remote_actor.shared_inbox_uri or remote_actor.inbox_uri, remote_actor.domain)],
        public=False,
    )
    relation.activity_id = activity.activity_uri
    await db.flush()
    return relation


async def claim_delivery(
    db: AsyncSession, *, worker_id: str, lease_seconds: int = 60
) -> str | None:
    now = _now()
    due = or_(
        (FederationDelivery.status.in_(["pending", "retry"]))
        & (FederationDelivery.next_attempt_at <= now),
        (FederationDelivery.status == "sending") & (FederationDelivery.lease_until <= now),
    )
    candidate = await db.scalar(
        select(FederationDelivery.id)
        .where(due)
        .order_by(FederationDelivery.next_attempt_at)
        .limit(1)
    )
    if candidate is None:
        return None
    result = await db.execute(
        update(FederationDelivery)
        .where(FederationDelivery.id == candidate, due)
        .values(
            status="sending",
            lease_owner=worker_id,
            lease_until=now + timedelta(seconds=lease_seconds),
            attempts=FederationDelivery.attempts + 1,
        )
    )
    return str(candidate) if getattr(result, "rowcount", 0) == 1 else None


async def deliver_one(db: AsyncSession, delivery_id: str) -> str:
    delivery = await db.get(FederationDelivery, delivery_id)
    if delivery is None or delivery.status != "sending":
        return "unavailable"
    activity = await db.get(FederationOutboxActivity, delivery.activity_id)
    if activity is None:
        delivery.status = "dead"
        delivery.last_error = "activity_missing"
        return delivery.status
    try:
        settings = await _federation_settings(db)
        domain, _ = validate_remote_url_syntax(delivery.target_inbox)
        if not federation_is_enabled(settings) or not await domain_allowed(db, domain, settings):
            delivery.status = "cancelled"
            delivery.last_error = "domain_not_allowed"
            delivery.lease_owner = None
            delivery.lease_until = None
            return delivery.status
        if not await _ensure_delivery_inbox(db, delivery, settings):
            return delivery.status
        await validate_remote_url(delivery.target_inbox)
        actor_result = await db.execute(
            select(LocalFederationActor).where(
                LocalFederationActor.actor_uri == activity.actor_uri,
                LocalFederationActor.enabled.is_(True),
            )
        )
        actor = actor_result.scalar_one_or_none()
        if actor is None:
            delivery.status = "cancelled"
            delivery.last_error = "signing_actor_disabled"
            return delivery.status
        url = urlsplit(delivery.target_inbox)
        body = activity.payload_json.encode("utf-8")
        from arborpress.auth.http_signatures import sign_legacy_request

        signed = await sign_legacy_request(
            db,
            actor.id,
            method="POST",
            path=f"{url.path or '/'}?{url.query}" if url.query else (url.path or "/"),
            host=url.netloc,
            body=body,
        )
        status = await post_remote(
            delivery.target_inbox,
            body=body,
            headers={
                **signed,
                "Content-Type": "application/activity+json; charset=utf-8",
                "Accept": 'application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
            },
        )
        delivery.response_status = status
        if 200 <= status < 300:
            delivery.status = "delivered"
            delivery.delivered_at = _now()
            delivery.last_error = None
        elif status in {404, 410} and delivery.attempts == 1:
            refreshed = await _refresh_delivery_inbox(db, delivery)
            if refreshed:
                delivery.status = "retry"
                delivery.next_attempt_at = _now()
                delivery.last_error = "inbox_refreshed_after_not_found"
            else:
                delivery.status = "dead"
                delivery.last_error = f"http_{status}_after_actor_refresh"
        elif status == 408 or status == 425 or status == 429 or status >= 500:
            await _retry_delivery(delivery, f"http_{status}")
        elif status in {301, 302, 303, 307, 308}:
            await _retry_delivery(delivery, "redirect_requires_actor_refresh", transient=False)
        else:
            delivery.status = "dead"
            delivery.last_error = f"http_{status}"
    except (FederationFetchError, ValueError) as exc:
        await _retry_delivery(delivery, str(exc)[:100])
    except Exception:
        log.exception("Federation delivery failed id=%s domain=%s", delivery.id, delivery.domain)
        await _retry_delivery(delivery, "internal_delivery_error")
    delivery.lease_owner = None
    delivery.lease_until = None
    return delivery.status


async def _ensure_delivery_inbox(
    db: AsyncSession, delivery: FederationDelivery, settings: dict[str, Any]
) -> bool:
    """Require a known, currently valid actor/inbox mapping before signed POST."""
    actor_uri = await db.scalar(
        select(Follower.remote_actor_uri)
        .where(
            Follower.remote_inbox_uri == delivery.target_inbox,
            Follower.direction.in_([FollowerDirection.INBOUND, FollowerDirection.OUTBOUND]),
        )
        .limit(1)
    )
    if actor_uri is None:
        actor_uri = await db.scalar(
            select(RemoteActor.actor_uri)
            .where(
                (RemoteActor.inbox_uri == delivery.target_inbox)
                | (RemoteActor.shared_inbox_uri == delivery.target_inbox)
            )
            .limit(1)
        )
    if actor_uri is None:
        delivery.status = "dead"
        delivery.last_error = "remote_actor_cache_missing"
        delivery.lease_owner = None
        delivery.lease_until = None
        return False
    from arborpress.federation.remote import fetch_remote_actor

    actor = await fetch_remote_actor(db, actor_uri, settings)
    valid_inboxes = {actor.inbox_uri}
    if actor.shared_inbox_uri:
        valid_inboxes.add(actor.shared_inbox_uri)
    if delivery.target_inbox in valid_inboxes:
        return True
    delivery.target_inbox = actor.shared_inbox_uri or actor.inbox_uri
    delivery.domain = actor.domain
    delivery.status = "retry"
    delivery.next_attempt_at = _now()
    delivery.last_error = "remote_actor_inbox_refreshed"
    delivery.lease_owner = None
    delivery.lease_until = None
    return False


async def _refresh_delivery_inbox(db: AsyncSession, delivery: FederationDelivery) -> bool:
    """Refresh a cached actor once after an inbox 404/410; never follow a redirect."""
    from arborpress.federation.remote import fetch_remote_actor

    relations = (
        await db.execute(
            select(Follower.remote_actor_uri).where(
                Follower.remote_inbox_uri == delivery.target_inbox,
                Follower.direction.in_([FollowerDirection.INBOUND, FollowerDirection.OUTBOUND]),
            )
        )
    ).scalars()
    actor_uri = relations.first()
    if actor_uri is None:
        return False
    try:
        actor = await fetch_remote_actor(db, actor_uri, await _federation_settings(db), force=True)
    except FederationFetchError, ValueError:
        return False
    inbox = actor.shared_inbox_uri or actor.inbox_uri
    try:
        domain, _path = validate_remote_url_syntax(inbox)
    except FederationFetchError:
        return False
    if domain != actor.domain or not await domain_allowed(
        db, domain, await _federation_settings(db)
    ):
        return False
    if inbox == delivery.target_inbox:
        return False
    delivery.target_inbox = inbox
    delivery.domain = domain
    return True


async def _retry_delivery(
    delivery: FederationDelivery, reason: str, *, transient: bool = True
) -> None:
    delivery.last_error = reason[:512]
    delivery.lease_owner = None
    delivery.lease_until = None
    if transient and delivery.attempts < delivery.max_attempts:
        base = min(3600, 2 ** min(delivery.attempts, 10))
        delivery.status = "retry"
        delivery.next_attempt_at = _now() + timedelta(
            seconds=base + secrets.randbelow(max(1, base // 4) + 1)
        )
    else:
        delivery.status = "dead"


async def run_delivery_batch(
    factory: async_sessionmaker[AsyncSession], *, batch_size: int = 20, worker_id: str | None = None
) -> int:
    worker = worker_id or f"federation-{uuid.uuid4()}"
    processed = 0
    for _ in range(max(1, min(batch_size, 100))):
        async with factory() as db:
            if not federation_is_enabled(await _federation_settings(db)):
                break
            delivery_id = await claim_delivery(db, worker_id=worker)
            await db.commit()
        if delivery_id is None:
            break
        async with factory() as db:
            await deliver_one(db, delivery_id)
            await db.commit()
        processed += 1
    return processed


async def run_worker(
    factory: async_sessionmaker[AsyncSession], *, stop_event: asyncio.Event, interval: float = 2.0
) -> None:
    while not stop_event.is_set():
        try:
            count = await run_delivery_batch(factory)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Federation worker iteration failed")
            count = 0
        if not count:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except TimeoutError:
                pass
