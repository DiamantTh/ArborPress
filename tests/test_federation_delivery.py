"""Phase 10B contracts for federation outbox, queue claims and inbox effects."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select


@pytest.mark.asyncio
async def test_activity_delivery_is_shared_inbox_deduplicated_and_leased(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.federation import services
    from arborpress.models.federation import (
        FederationDelivery,
        LocalFederationActor,
    )

    monkeypatch.setattr(services, "canonical_origin", lambda: "https://local.example")

    async def federation_settings(_db):
        return {"enabled": True, "mode": "full"}

    monkeypatch.setattr(services, "_federation_settings", federation_settings)

    async def allowed(_db, _domain, _settings):
        return True

    monkeypatch.setattr(services, "domain_allowed", allowed)
    actor = LocalFederationActor(
        id="local-actor",
        user_id="local-user",
        actor_uri="https://local.example/ap/actor/local",
        preferred_username="local",
        enabled=True,
    )
    # Actor foreign keys intentionally require an existing user.
    from arborpress.models.user import AccountType, User, UserRole

    db_session.add(
        User(
            id="local-user",
            username="local",
            display_name="Local",
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
    )
    db_session.add(actor)
    await db_session.flush()
    first = await services.enqueue_activity(
        db_session,
        actor=actor,
        activity_type="Create",
        obj={"id": "https://local.example/ap/object/p1", "type": "Article"},
        source_type="post",
        source_id="post-1",
        source_revision="1",
        recipients=[
            ("https://remote.example/inbox", "remote.example"),
            ("https://remote.example/inbox", "remote.example"),
        ],
    )
    count = await db_session.scalar(select(func.count(FederationDelivery.id)))
    assert count == 1
    delivery_id = await services.claim_delivery(db_session, worker_id="worker-a")
    assert delivery_id is not None
    assert await services.claim_delivery(db_session, worker_id="worker-b") is None
    delivery = await db_session.get(FederationDelivery, delivery_id)
    assert delivery is not None and delivery.status == "sending"
    assert delivery.lease_owner == "worker-a"
    delivery.lease_until = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
    await db_session.flush()
    assert await services.claim_delivery(db_session, worker_id="worker-b") == delivery_id
    assert first.activity_uri.startswith("https://local.example/ap/activities/")


@pytest.mark.asyncio
async def test_post_activity_uses_only_federated_primary_author(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.federation import services
    from arborpress.models.content import (
        Post,
        PostAuthorRelation,
        PostAuthorRole,
        PostStatus,
        PostVisibility,
    )
    from arborpress.models.federation import LocalFederationActor
    from arborpress.models.user import AccountType, User, UserRole

    monkeypatch.setattr(services, "canonical_origin", lambda: "https://local.example")

    async def federation_settings(_db):
        return {"enabled": True, "mode": "full"}

    async def allowed(_db, _domain, _settings):
        return True

    monkeypatch.setattr(services, "_federation_settings", federation_settings)
    monkeypatch.setattr(services, "domain_allowed", allowed)
    user = User(
        id="primary-user",
        username="primary",
        display_name="Primary",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    coauthor = User(
        id="coauthor-user",
        username="coauthor",
        display_name="Coauthor",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    post = Post(
        id="post-10b",
        short_id="post10b",
        author_id=user.id,
        slug="post-10b",
        title="A post",
        body_md="body",
        body_html="<p>safe</p><script>alert(1)</script>",
        status=PostStatus.PUBLISHED,
        visibility=PostVisibility.PUBLIC,
        published_at=datetime.now(UTC).replace(tzinfo=None),
    )
    db_session.add_all([user, coauthor, post])
    await db_session.flush()
    db_session.add_all(
        [
            PostAuthorRelation(
                post_id=post.id,
                user_id=user.id,
                role=PostAuthorRole.PRIMARY,
                position=0,
            ),
            PostAuthorRelation(
                post_id=post.id,
                user_id=coauthor.id,
                role=PostAuthorRole.COAUTHOR,
                position=1,
            ),
            LocalFederationActor(
                id="primary-actor",
                user_id=user.id,
                actor_uri="https://local.example/ap/actor/primary",
                preferred_username="primary",
                enabled=True,
            ),
            LocalFederationActor(
                id="coauthor-actor",
                user_id=coauthor.id,
                actor_uri="https://local.example/ap/actor/coauthor",
                preferred_username="coauthor",
                enabled=True,
            ),
        ]
    )
    await db_session.flush()
    activity = await services.enqueue_post_activity(
        db_session, post_id=post.id, source_revision="1"
    )
    assert activity is not None
    payload = json.loads(activity.payload_json)
    assert payload["actor"] == "https://local.example/ap/actor/primary"
    assert payload["object"]["attributedTo"] == payload["actor"]
    assert "<script>" not in payload["object"]["content"]


@pytest.mark.asyncio
async def test_remote_comment_uses_comment_model_without_guest_confirmation(db_session) -> None:
    from arborpress.comments import create_comment, resolve_comment_policy
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus, PostVisibility
    from arborpress.models.federation import RemoteActor

    post = Post(
        id="remote-comment-post",
        short_id="remotepost",
        slug="remote-comment-post",
        title="Post",
        body_md="body",
        body_html="<p>body</p>",
        status=PostStatus.PUBLISHED,
        visibility=PostVisibility.PUBLIC,
    )
    actor = RemoteActor(
        id="remote-actor",
        actor_uri="https://remote.example/actors/alice",
        domain="remote.example",
        actor_type="Person",
        inbox_uri="https://remote.example/inbox",
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1),
    )
    db_session.add_all([post, actor])
    await db_session.flush()
    policy = resolve_comment_policy(post, {"enabled": True, "moderation_mode": "always"})
    created = await create_comment(
        db_session,
        post=post,
        policy=policy,
        author_name="Alice",
        author_email=None,
        author_url=actor.actor_uri,
        body="A remote reply",
        remote_actor=actor,
        remote_object_uri="https://remote.example/notes/one",
    )
    stored = await db_session.get(Comment, created.comment.id)
    assert stored is not None
    assert stored.remote_actor_id == actor.id
    assert stored.author_user_id is None and stored.author_email is None
    assert stored.confirmation_token_hash is None
    assert stored.status == CommentStatus.PENDING_MODERATION


@pytest.mark.asyncio
async def test_signed_follow_intake_creates_existing_follower_and_queued_accept(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.federation import inbox, services
    from arborpress.models.federation import (
        FederationInboxActivity,
        FederationOutboxActivity,
        LocalFederationActor,
        RemoteActor,
    )
    from arborpress.models.user import (
        AccountType,
        Follower,
        FollowerDirection,
        FollowerState,
        User,
        UserRole,
    )

    settings = {"enabled": True, "mode": "full", "require_approval_to_follow": False}

    async def get_settings(_db):
        return settings

    async def allowed(_db, _domain, _settings):
        return True

    monkeypatch.setattr(inbox, "_settings", get_settings)
    monkeypatch.setattr(inbox, "domain_allowed", allowed)
    monkeypatch.setattr(services, "_federation_settings", get_settings)
    monkeypatch.setattr(services, "domain_allowed", allowed)
    monkeypatch.setattr(services, "canonical_origin", lambda: "https://local.example")
    user = User(
        id="follow-user",
        username="follow-user",
        display_name="Follow User",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    actor = LocalFederationActor(
        id="follow-local-actor",
        user_id=user.id,
        actor_uri="https://local.example/ap/actor/follow-user",
        preferred_username="follow-user",
        enabled=True,
    )
    remote = RemoteActor(
        id="follow-remote-actor",
        actor_uri="https://remote.example/actors/bob",
        domain="remote.example",
        actor_type="Person",
        inbox_uri="https://remote.example/inbox",
        shared_inbox_uri="https://remote.example/shared-inbox",
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1),
    )
    activity = {
        "id": "https://remote.example/activities/follow-1",
        "type": "Follow",
        "actor": remote.actor_uri,
        "object": actor.actor_uri,
    }
    intake = FederationInboxActivity(
        id="intake-follow",
        activity_uri=activity["id"],
        activity_type="Follow",
        actor_uri=remote.actor_uri,
        target_actor_id=actor.id,
        source_domain="remote.example",
        body_sha256="a" * 64,
        payload_json=json.dumps(activity),
        processing_state="processing",
        lease_owner="worker",
        lease_until=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=1),
    )
    db_session.add_all([user, actor, remote, intake])
    await db_session.flush()
    assert await inbox.process_claimed(db_session, intake.id, worker_id="worker") == "processed"
    relation = (
        await db_session.execute(
            select(Follower).where(Follower.direction == FollowerDirection.INBOUND)
        )
    ).scalar_one()
    assert relation.state == FollowerState.ACCEPTED
    assert relation.remote_inbox_uri == remote.shared_inbox_uri
    response = (
        await db_session.execute(
            select(FederationOutboxActivity).where(
                FederationOutboxActivity.activity_type == "Accept"
            )
        )
    ).scalar_one()
    assert json.loads(response.payload_json)["object"]["id"] == activity["id"]
    assert json.loads(response.payload_json)["to"] == [remote.actor_uri]


@pytest.mark.asyncio
async def test_outbound_follow_and_undo_reuse_existing_follower_model(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.federation import inbox, services
    from arborpress.models.federation import (
        FederationOutboxActivity,
        LocalFederationActor,
        RemoteActor,
    )
    from arborpress.models.user import (
        AccountType,
        Follower,
        FollowerDirection,
        FollowerState,
        User,
        UserRole,
    )

    async def get_settings(_db):
        return {"enabled": True, "mode": "full"}

    async def allowed(_db, _domain, _settings):
        return True

    monkeypatch.setattr(services, "_federation_settings", get_settings)
    monkeypatch.setattr(services, "domain_allowed", allowed)
    monkeypatch.setattr(services, "canonical_origin", lambda: "https://local.example")
    monkeypatch.setattr(inbox, "_settings", get_settings)
    monkeypatch.setattr(inbox, "domain_allowed", allowed)
    user = User(
        id="following-user",
        username="following",
        display_name="Following",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    local = LocalFederationActor(
        id="following-local-actor",
        user_id=user.id,
        actor_uri="https://local.example/ap/actor/following",
        preferred_username="following",
        enabled=True,
    )
    remote = RemoteActor(
        id="following-remote-actor",
        actor_uri="https://remote.example/actors/target",
        domain="remote.example",
        actor_type="Person",
        inbox_uri="https://remote.example/inbox",
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1),
    )
    db_session.add_all([user, local, remote])
    await db_session.flush()

    relation = await services.follow_remote_actor(
        db_session, local_actor=local, remote_actor=remote
    )
    assert relation.state == FollowerState.PENDING
    follow_activity = (
        await db_session.execute(
            select(FederationOutboxActivity).where(
                FederationOutboxActivity.activity_type == "Follow"
            )
        )
    ).scalar_one()
    follow_payload = json.loads(follow_activity.payload_json)
    assert follow_payload["object"] == remote.actor_uri
    assert follow_payload["to"] == [remote.actor_uri]
    assert follow_activity.activity_uri == relation.activity_id
    await inbox.unfollow_remote_actor(db_session, local_actor=local, remote_actor=remote)
    await inbox.unfollow_remote_actor(db_session, local_actor=local, remote_actor=remote)
    assert relation.state == FollowerState.UNDONE
    rows = (
        (
            await db_session.execute(
                select(FederationOutboxActivity).where(
                    FederationOutboxActivity.activity_type == "Undo"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    undo_payload = json.loads(rows[0].payload_json)
    assert undo_payload["object"]["id"] == relation.activity_id
    assert undo_payload["to"] == [remote.actor_uri]
    stored = (
        await db_session.execute(
            select(Follower).where(Follower.direction == FollowerDirection.OUTBOUND)
        )
    ).scalar_one()
    assert stored.state == FollowerState.UNDONE


@pytest.mark.asyncio
async def test_remote_update_creates_pending_revision_without_replacing_public_body(
    db_session,
) -> None:
    from arborpress.comments import (
        create_comment,
        create_remote_comment_revision,
        resolve_comment_policy,
    )
    from arborpress.models.content import (
        Comment,
        CommentRevision,
        CommentRevisionStatus,
        CommentStatus,
        Post,
        PostStatus,
        PostVisibility,
    )
    from arborpress.models.federation import RemoteActor

    post = Post(
        id="remote-update-post",
        short_id="remoteupdate",
        slug="remote-update-post",
        title="Post",
        body_md="body",
        body_html="<p>body</p>",
        status=PostStatus.PUBLISHED,
        visibility=PostVisibility.PUBLIC,
    )
    actor = RemoteActor(
        id="remote-update-actor",
        actor_uri="https://remote.example/actors/alice",
        domain="remote.example",
        actor_type="Person",
        inbox_uri="https://remote.example/inbox",
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1),
    )
    db_session.add_all([post, actor])
    await db_session.flush()
    policy = resolve_comment_policy(post, {"enabled": True, "moderation_mode": "always"})
    created = await create_comment(
        db_session,
        post=post,
        policy=policy,
        author_name="Alice",
        author_email=None,
        body="Published body",
        remote_actor=actor,
        remote_object_uri="https://remote.example/notes/update",
    )
    created.comment.status = CommentStatus.APPROVED
    await db_session.flush()

    revision = await create_remote_comment_revision(
        db_session,
        comment=created.comment,
        remote_actor_id=actor.id,
        body="Updated body",
        policy=policy,
    )
    assert created.comment.body == "Published body"
    assert revision.status == CommentRevisionStatus.PENDING
    stored = await db_session.get(Comment, created.comment.id)
    assert stored is not None and stored.body == "Published body"
    assert await db_session.scalar(select(CommentRevision.id)) == revision.id


@pytest.mark.asyncio
async def test_delivery_worker_signs_and_posts_only_to_claimed_inbox(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.auth import http_signatures
    from arborpress.federation import services
    from arborpress.models.federation import FederationDelivery, LocalFederationActor, RemoteActor
    from arborpress.models.user import AccountType, User, UserRole

    async def get_settings(_db):
        return {"enabled": True, "mode": "full"}

    async def allowed(_db, _domain, _settings):
        return True

    async def valid_url(_url):
        return ("remote.example",)

    async def signer(_db, _actor_id, *, method, path, host, body):
        assert method == "POST"
        assert path == "/inbox?source=ap"
        assert host == "remote.example"
        assert body
        return {"Date": "now", "Digest": "SHA-256=fixture", "Signature": "fixture"}

    sent: list[tuple[str, bytes, dict[str, str]]] = []

    async def post_remote(url, *, body, headers):
        sent.append((url, body, headers))
        return 202

    monkeypatch.setattr(services, "_federation_settings", get_settings)
    monkeypatch.setattr(services, "domain_allowed", allowed)
    monkeypatch.setattr(services, "validate_remote_url", valid_url)
    monkeypatch.setattr(services, "post_remote", post_remote)
    monkeypatch.setattr(http_signatures, "sign_legacy_request", signer)
    monkeypatch.setattr(services, "canonical_origin", lambda: "https://local.example")

    user = User(
        id="delivery-user",
        username="delivery",
        display_name="Delivery",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    actor = LocalFederationActor(
        id="delivery-local-actor",
        user_id=user.id,
        actor_uri="https://local.example/ap/actor/delivery",
        preferred_username="delivery",
        enabled=True,
    )
    remote = RemoteActor(
        id="delivery-remote-actor",
        actor_uri="https://remote.example/actors/delivery",
        domain="remote.example",
        actor_type="Person",
        inbox_uri="https://remote.example/inbox?source=ap",
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1),
    )
    db_session.add_all([user, actor, remote])
    await db_session.flush()
    activity = await services.enqueue_activity(
        db_session,
        actor=actor,
        activity_type="Create",
        obj={"id": "https://local.example/ap/object/delivery", "type": "Article"},
        source_type="post",
        source_id="delivery-post",
        source_revision="1",
        recipients=[("https://remote.example/inbox?source=ap", "remote.example")],
    )
    delivery_id = await services.claim_delivery(db_session, worker_id="delivery-worker")
    assert delivery_id is not None

    assert await services.deliver_one(db_session, delivery_id) == "delivered"
    delivery = await db_session.get(FederationDelivery, delivery_id)
    assert delivery is not None and delivery.status == "delivered"
    assert sent[0][0] == "https://remote.example/inbox?source=ap"
    assert sent[0][2]["Signature"] == "fixture"
    assert activity.activity_uri.encode() in sent[0][1]


@pytest.mark.asyncio
async def test_remote_note_create_update_delete_use_inbox_and_comment_pipeline(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.comments import resolve_comment_policy
    from arborpress.federation import inbox
    from arborpress.models.content import (
        Comment,
        CommentRevision,
        CommentRevisionStatus,
        CommentStatus,
        Post,
        PostStatus,
        PostVisibility,
    )
    from arborpress.models.federation import FederationInboxActivity, RemoteActor

    async def get_settings(_db):
        return {"enabled": True, "mode": "full"}

    async def allowed(_db, _domain, _settings):
        return True

    post = Post(
        id="inbox-remote-post",
        short_id="inboxremotepost",
        ap_object_id="https://local.example/ap/object/inboxremotepost",
        slug="inbox-remote-post",
        title="Post",
        body_md="body",
        body_html="<p>body</p>",
        status=PostStatus.PUBLISHED,
        visibility=PostVisibility.PUBLIC,
    )
    actor = RemoteActor(
        id="inbox-remote-actor",
        actor_uri="https://remote.example/actors/alice",
        domain="remote.example",
        actor_type="Person",
        inbox_uri="https://remote.example/inbox",
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1),
    )
    policy = resolve_comment_policy(post, {"enabled": True, "moderation_mode": "always"})
    monkeypatch.setattr(inbox, "_settings", get_settings)
    monkeypatch.setattr(inbox, "domain_allowed", allowed)

    async def get_policy(_db, _post_id):
        return policy

    monkeypatch.setattr(inbox, "_comment_policy", get_policy)
    db_session.add_all([post, actor])
    await db_session.flush()
    object_uri = "https://remote.example/notes/inbox-note"

    async def add_intake(activity_id: str, activity_type: str, object_value: object) -> str:
        payload = {
            "id": f"https://remote.example/activities/{activity_id}",
            "type": activity_type,
            "actor": actor.actor_uri,
            "object": object_value,
        }
        item = FederationInboxActivity(
            id=f"intake-{activity_id}",
            activity_uri=payload["id"],
            activity_type=activity_type,
            actor_uri=actor.actor_uri,
            source_domain=actor.domain,
            body_sha256=(activity_id.encode().hex() * 64)[:64],
            payload_json=json.dumps(payload),
            processing_state="processing",
            lease_owner="worker",
            lease_until=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=1),
        )
        db_session.add(item)
        await db_session.flush()
        assert await inbox.process_claimed(db_session, item.id, worker_id="worker") == "processed"
        return item.id

    create_object = {
        "id": object_uri,
        "type": "Note",
        "attributedTo": actor.actor_uri,
        "inReplyTo": post.ap_object_id,
        "content": "<p>Hello</p><script>alert(1)</script>",
    }
    await add_intake("create-remote-note", "Create", create_object)
    comment = (
        await db_session.execute(select(Comment).where(Comment.remote_object_uri == object_uri))
    ).scalar_one()
    assert comment.remote_actor_id == actor.id
    assert comment.author_user_id is None and comment.author_email is None
    assert comment.status == CommentStatus.PENDING_MODERATION
    assert comment.body == "Helloalert(1)"
    assert comment.confirmation_token_hash is None

    comment.status = CommentStatus.APPROVED
    await db_session.flush()
    update_object = {**create_object, "content": "<p>Edited</p>"}
    await add_intake("update-remote-note", "Update", update_object)
    revision = (
        await db_session.execute(
            select(CommentRevision).where(CommentRevision.comment_id == comment.id)
        )
    ).scalar_one()
    assert revision.status == CommentRevisionStatus.PENDING
    assert comment.body == "Helloalert(1)"

    await add_intake("delete-remote-note", "Delete", object_uri)
    assert comment.status == CommentStatus.DELETED
