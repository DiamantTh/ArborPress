"""ActivityPub Federation-Routen (§5).

Endpunkte:
  /.well-known/webfinger
  /.well-known/nodeinfo
  /nodeinfo/{version}
  /ap/actor/{handle}
  /ap/inbox/{handle}
  /ap/outbox/{handle}
  /ap/object/{id}

§5 Constraints:
- Operational-Accounts erzeugen KEINE Actor-Endpunkte
- Kein Language-Prefix auf diesen Routen
- Federated Content wird vor Rendering sanitisiert (bleach)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC
from typing import Any, cast
from urllib.parse import urlparse

import bleach  # type: ignore[import-untyped]
from quart import Blueprint, abort, jsonify, request
from quart.typing import ResponseReturnValue
from sqlalchemy import func, select

from arborpress.core.db import get_db_session
from arborpress.federation.policy import canonical_domain, canonical_origin, federation_is_enabled
from arborpress.federation.security import (
    FederationFetchError,
    normalize_domain,
    validate_remote_url_syntax,
)
from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.federation")
audit = get_audit_logger()

wellknown_bp = Blueprint("wellknown", __name__)
federation_bp = Blueprint("federation", __name__)

_AP_CONTENT_TYPE = "application/activity+json"
_JRD_CONTENT_TYPE = "application/jrd+json"


def _fed() -> dict[str, Any]:
    """Liefert Federation-Settings (Cache oder Defaults)."""
    from arborpress.core.site_settings import get_cached, get_defaults

    return get_cached("federation") or get_defaults("federation")


def _base_url() -> str:
    return canonical_origin()


def _federation_active(settings: dict[str, Any]) -> bool:
    try:
        return federation_is_enabled(settings)
    except Exception:
        return False


async def _load_local_actor(route_name: str) -> Any | None:
    """Resolve an immutable actor route URI to its explicit actor record."""
    from arborpress.models.federation import LocalFederationActor

    try:
        actor_uri = f"{_base_url()}/ap/actor/{route_name}"
    except FederationFetchError:
        return None
    from arborpress.models.federation import FederationInstanceIdentity

    async for db in get_db_session():
        identity = await db.get(FederationInstanceIdentity, 1)
        if identity is not None and identity.canonical_origin != _base_url():
            return None
        result = await db.execute(
            select(LocalFederationActor).where(
                LocalFederationActor.actor_uri == actor_uri,
                LocalFederationActor.enabled.is_(True),
            )
        )
        return result.scalar_one_or_none()
    return None


async def _load_actor_user(actor: Any) -> Any | None:
    from arborpress.models.user import AccountType, User

    async for db in get_db_session():
        user = await db.get(User, actor.user_id)
        if (
            user is not None
            and user.account_type == AccountType.PUBLIC
            and user.is_active
            and not user.federation_opt_out
        ):
            return user
    return None


async def _load_public_user(handle: str) -> Any | None:
    """Load a local public user eligible for federation."""
    from arborpress.models.user import AccountType, User

    async for db in get_db_session():
        stmt = select(User).where(
            func.lower(User.username) == handle.lower(),
            User.account_type == AccountType.PUBLIC,
            User.is_active == True,  # noqa: E712
            User.federation_opt_out == False,  # noqa: E712
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    return None


def _post_to_activity(post: Any, handle: str, actor_uri: str | None = None) -> dict[str, Any]:
    """Convert a published post into a blogging-friendly ActivityPub object."""
    base = _base_url()
    post_url = f"{base}/@{handle}/p/{post.slug}"
    object_id = post.ap_object_id or f"{base}/ap/object/{post.short_id}"
    published = None
    if post.published_at is not None:
        dt = post.published_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        published = dt.isoformat().replace("+00:00", "Z")

    payload = {
        "id": object_id,
        "type": "Article",
        "attributedTo": actor_uri or f"{base}/ap/actor/{handle}",
        "url": post_url,
        "name": post.title,
        "summary": post.excerpt or "",
        "content": post.body_html,
        "contentMap": {"de": post.body_html},
        "published": published,
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "cc": [f"{base}/ap/actor/{handle}/followers"],
    }
    return payload


async def _load_actor_by_username(handle: str) -> Any | None:
    from arborpress.models.federation import FederationInstanceIdentity, LocalFederationActor

    async for db in get_db_session():
        identity = await db.get(FederationInstanceIdentity, 1)
        if identity is not None and identity.canonical_origin != _base_url():
            return None
        result = await db.execute(
            select(LocalFederationActor).where(
                func.lower(LocalFederationActor.preferred_username) == handle.lower(),
                LocalFederationActor.enabled.is_(True),
            )
        )
        return result.scalar_one_or_none()
    return None


_INBOX_LIMIT = 256 * 1024
_SUPPORTED_INTAKE_TYPES = {"Follow", "Accept", "Reject", "Undo", "Create", "Update", "Delete"}
_ALLOWED_CONTEXTS = {
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://www.w3.org/ns/activitystreams#",
}
_HTML_TAGS = ["p", "br", "strong", "em", "a", "ul", "ol", "li", "blockquote", "span"]


def _sanitize_activity(value: Any, depth: int = 0) -> Any:
    """Keep a bounded JSON DTO and sanitize HTML-bearing ActivityStreams fields."""
    if depth > 8:
        return None
    if isinstance(value, dict):
        clean = {}
        for key, item in list(value.items())[:80]:
            if not isinstance(key, str) or len(key) > 64 or key.startswith("_"):
                continue
            if key == "@context":
                # Contexts are data only. No JSON-LD context is ever dereferenced.
                contexts = item if isinstance(item, list) else [item]
                clean[key] = [
                    context
                    for context in contexts[:4]
                    if isinstance(context, str) and context in _ALLOWED_CONTEXTS
                ]
            elif key in {"content", "summary"} and isinstance(item, str):
                clean[key] = bleach.clean(
                    item[:64_000],
                    tags=_HTML_TAGS,
                    attributes={"a": ["href", "rel"]},
                    protocols=["https", "http", "mailto"],
                    strip=True,
                )
            else:
                clean[key] = _sanitize_activity(item, depth + 1)
        return clean
    if isinstance(value, list):
        return [_sanitize_activity(item, depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:64_000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return None


async def _receive_inbox(fed: dict[str, Any], target_actor: Any | None) -> ResponseReturnValue:
    if not _federation_active(fed):
        abort(404)
    if fed.get("mode", "disabled") in {"outgoing_only", "disabled"}:
        abort(405)
    from arborpress.web.ratelimit import check_rate_limit

    remote_ip = request.remote_addr or "unknown"
    if not check_rate_limit(f"federation-inbox:{remote_ip}", "30/minute"):
        return jsonify({"error": "rate_limited"}), 429
    if request.scheme != "https":
        abort(400, "HTTPS is required for federation inbox requests")
    if request.content_length is not None and request.content_length > _INBOX_LIMIT:
        abort(413)
    content_type = request.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"application/activity+json", "application/ld+json"}:
        abort(415)
    # Quart normally receives its body limit from the global app config. Apply
    # the stricter federation-specific cap before consuming a chunked body too.
    request_body = getattr(request, "body", None)
    if request_body is not None and hasattr(request_body, "_max_content_length"):
        request_body._max_content_length = _INBOX_LIMIT
    body = cast(bytes, await request.get_data())
    if not body or len(body) > _INBOX_LIMIT:
        abort(413 if len(body) > _INBOX_LIMIT else 400)
    try:
        payload = json.loads(body)
    except ValueError, UnicodeDecodeError:
        abort(400, "Invalid ActivityStreams JSON")
    if not isinstance(payload, dict) or not isinstance(payload.get("actor"), str):
        abort(400, "Activity actor is required")
    if "@context" in payload:
        context = payload["@context"]
        contexts = context if isinstance(context, list) else [context]
        if (
            any(not isinstance(item, (str, dict)) for item in contexts)
            or any(isinstance(item, str) and item not in _ALLOWED_CONTEXTS for item in contexts)
            or len(contexts) > 4
        ):
            abort(400, "Invalid ActivityStreams context")
    activity_id = payload.get("id")
    activity_type = payload.get("type")
    if not isinstance(activity_id, str) or len(activity_id) > 2048:
        abort(400, "Stable activity id required")
    if not isinstance(activity_type, str) or len(activity_type) > 64:
        abort(400, "Activity type required")
    actor_uri = payload["actor"]
    try:
        actor_domain, _ = validate_remote_url_syntax(actor_uri)
        activity_domain, _ = validate_remote_url_syntax(activity_id)
    except FederationFetchError:
        abort(400, "HTTPS actor and activity IDs required")
    if actor_domain == canonical_domain():
        abort(400, "Remote actor required")

    async for db in get_db_session():
        from sqlalchemy.exc import IntegrityError

        from arborpress.federation.policy import domain_allowed
        from arborpress.models.federation import FederationInboxActivity

        if not await domain_allowed(db, actor_domain, fed):
            abort(403, "Federation domain blocked")
        if not check_rate_limit(f"federation-domain:{actor_domain}", "120/minute"):
            return jsonify({"error": "rate_limited"}), 429
        # Signature verification is mandatory; old per-site false settings cannot downgrade it.
        from arborpress.auth.http_signatures import verify_request_signature

        try:
            expected_netloc = urlparse(canonical_origin()).netloc.lower()
        except FederationFetchError:
            abort(503, "Federation origin is not configured")
        if request.host.lower() != expected_netloc:
            abort(400, "Unexpected request authority")
        signature = await verify_request_signature(
            method=request.method,
            path=request.full_path.rstrip("?"),
            headers={key.lower(): value for key, value in request.headers.items()},
            body=body,
            db=db,
            federation_settings=fed,
        )
        if not signature.valid:
            abort(401, "HTTP Signature invalid")
        if signature.actor_uri != actor_uri:
            abort(401, "Activity actor does not own signing key")
        if not check_rate_limit(f"federation-actor:{signature.actor_uri}", "60/minute"):
            return jsonify({"error": "rate_limited"}), 429
        if activity_domain == canonical_domain():
            abort(400, "Remote activity id required")

        body_hash = hashlib.sha256(body).hexdigest()
        existing_result = await db.execute(
            select(FederationInboxActivity).where(
                FederationInboxActivity.activity_uri == activity_id
            )
        )
        existing = existing_result.scalar_one_or_none()
        if existing:
            if existing.body_sha256 != body_hash:
                abort(409, "Activity id body conflict")
            return jsonify({"status": "duplicate"}), 202

        safe_payload = _sanitize_activity(payload)
        state = "received" if activity_type in _SUPPORTED_INTAKE_TYPES else "ignored"
        db.add(
            FederationInboxActivity(
                activity_uri=activity_id,
                activity_type=activity_type,
                actor_uri=actor_uri,
                target_actor_id=target_actor.id if target_actor is not None else None,
                source_domain=actor_domain,
                body_sha256=body_hash,
                payload_json=json.dumps(safe_payload, ensure_ascii=False, separators=(",", ":")),
                processing_state=state,
            )
        )
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            duplicate_result = await db.execute(
                select(FederationInboxActivity).where(
                    FederationInboxActivity.activity_uri == activity_id
                )
            )
            concurrent = duplicate_result.scalar_one_or_none()
            if concurrent is not None and concurrent.body_sha256 == body_hash:
                return jsonify({"status": "duplicate"}), 202
            abort(409, "Activity id body conflict")
        log.info("Federation inbox intake accepted type=%s domain=%s", activity_type, actor_domain)
        return jsonify({"status": "accepted"}), 202
    abort(503, "Federation database is unavailable")


# ---------------------------------------------------------------------------
# §5 /.well-known/webfinger
# ---------------------------------------------------------------------------


@wellknown_bp.get("/.well-known/webfinger")
async def webfinger() -> ResponseReturnValue:
    fed = _fed()
    if not _federation_active(fed):
        abort(404)

    resource = request.args.get("resource", "")
    if not resource.startswith("acct:"):
        abort(400, "resource must start with acct:")

    acct = resource.removeprefix("acct:")
    handle, _, domain = acct.partition("@")
    handle = handle.lstrip("@")
    try:
        base = _base_url()
        base_host = canonical_domain()
    except FederationFetchError:
        abort(503, "Federation HTTPS origin is not configured")
    try:
        supplied_domain = normalize_domain(domain)
    except FederationFetchError:
        abort(404)
    if not handle or not domain or supplied_domain != base_host:
        abort(404)

    actor = await _load_actor_by_username(handle)
    if actor is None:
        abort(404)
    user = await _load_actor_user(actor)
    if user is None:
        abort(404)

    jrd = {
        "subject": f"acct:{user.username}@{base_host}",
        "aliases": [f"{base}/@{user.username}"],
        "links": [
            {
                "rel": "self",
                "type": _AP_CONTENT_TYPE,
                "href": actor.actor_uri,
            },
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": f"{base}/@{user.username}",
            },
        ],
    }
    return jsonify(jrd), 200, {"Content-Type": _JRD_CONTENT_TYPE}


# ---------------------------------------------------------------------------
# §5 /.well-known/nodeinfo + /nodeinfo/{version}
# ---------------------------------------------------------------------------


@wellknown_bp.get("/.well-known/nodeinfo")
async def nodeinfo_discovery() -> ResponseReturnValue:
    fed = _fed()
    if not _federation_active(fed):
        abort(404)
    try:
        base = _base_url()
    except FederationFetchError:
        abort(503, "Federation HTTPS origin is not configured")
    return jsonify(
        {
            "links": [
                {
                    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.1",
                    "href": f"{base}/nodeinfo/2.1",
                }
            ]
        }
    )


@federation_bp.get("/nodeinfo/<version>")
async def nodeinfo(version: str) -> ResponseReturnValue:
    fed = _fed()
    if not _federation_active(fed):
        abort(404)
    try:
        _base_url()
    except FederationFetchError:
        abort(503, "Federation HTTPS origin is not configured")
    if version not in ("2.0", "2.1"):
        abort(404)

    user_total = 0
    local_posts = 0
    try:
        from arborpress.models.content import Post, PostStatus, PostVisibility
        from arborpress.models.user import AccountType, User

        async for db in get_db_session():
            user_total = int(
                (
                    await db.execute(
                        select(func.count())
                        .select_from(User)
                        .where(
                            User.account_type == AccountType.PUBLIC,
                            User.is_active == True,  # noqa: E712
                        )
                    )
                ).scalar_one()
            )
            local_posts = int(
                (
                    await db.execute(
                        select(func.count())
                        .select_from(Post)
                        .where(
                            Post.status == PostStatus.PUBLISHED,
                            Post.visibility == PostVisibility.PUBLIC,
                        )
                    )
                ).scalar_one()
            )
    except Exception as exc:  # noqa: BLE001
        log.debug("NodeInfo stats fallback: %s", exc)

    return jsonify(
        {
            "version": version,
            "software": {"name": "arborpress", "version": "0.1.0"},
            "protocols": ["activitypub"],
            "usage": {"users": {"total": user_total}, "localPosts": local_posts},
            "openRegistrations": False,
            "metadata": {
                "nodeName": fed.get("instance_name", ""),
                "nodeDescription": fed.get("instance_description", ""),
            },
        }
    )


# ---------------------------------------------------------------------------
# §5 ActivityPub Actor / Inbox / Outbox / Object
# ---------------------------------------------------------------------------


@federation_bp.get("/ap/actor/<handle>")
async def ap_actor(handle: str) -> ResponseReturnValue:
    fed = _fed()
    if not _federation_active(fed):
        abort(404)
    local_actor = await _load_local_actor(handle)
    if local_actor is None:
        abort(404)
    user = await _load_actor_user(local_actor)
    if user is None:
        abort(404)

    base = _base_url()
    from arborpress.models.user import ActorKeypair

    key = None
    if local_actor.current_keypair_id:
        async for db in get_db_session():
            key = await db.get(ActorKeypair, local_actor.current_keypair_id)
    actor: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        "type": "Person",
        "id": local_actor.actor_uri,
        "preferredUsername": local_actor.preferred_username,
        "name": user.display_name,
        "summary": bleach.clean(user.bio or "", tags=[], strip=True)[:4000],
        "url": f"{base}/@{user.username}",
        "inbox": f"{base}/ap/inbox/{local_actor.actor_uri.rsplit('/', 1)[-1]}",
        "outbox": f"{base}/ap/outbox/{local_actor.actor_uri.rsplit('/', 1)[-1]}",
        "followers": f"{base}/ap/actor/{local_actor.actor_uri.rsplit('/', 1)[-1]}/followers",
    }
    if key is not None:
        actor["publicKey"] = {
            "id": key.key_id_url,
            "owner": local_actor.actor_uri,
            "publicKeyPem": key.public_key_pem,
        }
    else:
        abort(404)
    return jsonify(actor), 200, {"Content-Type": _AP_CONTENT_TYPE}


@federation_bp.post("/ap/inbox/<handle>")
async def ap_inbox(handle: str) -> ResponseReturnValue:
    fed = _fed()
    target = await _load_local_actor(handle)
    if target is None:
        abort(404)
    return await _receive_inbox(fed, target)


@federation_bp.post("/ap/inbox")
async def ap_shared_inbox() -> ResponseReturnValue:
    fed = _fed()
    return await _receive_inbox(fed, None)


@federation_bp.get("/ap/inbox/<handle>")
async def ap_inbox_not_public(handle: str) -> ResponseReturnValue:
    abort(404)


@federation_bp.get("/ap/outbox/<handle>")
async def ap_outbox(handle: str) -> ResponseReturnValue:
    fed = _fed()
    if not _federation_active(fed):
        abort(404)
    if fed.get("mode", "disabled") == "inbox_only":
        abort(405)

    local_actor = await _load_local_actor(handle)
    if local_actor is None:
        abort(404)
    user = await _load_actor_user(local_actor)
    if user is None:
        abort(404)

    from arborpress.models.content import Post, PostStatus, PostVisibility

    items: list[dict[str, Any]] = []
    async for db in get_db_session():
        stmt = (
            select(Post)
            .where(
                Post.author_id == user.id,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
            .order_by(Post.published_at.desc())
            .limit(20)
        )
        result = await db.execute(stmt)
        posts = result.scalars().all()
        items = [_post_to_activity(post, user.username, local_actor.actor_uri) for post in posts]

    base = _base_url()
    outbox = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "OrderedCollection",
        "id": f"{base}/ap/outbox/{user.username}",
        "totalItems": len(items),
        "orderedItems": items,
    }
    return jsonify(outbox), 200, {"Content-Type": _AP_CONTENT_TYPE}


@federation_bp.get("/ap/object/<obj_id>")
async def ap_object(obj_id: str) -> ResponseReturnValue:
    fed = _fed()
    if not _federation_active(fed):
        abort(404)
    try:
        origin = _base_url()
    except FederationFetchError:
        abort(503, "Federation HTTPS origin is not configured")

    from arborpress.models.content import Post, PostStatus, PostVisibility
    from arborpress.models.federation import FederationInstanceIdentity, LocalFederationActor
    from arborpress.models.user import AccountType, User

    async for db in get_db_session():
        stmt = (
            select(Post, User, LocalFederationActor)
            .join(User, User.id == Post.author_id)
            .join(LocalFederationActor, LocalFederationActor.user_id == User.id)
            .where(
                (Post.short_id == obj_id) | (Post.id == obj_id) | (Post.ap_object_id == obj_id),
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
                User.account_type == AccountType.PUBLIC,
                User.is_active == True,  # noqa: E712
                User.federation_opt_out == False,  # noqa: E712
                LocalFederationActor.enabled.is_(True),
            )
            .limit(1)
        )
        result = await db.execute(stmt)
        row = result.first()
        if row is None:
            abort(404)
        post, user, local_actor = row
        identity = await db.get(FederationInstanceIdentity, 1)
        if identity is not None and identity.canonical_origin != origin:
            abort(503, "Federation origin migration is required")
        payload = _post_to_activity(post, user.username, local_actor.actor_uri)
        return jsonify(payload), 200, {"Content-Type": _AP_CONTENT_TYPE}

    abort(404)
