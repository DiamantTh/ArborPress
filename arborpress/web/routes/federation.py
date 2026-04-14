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

import logging
from datetime import UTC
from urllib.parse import urlparse

import bleach
from quart import Blueprint, abort, jsonify, request
from sqlalchemy import func, select

from arborpress.core.config import get_settings
from arborpress.core.db import get_db_session
from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.federation")
audit = get_audit_logger()

wellknown_bp = Blueprint("wellknown", __name__)
federation_bp = Blueprint("federation", __name__)

_AP_CONTENT_TYPE = "application/activity+json"
_JRD_CONTENT_TYPE = "application/jrd+json"


def _fed() -> dict:
    """Liefert Federation-Settings (Cache oder Defaults)."""
    from arborpress.core.site_settings import get_cached, get_defaults
    return get_cached("federation") or get_defaults("federation")


def _base_url() -> str:
    return get_settings().web.base_url.rstrip("/")


async def _load_public_user(handle: str):
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


def _post_to_activity(post, handle: str) -> dict:
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
        "attributedTo": f"{base}/ap/actor/{handle}",
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


# ---------------------------------------------------------------------------
# §5 /.well-known/webfinger
# ---------------------------------------------------------------------------


@wellknown_bp.get("/.well-known/webfinger")
async def webfinger() -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)

    resource = request.args.get("resource", "")
    if not resource.startswith("acct:"):
        abort(400, "resource must start with acct:")

    acct = resource.removeprefix("acct:")
    handle, _, domain = acct.partition("@")
    handle = handle.lstrip("@")
    base = _base_url()
    base_host = (urlparse(base).hostname or "").lower()
    if not handle or not domain or domain.lower() != base_host:
        abort(404)

    user = await _load_public_user(handle)
    if user is None:
        abort(404)

    jrd = {
        "subject": f"acct:{user.username}@{base_host}",
        "aliases": [f"{base}/@{user.username}"],
        "links": [
            {
                "rel": "self",
                "type": _AP_CONTENT_TYPE,
                "href": f"{base}/ap/actor/{user.username}",
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
async def nodeinfo_discovery() -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)
    base = get_settings().web.base_url.rstrip("/")
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
async def nodeinfo(version: str) -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)
    if version not in ("2.0", "2.1"):
        abort(404)

    user_total = 0
    local_posts = 0
    try:
        from arborpress.models.content import Post, PostStatus, PostVisibility
        from arborpress.models.user import AccountType, User

        async for db in get_db_session():
            user_total = int((await db.execute(select(func.count()).select_from(User).where(
                User.account_type == AccountType.PUBLIC,
                User.is_active == True,  # noqa: E712
            ))).scalar_one())
            local_posts = int((await db.execute(select(func.count()).select_from(Post).where(
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            ))).scalar_one())
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
async def ap_actor(handle: str) -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)

    user = await _load_public_user(handle)
    if user is None:
        abort(404)

    base = _base_url()
    actor: dict = {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        "type": "Person",
        "id": f"{base}/ap/actor/{user.username}",
        "preferredUsername": user.username,
        "name": user.display_name,
        "summary": user.bio or "",
        "url": f"{base}/@{user.username}",
        "inbox": f"{base}/ap/inbox/{user.username}",
        "outbox": f"{base}/ap/outbox/{user.username}",
    }
    if getattr(user, "actor_keypair", None) is not None:
        actor["publicKey"] = {
            "id": getattr(user.actor_keypair, "key_id_url", f"{base}/ap/actor/{user.username}#main-key"),
            "owner": f"{base}/ap/actor/{user.username}",
            "publicKeyPem": user.actor_keypair.public_key_pem,
        }
    return jsonify(actor), 200, {"Content-Type": _AP_CONTENT_TYPE}


@federation_bp.post("/ap/inbox/<handle>")
async def ap_inbox(handle: str) -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") in ("disabled", "outgoing_only"):
        abort(405)

    user = await _load_public_user(handle)
    if user is None:
        abort(404)

    raw = await request.get_json(force=True, silent=True)
    if not raw:
        abort(400)

    if fed.get("require_http_signature", True):
        if not request.headers.get("Signature"):
            abort(401, "HTTP Signature required")
        # Verification is intentionally not claimed until implemented.
        return jsonify({"status": "not_implemented", "detail": "Incoming federation verification not enabled yet"}), 501

    if isinstance(raw.get("content"), str):
        raw["content"] = bleach.clean(
            raw["content"],
            tags=["p", "br", "strong", "em", "a", "ul", "ol", "li"],
            strip=True,
        )

    audit.info("AP inbox received | handle=%s type=%s", handle, raw.get("type"))
    return jsonify({"status": "accepted_stub"}), 202


@federation_bp.get("/ap/outbox/<handle>")
async def ap_outbox(handle: str) -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)
    if fed.get("mode", "disabled") == "inbox_only":
        abort(405)

    user = await _load_public_user(handle)
    if user is None:
        abort(404)

    from arborpress.models.content import Post, PostStatus, PostVisibility

    items: list[dict] = []
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
        items = [_post_to_activity(post, user.username) for post in posts]

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
async def ap_object(obj_id: str) -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)

    from arborpress.models.content import Post, PostStatus, PostVisibility
    from arborpress.models.user import AccountType, User

    async for db in get_db_session():
        stmt = (
            select(Post, User)
            .join(User, User.id == Post.author_id)
            .where(
                (Post.short_id == obj_id) | (Post.id == obj_id) | (Post.ap_object_id == obj_id),
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
                User.account_type == AccountType.PUBLIC,
                User.is_active == True,  # noqa: E712
            )
            .limit(1)
        )
        result = await db.execute(stmt)
        row = result.first()
        if row is None:
            abort(404)
        post, user = row
        payload = _post_to_activity(post, user.username)
        return jsonify(payload), 200, {"Content-Type": _AP_CONTENT_TYPE}

    abort(404)
