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

import bleach
from quart import Blueprint, abort, jsonify, request

from arborpress.core.config import get_settings
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

    # acct:handle@domain
    handle = resource.removeprefix("acct:").split("@")[0].lstrip("@")
    # TODO: User-Lookup, OPERATIONAL-Accounts → 404
    # §4: Operational accounts must not be discoverable via WebFinger
    base = get_settings().web.base_url.rstrip("/")

    jrd = {
        "subject": resource,
        "links": [
            {
                "rel": "self",
                "type": _AP_CONTENT_TYPE,
                "href": f"{base}/ap/actor/{handle}",
            }
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
    return jsonify(
        {
            "version": version,
            "software": {"name": "arborpress", "version": "0.1.0"},
            "protocols": ["activitypub"],
            "usage": {"users": {"total": 0}, "localPosts": 0},
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

    # TODO: User-Lookup; §4: Operational-Accounts → 404
    base = get_settings().web.base_url.rstrip("/")
    actor = {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        "type": "Person",
        "id": f"{base}/ap/actor/{handle}",
        "preferredUsername": handle,
        "inbox": f"{base}/ap/inbox/{handle}",
        "outbox": f"{base}/ap/outbox/{handle}",
        # TODO: publicKey
    }
    return jsonify(actor), 200, {"Content-Type": _AP_CONTENT_TYPE}


@federation_bp.post("/ap/inbox/<handle>")
async def ap_inbox(handle: str) -> tuple:
    fed = _fed()
    # §5 inbox_only erlaubt empfangen ohne outbox
    if fed.get("mode", "disabled") in ("disabled", "outgoing_only"):
        abort(405)

    raw = await request.get_json(force=True, silent=True)
    if not raw:
        abort(400)

    # §10 / §5: Federierter Inhalt wird sanitisiert
    if isinstance(raw.get("content"), str):
        raw["content"] = bleach.clean(
            raw["content"],
            tags=["p", "br", "strong", "em", "a", "ul", "ol", "li"],
            strip=True,
        )

    audit.info("AP inbox received | handle=%s type=%s", handle, raw.get("type"))
    # TODO: Inbox processing (verify HTTP Signature, process activity)
    return jsonify({"status": "accepted"}), 202


@federation_bp.get("/ap/outbox/<handle>")
async def ap_outbox(handle: str) -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)
    if fed.get("mode", "disabled") == "inbox_only":
        abort(405)

    base = get_settings().web.base_url.rstrip("/")
    outbox = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "OrderedCollection",
        "id": f"{base}/ap/outbox/{handle}",
        "totalItems": 0,
        "orderedItems": [],  # TODO: Posts laden
    }
    return jsonify(outbox), 200, {"Content-Type": _AP_CONTENT_TYPE}


@federation_bp.get("/ap/object/<obj_id>")
async def ap_object(obj_id: str) -> tuple:
    fed = _fed()
    if fed.get("mode", "disabled") == "disabled":
        abort(404)
    # TODO: ap_object_id lookup in posts
    abort(404)
