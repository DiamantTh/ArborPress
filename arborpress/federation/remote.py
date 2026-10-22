"""Validated remote actor discovery and expiring actor/key cache."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import bleach  # type: ignore[import-untyped]
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.federation.policy import domain_allowed
from arborpress.federation.security import (
    FederationFetchError,
    fetch_remote,
    normalize_domain,
    validate_remote_url_syntax,
)
from arborpress.models.federation import RemoteActor, RemoteActorKey

ACTOR_TTL = timedelta(hours=1)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _clean_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    return bleach.clean(value, tags=[], strip=True)[:limit] or None


async def fetch_remote_actor(
    db: AsyncSession,
    actor_uri: str,
    settings: dict[str, Any],
    *,
    force: bool = False,
    signing_actor_id: str | None = None,
) -> RemoteActor:
    parts = urlsplit(actor_uri)
    try:
        host, _ = validate_remote_url_syntax(actor_uri)
    except FederationFetchError:
        raise
    if parts.fragment or parts.query or not await domain_allowed(db, host, settings):
        raise FederationFetchError("domain_not_allowed")
    normalized = f"https://{host}{parts.path or '/'}"
    if parts.port not in (None, 443):
        normalized = f"https://{host}:{parts.port}{parts.path or '/'}"
    result = await db.execute(select(RemoteActor).where(RemoteActor.actor_uri == normalized))
    cached = result.scalar_one_or_none()
    now = _utcnow()
    if cached and cached.expires_at > now and not force:
        return cached

    try:
        response = await fetch_remote(normalized, db=db, signing_actor_id=signing_actor_id)
    except FederationFetchError as exc:
        if cached is not None and str(exc) in {"http_status_404", "http_status_410"}:
            cached.health_state = "gone"
            cached.last_error = str(exc)
            cached.fetched_at = now
            cached.expires_at = now + ACTOR_TTL
            await db.flush()
        raise
    try:
        document = json.loads(response.body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise FederationFetchError("actor_json_invalid") from exc
    if not isinstance(document, dict) or document.get("id") != normalized:
        raise FederationFetchError("actor_identity_mismatch")
    actor_type = document.get("type")
    inbox = document.get("inbox")
    if actor_type not in {"Person", "Service", "Organization", "Application", "Group"}:
        raise FederationFetchError("actor_type_invalid")
    if not isinstance(inbox, str):
        raise FederationFetchError("actor_inbox_missing")
    try:
        inbox_host, _ = validate_remote_url_syntax(inbox)
    except FederationFetchError as exc:
        raise FederationFetchError("actor_inbox_invalid") from exc
    if not inbox_host or not await domain_allowed(db, inbox_host, settings):
        raise FederationFetchError("actor_inbox_domain_not_allowed")

    shared_inbox = None
    endpoints = document.get("endpoints")
    if isinstance(endpoints, dict) and isinstance(endpoints.get("sharedInbox"), str):
        candidate = endpoints["sharedInbox"]
        try:
            candidate_host, _ = validate_remote_url_syntax(candidate)
        except FederationFetchError:
            candidate_host = ""
        if candidate_host and await domain_allowed(db, candidate_host, settings):
            shared_inbox = candidate[:2048]

    if cached is None:
        cached = RemoteActor(
            actor_uri=normalized,
            domain=normalize_domain(parts.hostname or ""),
            actor_type=actor_type,
            preferred_username=_clean_text(document.get("preferredUsername"), 256),
            display_name=_clean_text(document.get("name"), 512),
            summary_text=_clean_text(document.get("summary"), 4000),
            inbox_uri=inbox[:2048],
            shared_inbox_uri=shared_inbox,
            fetched_at=now,
            expires_at=now + ACTOR_TTL,
            etag=response.headers.get("etag"),
            modified=response.headers.get("last-modified"),
        )
        db.add(cached)
    else:
        cached.actor_type = actor_type
        cached.preferred_username = _clean_text(document.get("preferredUsername"), 256)
        cached.display_name = _clean_text(document.get("name"), 512)
        cached.summary_text = _clean_text(document.get("summary"), 4000)
        cached.inbox_uri = inbox[:2048]
        cached.shared_inbox_uri = shared_inbox
        cached.fetched_at = now
        cached.expires_at = now + ACTOR_TTL
        cached.etag = response.headers.get("etag")
        cached.modified = response.headers.get("last-modified")
        cached.health_state = "active"
        cached.last_error = None
    await db.flush()

    keys = document.get("publicKey", [])
    if isinstance(keys, dict):
        keys = [keys]
    if isinstance(keys, list):
        for key in keys[:8]:
            if not isinstance(key, dict):
                continue
            key_id = key.get("id")
            owner = key.get("owner")
            pem = key.get("publicKeyPem")
            if not isinstance(key_id, str) or owner != normalized or not isinstance(pem, str):
                continue
            if urlsplit(key_id).fragment == "" or key_id.split("#", 1)[0] != normalized:
                continue
            key_result = await db.execute(
                select(RemoteActorKey).where(RemoteActorKey.key_id == key_id)
            )
            cached_key = key_result.scalar_one_or_none()
            if cached_key is None:
                db.add(
                    RemoteActorKey(
                        remote_actor_id=cached.id,
                        key_id=key_id,
                        owner_uri=normalized,
                        public_key_pem=pem[:8192],
                        fetched_at=now,
                        expires_at=now + ACTOR_TTL,
                    )
                )
            else:
                cached_key.remote_actor_id = cached.id
                cached_key.owner_uri = normalized
                cached_key.public_key_pem = pem[:8192]
                cached_key.fetched_at = now
                cached_key.expires_at = now + ACTOR_TTL
    await db.flush()
    return cached


async def resolve_remote_key(
    db: AsyncSession,
    key_id: str,
    settings: dict[str, Any],
    *,
    force_refresh: bool = False,
) -> tuple[str, str] | None:
    """Return (owner actor URI, PEM), fetching only through the guarded layer."""
    parts = urlsplit(key_id)
    if not parts.fragment or parts.query or not parts.hostname:
        return None
    actor_uri = key_id.split("#", 1)[0]
    if not await domain_allowed(db, parts.hostname, settings):
        return None
    result = await db.execute(select(RemoteActorKey).where(RemoteActorKey.key_id == key_id))
    key = result.scalar_one_or_none()
    now = _utcnow()
    if key and key.expires_at > now and not force_refresh:
        return key.owner_uri, key.public_key_pem
    try:
        actor = await fetch_remote_actor(db, actor_uri, settings, force=force_refresh)
    except FederationFetchError:
        return None
    result = await db.execute(select(RemoteActorKey).where(RemoteActorKey.key_id == key_id))
    key = result.scalar_one_or_none()
    if key is None or key.remote_actor_id != actor.id or key.owner_uri != actor.actor_uri:
        return None
    return key.owner_uri, key.public_key_pem


def new_cache_id() -> str:
    return str(uuid.uuid4())
