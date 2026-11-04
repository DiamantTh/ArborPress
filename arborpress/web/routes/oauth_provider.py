"""ArborPress OAuth 2.0 / OpenID Connect provider endpoints."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlencode, urlsplit

from quart import Blueprint, abort, jsonify, redirect, render_template, request, session
from quart.typing import ResponseReturnValue
from sqlalchemy import CursorResult, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.auth.oauth_server import (
    SUPPORTED_SCOPES,
    TOKEN_REFRESH,
    OAuthError,
    consume_bearer,
    digest,
    issue_code,
    jwks,
    rotate_refresh,
    server_state,
    token_response,
    verify_pkce,
)
from arborpress.core.audit import write_audit_event
from arborpress.core.db import get_db_session
from arborpress.models.oidc import (
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthGrant,
    OAuthIdempotencyKey,
    OAuthToken,
    OAuthTokenFamily,
)
from arborpress.web.security import validate_csrf

if TYPE_CHECKING:
    from arborpress.models.content import Media, Post
    from arborpress.models.user import User

log = logging.getLogger("arborpress.web.oauth_provider")
oauth_provider_bp = Blueprint("oauth_provider", __name__)
_RESOURCE_PAGE_SIZE = 50
_IDEMPOTENCY_TTL = timedelta(hours=24)
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _resource_error(code: str, status: int, message: str | None = None) -> ResponseReturnValue:
    response = jsonify(error={"code": code, "message": message or code.replace("_", " ")})
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


async def _resource_context(
    db: AsyncSession, scope: str
) -> tuple[
    tuple[OAuthToken, OAuthTokenFamily, OAuthGrant, User] | None,
    ResponseReturnValue | None,
]:
    """Resolve bearer-only OAuth identity; browser cookies are never a fallback."""
    from arborpress.models.user import User

    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer ") or len(authorization) > 8192:
        return None, _resource_error("invalid_token", 401)
    consumed = await consume_bearer(db, authorization[7:])
    if consumed is None:
        return None, _resource_error("invalid_token", 401)
    token_row, family, grant = consumed
    if scope not in token_row.scopes.split():
        return None, _resource_error("insufficient_scope", 403)
    user = await db.get(User, family.user_id)
    if user is None or not user.is_active:
        return None, _resource_error("invalid_token", 401)
    return (token_row, family, grant, user), None


def _resource_page() -> tuple[int, int] | None:
    if len(request.args.getlist("page")) > 1 or len(request.args.getlist("per_page")) > 1:
        return None
    try:
        page = int(request.args.get("page", "1"))
        per_page = int(request.args.get("per_page", "20"))
    except ValueError:
        return None
    if page < 1 or page > 1_000_000 or per_page < 1 or per_page > _RESOURCE_PAGE_SIZE:
        return None
    return page, per_page


def _api_post(post: Post, *, detail: bool = False) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": post.short_id,
        "slug": post.slug,
        "title": post.title,
        "excerpt": post.excerpt,
        "status": post.status.value,
        "visibility": post.visibility.value,
        "published_at": post.published_at.isoformat() if post.published_at else None,
        "url": f"/p/{post.slug}",
    }
    if detail:
        item.update(body_markdown=post.body_md, body_html=post.body_html)
    return item


async def _idempotency_record(
    db: AsyncSession,
    *,
    family: OAuthTokenFamily,
    user_id: str,
    resource_type: str,
    request_hash: str,
) -> tuple[OAuthIdempotencyKey | None, str | None]:
    raw_key = request.headers.get("Idempotency-Key")
    if raw_key is None:
        return None, None
    if not _IDEMPOTENCY_KEY_RE.fullmatch(raw_key):
        return None, "invalid_idempotency_key"
    now = datetime.now(UTC).replace(tzinfo=None)
    await db.execute(
        delete(OAuthIdempotencyKey).where(OAuthIdempotencyKey.expires_at <= now)
    )
    key_hash = digest(raw_key)
    existing = await db.scalar(
        select(OAuthIdempotencyKey)
        .where(
            OAuthIdempotencyKey.client_id == family.client_id,
            OAuthIdempotencyKey.user_id == user_id,
            OAuthIdempotencyKey.key_hash == key_hash,
            OAuthIdempotencyKey.expires_at > now,
        )
        .with_for_update()
    )
    if existing is not None:
        if existing.resource_type != resource_type or existing.request_hash != request_hash:
            return existing, "idempotency_conflict"
        return existing, None
    return (
        OAuthIdempotencyKey(
            id=str(uuid.uuid4()),
            client_id=family.client_id,
            user_id=user_id,
            key_hash=key_hash,
            request_hash=request_hash,
            resource_type=resource_type,
            resource_id="pending",
            expires_at=now + _IDEMPOTENCY_TTL,
        ),
        None,
    )


def _api_body_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resource_json(data: Any) -> ResponseReturnValue:
    return cast(ResponseReturnValue, jsonify(data))


def _json_error(error: str, status: int = 400) -> ResponseReturnValue:
    response = jsonify(error=error)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _rate_limit(name: str, limit: str) -> None:
    from arborpress.web.ratelimit import check_rate_limit

    if not check_rate_limit(f"oauth:{name}:{request.remote_addr or 'unknown'}", limit):
        abort(429)


def _authorization_error(redirect_uri: str, error: str, state: str | None) -> ResponseReturnValue:
    values = {"error": error}
    if state is not None:
        values["state"] = state
    parsed = urlsplit(redirect_uri)
    separator = "&" if parsed.query else "?"
    return redirect(f"{redirect_uri}{separator}{urlencode(values)}", code=302)


def _code_redirect(redirect_uri: str, code: str, state: str) -> str:
    parsed = urlsplit(redirect_uri)
    separator = "&" if parsed.query else "?"
    return f"{redirect_uri}{separator}{urlencode({'code': code, 'state': state})}"


def _client_credentials(form: Any) -> tuple[str, str | None]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        if form.get("client_id") or form.get("client_secret"):
            return "", None
        try:
            decoded = base64.b64decode(auth[6:], validate=True).decode()
            client_id, secret = decoded.split(":", 1)
            return client_id, secret
        except ValueError, UnicodeDecodeError:
            return "", None
    return str(form.get("client_id") or ""), (
        str(form.get("client_secret")) if form.get("client_secret") is not None else None
    )


async def _authenticate_client(db: AsyncSession, form: Any) -> OAuthClient:
    client_id, secret = _client_credentials(form)
    client = await db.get(OAuthClient, client_id)
    if client is None or not client.enabled:
        raise OAuthError("invalid_client")
    if client.client_type == "confidential":
        if (
            not secret
            or not client.secret_hash
            or not secrets.compare_digest(digest(secret), client.secret_hash)
        ):
            raise OAuthError("invalid_client")
    elif secret:
        raise OAuthError("invalid_client")
    return client


@oauth_provider_bp.get("/.well-known/openid-configuration")
async def discovery() -> ResponseReturnValue:
    async for db in get_db_session():
        try:
            state = await server_state(db)
            await db.commit()
        except OAuthError:
            abort(404)
        issuer = state.issuer
    response = jsonify(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "userinfo_endpoint": f"{issuer}/oauth/userinfo",
            "revocation_endpoint": f"{issuer}/oauth/revoke",
            "jwks_uri": f"{issuer}/oauth/jwks",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": sorted(SUPPORTED_SCOPES),
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "name",
                "preferred_username",
            ],
        }
    )
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@oauth_provider_bp.get("/oauth/jwks")
async def public_jwks() -> ResponseReturnValue:
    async for db in get_db_session():
        try:
            await server_state(db)
            keys = await jwks(db)
            await db.commit()
        except OAuthError:
            abort(404)
    response = jsonify(keys)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@oauth_provider_bp.get("/oauth/authorize")
async def authorize() -> ResponseReturnValue:
    _rate_limit("authorize", "30/minute")
    # OAuth2Request is Authlib's protocol request abstraction; browser query
    # parameters are independently validated below before a redirect is trusted.
    from authlib.oauth2.rfc6749 import OAuth2Request
    from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload

    payload = {key: request.args.get(key) for key in request.args}
    request_uri = (
        request.url
        if request.url.startswith("https://")
        else "https://oauth.local.invalid/oauth/authorize"
    )
    protocol_request = OAuth2Request(request.method, request_uri, headers=request.headers)
    protocol_request.payload = BasicOAuth2Payload(payload)
    for name in (
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
        "nonce",
    ):
        if len(request.args.getlist(name)) > 1:
            abort(400)
    client_id = str(protocol_request.payload.client_id or "")
    redirect_uri = str(protocol_request.payload.redirect_uri or "")
    state_value = protocol_request.payload.state
    if protocol_request.payload.response_type != "code":
        abort(400)
    raw_scope = str(protocol_request.payload.scope or "")
    scopes = sorted(set(raw_scope.split()))
    challenge = str(request.args.get("code_challenge") or "")
    if (
        not client_id
        or not redirect_uri
        or len(redirect_uri) > 2048
        or not state_value
        or not challenge
        or len(challenge) > 128
        or len(raw_scope) > 512
        or request.args.get("code_challenge_method") != "S256"
        or len(str(state_value)) > 512
    ):
        abort(400)
    async for db in get_db_session():
        try:
            await server_state(db)
        except OAuthError:
            abort(404)
        client = await db.get(OAuthClient, client_id)
        if client is None or not client.enabled:
            abort(400)
        allowed_redirects = json.loads(client.redirect_uris)
        if redirect_uri not in allowed_redirects:
            abort(400)
        allowed_scopes = set(json.loads(client.allowed_scopes)) & SUPPORTED_SCOPES
        if not scopes or not set(scopes) <= allowed_scopes:
            return _authorization_error(redirect_uri, "invalid_scope", str(state_value))
        if client.client_type == "public" and not challenge:
            return _authorization_error(redirect_uri, "invalid_request", str(state_value))
        nonce = request.args.get("nonce")
        if "openid" in scopes and (not nonce or len(nonce) > 256):
            return _authorization_error(redirect_uri, "invalid_request", str(state_value))
        user_id = str(session.get("user_id") or "")
        if session.get("recovery_only"):
            abort(403)
        if not user_id:
            resume = request.full_path
            if not resume.startswith("/oauth/authorize?") or len(resume) > 2048:
                abort(400)
            session["oauth_resume"] = resume
            await db.commit()
            return await render_template("oauth/login_required.html", login_url="/auth/login"), 401
        from arborpress.models.user import User

        user = await db.get(User, user_id)
        if user is None or not user.is_active:
            session.clear()
            return await render_template("oauth/login_required.html", login_url="/auth/login"), 401
        session.pop("oauth_resume", None)
        grant = await db.scalar(
            select(OAuthGrant).where(
                OAuthGrant.user_id == user_id, OAuthGrant.client_id == client_id
            )
        )
        if grant and grant.revoked_at is None and set(grant.scopes.split()) >= set(scopes):
            code = await issue_code(
                db,
                client=client,
                grant=grant,
                user_id=user_id,
                redirect_uri=redirect_uri,
                scopes=scopes,
                challenge=challenge,
                nonce=request.args.get("nonce"),
            )
            await db.commit()
            return redirect(_code_redirect(redirect_uri, code, str(state_value)))
        request_id = secrets.token_urlsafe(32)
        session["oauth_consent"] = {
            "id_hash": digest(request_id),
            "user_id": user_id,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "challenge": challenge,
            "nonce": request.args.get("nonce"),
            "state": str(state_value),
            "created": datetime.now(UTC).timestamp(),
        }
        await db.commit()
        return await render_template(
            "oauth/consent.html",
            client=client,
            scopes=scopes,
            request_id=request_id,
            noindex=True,
        )
    abort(500)


@oauth_provider_bp.post("/oauth/authorize/consent")
async def consent() -> ResponseReturnValue:
    await validate_csrf()
    pending = session.pop("oauth_consent", None)
    if (
        not isinstance(pending, dict)
        or datetime.now(UTC).timestamp() - float(pending.get("created", 0)) > 600
    ):
        abort(400)
    form = await request.form
    if not secrets.compare_digest(
        digest(str(form.get("request_id") or "")), str(pending.get("id_hash"))
    ):
        abort(400)
    if str(session.get("user_id") or "") != str(pending.get("user_id")):
        abort(403)
    redirect_uri = str(pending["redirect_uri"])
    if form.get("decision") != "approve":
        return _authorization_error(redirect_uri, "access_denied", str(pending["state"]))
    async for db in get_db_session():
        client = await db.get(OAuthClient, str(pending["client_id"]))
        if (
            client is None
            or not client.enabled
            or redirect_uri not in json.loads(client.redirect_uris)
        ):
            abort(400)
        user_id = str(pending["user_id"])
        scopes = str(pending["scope"]).split()
        grant = await db.scalar(
            select(OAuthGrant)
            .where(OAuthGrant.user_id == user_id, OAuthGrant.client_id == client.client_id)
            .with_for_update()
        )
        now = datetime.now(UTC).replace(tzinfo=None)
        if grant is None:
            grant = OAuthGrant(
                id=str(uuid.uuid4()),
                user_id=user_id,
                client_id=client.client_id,
                scopes=" ".join(scopes),
            )
            db.add(grant)
        else:
            existing_scopes = set(grant.scopes.split()) if grant.revoked_at is None else set()
            grant.scopes = " ".join(sorted(existing_scopes | set(scopes)))
            grant.revoked_at = None
            grant.granted_at = now
        code = await issue_code(
            db,
            client=client,
            grant=grant,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            challenge=str(pending["challenge"]),
            nonce=pending.get("nonce"),
        )
        await write_audit_event(
            event_type="oauth_grant_created",
            outcome="success",
            actor_id=user_id,
            target_id=client.client_id,
            detail=f"client_id={client.client_id}; scopes={','.join(scopes)}",
            db=db,
        )
        await db.commit()
        return redirect(_code_redirect(redirect_uri, code, str(pending["state"])))
    abort(500)


@oauth_provider_bp.post("/oauth/token")
async def token() -> ResponseReturnValue:
    _rate_limit("token", "20/minute")
    form = await request.form
    grant_type = str(form.get("grant_type") or "")
    async for db in get_db_session():
        try:
            client = await _authenticate_client(db, form)
            await server_state(db)
            if grant_type == "authorization_code":
                code = str(form.get("code") or "")
                redirect_uri = str(form.get("redirect_uri") or "")
                verifier = str(form.get("code_verifier") or "")
                row = await db.scalar(
                    select(OAuthAuthorizationCode)
                    .where(OAuthAuthorizationCode.code_hash == digest(code))
                    .with_for_update()
                )
                if row is None or row.client_id != client.client_id:
                    raise OAuthError("invalid_grant")
                if row.consumed_at is not None or row.expires_at <= datetime.now(UTC).replace(
                    tzinfo=None
                ):
                    raise OAuthError("invalid_grant")
                if redirect_uri != row.redirect_uri or not verify_pkce(
                    verifier, row.code_challenge
                ):
                    raise OAuthError("invalid_grant")
                matched = cast(CursorResult[Any], await db.execute(
                    update(OAuthAuthorizationCode)
                    .where(
                        OAuthAuthorizationCode.id == row.id,
                        OAuthAuthorizationCode.consumed_at.is_(None),
                    )
                    .values(consumed_at=datetime.now(UTC).replace(tzinfo=None))
                ))
                if matched.rowcount != 1:
                    raise OAuthError("invalid_grant")
                grant = await db.get(OAuthGrant, row.grant_id)
                user = await db.get(
                    __import__("arborpress.models.user", fromlist=["User"]).User, row.user_id
                )
                if (
                    grant is None
                    or grant.revoked_at is not None
                    or user is None
                    or not user.is_active
                ):
                    raise OAuthError("invalid_grant")
                body = await token_response(
                    db,
                    user_id=row.user_id,
                    client_id=client.client_id,
                    grant=grant,
                    scopes=row.scopes,
                    nonce=row.nonce,
                )
            elif grant_type == "refresh_token":
                if client.client_type == "public" and not form.get("client_id"):
                    raise OAuthError("invalid_client")
                requested_scope = str(form.get("scope") or "").split()
                body = await rotate_refresh(
                    db,
                    str(form.get("refresh_token") or ""),
                    client.client_id,
                    requested_scope or None,
                )
                if body.get("scope") and not set(str(body["scope"]).split()) <= set(
                    json.loads(client.allowed_scopes)
                ):
                    raise OAuthError("invalid_grant")
            else:
                raise OAuthError("unsupported_grant_type")
            await db.commit()
        except OAuthError as exc:
            await db.rollback()
            return _json_error(str(exc), 401 if str(exc) == "invalid_client" else 400)
    response = jsonify(body)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@oauth_provider_bp.post("/oauth/revoke")
async def revoke() -> ResponseReturnValue:
    _rate_limit("revoke", "20/minute")
    form = await request.form
    async for db in get_db_session():
        try:
            client = await _authenticate_client(db, form)
        except OAuthError:
            return _json_error("invalid_client", 401)
        raw = str(form.get("token") or "")
        row = await db.scalar(select(OAuthToken).where(OAuthToken.token_hash == digest(raw)))
        if row:
            family = await db.get(OAuthTokenFamily, row.family_id)
            if family and family.client_id == client.client_id:
                now = datetime.now(UTC).replace(tzinfo=None)
                if row.token_type == TOKEN_REFRESH:
                    family.revoked_at = now
                    await db.execute(
                        update(OAuthToken)
                        .where(OAuthToken.family_id == family.id)
                        .values(revoked_at=now)
                    )
                else:
                    row.revoked_at = now
                await write_audit_event(
                    event_type="oauth_token_revoked",
                    outcome="success",
                    actor_id=family.user_id,
                    target_id=client.client_id,
                    detail=f"client_id={client.client_id}; token_type={row.token_type}",
                    db=db,
                )
        await db.commit()
        return ("", 200, {"Cache-Control": "no-store"})
    return _json_error("server_error", 500)


@oauth_provider_bp.get("/oauth/userinfo")
@oauth_provider_bp.get("/api/v1/oauth/me")
async def userinfo() -> ResponseReturnValue:
    raw = request.headers.get("Authorization", "")
    if not raw.startswith("Bearer ") or len(raw) > 8192:
        return _json_error("invalid_token", 401)
    async for db in get_db_session():
        consumed = await consume_bearer(db, raw[7:])
        if consumed is None:
            return _json_error("invalid_token", 401)
        token_row, family, grant = consumed
        scopes = set(token_row.scopes.split())
        is_user_profile = request.path == "/api/v1/oauth/me"
        required_scope = "profile" if is_user_profile else "openid"
        if required_scope not in scopes:
            return _json_error("insufficient_scope", 403)
        from arborpress.models.user import User

        user = await db.get(User, family.user_id)
        from arborpress.models.oidc import OIDCSubject

        subject = await db.scalar(
            select(OIDCSubject.subject).where(OIDCSubject.user_id == family.user_id)
        )
        if subject is None:
            subject = await __import__(
                "arborpress.auth.oauth_server", fromlist=["stable_subject"]
            ).stable_subject(db, family.user_id)
        if is_user_profile:
            result = {
                "username": user.username if user else None,
                "display_name": user.display_name if user else None,
                "bio": user.bio if user else None,
                "website": user.website if user else None,
            }
        else:
            result = {"sub": subject}
            if "profile" in scopes and user:
                result.update(name=user.display_name, preferred_username=user.username)
        await db.commit()
        response = jsonify(result)
        response.headers["Cache-Control"] = "no-store"
        return response
    abort(500)


@oauth_provider_bp.get("/api/v1/oauth/posts")
async def oauth_posts() -> ResponseReturnValue:
    page_data = _resource_page()
    if page_data is None:
        return _resource_error("invalid_pagination", 400)
    page, per_page = page_data
    async for db in get_db_session():
        context, error = await _resource_context(db, "posts:read")
        if error is not None:
            return error
        from arborpress.models.content import Post, PostStatus, PostVisibility

        base = (Post.status == PostStatus.PUBLISHED) & (Post.visibility == PostVisibility.PUBLIC)
        total = int(await db.scalar(select(func.count(Post.id)).where(base)) or 0)
        posts = list(
            (
                await db.scalars(
                    select(Post)
                    .where(base)
                    .order_by(Post.published_at.desc(), Post.id.asc())
                    .offset((page - 1) * per_page)
                    .limit(per_page)
                )
            ).all()
        )
        response = jsonify({
            "items": [_api_post(post) for post in posts],
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": max(1, (total + per_page - 1) // per_page),
        })
        response.headers["Cache-Control"] = "no-store"
        return response
    return _resource_error("server_error", 500)


@oauth_provider_bp.get("/api/v1/oauth/posts/<slug>")
async def oauth_post_detail(slug: str) -> ResponseReturnValue:
    async for db in get_db_session():
        context, error = await _resource_context(db, "posts:read")
        if error is not None:
            return error
        from arborpress.models.content import Post, PostStatus, PostVisibility

        post = await db.scalar(
            select(Post).where(
                Post.slug == slug,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
        )
        if post is None:
            return _resource_error("not_found", 404)
        response = jsonify(_api_post(post, detail=True))
        response.headers["Cache-Control"] = "no-store"
        return response
    return _resource_error("server_error", 500)


@oauth_provider_bp.post("/api/v1/oauth/posts")
async def oauth_post_create() -> ResponseReturnValue:
    _rate_limit("resource-post-write", "30/minute")
    raw_body = await request.get_data()
    raw_body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body
    if len(raw_body) > 256 * 1024:
        return _resource_error("request_too_large", 413)
    data = await request.get_json(silent=True)
    if not isinstance(data, dict):
        return _resource_error("invalid_json", 400)
    if set(data) - {"title", "slug", "body", "excerpt", "lang"}:
        return _resource_error("unsupported_field", 400)
    async for db in get_db_session():
        context, error = await _resource_context(db, "posts:write")
        if error is not None:
            return error
        assert context is not None
        _token, family, _grant, user = context
        from arborpress.auth.permissions import can
        from arborpress.core.markdown import render_md_async
        from arborpress.core.validators import is_valid_slug, strip_control_chars
        from arborpress.models.content import Post, PostStatus, PostVisibility

        if not await can(db, user, "content.create"):
            return _resource_error("forbidden", 403)
        title = strip_control_chars(str(data.get("title") or "")).strip()
        slug = strip_control_chars(str(data.get("slug") or "")).strip().lower()
        body = str(data.get("body") or "")
        if not title or len(title) > 512:
            return _resource_error("invalid_title", 400)
        if not is_valid_slug(slug):
            return _resource_error("invalid_slug", 400)
        if len(body) > 500_000:
            return _resource_error("content_too_large", 413)
        receipt, receipt_error = await _idempotency_record(
            db,
            family=family,
            user_id=str(user.id),
            resource_type="post",
            request_hash=_api_body_hash(raw_body_bytes),
        )
        if receipt_error:
            status = 409 if receipt_error == "idempotency_conflict" else 400
            return _resource_error(receipt_error, status)
        if receipt is not None and receipt.resource_id != "pending":
            existing = await db.get(Post, receipt.resource_id)
            if existing is not None:
                await db.commit()
                return jsonify(_api_post(existing, detail=True)), 200
        if await db.scalar(select(Post.id).where(Post.slug == slug)):
            return _resource_error("slug_conflict", 409)
        post = Post(
            id=str(uuid.uuid4()),
            short_id=secrets.token_urlsafe(8)[:10],
            author_id=str(user.id),
            slug=slug,
            title=title,
            body_md=body,
            body_html=await render_md_async(body),
            excerpt=str(data.get("excerpt") or "").strip()[:400] or None,
            status=PostStatus.DRAFT,
            visibility=PostVisibility.PUBLIC,
            lang=str(data["lang"])[:8] if data.get("lang") else None,
            reading_time_min=Post.calc_reading_time(body),
            published_at=None,
        )
        from arborpress.content.authors import ensure_primary_author

        db.add(post)
        await db.flush()
        await ensure_primary_author(
            db, post=post, user_id=str(user.id), actor_user_id=str(user.id)
        )
        if receipt is not None:
            receipt.resource_id = str(post.id)
            db.add(receipt)
        await write_audit_event(
            event_type="oauth_resource_post_created",
            outcome="success",
            actor_id=str(user.id),
            target_id=str(post.id),
            detail=f"client_id={family.client_id}",
            db=db,
        )
        await db.commit()
        return jsonify(_api_post(post, detail=True)), 201
    return _resource_error("server_error", 500)


@oauth_provider_bp.patch("/api/v1/oauth/posts/<slug>")
@oauth_provider_bp.put("/api/v1/oauth/posts/<slug>")
async def oauth_post_update(slug: str) -> ResponseReturnValue:
    _rate_limit("resource-post-write", "30/minute")
    raw_body = await request.get_data()
    raw_body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body
    if len(raw_body) > 256 * 1024:
        return _resource_error("request_too_large", 413)
    data = await request.get_json(silent=True)
    if not isinstance(data, dict) or not data or set(data) - {"title", "body", "excerpt"}:
        return _resource_error("invalid_fields", 400)
    async for db in get_db_session():
        context, error = await _resource_context(db, "posts:write")
        if error is not None:
            return error
        assert context is not None
        _token, family, _grant, user = context
        from arborpress.auth.permissions import can
        from arborpress.core.markdown import render_md_async
        from arborpress.core.validators import strip_control_chars
        from arborpress.models.content import Post, PostRevision

        post = await db.scalar(select(Post).where(Post.slug == slug).with_for_update())
        if post is None:
            return _resource_error("not_found", 404)
        if not await can(db, user, "content.edit", post):
            return _resource_error("forbidden", 403)
        old_title, old_body, old_excerpt = post.title, post.body_md, post.excerpt
        if "title" in data:
            title = strip_control_chars(str(data["title"] or "")).strip()
            if not title or len(title) > 512:
                return _resource_error("invalid_title", 400)
            post.title = title
        if "body" in data:
            body = str(data["body"] or "")
            if len(body) > 500_000:
                return _resource_error("content_too_large", 413)
            post.body_md = body
            post.body_html = await render_md_async(body)
            post.reading_time_min = Post.calc_reading_time(body)
        if "excerpt" in data:
            post.excerpt = strip_control_chars(str(data["excerpt"] or "")).strip()[:400] or None
        content_changed = (post.title, post.body_md, post.excerpt) != (
            old_title,
            old_body,
            old_excerpt,
        )
        if (post.title, post.body_md) != (old_title, old_body):
            previous = int(
                await db.scalar(
                    select(func.max(PostRevision.rev_number)).where(PostRevision.post_id == post.id)
                )
                or 0
            )
            db.add(
                PostRevision(
                    id=str(uuid.uuid4()),
                    post_id=str(post.id),
                    rev_number=previous + 1,
                    title=old_title,
                    body_md=old_body,
                    diff_to_prev=PostRevision.make_diff(old_body, post.body_md),
                    changed_by_id=str(user.id),
                    change_summary="OAuth API edit",
                )
            )
        receipt, receipt_error = await _idempotency_record(
            db,
            family=family,
            user_id=str(user.id),
            resource_type="post_update",
            request_hash=_api_body_hash(raw_body_bytes + b"\0" + slug.encode()),
        )
        if receipt_error:
            await db.rollback()
            status = 409 if receipt_error == "idempotency_conflict" else 400
            return _resource_error(receipt_error, status)
        if receipt is not None and receipt.resource_id != "pending":
            resource_id = receipt.resource_id
            await db.rollback()
            post = await db.get(Post, resource_id)
            if post:
                return _resource_json(_api_post(post, detail=True))
            return _resource_error("not_found", 404)
        if receipt is not None:
            receipt.resource_id = str(post.id)
            db.add(receipt)
        if (
            content_changed
            and post.status.value == "published"
            and post.visibility.value == "public"
        ):
            await db.flush()
            from arborpress.federation.services import enqueue_post_activity

            await enqueue_post_activity(
                db,
                post_id=str(post.id),
                activity_type="Update",
                source_revision=str(post.updated_at or uuid.uuid4()),
            )
        await write_audit_event(
            event_type="oauth_resource_post_updated",
            outcome="success",
            actor_id=str(user.id),
            target_id=str(post.id),
            detail=f"client_id={family.client_id}",
            db=db,
        )
        await db.commit()
        return _resource_json(_api_post(post, detail=True))
    return _resource_error("server_error", 500)


@oauth_provider_bp.get("/api/v1/oauth/comments")
async def oauth_comments_list() -> ResponseReturnValue:
    page_data = _resource_page()
    if page_data is None:
        return _resource_error("invalid_pagination", 400)
    page, per_page = page_data
    async for db in get_db_session():
        context, error = await _resource_context(db, "comments:read")
        if error is not None:
            return error
        from arborpress.models.content import (
            Comment,
            CommentStatus,
            Post,
            PostStatus,
            PostVisibility,
        )

        base = (
            (Comment.status == CommentStatus.APPROVED)
            & (Post.status == PostStatus.PUBLISHED)
            & (Post.visibility == PostVisibility.PUBLIC)
        )
        total = int(await db.scalar(select(func.count(Comment.id)).join(Post).where(base)) or 0)
        rows = (
            await db.execute(
                select(Comment, Post.slug)
                .join(Post)
                .where(base)
                .order_by(Comment.created_at.desc(), Comment.id.asc())
                .offset((page - 1) * per_page)
                .limit(per_page)
            )
        ).all()
        items = [
            {
                "id": comment.id,
                "post": slug,
                "author": comment.author_name,
                "body": comment.body,
                "created_at": comment.created_at.isoformat() if comment.created_at else None,
                "parent_id": comment.parent_id,
                "edited": comment.is_edited,
            }
            for comment, slug in rows
        ]
        return _resource_json(
            {"items": items, "page": page, "per_page": per_page, "total": total}
        )
    return _resource_error("server_error", 500)


@oauth_provider_bp.post("/api/v1/oauth/posts/<slug>/comments")
async def oauth_comment_create(slug: str) -> ResponseReturnValue:
    _rate_limit("resource-comment-write", "30/minute")
    raw_body = await request.get_data()
    raw_body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body
    if len(raw_body) > 64 * 1024:
        return _resource_error("request_too_large", 413)
    data = await request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {"body", "parent_id"}:
        return _resource_error("invalid_fields", 400)
    async for db in get_db_session():
        context, error = await _resource_context(db, "comments:write")
        if error is not None:
            return error
        assert context is not None
        _token, family, _grant, user = context
        from arborpress.auth.permissions import can
        from arborpress.comments import CommentPolicyError, create_comment, resolve_comment_policy
        from arborpress.core.site_settings import get_section
        from arborpress.models.content import Comment, Post, PostStatus, PostVisibility

        post = await db.scalar(
            select(Post).where(
                Post.slug == slug,
                Post.status == PostStatus.PUBLISHED,
                Post.visibility == PostVisibility.PUBLIC,
            )
        )
        if post is None:
            return _resource_error("not_found", 404)
        if not await can(db, user, "comments.create", post):
            return _resource_error("forbidden", 403)
        body = str(data.get("body") or "")
        if len(body) > 10_000:
            return _resource_error("content_too_large", 413)
        receipt, receipt_error = await _idempotency_record(
            db,
            family=family,
            user_id=str(user.id),
            resource_type="comment",
            request_hash=_api_body_hash(raw_body_bytes),
        )
        if receipt_error:
            await db.rollback()
            status = 409 if receipt_error == "idempotency_conflict" else 400
            return _resource_error(receipt_error, status)
        if receipt is not None and receipt.resource_id != "pending":
            comment = await db.get(Comment, receipt.resource_id)
            if comment is not None:
                await db.commit()
                return jsonify({"id": comment.id, "status": comment.status.value}), 200
        policy = resolve_comment_policy(post, await get_section("comments", db))
        try:
            created = await create_comment(
                db,
                post=post,
                policy=policy,
                author_name=user.display_name or user.username,
                author_email=None,
                author_user=user,
                body=body,
                parent_id=str(data["parent_id"]) if data.get("parent_id") else None,
                ip_address=None,
                user_agent="",
            )
        except CommentPolicyError:
            await db.rollback()
            return _resource_error(
                "comment_rejected", 400, "The comment does not meet site policy."
            )
        if receipt is not None:
            receipt.resource_id = str(created.comment.id)
            db.add(receipt)
        await db.commit()
        return cast(
            ResponseReturnValue,
            (jsonify({"id": created.comment.id, "status": created.comment.status.value}), 201),
        )
    return _resource_error("server_error", 500)


@oauth_provider_bp.patch("/api/v1/oauth/comments/<comment_id>")
async def oauth_comment_update(comment_id: str) -> ResponseReturnValue:
    _rate_limit("resource-comment-write", "30/minute")
    data = await request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) != {"body"}:
        return _resource_error("invalid_fields", 400)
    async for db in get_db_session():
        context, error = await _resource_context(db, "comments:write")
        if error is not None:
            return error
        assert context is not None
        _token, _family, _grant, user = context
        from arborpress.comments import (
            CommentPolicyError,
            create_comment_revision,
            resolve_comment_policy,
        )
        from arborpress.core.site_settings import get_section
        from arborpress.models.content import Comment, Post

        comment = await db.get(Comment, comment_id)
        post = await db.get(Post, comment.post_id) if comment else None
        if comment is None or post is None or comment.author_user_id != str(user.id):
            return _resource_error("not_found", 404)
        policy = resolve_comment_policy(post, await get_section("comments", db))
        try:
            revision = await create_comment_revision(
                db, comment_id=comment_id, actor_user=user, body=str(data["body"]), policy=policy
            )
        except CommentPolicyError:
            await db.rollback()
            return _resource_error(
                "comment_edit_rejected", 403, "The comment revision does not meet site policy."
            )
        await db.commit()
        return _resource_json(
            {
                "id": comment.id,
                "revision": revision.revision_number,
                "status": revision.status.value,
            }
        )
    return _resource_error("server_error", 500)


@oauth_provider_bp.get("/api/v1/oauth/media")
async def oauth_media_list() -> ResponseReturnValue:
    page_data = _resource_page()
    if page_data is None:
        return _resource_error("invalid_pagination", 400)
    page, per_page = page_data
    async for db in get_db_session():
        context, error = await _resource_context(db, "media:read")
        if error is not None:
            return error
        assert context is not None
        _token, _family, _grant, user = context
        from arborpress.models.content import Media

        base = Media.uploader_id == str(user.id)
        total = int(await db.scalar(select(func.count(Media.id)).where(base)) or 0)
        rows = list(
            (
                await db.scalars(
                    select(Media)
                    .where(base)
                    .order_by(Media.uploaded_at.desc(), Media.id.asc())
                    .offset((page - 1) * per_page)
                    .limit(per_page)
                )
            ).all()
        )
        return _resource_json(
            {
                "items": [_api_media(item) for item in rows],
                "page": page,
                "per_page": per_page,
                "total": total,
            }
        )
    return _resource_error("server_error", 500)


@oauth_provider_bp.get("/api/v1/oauth/media/<media_id>")
async def oauth_media_detail(media_id: str) -> ResponseReturnValue:
    async for db in get_db_session():
        context, error = await _resource_context(db, "media:read")
        if error is not None:
            return error
        assert context is not None
        _token, _family, _grant, user = context
        from arborpress.models.content import Media

        item = await db.scalar(
            select(Media).where(Media.id == media_id, Media.uploader_id == str(user.id))
        )
        if item is None:
            return _resource_error("not_found", 404)
        return _resource_json(_api_media(item))
    return _resource_error("server_error", 500)


def _api_media(item: Media) -> dict[str, Any]:
    from arborpress.core.config import get_settings

    return {
        "id": item.id,
        "url": f"{get_settings().web.base_url.rstrip('/')}/media/{item.storage_path}",
        "mime_type": item.mime_type,
        "size_bytes": item.size_bytes,
        "width": item.width,
        "height": item.height,
        "alt_text": item.alt_text,
    }


@oauth_provider_bp.post("/api/v1/oauth/media")
async def oauth_media_upload() -> ResponseReturnValue:
    _rate_limit("resource-media-write", "10/minute")
    from arborpress.media.service import MAX_MEDIA_BYTES, MediaUploadError, store_media_upload

    async for db in get_db_session():
        context, error = await _resource_context(db, "media:write")
        if error is not None:
            return error
        assert context is not None
        _token, family, _grant, user = context
        files = await request.files
        form = await request.form
        upload = files.get("file")
        if upload is None:
            return _resource_error("missing_file", 400)
        data = upload.read(MAX_MEDIA_BYTES + 1)
        if len(data) > MAX_MEDIA_BYTES:
            return _resource_error("media_size_limit", 413)
        from arborpress.auth.permissions import can
        from arborpress.models.content import Media

        if not await can(db, user, "media.upload"):
            return _resource_error("forbidden", 403)
        request_hash = _api_body_hash(
            data
            + b"\0"
            + (upload.content_type or "").encode()
            + b"\0"
            + (form.get("alt_text") or "").encode()
        )
        receipt, receipt_error = await _idempotency_record(
            db,
            family=family,
            user_id=str(user.id),
            resource_type="media",
            request_hash=request_hash,
        )
        if receipt_error:
            status = 409 if receipt_error == "idempotency_conflict" else 400
            return _resource_error(receipt_error, status)
        if receipt is not None and receipt.resource_id != "pending":
            existing = await db.get(Media, receipt.resource_id)
            if existing is not None:
                await db.commit()
                return jsonify(_api_media(existing)), 200
        try:
            item = await store_media_upload(
                db,
                uploader_id=str(user.id),
                filename=upload.filename or "upload",
                content_type=upload.content_type or "",
                data=data,
                alt_text=form.get("alt_text"),
            )
        except MediaUploadError as exc:
            await db.rollback()
            return _resource_error(str(exc), 413 if "limit" in str(exc) else 415)
        if receipt is not None:
            receipt.resource_id = str(item.id)
            db.add(receipt)
        await write_audit_event(
            event_type="oauth_resource_media_uploaded",
            outcome="success",
            actor_id=str(user.id),
            target_id=str(item.id),
            detail=f"client_id={family.client_id};size={item.size_bytes}",
            db=db,
        )
        await db.commit()
        return jsonify(_api_media(item)), 201
    return _resource_error("server_error", 500)


@oauth_provider_bp.get("/account/authorized-apps")
async def authorized_apps() -> ResponseReturnValue:
    user_id = str(session.get("user_id") or "")
    if not user_id or session.get("recovery_only"):
        return redirect("/auth/login")
    async for db in get_db_session():
        from arborpress.auth.sessions import refresh_session_identity

        if await refresh_session_identity(db, session) is None:
            session.clear()
            abort(401)
        rows = (
            await db.execute(
                select(OAuthGrant, OAuthClient)
                .join(OAuthClient, OAuthClient.client_id == OAuthGrant.client_id)
                .where(OAuthGrant.user_id == user_id, OAuthGrant.revoked_at.is_(None))
            )
        ).all()
        return await render_template("oauth/authorized_apps.html", entries=rows, noindex=True)
    abort(500)


@oauth_provider_bp.post("/account/authorized-apps/<grant_id>/revoke")
async def revoke_grant(grant_id: str) -> ResponseReturnValue:
    await validate_csrf()
    user_id = str(session.get("user_id") or "")
    if not user_id or session.get("recovery_only"):
        abort(401)
    async for db in get_db_session():
        from arborpress.auth.sessions import refresh_session_identity

        if await refresh_session_identity(db, session) is None:
            session.clear()
            abort(401)
        grant = await db.get(OAuthGrant, grant_id, with_for_update=True)
        if grant is None or grant.user_id != user_id:
            abort(404)
        now = datetime.now(UTC).replace(tzinfo=None)
        grant.revoked_at = now
        families = (
            (
                await db.execute(
                    select(OAuthTokenFamily).where(OAuthTokenFamily.grant_id == grant.id)
                )
            )
            .scalars()
            .all()
        )
        for family in families:
            family.revoked_at = now
            await db.execute(
                update(OAuthToken).where(OAuthToken.family_id == family.id).values(revoked_at=now)
            )
        await write_audit_event(
            event_type="oauth_grant_revoked",
            outcome="success",
            actor_id=user_id,
            target_id=grant.client_id,
            detail=f"client_id={grant.client_id}; source=user",
            db=db,
        )
        await db.commit()
        return redirect("/account/authorized-apps")
    abort(500)
