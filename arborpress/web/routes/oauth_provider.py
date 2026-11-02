"""ArborPress OAuth 2.0 / OpenID Connect provider endpoints."""

from __future__ import annotations

import base64
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode, urlsplit

from quart import Blueprint, abort, jsonify, redirect, render_template, request, session
from quart.typing import ResponseReturnValue
from sqlalchemy import CursorResult, select, update
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
    OAuthToken,
    OAuthTokenFamily,
)
from arborpress.web.security import validate_csrf

log = logging.getLogger("arborpress.web.oauth_provider")
oauth_provider_bp = Blueprint("oauth_provider", __name__)


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
    raw = request.headers.get("Authorization", "")
    if not raw.startswith("Bearer ") or len(raw) > 8192:
        return _json_error("invalid_token", 401)
    async for db in get_db_session():
        consumed = await consume_bearer(db, raw[7:])
        if consumed is None:
            return _json_error("invalid_token", 401)
        token_row, _family, _grant = consumed
        if "posts:read" not in token_row.scopes.split():
            return _json_error("insufficient_scope", 403)
        from arborpress.models.content import Post, PostStatus, PostVisibility

        posts = (
            (
                await db.execute(
                    select(Post)
                    .where(
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                    .order_by(Post.published_at.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
        await db.commit()
        response = jsonify(
            {
                "items": [
                    {
                        "id": post.short_id,
                        "slug": post.slug,
                        "title": post.title,
                        "excerpt": post.excerpt,
                        "published_at": post.published_at.isoformat()
                        if post.published_at
                        else None,
                        "url": f"/p/{post.slug}",
                    }
                    for post in posts
                ]
            }
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    abort(500)


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
