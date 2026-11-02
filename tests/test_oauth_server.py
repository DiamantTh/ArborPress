"""OAuth/OIDC authorization server storage and protocol regressions."""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid

import pytest
from sqlalchemy import select


def _settings_for_provider():
    from arborpress.core.config import Settings

    return Settings(web={"base_url": "https://accounts.example.test"})


@pytest.mark.asyncio
async def test_subject_is_stable_and_key_is_separate_encrypted_jwks(db_session, monkeypatch):
    from arborpress.auth import oauth_server
    from arborpress.models.oidc import OIDCSigningKey, OIDCSubject
    from arborpress.models.user import User

    monkeypatch.setattr(oauth_server, "get_settings", _settings_for_provider)
    user = User(username=f"oauth-{uuid.uuid4().hex[:10]}", display_name="OIDC Subject")
    db_session.add(user)
    await db_session.flush()
    subject1 = await oauth_server.stable_subject(db_session, str(user.id))
    subject2 = await oauth_server.stable_subject(db_session, str(user.id))
    key = await oauth_server.create_signing_key(db_session)
    keys = await oauth_server.jwks(db_session)
    assert subject1 == subject2
    assert subject1 != str(user.id)
    assert key.private_key_enc != key.public_key_pem.encode()
    assert keys["keys"][0]["kid"] == key.kid
    assert keys["keys"][0]["alg"] == "RS256"
    assert await db_session.scalar(
        select(OIDCSubject.id).where(OIDCSubject.user_id == str(user.id))
    )
    assert await db_session.get(OIDCSigningKey, key.kid)
    rotated = await oauth_server.create_signing_key(db_session, rotate=True)
    assert rotated.kid != key.kid
    assert rotated.is_current is True
    assert key.is_current is False
    assert key.private_key_enc == b""
    rotated_keys = await oauth_server.jwks(db_session)
    assert {item["kid"] for item in rotated_keys["keys"]} == {key.kid, rotated.kid}


@pytest.mark.asyncio
async def test_opaque_access_token_refresh_rotation_and_reuse_revokes_family(
    test_engine, monkeypatch
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.auth import oauth_server
    from arborpress.models.oidc import (
        OAuthClient,
        OAuthGrant,
        OAuthToken,
        OAuthTokenFamily,
        OIDCServerSettings,
    )
    from arborpress.models.user import User

    monkeypatch.setattr(oauth_server, "get_settings", _settings_for_provider)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(username=f"oauth-token-{uuid.uuid4().hex[:10]}", display_name="Token User")
        client_id = "ap_" + secrets.token_urlsafe(16)
        db.add_all(
            [
                user,
                OIDCServerSettings(id=1, issuer="https://accounts.example.test", enabled=True),
                OAuthClient(
                    client_id=client_id,
                    name="Fixture App",
                    client_type="public",
                    secret_hash=None,
                    redirect_uris='["https://client.example/callback"]',
                    allowed_scopes='["openid", "profile", "posts:read"]',
                    enabled=True,
                ),
            ]
        )
        await db.flush()
        grant = OAuthGrant(
            id=str(uuid.uuid4()),
            user_id=str(user.id),
            client_id=client_id,
            scopes="openid profile posts:read",
        )
        db.add(grant)
        await db.flush()
        response = await oauth_server.token_response(
            db,
            user_id=str(user.id),
            client_id=client_id,
            grant=grant,
            scopes=grant.scopes,
            nonce="nonce-fixture",
        )
        raw_access = response["access_token"]
        raw_refresh = response["refresh_token"]
        access_row = await db.scalar(
            select(OAuthToken).where(
                OAuthToken.token_hash == hashlib.sha256(raw_access.encode()).hexdigest()
            )
        )
        assert access_row is not None
        assert access_row.token_hash != raw_access
        assert response["id_token"]
        accepted = await oauth_server.consume_bearer(db, raw_access)
        assert accepted is not None
        rotated = await oauth_server.rotate_refresh(db, raw_refresh, client_id)
        assert rotated["refresh_token"] != raw_refresh
        await db.commit()
        with pytest.raises(oauth_server.OAuthError, match="invalid_grant"):
            await oauth_server.rotate_refresh(db, raw_refresh, client_id)
        family = await db.scalar(
            select(OAuthTokenFamily).where(OAuthTokenFamily.grant_id == grant.id)
        )
        assert family is not None and family.revoked_at is not None
        expired_family = OAuthTokenFamily(
            id=str(uuid.uuid4()),
            grant_id=grant.id,
            client_id=client_id,
            user_id=str(user.id),
            expires_at=oauth_server._now() - oauth_server.REFRESH_FAMILY_TTL,
        )
        expired_refresh = secrets.token_urlsafe(40)
        db.add(expired_family)
        await db.flush()
        db.add(
            OAuthToken(
                id=str(uuid.uuid4()),
                token_hash=oauth_server.digest(expired_refresh),
                token_type=oauth_server.TOKEN_REFRESH,
                family_id=expired_family.id,
                scopes=grant.scopes,
                expires_at=oauth_server._now() + oauth_server.REFRESH_TTL,
            )
        )
        await db.flush()
        with pytest.raises(oauth_server.OAuthError, match="invalid_grant"):
            await oauth_server.rotate_refresh(db, expired_refresh, client_id)


def test_pkce_s256_and_exact_redirect_validation():
    from arborpress.auth.oauth_server import OAuthError, validate_redirects, verify_pkce

    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert verify_pkce(verifier, challenge)
    assert not verify_pkce(verifier, "wrong")
    assert validate_redirects(["https://client.example/callback?x=1"]) == [
        "https://client.example/callback?x=1"
    ]
    for invalid in (
        "https://*.example/callback",
        "http://client.example/callback",
        "https://user:pass@client.example/callback",
        "https://client.example/callback#frag",
    ):
        with pytest.raises(OAuthError):
            validate_redirects([invalid])


@pytest.mark.asyncio
async def test_client_authentication_public_and_confidential(db_session, app):
    from arborpress.models.oidc import OAuthClient
    from arborpress.web.routes.oauth_provider import _authenticate_client

    secret = secrets.token_urlsafe(32)
    client = OAuthClient(
        client_id="confidential_fixture",
        name="Confidential",
        client_type="confidential",
        secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
        redirect_uris="[]",
        allowed_scopes="[]",
        enabled=True,
    )
    public = OAuthClient(
        client_id="public_fixture",
        name="Public",
        client_type="public",
        secret_hash=None,
        redirect_uris="[]",
        allowed_scopes="[]",
        enabled=True,
    )
    db_session.add_all([client, public])
    await db_session.flush()

    class Form(dict):
        pass

    async with app.test_request_context("/oauth/token", method="POST"):
        assert await _authenticate_client(db_session, Form(client_id="public_fixture")) is public
        assert (
            await _authenticate_client(
                db_session, Form(client_id="confidential_fixture", client_secret=secret)
            )
            is client
        )
        from arborpress.auth.oauth_server import OAuthError

        invalid_value = "known-invalid-fixture-secret"
        with pytest.raises(OAuthError):
            await _authenticate_client(
                db_session,
                Form(client_id="confidential_fixture", client_secret=invalid_value),
            )


@pytest.mark.asyncio
async def test_authorization_code_consent_pkce_and_single_use(client, test_engine, monkeypatch):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.auth import oauth_server
    from arborpress.core.config import Settings
    from arborpress.models.oidc import OAuthClient, OIDCServerSettings
    from arborpress.models.user import User

    settings = Settings(web={"base_url": "https://accounts.example.test"})
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: settings)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setattr(oauth_server, "get_settings", lambda: settings)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    user_id = str(uuid.uuid4())
    client_id = "ap_e2e_" + secrets.token_urlsafe(12)
    async with factory() as db:
        state = await db.get(OIDCServerSettings, 1)
        if state is None:
            state = OIDCServerSettings(id=1, issuer="https://accounts.example.test", enabled=True)
            db.add(state)
        else:
            state.issuer = "https://accounts.example.test"
            state.enabled = True
        db.add_all(
            [
                User(
                    id=user_id,
                    username=f"oauth-e2e-{uuid.uuid4().hex[:8]}",
                    display_name="OAuth E2E",
                ),
                OAuthClient(
                    client_id=client_id,
                    name="E2E client",
                    client_type="public",
                    secret_hash=None,
                    redirect_uris='["https://client.example/cb?tenant=one"]',
                    allowed_scopes='["openid", "profile", "posts:read"]',
                    enabled=True,
                ),
            ]
        )
        await db.commit()

    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    query = {
        "client_id": client_id,
        "redirect_uri": "https://client.example/cb?tenant=one",
        "response_type": "code",
        "scope": "openid profile posts:read",
        "state": "state-value-is-preserved",
        "nonce": "nonce-value",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    login_required = await client.get("/oauth/authorize", query_string=query)
    assert login_required.status_code == 401
    async with client.session_transaction() as browser:
        assert browser["oauth_resume"].startswith("/oauth/authorize?")
        assert "access_token" not in browser["oauth_resume"]
        browser["user_id"] = user_id
    response = await client.get("/oauth/authorize", query_string=query)
    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    import re

    csrf = re.search(r'name="_csrf" value="([^"]+)"', html).group(1)
    request_id = re.search(r'name="request_id" value="([^"]+)"', html).group(1)
    async with client.session_transaction() as browser:
        assert browser.get("_csrf_token") == csrf
    response = await client.post(
        "/oauth/authorize/consent",
        form={
            "_csrf": csrf,
            "request_id": request_id,
            "decision": "approve",
        },
    )
    assert response.status_code == 302, await response.get_data(as_text=True)
    location = response.headers["Location"]
    from urllib.parse import parse_qs, urlsplit

    callback = parse_qs(urlsplit(location).query)
    assert callback["tenant"] == ["one"]
    assert callback["state"] == ["state-value-is-preserved"]
    code = callback["code"][0]

    token_response = await client.post(
        "/oauth/token",
        form={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": "https://client.example/cb?tenant=one",
            "code_verifier": verifier,
        },
    )
    assert token_response.status_code == 200
    tokens = await token_response.get_json()
    assert tokens["token_type"] == "Bearer"  # noqa: S105
    assert tokens["id_token"]
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    import jwt

    async with factory() as db:
        from arborpress.models.oidc import OIDCSigningKey

        signing_key = await db.scalar(
            select(OIDCSigningKey).where(OIDCSigningKey.is_current.is_(True))
        )
        claims = jwt.decode(
            tokens["id_token"],
            signing_key.public_key_pem,
            algorithms=["RS256"],
            audience=client_id,
            issuer="https://accounts.example.test",
        )
        assert claims["nonce"] == "nonce-value"
        assert claims["sub"]
    replay = await client.post(
        "/oauth/token",
        form={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": "https://client.example/cb?tenant=one",
            "code_verifier": verifier,
        },
    )
    assert replay.status_code == 400
    assert (await replay.get_json())["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_bearer_api_requires_scope_and_ignores_session(client, test_engine, monkeypatch):
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.auth import oauth_server
    from arborpress.auth.oauth_server import digest
    from arborpress.models.oidc import (
        OAuthClient,
        OAuthGrant,
        OAuthToken,
        OAuthTokenFamily,
    )
    from arborpress.models.user import User

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    user_id = str(uuid.uuid4())
    client_id = "ap_api_" + secrets.token_urlsafe(12)
    raw = secrets.token_urlsafe(40)
    async with factory() as db:
        user = User(
            id=user_id, username=f"oauth-api-{uuid.uuid4().hex[:8]}", display_name="API User"
        )
        oauth_client = OAuthClient(
            client_id=client_id,
            name="API",
            client_type="public",
            secret_hash=None,
            redirect_uris='["https://client.example/cb"]',
            allowed_scopes='["profile"]',
            enabled=True,
        )
        grant = OAuthGrant(
            id=str(uuid.uuid4()), user_id=user_id, client_id=client_id, scopes="profile"
        )
        family = OAuthTokenFamily(
            id=str(uuid.uuid4()), grant_id=grant.id, client_id=client_id, user_id=user_id
        )
        db.add_all(
            [
                user,
                oauth_client,
                grant,
                family,
                OAuthToken(
                    id=str(uuid.uuid4()),
                    token_hash=digest(raw),
                    token_type=oauth_server.TOKEN_ACCESS,
                    family_id=family.id,
                    scopes="profile",
                    expires_at=oauth_server._now() + oauth_server.ACCESS_TTL,
                ),
            ]
        )
        await db.commit()
    async with client.session_transaction() as browser:
        browser["user_id"] = user_id
    denied = await client.get("/api/v1/oauth/posts", headers={"Authorization": f"Bearer {raw}"})
    assert denied.status_code == 403
    profile = await client.get("/api/v1/oauth/me", headers={"Authorization": f"Bearer {raw}"})
    assert profile.status_code == 200
    assert "sub" not in await profile.get_json()
    missing = await client.get("/api/v1/oauth/me")
    assert missing.status_code == 401


@pytest.mark.asyncio
async def test_oauth_revocation_of_access_token_does_not_revoke_user_consent(
    client, test_engine, monkeypatch
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.auth.oauth_server import ACCESS_TTL, TOKEN_ACCESS, TOKEN_REFRESH, _now, digest
    from arborpress.models.oidc import OAuthClient, OAuthGrant, OAuthToken, OAuthTokenFamily
    from arborpress.models.user import User

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    user_id = str(uuid.uuid4())
    client_id = "ap_revoke_" + secrets.token_urlsafe(12)
    access_raw = secrets.token_urlsafe(40)
    refresh_raw = secrets.token_urlsafe(40)
    grant_id = str(uuid.uuid4())
    family_id = str(uuid.uuid4())
    async with factory() as db:
        db.add_all(
            [
                User(
                    id=user_id,
                    username=f"oauth-revoke-{uuid.uuid4().hex[:8]}",
                    display_name="Revoke User",
                ),
                OAuthClient(
                    client_id=client_id,
                    name="Revoke fixture",
                    client_type="public",
                    secret_hash=None,
                    redirect_uris='["https://client.example/cb"]',
                    allowed_scopes='["profile"]',
                    enabled=True,
                ),
                OAuthGrant(
                    id=grant_id, user_id=user_id, client_id=client_id, scopes="profile"
                ),
                OAuthTokenFamily(
                    id=family_id,
                    grant_id=grant_id,
                    client_id=client_id,
                    user_id=user_id,
                ),
                OAuthToken(
                    id=str(uuid.uuid4()),
                    token_hash=digest(access_raw),
                    token_type=TOKEN_ACCESS,
                    family_id=family_id,
                    scopes="profile",
                    expires_at=_now() + ACCESS_TTL,
                ),
                OAuthToken(
                    id=str(uuid.uuid4()),
                    token_hash=digest(refresh_raw),
                    token_type=TOKEN_REFRESH,
                    family_id=family_id,
                    scopes="profile",
                    expires_at=_now() + ACCESS_TTL,
                ),
            ]
        )
        await db.commit()

    response = await client.post(
        "/oauth/revoke", form={"client_id": client_id, "token": access_raw}
    )
    assert response.status_code == 200
    async with factory() as db:
        grant = await db.get(OAuthGrant, grant_id)
        access = await db.scalar(
            select(OAuthToken).where(OAuthToken.token_hash == digest(access_raw))
        )
        refresh = await db.scalar(
            select(OAuthToken).where(OAuthToken.token_hash == digest(refresh_raw))
        )
        assert grant is not None and grant.revoked_at is None
        assert access is not None and access.revoked_at is not None
        assert refresh is not None and refresh.revoked_at is None


@pytest.mark.asyncio
async def test_oauth_admin_overview_is_ssr_and_does_not_render_secrets(
    client, test_engine, monkeypatch
):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.core.config import Settings
    from arborpress.models.user import User, UserRole, UserSession

    monkeypatch.setattr(
        "arborpress.core.config.get_settings",
        lambda: Settings(web={"base_url": "https://accounts.example.test"}),
    )
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    user_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    async with factory() as db:
        user = User(
            id=user_id,
            username=f"oauth-admin-{uuid.uuid4().hex[:8]}",
            display_name="OAuth Administrator",
            role=UserRole.ADMIN,
        )
        now = datetime.now(UTC).replace(tzinfo=None)
        db.add_all(
            [
                user,
                UserSession(
                    id=session_id,
                    user_id=user_id,
                    expires_at=now + timedelta(hours=1),
                    last_seen_at=now,
                    is_valid=True,
                    is_tls=True,
                    is_cli=False,
                ),
            ]
        )
        await db.commit()
    async with client.session_transaction() as browser:
        browser.update(
            {
                "user_id": user_id,
                "user_role": "admin",
                "session_id": session_id,
                "user_name": "admin",
                "account_type": "operational",
            }
        )
    response = await client.get("/admin/oauth")
    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert "OAuth 2.0 / OpenID Connect Provider" in html
    assert "Redirect URIs" in html
    assert "private_key" not in html
    assert "client_secret" not in html
