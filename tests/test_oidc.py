"""OIDC cryptographic and identity-resolution regression coverage."""

from __future__ import annotations

import json
import uuid
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.auth import oidc


def _fixture_key():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public_jwk.update({"kid": "fixture-kid", "use": "sig", "alg": "RS256"})
    return private, {"keys": [public_jwk]}


def _token(private, **overrides):
    import time

    claims = {
        "iss": "https://issuer.example",
        "sub": "stable-subject",
        "aud": "arborpress",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
        "nonce": "expected-nonce",
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "fixture-kid"})


def test_verify_id_token_accepts_valid_rsa_identity():
    private, jwks = _fixture_key()
    result = oidc.verify_id_token(
        _token(private, jku="https://attacker.invalid/jwks"),
        metadata={},
        issuer="https://issuer.example",
        client_id="arborpress",
        nonce="expected-nonce",
        jwks=jwks,
    )
    assert result["sub"] == "stable-subject"


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"iss": "https://other.example"}, "id_token_verification_failed"),
        ({"aud": "other-client"}, "id_token_verification_failed"),
        ({"nonce": "wrong"}, "nonce_mismatch"),
        ({"sub": ""}, "subject_invalid"),
        ({"aud": ["arborpress", "other"]}, "authorized_party_mismatch"),
        ({"aud": ["arborpress", "other"], "azp": "arborpress"}, None),
    ],
)
def test_verify_id_token_claim_policy(claims, expected):
    private, jwks = _fixture_key()
    token = _token(private, **claims)
    if expected is None:
        assert oidc.verify_id_token(
            token,
            metadata={},
            issuer="https://issuer.example",
            client_id="arborpress",
            nonce="expected-nonce",
            jwks=jwks,
        )["sub"] == "stable-subject"
    else:
        with pytest.raises(oidc.OIDCError, match=expected):
            oidc.verify_id_token(
                token,
                metadata={},
                issuer="https://issuer.example",
                client_id="arborpress",
                nonce="expected-nonce",
                jwks=jwks,
            )


def test_verify_rejects_expired_and_not_yet_valid_tokens():
    import time

    private, jwks = _fixture_key()
    for token in (
        _token(private, exp=int(time.time()) - 500),
        _token(private, nbf=int(time.time()) + 500),
    ):
        with pytest.raises(oidc.OIDCError):
            oidc.verify_id_token(
                token,
                metadata={},
                issuer="https://issuer.example",
                client_id="arborpress",
                nonce="expected-nonce",
                jwks=jwks,
            )


def test_verify_rejects_unknown_kid_and_bad_signature():
    private, jwks = _fixture_key()
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "sub": "subject",
            "aud": "arborpress",
            "iat": 1_900_000_000,
            "exp": 1_900_000_300,
            "nonce": "expected-nonce",
        },
        private,
        algorithm="RS256",
        headers={"kid": "unknown"},
    )
    with pytest.raises(oidc.OIDCError, match="signing_key_not_found"):
        oidc.verify_id_token(
            token, metadata={}, issuer="https://issuer.example", client_id="arborpress",
            nonce="expected-nonce", jwks=jwks,
        )
    other, _ = _fixture_key()
    with pytest.raises(oidc.OIDCError, match="id_token_verification_failed"):
        oidc.verify_id_token(
            _token(other), metadata={}, issuer="https://issuer.example", client_id="arborpress",
            nonce="expected-nonce", jwks=jwks,
        )


def test_provider_url_rejects_private_and_non_https_targets():
    for url in (
        "http://issuer.example",
        "https://127.0.0.1/metadata",
        "https://169.254.169.254/latest",
        "https://user:password@issuer.example",
        "file:///etc/passwd",
    ):
        with pytest.raises(oidc.OIDCError):
            oidc._https_url(url)


def test_userinfo_must_match_verified_id_token_subject():
    verified = {"sub": "right-subject", "iss": "https://issuer.example"}
    with pytest.raises(oidc.OIDCError, match="userinfo_subject_mismatch"):
        oidc.merge_userinfo(verified, {"sub": "attacker-subject", "email": "x@example.test"})
    assert oidc.merge_userinfo(verified, {"sub": "right-subject", "name": "Display"}) == {
        "sub": "right-subject", "iss": "https://issuer.example", "name": "Display"
    }


@pytest.mark.asyncio
async def test_discovery_checks_issuer_and_redirects(monkeypatch):
    async def public(_url):
        return ("93.184.216.34",)

    monkeypatch.setattr(oidc, "validate_provider_url", public)
    payload = {
        "issuer": "https://attacker.example",
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
    }
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, json=payload, headers={"content-type": "application/json"}
        )
    )
    with pytest.raises(oidc.OIDCError, match="issuer_mismatch"):
        await oidc.discover(
            {"issuer": "https://issuer.example", "discovery_url": "https://issuer.example/.well-known"},
            transport=transport,
        )
    payload["issuer"] = "https://issuer.example"
    valid_transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, json=payload, headers={"content-type": "application/json"}
        )
    )
    result = await oidc.discover(
        {"issuer": "https://issuer.example", "discovery_url": "https://issuer.example/.well-known"},
        transport=valid_transport,
    )
    assert result["jwks_uri"] == "https://issuer.example/jwks"
    redirect_transport = httpx.MockTransport(
        lambda request: httpx.Response(302, headers={"location": "http://127.0.0.1"})
    )
    with pytest.raises(oidc.OIDCError, match="provider_redirect_rejected"):
        await oidc.request_json("https://issuer.example/metadata", transport=redirect_transport)


@pytest.mark.asyncio
async def test_unknown_kid_causes_only_one_jwks_refresh(monkeypatch):
    private, jwks = _fixture_key()
    token = jwt.encode(
        {
            "iss": "https://issuer.example", "sub": "subject", "aud": "arborpress",
            "iat": 1_900_000_000, "exp": 1_900_000_300, "nonce": "nonce",
        },
        private,
        algorithm="RS256",
        headers={"kid": "new-key"},
    )
    calls = 0

    async def fake_json(_url, **_kwargs):
        nonlocal calls
        calls += 1
        return jwks

    monkeypatch.setattr(oidc, "request_json", fake_json)
    with pytest.raises(oidc.OIDCError, match="signing_key_not_found"):
        await oidc.verify_id_token_from_provider(
            token,
            metadata={"jwks_uri": "https://issuer.example/jwks"},
            issuer="https://issuer.example",
            client_id="arborpress",
            nonce="nonce",
        )
    assert calls == 2


@pytest.mark.asyncio
async def test_external_identity_unique_issuer_subject(db_session):
    from arborpress.models.user import ExternalIdentity, User

    user_a = User(username=f"oidc-a-{uuid.uuid4().hex[:8]}", display_name="A")
    user_b = User(username=f"oidc-b-{uuid.uuid4().hex[:8]}", display_name="B")
    db_session.add_all([user_a, user_b])
    await db_session.flush()
    db_session.add(ExternalIdentity(
        user_id=str(user_a.id), provider_id="provider", issuer="https://issuer.example",
        subject="same-subject",
    ))
    await db_session.flush()
    db_session.add(ExternalIdentity(
        user_id=str(user_b.id), provider_id="other-provider", issuer="https://issuer.example",
        subject="same-subject",
    ))
    with pytest.raises(IntegrityError):
        await db_session.flush()


@pytest.mark.asyncio
async def test_sso_begin_uses_server_side_provider_bound_flow(client, monkeypatch):
    from arborpress.web.routes import sso

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setattr(sso, "_get_provider_config", lambda provider: {
        "id": provider, "issuer": "https://issuer.example", "client_id": "arborpress",
        "name": "Example", "scopes": ["openid", "profile"],
    })
    async def resolved(provider_cfg):
        metadata = {
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/jwks",
        }
        return {**provider_cfg, **metadata, "_oidc_metadata": metadata}
    monkeypatch.setattr(sso, "_resolve_provider_endpoints", resolved)
    response = await client.get("/auth/sso/example")
    assert response.status_code == 302
    params = parse_qs(urlparse(response.headers["Location"]).query)
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["nonce"] and params["state"]
    assert params["redirect_uri"][0].endswith("/auth/sso/example/callback")
    assert "arborpress_oidc_flow=" in response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in response.headers.get("Set-Cookie", "")
    assert "SameSite=Lax" in response.headers.get("Set-Cookie", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("callback_provider,alter_state", [("example", True), ("other", False)])
async def test_callback_rejects_state_mismatch_and_provider_swap(
    client, monkeypatch, callback_provider, alter_state
):
    from arborpress.web.routes import sso

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    providers = {
        name: {
            "id": name, "issuer": f"https://{name}.example", "client_id": "client",
            "name": name, "scopes": ["openid"],
        }
        for name in ("example", "other")
    }
    monkeypatch.setattr(sso, "_get_provider_config", lambda name: providers.get(name))

    async def resolved(provider):
        metadata = {
            "issuer": provider["issuer"],
            "authorization_endpoint": f"{provider['issuer']}/authorize",
            "token_endpoint": f"{provider['issuer']}/token",
            "jwks_uri": f"{provider['issuer']}/jwks",
        }
        return {**provider, **metadata, "_oidc_metadata": metadata}

    monkeypatch.setattr(sso, "_resolve_provider_endpoints", resolved)
    started = await client.get("/auth/sso/example")
    values = parse_qs(urlparse(started.headers["Location"]).query)
    state = values["state"][0] + ("x" if alter_state else "")
    callback = await client.get(
        f"/auth/sso/{callback_provider}/callback?code=unused&state={state}"
    )
    assert callback.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["inactive", "sso_disabled"])
async def test_callback_rejects_inactive_or_sso_disabled_identity(
    client, test_engine, monkeypatch, status
):
    from arborpress.models.user import ExternalIdentity, User
    from arborpress.web.routes import sso

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    provider = {
        "id": "corp", "issuer": "https://issuer.example", "client_id": "arborpress",
        "name": "Corp", "scopes": ["openid"], "auto_create": False,
    }
    monkeypatch.setattr(sso, "_get_provider_config", lambda _name: provider)
    metadata = {
        "issuer": provider["issuer"],
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
    }

    async def resolved(_provider):
        return {**provider, **metadata, "_oidc_metadata": metadata}

    monkeypatch.setattr(sso, "_resolve_provider_endpoints", resolved)
    private, jwks = _fixture_key()
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=f"oidc-{status}", display_name="OIDC User",
            is_active=status != "inactive", sso_disabled=status == "sso_disabled",
        )
        db.add(user)
        await db.flush()
        db.add(ExternalIdentity(
            user_id=str(user.id), provider_id="corp", issuer=provider["issuer"],
            subject="subject-" + status,
        ))
        await db.commit()

    started = await client.get("/auth/sso/corp")
    values = parse_qs(urlparse(started.headers["Location"]).query)
    token = _token(private, nonce=values["nonce"][0], sub="subject-" + status)

    async def fake_json(url, *, method="GET", **_kwargs):
        if method == "POST":
            return {"access_token": "access", "id_token": token}
        return jwks

    monkeypatch.setattr(sso, "request_json", fake_json)
    monkeypatch.setattr(oidc, "request_json", fake_json)
    response = await client.get(
        "/auth/sso/corp/callback?code=one-time&state=" + values["state"][0]
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_provider_config_ignores_legacy_autolink_and_disables_autocreate(monkeypatch):
    from arborpress.web.routes import sso

    monkeypatch.setattr(sso, "_load_sso_config", lambda: {
        "providers": {"corp": {
            "issuer": "https://issuer.example", "client_id": "client",
            "auto_link_by_email": True, "role_mapping": {"default": "admin"},
        }}
    })
    provider = sso._get_provider_config("corp")
    assert provider is not None
    assert provider["auto_create"] is False
    assert "auto_link_by_email" not in provider
    assert "role_mapping" not in provider


@pytest.mark.asyncio
async def test_callback_does_not_link_by_email_or_username(client, test_engine, monkeypatch):
    from arborpress.models.user import ExternalIdentity, User, UserRole
    from arborpress.web.routes import sso

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    provider = {
        "id": "corp", "issuer": "https://issuer.example", "client_id": "arborpress",
        "client_secret": "private-test-secret", "name": "Corp", "scopes": ["openid", "email"],
        "auto_create": True, "auto_link_by_email": True,
        "role_mapping": {"default": "admin"},
    }
    monkeypatch.setattr(sso, "_get_provider_config", lambda _provider: provider)
    metadata = {
        "issuer": provider["issuer"],
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
        "userinfo_endpoint": "https://issuer.example/userinfo",
    }

    async def resolved(_provider):
        return {**provider, **metadata, "_oidc_metadata": metadata}

    monkeypatch.setattr(sso, "_resolve_provider_endpoints", resolved)
    private, jwks = _fixture_key()
    authorization = await client.get("/auth/sso/corp")
    assert authorization.status_code == 302, authorization.get_data(as_text=True)
    params = parse_qs(urlparse(authorization.headers["Location"]).query)
    assert "state" in params, authorization.headers["Location"]
    state, nonce = params["state"][0], params["nonce"][0]
    token = _token(
        private,
        nonce=nonce,
        preferred_username="existing-name",
        email="existing@example.test",
        email_verified=True,
        role="admin",
    )

    token_exchange = {}

    async def fake_json(url, *, method="GET", **kwargs):
        if method == "POST":
            token_exchange.update(kwargs)
            return {"access_token": "one-time-access-token", "id_token": token}
        if url.endswith("/jwks"):
            return jwks
        return {"sub": "stable-subject", "email": "existing@example.test", "email_verified": True}

    monkeypatch.setattr(sso, "request_json", fake_json)
    monkeypatch.setattr(oidc, "request_json", fake_json)
    monkeypatch.setattr(sso, "verify_id_token_from_provider", oidc.verify_id_token_from_provider)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        original = User(
            username="existing-name", display_name="Original", email="existing@example.test",
            role=UserRole.ADMIN,
        )
        db.add(original)
        await db.commit()
        original_id = str(original.id)

    response = await client.get(f"/auth/sso/corp/callback?code=temporary-code&state={state}")
    assert response.status_code == 302
    assert token_exchange["auth"] == ("arborpress", "private-test-secret")
    assert "client_secret" not in token_exchange["data"]
    async with factory() as db:
        identity = (await db.execute(select(ExternalIdentity).where(
            ExternalIdentity.issuer == provider["issuer"],
            ExternalIdentity.subject == "stable-subject",
        ))).scalar_one()
        linked = await db.get(User, identity.user_id)
        original_after = await db.get(User, original_id)
        assert linked is not None and original_after is not None
        assert linked.id != original_after.id
        assert linked.username != original_after.username
        assert linked.email is None
        assert linked.role == UserRole.VIEWER
        assert original_after.role == UserRole.ADMIN
        assert linked.display_name == linked.username
    replay = await client.get(f"/auth/sso/corp/callback?code=temporary-code&state={state}")
    assert replay.status_code == 400
