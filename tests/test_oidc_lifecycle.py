"""OIDC linking, last-login protection, provider lifecycle and privacy tests."""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.auth import oidc
from arborpress.auth.stepup import grant_stepup


async def _provider(db, provider_id="corp", **overrides):
    from arborpress.models.oidc import OIDCProvider

    data = {
        "name": "Corp",
        "issuer": "https://issuer.example",
        "client_id": "arborpress",
        "scopes": '["openid","profile","email"]',
        "enabled": True,
        "auto_create": False,
    }
    data.update(overrides)
    row = await db.get(OIDCProvider, provider_id)
    if row is None:
        row = OIDCProvider(id=provider_id, **data)
        db.add(row)
    else:
        for key, value in data.items():
            setattr(row, key, value)
    return row


async def _session_user(test_engine, username="oidc-lifecycle"):
    from arborpress.models.user import User, UserRole, UserSession

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=f"{username}-{uuid.uuid4().hex[:8]}", display_name="Lifecycle User",
            role=UserRole.VIEWER,
        )
        db.add(user)
        await db.flush()
        user_session = UserSession(
            user_id=str(user.id), expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC), is_valid=True, is_tls=False, is_cli=False,
        )
        db.add(user_session)
        await db.commit()
        return str(user.id), user_session.id, user.username


def _rsa_fixture():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    public.update({"kid": "lifecycle-key", "use": "sig", "alg": "RS256"})
    return private, {"keys": [public]}


@pytest.mark.asyncio
async def test_login_method_resolver_counts_real_methods_and_active_oidc_only(
    db_session, monkeypatch,
):
    from arborpress.auth.policy import usable_login_methods
    from arborpress.core.config import Settings
    from arborpress.models.user import ExternalIdentity, MFADevice, MFADeviceType, User

    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: Settings())
    user = User(username=f"resolver-{uuid.uuid4().hex[:8]}", display_name="Resolver")
    db_session.add(user)
    await db_session.flush()
    totp = MFADevice(
        user_id=str(user.id), device_type=MFADeviceType.TOTP, label="only factor",
        secret_enc=b"encrypted", is_active=True, verification_status="verified",
    )
    db_session.add(totp)
    provider_id = f"resolver-{uuid.uuid4().hex[:10]}"
    issuer = f"https://{provider_id}.example"
    from arborpress.models.oidc import OIDCProvider
    db_session.add(OIDCProvider(
        id=provider_id, name="Resolver", issuer=issuer,
        client_id="client", scopes='["openid"]', enabled=True, auto_create=False,
    ))
    identity = ExternalIdentity(
        user_id=str(user.id), provider_id=provider_id,
        issuer=issuer, subject="stable-subject",
    )
    db_session.add(identity)
    await db_session.flush()
    assert await usable_login_methods(db_session, user) == {f"oidc:{provider_id}"}
    assert await usable_login_methods(
        db_session, user, exclude_external_identity_id=str(identity.id)
    ) == set()
    provider = await db_session.get(OIDCProvider, provider_id)
    provider.enabled = False
    assert await usable_login_methods(db_session, user) == set()
    provider.enabled = True
    user.sso_disabled = True
    assert await usable_login_methods(db_session, user) == set()


@pytest.mark.asyncio
async def test_provider_secret_is_encrypted_issuer_is_immutable_when_linked_and_disable_retains(
    db_session,
):
    from arborpress.auth.oidc_providers import (
        OIDCProviderError,
        provider_config,
        rotate_provider_secret,
        safe_provider,
        save_provider,
        set_provider_enabled,
    )
    from arborpress.models.oidc import OIDCProvider
    from arborpress.models.user import ExternalIdentity, User

    row = await save_provider(db_session, {
        "id": "lifecycle", "name": "Lifecycle", "issuer": "https://issuer.example",
        "client_id": "client", "scopes": ["openid"], "enabled": True,
    })
    await rotate_provider_secret(db_session, row.id, "private-client-secret")
    assert b"private-client-secret" not in row.client_secret_enc
    assert safe_provider(row)["has_secret"] is True
    assert provider_config(row)["client_secret"] == "private-client-secret"  # noqa: S105
    user = User(username=f"provider-{uuid.uuid4().hex[:8]}", display_name="Provider")
    db_session.add(user)
    await db_session.flush()
    db_session.add(ExternalIdentity(
        user_id=str(user.id), provider_id=row.id, issuer=row.issuer, subject="subject",
    ))
    await db_session.flush()
    with pytest.raises(OIDCProviderError, match="Issuer cannot change"):
        await save_provider(db_session, {
            "id": row.id, "name": "Changed", "issuer": "https://other.example",
            "client_id": "client", "scopes": ["openid"],
        })
    await set_provider_enabled(db_session, row.id, False)
    assert (await db_session.execute(select(ExternalIdentity.id).where(
        ExternalIdentity.provider_id == row.id,
    ))).scalar_one()
    assert (await db_session.get(OIDCProvider, row.id)).enabled is False


@pytest.mark.parametrize(
    "issuer",
    [
        "http://issuer.example", "https://user@issuer.example",
        "https://issuer.example:99999", "https://issuer.example/path?query=1",
    ],
)
def test_provider_configuration_rejects_unsafe_issuer_urls(issuer):
    from arborpress.auth.oidc_providers import OIDCProviderError, _validate_provider

    with pytest.raises(OIDCProviderError):
        _validate_provider({
            "id": "unsafe", "name": "Unsafe", "issuer": issuer, "client_id": "client",
        })


@pytest.mark.asyncio
async def test_daily_failure_aggregate_is_bounded_and_retention_only_prunes_diagnostics(db_session):
    from arborpress.auth.oidc_providers import diagnostics, prune_diagnostics, record_failure
    from arborpress.models.oidc import OIDCFailureDaily, OIDCProvider

    provider_id = f"aggregate-{uuid.uuid4().hex[:10]}"
    db_session.add(OIDCProvider(
        id=provider_id, name="Aggregate", issuer=f"https://{provider_id}.example",
        client_id="client", scopes='["openid"]', enabled=True, auto_create=False,
    ))
    await db_session.flush()
    before_unknown = sum(
        item["count"] for item in await diagnostics(db_session)
        if item["provider_id"] == "unknown" and item["failure_class"] == "token_exchange"
    )
    await record_failure(db_session, provider_id, "nonce")
    await record_failure(db_session, provider_id, "nonce")
    await record_failure(db_session, "attacker-controlled-provider-name", "raw-subject")
    summaries = await diagnostics(db_session)
    assert next(item["count"] for item in summaries if item["provider_id"] == provider_id) == 2
    after_unknown = sum(
        item["count"] for item in summaries
        if item["provider_id"] == "unknown" and item["failure_class"] == "token_exchange"
    )
    assert after_unknown == before_unknown + 1
    old = OIDCFailureDaily(
        day=datetime.now(UTC).date() - timedelta(days=45), provider_id=provider_id,
        failure_class="discovery", count=4,
    )
    db_session.add(old)
    await db_session.flush()
    assert await prune_diagnostics(db_session, days=30) == 1


@pytest.mark.asyncio
async def test_linking_uses_separate_stepup_bound_oidc_flow_and_explicit_confirmation(
    client, test_engine, monkeypatch,
):
    from arborpress.models.user import ExternalIdentity
    from arborpress.web.routes import sso

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    user_id, session_id, username = await _session_user(test_engine, "linking")
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        await _provider(db)
        await db.commit()
    async with client.session_transaction() as browser:
        browser["user_id"] = user_id
        browser["user_name"] = username
        browser["session_id"] = session_id
        csrf_value = uuid.uuid4().hex
        browser["_csrf_token"] = csrf_value
        await grant_stepup(
            browser, user_id, "link_external_identity", target="corp"
        )

    metadata = {
        "issuer": "https://issuer.example",
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
    }

    async def resolved(config):
        return {**config, **metadata, "_oidc_metadata": metadata}

    private, jwks = _rsa_fixture()
    monkeypatch.setattr(sso, "_resolve_provider_endpoints", resolved)
    started = await client.get("/auth/sso/corp/link")
    assert started.status_code == 302
    params = parse_qs(urlparse(started.headers["Location"]).query)
    assert params["redirect_uri"][0].endswith("/auth/sso/corp/link/callback")
    assert params["code_challenge_method"] == ["S256"]
    token = jwt.encode({
        "iss": metadata["issuer"], "sub": "linked-subject", "aud": "arborpress",
        "iat": int(time.time()), "exp": int(time.time()) + 300,
        "nonce": params["nonce"][0],
    }, private, algorithm="RS256", headers={"kid": "lifecycle-key"})

    async def fake_json(url, *, method="GET", **_kwargs):
        return {"access_token": "ephemeral", "id_token": token} if method == "POST" else jwks

    monkeypatch.setattr(sso, "request_json", fake_json)
    monkeypatch.setattr(oidc, "request_json", fake_json)
    callback = await client.get(
        "/auth/sso/corp/link/callback?code=temporary&state=" + params["state"][0]
    )
    assert callback.status_code == 200
    assert "bewusst" in (await callback.get_data(as_text=True))
    async with factory() as db:
        assert (await db.execute(select(ExternalIdentity.id).where(
            ExternalIdentity.issuer == metadata["issuer"],
            ExternalIdentity.subject == "linked-subject",
        ))).scalar_one_or_none() is None

    pending_id = _extract_pending_id(await callback.get_data(as_text=True))
    confirmed = await client.post(
        f"/auth/sso/link/confirm/{pending_id}",
        form={"_csrf": csrf_value},
        headers={"Origin": "http://localhost:8066"},
    )
    assert confirmed.status_code == 302
    async with factory() as db:
        identity = (await db.execute(select(ExternalIdentity).where(
            ExternalIdentity.issuer == metadata["issuer"],
            ExternalIdentity.subject == "linked-subject",
        ))).scalar_one()
        assert identity.user_id == user_id
    replay = await client.post(
        f"/auth/sso/link/confirm/{pending_id}",
        form={"_csrf": csrf_value},
        headers={"Origin": "http://localhost:8066"},
    )
    assert replay.status_code == 403


def _extract_pending_id(html: str) -> str:
    import re

    match = re.search(r"/auth/sso/link/confirm/([a-f0-9-]{36})", html)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
async def test_unlink_denies_last_login_method_and_allows_another_real_method(
    client, test_engine, monkeypatch,
):
    from arborpress.models.user import ExternalIdentity, WebAuthnCredential

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    user_id, session_id, username = await _session_user(test_engine, "unlink")
    async with factory() as db:
        await _provider(db, "unlink-provider")
        identity = ExternalIdentity(
            user_id=user_id, provider_id="unlink-provider", issuer="https://issuer.example",
            subject="unlink-subject",
        )
        db.add(identity)
        await db.commit()
        identity_id = str(identity.id)
    async with client.session_transaction() as browser:
        browser["user_id"] = user_id
        browser["user_name"] = username
        browser["session_id"] = session_id
        await grant_stepup(browser, user_id, "unlink_external_identity", target=identity_id)
    blocked = await client.post(
        f"/auth/sso/identities/{identity_id}/unlink", json={},
        headers={"Origin": "http://localhost:8066"},
    )
    assert blocked.status_code == 409
    async with factory() as db:
        assert await db.get(ExternalIdentity, identity_id) is not None
        db.add(WebAuthnCredential(
            user_id=user_id, label="Recovery key", credential_id=uuid.uuid4().bytes,
            public_key=b"test-public-key", uv_capable=True, verification_status="verified",
        ))
        await db.commit()
    async with client.session_transaction() as browser:
        await grant_stepup(browser, user_id, "unlink_external_identity", target=identity_id)
    removed = await client.post(
        f"/auth/sso/identities/{identity_id}/unlink", json={},
        headers={"Origin": "http://localhost:8066"},
    )
    assert removed.status_code == 200
    async with factory() as db:
        assert await db.get(ExternalIdentity, identity_id) is None


@pytest.mark.asyncio
async def test_oidc_admin_provider_create_secret_rotation_and_disable_are_stepup_csrf_protected(
    client, test_engine, monkeypatch,
):
    from arborpress.models.oidc import OIDCProvider
    from arborpress.models.user import AccountType, ExternalIdentity, User, UserRole, UserSession

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=f"oidc-admin-{uuid.uuid4().hex[:8]}", display_name="OIDC Admin",
            account_type=AccountType.OPERATIONAL, role=UserRole.ADMIN, is_active=True,
        )
        db.add(user)
        await db.flush()
        admin_id = str(user.id)
        user_session = UserSession(
            user_id=admin_id, expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC), is_valid=True, is_tls=False, is_cli=False,
        )
        db.add(user_session)
        await db.commit()
        session_id = user_session.id

    async with client.session_transaction() as browser:
        browser["user_id"] = admin_id
        browser["user_name"] = user.username
        browser["user_role"] = "admin"
        browser["account_type"] = "operational"
        browser["session_id"] = session_id
        csrf_value = uuid.uuid4().hex
        browser["_csrf_token"] = csrf_value
        await grant_stepup(browser, admin_id, "manage_oidc_provider", target="instance")

    headers = {"Origin": "http://localhost:8066"}
    created = await client.post("/admin/oidc/providers", form={
        "_csrf": csrf_value, "id": "managed", "name": "Managed",
        "issuer": "https://managed.example", "client_id": "client",
        "scopes": "openid profile", "enabled": "on",
    }, headers=headers)
    assert created.status_code == 302

    async with client.session_transaction() as browser:
        await grant_stepup(browser, admin_id, "rotate_oidc_client_secret", target="instance")
    rotated = await client.post(
        "/admin/oidc/providers/managed/secret",
        form={"_csrf": csrf_value, "client_secret": "rotate-me-secret"},
        headers=headers,
    )
    assert rotated.status_code == 302

    async with factory() as db:
        row = await db.get(OIDCProvider, "managed")
        assert row is not None
        assert row.client_secret_enc is not None
        assert b"rotate-me-secret" not in row.client_secret_enc
        db.add(ExternalIdentity(
            user_id=admin_id, provider_id="managed", issuer=row.issuer, subject="admin-oidc-sub",
        ))
        await db.commit()

    page = await client.get("/admin/oidc/providers")
    assert page.status_code == 200
    body = await page.get_data(as_text=True)
    assert "rotate-me-secret" not in body
    assert "managed.example" in body

    async with client.session_transaction() as browser:
        await grant_stepup(browser, admin_id, "manage_oidc_provider", target="instance")
    disabled = await client.post(
        "/admin/oidc/providers/managed/enabled",
        form={"_csrf": csrf_value, "enabled": "false"}, headers=headers,
    )
    assert disabled.status_code == 302
    async with factory() as db:
        assert (await db.get(OIDCProvider, "managed")).enabled is False
        assert (await db.execute(select(ExternalIdentity.id).where(
            ExternalIdentity.provider_id == "managed",
        ))).scalar_one()

    async with client.session_transaction() as browser:
        await grant_stepup(browser, admin_id, "manage_oidc_provider", target="instance")
    async with factory() as db:
        admin = await db.get(User, admin_id)
        admin.role = UserRole.AUTHOR
        await db.commit()
    denied = await client.post(
        "/admin/oidc/providers/managed/enabled",
        form={"_csrf": csrf_value, "enabled": "true"}, headers=headers,
    )
    assert denied.status_code == 403
