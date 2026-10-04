"""Regression coverage for the unified auth ceremonies and policy helpers."""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.auth.webauthn import WebAuthnService, decode_credential_id


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def test_credential_id_is_base64url_not_hex():
    assert decode_credential_id("-_8") == b"\xfb\xff"
    assert decode_credential_id("-_8=") == b"\xfb\xff"
    with pytest.raises(ValueError):
        decode_credential_id("not a credential id")


def test_json_origin_uses_exact_browser_origin():
    from arborpress.web.routes.auth import _origin_from_headers

    assert _origin_from_headers("https://example.test", None) == "https://example.test"
    assert _origin_from_headers(None, "https://example.test/path?q=1") == "https://example.test"
    assert _origin_from_headers("https://example.test.attacker.invalid", None) != "https://example.test"
    assert _origin_from_headers(None, None) == ""


def test_webauthn_options_use_uv_required_and_user_allow_list():
    from webauthn.helpers import options_to_json

    service = WebAuthnService("example.test", "ArborPress", "https://example.test")
    options = json.loads(options_to_json(service.generate_authentication_options([b"\xfb\xff"])))
    assert options["userVerification"] == "required"
    assert options["allowCredentials"] == [{"id": "-_8", "type": "public-key"}]


def test_shared_policy_keeps_password_recovery_limited_and_sso_mfa_explicit():
    from types import SimpleNamespace

    from arborpress.auth.policy import requires_second_factor

    user = SimpleNamespace(require_uv=False)
    auth_settings = SimpleNamespace(require_uv=False)
    policy = {"require_mfa_after_sso": False, "require_2fa_after_passkey": False}
    assert not requires_second_factor(
        user, "password", set(), auth_settings=auth_settings, webauthn_settings=policy
    )
    assert requires_second_factor(
        user, "password", {"webauthn"}, auth_settings=auth_settings, webauthn_settings=policy
    )
    assert not requires_second_factor(
        user, "sso", set(), auth_settings=auth_settings, webauthn_settings=policy
    )
    policy["require_mfa_after_sso"] = True
    assert requires_second_factor(
        user, "sso", {"totp"}, auth_settings=auth_settings, webauthn_settings=policy
    )


def test_webauthn_verification_uses_counter_policy(monkeypatch):
    observed = {}

    def verify(**kwargs):
        observed.update(kwargs)
        return object()

    monkeypatch.setattr("arborpress.auth.webauthn.webauthn.verify_authentication_response", verify)
    loose = WebAuthnService("example.test", "ArborPress", "https://example.test")
    loose.verify_authentication(object(), b"challenge", b"public", 42)
    assert observed["require_user_verification"] is True
    assert observed["credential_current_sign_count"] == 0

    strict = WebAuthnService(
        "example.test", "ArborPress", "https://example.test", counter_strict=True
    )
    strict.verify_authentication(object(), b"challenge", b"public", 42)
    assert observed["credential_current_sign_count"] == 42


@pytest.mark.asyncio
async def test_webauthn_settings_clamp_legacy_limits_and_ttl(monkeypatch):
    import arborpress.core.site_settings as settings

    async def legacy_values(section, db):
        return {
            "user_verification": "preferred",
            "challenge_ttl_seconds": 50_000,
            "webauthn_credential_limit": 500,
        }

    monkeypatch.setattr(settings, "get_section", legacy_values)
    effective = await settings.get_webauthn_settings(object())
    assert effective["user_verification"] == "required"
    assert effective["challenge_ttl_seconds"] == 900
    assert effective["webauthn_credential_limit"] == 100


@pytest.mark.asyncio
async def test_totp_limit_is_separate_and_hard_capped(monkeypatch):
    import arborpress.auth.mfa as mfa
    from arborpress.models.user import MFADeviceType

    async def policies(db):
        return {
            "totp_credential_limit": 500,
            "hotp_credential_limit": 10,
            "plugin_mfa_limit": 20,
        }

    monkeypatch.setattr("arborpress.core.site_settings.get_security_settings", policies)
    assert await mfa.get_device_limit(None, MFADeviceType.TOTP) == 50
    assert await mfa.get_device_limit(None, MFADeviceType.HOTP) == 10
    assert await mfa.get_device_limit(None, MFADeviceType.PLUGIN) == 20
    assert settings_defaults_totp_limit() == 5


def settings_defaults_totp_limit():
    from arborpress.core.site_settings import get_defaults

    return get_defaults("security")["totp_credential_limit"]


@pytest.mark.asyncio
async def test_username_first_begin_only_returns_that_users_credentials(
    client, test_engine, monkeypatch
):
    import arborpress.models  # noqa: F401
    from arborpress.models.user import User, WebAuthnCredential

    user_a, user_b = f"wa-{uuid.uuid4().hex[:12]}", f"wb-{uuid.uuid4().hex[:12]}"
    cred_a, cred_b = b"credential-a-" + uuid.uuid4().bytes, b"credential-b-" + uuid.uuid4().bytes
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        a = User(username=user_a, display_name=user_a)
        b = User(username=user_b, display_name=user_b)
        db.add_all([a, b])
        await db.flush()
        db.add_all([
            WebAuthnCredential(
                user_id=str(a.id), label="A", credential_id=cred_a, public_key=b"key-a"
            ),
            WebAuthnCredential(
                user_id=str(b.id), label="B", credential_id=cred_b, public_key=b"key-b"
            ),
        ])
        await db.commit()

    async def service():
        return WebAuthnService("localhost", "ArborPress", "http://localhost")

    monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", service)
    response = await client.post(
        "/auth/login/begin", json={"identifier": user_a}, content_type="application/json",
        headers={"Origin": "http://localhost:8066"},
    )
    assert response.status_code == 200
    payload = await response.get_json()
    assert payload["userVerification"] == "required"
    assert payload["allowCredentials"] == [
        {"id": _b64u(cred_a), "type": "public-key"}
    ]


@pytest.mark.asyncio
async def test_login_completion_cannot_use_another_users_credential(
    client, test_engine, monkeypatch
):
    import arborpress.models  # noqa: F401
    from arborpress.models.user import User, WebAuthnCredential

    name_a, name_b = f"ctx-a-{uuid.uuid4().hex[:12]}", f"ctx-b-{uuid.uuid4().hex[:12]}"
    cred_a, cred_b = b"ctx-credential-a-" + uuid.uuid4().bytes, b"ctx-credential-b-" + uuid.uuid4().bytes
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        a = User(username=name_a, display_name=name_a)
        b = User(username=name_b, display_name=name_b)
        db.add_all([a, b])
        await db.flush()
        db.add_all([
            WebAuthnCredential(
                user_id=str(a.id), label="A", credential_id=cred_a, public_key=b"key-a"
            ),
            WebAuthnCredential(
                user_id=str(b.id), label="B", credential_id=cred_b, public_key=b"key-b"
            ),
        ])
        await db.commit()

    async def service():
        return WebAuthnService("localhost", "ArborPress", "http://localhost")

    monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", service)
    begin = await client.post(
        "/auth/login/begin", json={"identifier": name_a}, content_type="application/json",
        headers={"Origin": "http://localhost:8066"},
    )
    assert begin.status_code == 200
    response = await client.post(
        "/auth/login/complete",
        json={"id": _b64u(cred_b), "rawId": _b64u(cred_b)},
        content_type="application/json",
        headers={"Origin": "http://localhost:8066"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_public_register_begin_does_not_open_username_enrollment(client, monkeypatch):
    async def service():
        return WebAuthnService("localhost", "ArborPress", "http://localhost")

    monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", service)
    response = await client.post(
        "/auth/register/begin",
        json={"user_name": "existing-user"},
        content_type="application/json",
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_pending_state_is_one_shot_and_expiry_checked(db_session):
    from arborpress.auth.pending import consume_pending, create_pending, utcnow_naive

    pending = await create_pending(
        db_session, purpose="test", user_id=None, ttl_seconds=300, challenge=b"challenge"
    )
    await db_session.commit()
    consumed = await consume_pending(db_session, pending_id=pending.id, purpose="test")
    assert consumed is not None
    await db_session.commit()
    replay = await consume_pending(db_session, pending_id=pending.id, purpose="test")
    assert replay is None

    expired = await create_pending(
        db_session, purpose="expired", user_id=None, ttl_seconds=300, challenge=b"challenge"
    )
    expired.expires_at = utcnow_naive()
    await db_session.commit()
    assert await consume_pending(
        db_session, pending_id=expired.id, purpose="expired"
    ) is None


@pytest.mark.asyncio
async def test_lockout_policy_counts_only_usable_paths(db_session, monkeypatch):
    from arborpress.auth.policy import assert_auth_path_remains, usable_auth_paths
    from arborpress.core.config import Settings
    from arborpress.models.user import MFADevice, MFADeviceType, User, WebAuthnCredential

    monkeypatch.setattr("arborpress.web.routes.sso.get_configured_providers", lambda: [])
    settings = Settings()
    settings.auth.legacy_password_enabled = True
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: settings)
    name = f"paths-{uuid.uuid4().hex[:12]}"
    user = User(username=name, display_name=name)
    db_session.add(user)
    await db_session.flush()

    credential = WebAuthnCredential(
        user_id=str(user.id), label="Only key",
        credential_id=uuid.uuid4().bytes, public_key=b"key",
    )
    db_session.add(credential)
    await db_session.flush()
    assert await usable_auth_paths(db_session, user) == {"webauthn"}
    with pytest.raises(ValueError):
        await assert_auth_path_remains(
            db_session, user, exclude_webauthn_id=str(credential.id)
        )

    await db_session.delete(credential)
    legacy_totp = MFADevice(
        user_id=str(user.id), device_type=MFADeviceType.TOTP,
        label="Legacy", secret_enc=b"encrypted", is_active=True,
        verification_status="unknown",
    )
    db_session.add(legacy_totp)
    await db_session.flush()
    assert await usable_auth_paths(db_session, user) == set()
    with pytest.raises(ValueError):
        await assert_auth_path_remains(db_session, user)

    legacy_totp.verification_status = "verified"
    assert await usable_auth_paths(db_session, user) == {"totp"}

    user.legacy_password_enabled = True
    user.legacy_password_hash = "test-hash"
    assert await usable_auth_paths(db_session, user) == {"totp", "password+second_factor"}
    await db_session.delete(legacy_totp)
    assert await usable_auth_paths(db_session, user) == {"password_recovery"}
    with pytest.raises(ValueError):
        await assert_auth_path_remains(db_session, user, exclude_password=True)


@pytest.mark.asyncio
async def test_last_active_admin_is_protected(db_session):
    from arborpress.auth.policy import is_last_active_admin
    from arborpress.models.user import User, UserRole

    name = f"admin-{uuid.uuid4().hex[:12]}"
    admin = User(username=name, display_name=name, role=UserRole.ADMIN)
    db_session.add(admin)
    await db_session.flush()
    assert await is_last_active_admin(db_session, admin)

    second = User(
        username=f"{name}-2", display_name=f"{name}-2", role=UserRole.ADMIN
    )
    db_session.add(second)
    await db_session.flush()
    assert not await is_last_active_admin(db_session, admin)
