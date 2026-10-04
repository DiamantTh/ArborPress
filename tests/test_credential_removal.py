"""Credential removal policy, step-up evidence, and serialization regressions."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from arborpress.auth.policy import (
    credential_removal_decision,
    lock_user_for_credential_change,
    recovery_has_new_auth_path,
    usable_totp_device_ids,
    usable_webauthn_credential_ids,
)
from arborpress.auth.stepup import StepUpEvidence


async def _user(db, prefix: str = "remove") -> str:
    from arborpress.models.user import User

    username = f"{prefix}-{uuid.uuid4().hex[:12]}"
    user = User(username=username, display_name=username)
    db.add(user)
    await db.flush()
    return str(user.id)


async def _webauthn(db, user_id: str, *, uv_capable: bool | None = True) -> str:
    from arborpress.models.user import WebAuthnCredential

    row = WebAuthnCredential(
        user_id=user_id,
        label=f"Key {uuid.uuid4().hex[:8]}",
        credential_id=uuid.uuid4().bytes,
        public_key=b"public-key",
        uv_capable=uv_capable,
        verification_status="unknown",
    )
    db.add(row)
    await db.flush()
    return str(row.id)


async def _totp(
    db,
    user_id: str,
    *,
    active: bool = True,
    status: str = "verified",
) -> str:
    from arborpress.models.user import MFADevice, MFADeviceType

    row = MFADevice(
        user_id=user_id,
        device_type=MFADeviceType.TOTP,
        label=f"OTP {uuid.uuid4().hex[:8]}",
        secret_enc=b"encrypted-secret",
        is_active=active,
        verification_status=status,
    )
    db.add(row)
    await db.flush()
    return str(row.id)


def _fido_evidence(credential_id: str) -> StepUpEvidence:
    return StepUpEvidence("webauthn", "user_verified", confirming_credential_id=credential_id)


def _totp_evidence(device_id: str) -> StepUpEvidence:
    return StepUpEvidence("totp", "otp_verified", confirming_mfa_device_id=device_id)


@pytest.mark.asyncio
async def test_webauthn_removal_requires_uv_and_enforces_remaining_factor_rules(db_session):
    user_id = await _user(db_session)
    three = [await _webauthn(db_session, user_id) for _ in range(3)]
    await _totp(db_session, user_id)

    # At 3+, any currently usable FIDO2 key, including the target, can confirm.
    for confirmer in three:
        result = await credential_removal_decision(
            db_session, user_id=user_id, credential_type="webauthn",
            target_id=three[0], evidence=_fido_evidence(confirmer),
        )
        assert result.allowed
        assert result.usable_count == 3

    two_user = await _user(db_session, "two-fido")
    two = [await _webauthn(db_session, two_user) for _ in range(2)]
    assert (await credential_removal_decision(
        db_session, user_id=two_user, credential_type="webauthn", target_id=two[0],
        evidence=_fido_evidence(two[1]),
    )).allowed
    self_confirm = await credential_removal_decision(
        db_session, user_id=two_user, credential_type="webauthn", target_id=two[0],
        evidence=_fido_evidence(two[0]),
    )
    assert not self_confirm.allowed
    assert self_confirm.reason == "different_webauthn_required"

    # The WebAuthn 1 -> 0 rule is independent of another factor's presence.
    one_user = await _user(db_session, "single-fido")
    only_key = await _webauthn(db_session, one_user)
    await _totp(db_session, one_user)
    last = await credential_removal_decision(
        db_session, user_id=one_user, credential_type="webauthn", target_id=only_key,
        evidence=_fido_evidence(only_key),
    )
    assert not last.allowed and last.reason == "last_webauthn_credential"

    assert not (await credential_removal_decision(
        db_session, user_id=user_id, credential_type="webauthn", target_id=three[0],
        evidence=_totp_evidence(await _totp(db_session, user_id)),
    )).allowed
    assert not (await credential_removal_decision(
        db_session, user_id=user_id, credential_type="webauthn", target_id=three[0],
        evidence=StepUpEvidence("password", "password"),
    )).allowed

    other_user = await _user(db_session, "foreign-fido")
    foreign_key = await _webauthn(db_session, other_user)
    cross_user = await credential_removal_decision(
        db_session, user_id=user_id, credential_type="webauthn", target_id=three[0],
        evidence=_fido_evidence(foreign_key),
    )
    assert not cross_user.allowed


@pytest.mark.asyncio
async def test_webauthn_only_one_remaining_is_a_valid_account_path(db_session, monkeypatch):
    from arborpress.auth.policy import usable_auth_paths
    from arborpress.core.config import Settings

    monkeypatch.setattr("arborpress.web.routes.sso.get_configured_providers", lambda: [])
    settings = Settings()
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: settings)
    user_id = await _user(db_session, "passkey-only")
    key_id = await _webauthn(db_session, user_id)
    from arborpress.models.user import User

    user = await db_session.get(User, user_id)
    assert await usable_auth_paths(db_session, user) == {"webauthn"}
    decision = await credential_removal_decision(
        db_session, user_id=user_id, credential_type="webauthn", target_id=key_id,
        evidence=_fido_evidence(key_id),
    )
    assert not decision.allowed
    assert await usable_webauthn_credential_ids(db_session, user_id) == {key_id}


@pytest.mark.asyncio
async def test_recovery_completion_requires_a_new_usable_factor(db_session):
    from arborpress.models.user import User

    user_id = await _user(db_session, "recovery-factor")
    old_key = await _webauthn(db_session, user_id)
    old_totp = await _totp(db_session, user_id)
    user = await db_session.get(User, user_id)
    recovery_context = {
        "baseline_webauthn_ids": [old_key],
        "baseline_totp_ids": [old_totp],
    }
    assert not await recovery_has_new_auth_path(
        db_session, user, recovery_context
    )

    # Pending or unconfirmed TOTP records do not count as a replacement.
    await _totp(db_session, user_id, active=False, status="pending")
    await _totp(db_session, user_id, active=True, status="unknown")
    assert not await recovery_has_new_auth_path(
        db_session, user, recovery_context
    )

    new_key = await _webauthn(db_session, user_id)
    assert await recovery_has_new_auth_path(
        db_session, user, recovery_context
    )
    assert not await recovery_has_new_auth_path(
        db_session,
        user,
        recovery_context,
        exclude_webauthn_id=new_key,
    )


@pytest.mark.asyncio
async def test_totp_removal_policy_supports_totp_and_fido2_stepup(db_session):
    user_id = await _user(db_session, "totp-three")
    fido = await _webauthn(db_session, user_id)
    totp_ids = [await _totp(db_session, user_id) for _ in range(3)]
    for evidence in (
        _totp_evidence(totp_ids[0]),
        _totp_evidence(totp_ids[2]),
        _fido_evidence(fido),
    ):
        result = await credential_removal_decision(
            db_session, user_id=user_id, credential_type="totp",
            target_id=totp_ids[0], evidence=evidence,
        )
        assert result.allowed and result.usable_count == 3

    two_user = await _user(db_session, "totp-two")
    two_fido = await _webauthn(db_session, two_user)
    two_totp = [await _totp(db_session, two_user) for _ in range(2)]
    other_totp = await credential_removal_decision(
        db_session, user_id=two_user, credential_type="totp", target_id=two_totp[0],
        evidence=_totp_evidence(two_totp[1]),
    )
    assert other_totp.allowed
    self_totp = await credential_removal_decision(
        db_session, user_id=two_user, credential_type="totp", target_id=two_totp[0],
        evidence=_totp_evidence(two_totp[0]),
    )
    assert not self_totp.allowed and self_totp.reason == "different_totp_required"
    assert (await credential_removal_decision(
        db_session, user_id=two_user, credential_type="totp", target_id=two_totp[0],
        evidence=_fido_evidence(two_fido),
    )).allowed

    one_user = await _user(db_session, "totp-one")
    only_totp = await _totp(db_session, one_user)
    no_fido = await credential_removal_decision(
        db_session, user_id=one_user, credential_type="totp", target_id=only_totp,
        evidence=_totp_evidence(only_totp),
    )
    assert not no_fido.allowed
    assert no_fido.reason == "last_totp_requires_webauthn"
    one_fido = await _webauthn(db_session, one_user)
    with_fido_totp_proof = await credential_removal_decision(
        db_session, user_id=one_user, credential_type="totp", target_id=only_totp,
        evidence=_totp_evidence(only_totp),
    )
    assert not with_fido_totp_proof.allowed
    assert (await credential_removal_decision(
        db_session, user_id=one_user, credential_type="totp", target_id=only_totp,
        evidence=_fido_evidence(one_fido),
    )).allowed

    assert not (await credential_removal_decision(
        db_session, user_id=two_user, credential_type="totp", target_id=two_totp[0],
        evidence=StepUpEvidence("password", "password"),
    )).allowed


@pytest.mark.asyncio
async def test_unconfirmed_inactive_and_pending_totp_are_not_removal_paths(db_session):
    from arborpress.auth.pending import create_pending

    user_id = await _user(db_session, "totp-unusable")
    fido_id = await _webauthn(db_session, user_id)
    unknown = await _totp(db_session, user_id, status="unknown")
    inactive = await _totp(db_session, user_id, active=False)
    await create_pending(
        db_session, purpose="totp_enrollment", user_id=user_id,
        ttl_seconds=300, label="Pending authenticator",
    )
    decision = await credential_removal_decision(
        db_session, user_id=user_id, credential_type="totp", target_id=unknown,
        evidence=_fido_evidence(fido_id),
    )
    assert decision.allowed and decision.usable_count == 0
    assert await usable_totp_device_ids(db_session, user_id) == set()
    inactive_decision = await credential_removal_decision(
        db_session, user_id=user_id, credential_type="totp", target_id=inactive,
        evidence=_fido_evidence(fido_id),
    )
    assert inactive_decision.allowed and inactive_decision.usable_count == 0


@pytest.mark.asyncio
async def test_stepup_rejects_wrong_auth_method_assurance_and_replay(db_session):
    from arborpress.auth.stepup import assert_stepup, grant_stepup

    user_id = await _user(db_session, "step-up-method")
    session = {"session_id": str(uuid.uuid4())}
    await grant_stepup(
        session, user_id, "remove_webauthn_credential", "target-key",
        auth_method="totp", assurance_level="otp_verified",
        confirming_mfa_device_id=str(uuid.uuid4()), db=db_session,
    )
    with pytest.raises(PermissionError):
        await assert_stepup(
            session, user_id, "remove_webauthn_credential", "target-key",
            required_evidence={"webauthn": "user_verified"}, db=db_session,
        )
    evidence = await assert_stepup(
        session, user_id, "remove_webauthn_credential", "target-key",
        required_evidence={"totp": "otp_verified"}, db=db_session,
    )
    assert evidence is not None and evidence.auth_method == "totp"
    with pytest.raises(PermissionError):
        await assert_stepup(
            session, user_id, "remove_webauthn_credential", "target-key", db=db_session
        )


@pytest.mark.asyncio
async def test_stepup_rejects_another_session_and_expired_grants(db_session):
    from arborpress.auth.stepup import assert_stepup, grant_stepup
    from arborpress.models.user import StepUpGrant

    user_id = await _user(db_session, "step-up-session")
    original = {"session_id": str(uuid.uuid4())}
    await grant_stepup(
        original, user_id, "remove_webauthn_credential", "target-key",
        auth_method="webauthn", assurance_level="user_verified",
        confirming_credential_id="confirming-key", db=db_session,
    )
    copied_to_other_session = {
        "session_id": str(uuid.uuid4()),
        "_arborpress_stepup_grants": original["_arborpress_stepup_grants"],
    }
    with pytest.raises(PermissionError):
        await assert_stepup(
            copied_to_other_session, user_id,
            "remove_webauthn_credential", "target-key", db=db_session,
        )

    grant = (await db_session.execute(select(StepUpGrant).where(
        StepUpGrant.user_id == user_id,
    ))).scalar_one()
    grant.expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
    with pytest.raises(PermissionError):
        await assert_stepup(
            original, user_id, "remove_webauthn_credential", "target-key", db=db_session,
        )


@pytest.mark.asyncio
async def test_webauthn_remove_route_enforces_three_two_one_rules(
    client, test_engine, monkeypatch
):
    from arborpress.auth.stepup import grant_stepup
    from arborpress.models.user import (
        MFADevice,
        MFADeviceType,
        User,
        UserSession,
        WebAuthnCredential,
    )

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    async with factory() as db:
        name = f"fido-remove-{uuid.uuid4().hex[:8]}"
        user = User(username=name, display_name=name)
        db.add(user)
        await db.flush()
        user_id = str(user.id)
        db_session = UserSession(
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC),
            is_valid=True,
            is_tls=False,
            is_cli=False,
        )
        db.add(db_session)
        credentials = []
        for index in range(3):
            credential = WebAuthnCredential(
                user_id=user_id,
                label=f"Security key {index}",
                credential_id=uuid.uuid4().bytes,
                public_key=b"public-key",
                uv_capable=True,
            )
            credentials.append(credential)
            db.add(credential)
        # A different factor cannot authorize FIDO2 credential removal.
        db.add(MFADevice(
            user_id=user_id,
            device_type=MFADeviceType.TOTP,
            label="Authenticator",
            secret_enc=b"encrypted-secret",
            is_active=True,
            verification_status="verified",
        ))
        await db.commit()
        session_id = db_session.id
        credential_ids = [str(item.id) for item in credentials]

    async with client.session_transaction() as browser_session:
        browser_session.update(
            {"user_id": user_id, "user_name": name, "session_id": session_id}
        )

    headers = {"Origin": "http://localhost:8066"}

    async def authorize(target_id: str, confirming_id: str) -> None:
        async with client.session_transaction() as browser_session:
            async with factory() as db:
                await grant_stepup(
                    browser_session,
                    user_id,
                    "remove_webauthn_credential",
                    target_id,
                    auth_method="webauthn",
                    assurance_level="user_verified",
                    confirming_credential_id=confirming_id,
                    db=db,
                )
                await db.commit()

    async def remove(target_id: str, confirming_id: str):
        await authorize(target_id, confirming_id)
        return await client.post(
            f"/auth/credentials/{target_id}/remove", json={}, headers=headers
        )

    # At 3 -> 2, the target credential may confirm its own removal.
    first = await remove(credential_ids[0], credential_ids[0])
    assert first.status_code == 200

    # At 2 -> 1, self-confirmation is rejected and consumes that grant.
    self_confirm = await remove(credential_ids[1], credential_ids[1])
    assert self_confirm.status_code == 409
    # The other remaining credential can then confirm the removal.
    other_confirm = await remove(credential_ids[1], credential_ids[2])
    assert other_confirm.status_code == 200

    # FIDO2 1 -> 0 is blocked even though a valid TOTP remains.
    last = await remove(credential_ids[2], credential_ids[2])
    assert last.status_code == 409
    async with factory() as db:
        remaining = (await db.execute(select(WebAuthnCredential.id).where(
            WebAuthnCredential.user_id == user_id,
        ))).scalars().all()
        assert [str(value) for value in remaining] == [credential_ids[2]]


@pytest.mark.asyncio
async def test_totp_stepup_route_uses_shared_grant_and_allows_three_to_two_remove(
    client, test_engine, monkeypatch
):
    from arborpress.auth.mfa import TOTPService, encrypt_secret
    from arborpress.models.user import (
        MFADevice,
        MFADeviceType,
        StepUpGrant,
        User,
        UserSession,
    )

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    async with factory() as db:
        name = f"totp-http-{uuid.uuid4().hex[:8]}"
        user = User(username=name, display_name=name)
        db.add(user)
        await db.flush()
        user_id = str(user.id)
        db_session = UserSession(
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC),
            is_valid=True,
            is_tls=False,
            is_cli=False,
        )
        db.add(db_session)
        totp_service = TOTPService()
        devices = []
        for index in range(3):
            secret = totp_service.generate_secret()
            device = MFADevice(
                user_id=user_id,
                device_type=MFADeviceType.TOTP,
                label=f"Authenticator {index}",
                secret_enc=encrypt_secret(secret),
                is_active=True,
                verification_status="verified",
            )
            devices.append((device, secret))
            db.add(device)
        await db.commit()
        session_id = db_session.id
        target_id = str(devices[0][0].id)
        confirming_id = str(devices[0][0].id)
        code = totp_service.current_token(devices[0][1])

    async with client.session_transaction() as browser_session:
        browser_session["user_id"] = user_id
        browser_session["user_name"] = name
        browser_session["session_id"] = session_id

    headers = {"Origin": "http://localhost:8066"}
    begin = await client.post(
        "/auth/stepup/begin",
        json={"action": "remove_totp_credential", "target": target_id},
        headers=headers,
    )
    assert begin.status_code == 200
    assert (await begin.get_json())["totp_only"] is True

    complete = await client.post(
        "/auth/stepup/totp/complete", json={"code": code}, headers=headers
    )
    assert complete.status_code == 200
    async with factory() as db:
        grant = (await db.execute(select(StepUpGrant).where(
            StepUpGrant.user_id == user_id,
            StepUpGrant.action == "remove_totp_credential",
            StepUpGrant.target == target_id,
        ))).scalar_one()
        assert grant.auth_method == "totp"
        assert grant.assurance_level == "otp_verified"
        assert grant.confirming_mfa_device_id == confirming_id

    removed = await client.post(
        f"/auth/totp/{target_id}/remove", json={}, headers=headers
    )
    assert removed.status_code == 200
    async with factory() as db:
        count = (await db.execute(select(func.count()).select_from(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
            MFADevice.verification_status == "verified",
        ))).scalar_one()
        assert count == 2


@pytest.mark.asyncio
async def test_totp_enrollment_is_pending_until_verified_and_each_secret_is_independent(
    client, test_engine, monkeypatch
):
    import pyotp

    from arborpress.auth.mfa import TOTPService, decrypt_secret
    from arborpress.auth.stepup import grant_stepup
    from arborpress.models.user import MFADevice, MFADeviceType, User, UserSession

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    async with factory() as db:
        name = f"totp-enroll-{uuid.uuid4().hex[:8]}"
        user = User(username=name, display_name=name)
        db.add(user)
        await db.flush()
        user_id = str(user.id)
        db_session = UserSession(
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC),
            is_valid=True,
            is_tls=False,
            is_cli=False,
        )
        db.add(db_session)
        await db.commit()
        session_id = db_session.id

    async with client.session_transaction() as browser_session:
        browser_session.update(
            {"user_id": user_id, "user_name": name, "session_id": session_id}
        )

    headers = {"Origin": "http://localhost:8066"}
    service = TOTPService()

    async def begin(label: str) -> dict:
        async with client.session_transaction() as browser_session:
            await grant_stepup(
                browser_session,
                user_id,
                "add_totp_credential",
                user_id,
                auth_method="webauthn",
                assurance_level="user_verified",
                confirming_credential_id=str(uuid.uuid4()),
            )
        response = await client.post(
            "/auth/totp/begin", json={"label": label}, headers=headers
        )
        assert response.status_code == 200
        return await response.get_json()

    first = await begin("Phone one")
    first_secret = pyotp.parse_uri(first["provisioning_uri"]).secret.encode()
    async with factory() as db:
        assert (await db.execute(select(func.count()).select_from(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
        ))).scalar_one() == 0
    invalid_code = "00000000"
    while service.verify(first_secret, invalid_code, user_id=user_id):
        invalid_code = f"{(int(invalid_code) + 1) % 100000000:08d}"
    rejected = await client.post(
        "/auth/totp/complete", json={"code": invalid_code}, headers=headers
    )
    assert rejected.status_code == 400
    async with factory() as db:
        assert (await db.execute(select(func.count()).select_from(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
        ))).scalar_one() == 0

    accepted = await begin("Phone one")
    accepted_secret = pyotp.parse_uri(accepted["provisioning_uri"]).secret.encode()
    completed = await client.post(
        "/auth/totp/complete",
        json={"code": service.current_token(accepted_secret)},
        headers=headers,
    )
    assert completed.status_code == 201

    second = await begin("Tablet")
    second_secret = pyotp.parse_uri(second["provisioning_uri"]).secret.encode()
    completed = await client.post(
        "/auth/totp/complete",
        json={"code": service.current_token(second_secret)},
        headers=headers,
    )
    assert completed.status_code == 201
    async with factory() as db:
        devices = (await db.execute(select(MFADevice).where(
            MFADevice.user_id == user_id,
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
            MFADevice.verification_status == "verified",
        ))).scalars().all()
        assert {device.label for device in devices} == {"Phone one", "Tablet"}
        persisted_secrets = {decrypt_secret(device.secret_enc) for device in devices}
        assert len(persisted_secrets) == 2


@pytest.mark.asyncio
async def test_web_authn_stepup_persists_only_verified_fido_evidence(
    client, test_engine, monkeypatch
):
    import base64
    from types import SimpleNamespace

    from arborpress.auth.webauthn import WebAuthnService
    from arborpress.models.user import StepUpGrant, User, UserSession, WebAuthnCredential

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    credential_raw_id = b"stepup-credential-" + uuid.uuid4().bytes
    async with factory() as db:
        name = f"fido-stepup-{uuid.uuid4().hex[:8]}"
        user = User(username=name, display_name=name)
        db.add(user)
        await db.flush()
        user_id = str(user.id)
        credential = WebAuthnCredential(
            user_id=user_id,
            label="Security key",
            credential_id=credential_raw_id,
            public_key=b"public-key",
            uv_capable=True,
        )
        db.add(credential)
        db_session = UserSession(
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC),
            is_valid=True,
            is_tls=False,
            is_cli=False,
        )
        db.add(db_session)
        await db.commit()
        session_id = db_session.id
        credential_row_id = str(credential.id)

    verification_uv = {"value": False}
    wa = WebAuthnService("localhost", "ArborPress", "http://localhost:8066")
    wa.verify_authentication = lambda **_: SimpleNamespace(
        user_verified=verification_uv["value"], new_sign_count=1
    )

    async def service():
        return wa

    monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", service)
    async with client.session_transaction() as browser_session:
        browser_session.update(
            {"user_id": user_id, "user_name": name, "session_id": session_id}
        )

    headers = {"Origin": "http://localhost:8066"}
    action = "remove_webauthn_credential"
    begin = await client.post(
        "/auth/stepup/begin",
        json={"action": action, "target": credential_row_id},
        headers=headers,
    )
    assert begin.status_code == 200
    credential_b64 = base64.urlsafe_b64encode(credential_raw_id).decode().rstrip("=")
    assertion = {
        "id": credential_b64,
        "rawId": credential_b64,
        "type": "public-key",
        "response": {
            "authenticatorData": base64.urlsafe_b64encode(b"auth-data").decode().rstrip("="),
            "clientDataJSON": base64.urlsafe_b64encode(b"client-data").decode().rstrip("="),
            "signature": base64.urlsafe_b64encode(b"signature").decode().rstrip("="),
            "userHandle": None,
        },
    }
    rejected = await client.post(
        "/auth/stepup/complete", json=assertion, headers=headers
    )
    assert rejected.status_code == 401
    async with factory() as db:
        assert (await db.execute(select(func.count()).select_from(StepUpGrant).where(
            StepUpGrant.user_id == user_id,
        ))).scalar_one() == 0

    verification_uv["value"] = True
    begin = await client.post(
        "/auth/stepup/begin",
        json={"action": action, "target": credential_row_id},
        headers=headers,
    )
    assert begin.status_code == 200
    accepted = await client.post(
        "/auth/stepup/complete", json=assertion, headers=headers
    )
    assert accepted.status_code == 200
    async with factory() as db:
        grant = (await db.execute(select(StepUpGrant).where(
            StepUpGrant.user_id == user_id,
            StepUpGrant.action == action,
        ))).scalar_one()
        assert grant.auth_method == "webauthn"
        assert grant.assurance_level == "user_verified"
        assert grant.confirming_credential_id == credential_row_id


@pytest.mark.asyncio
async def test_concurrent_webauthn_removals_cannot_remove_both_remaining_keys(test_engine):
    from arborpress.models.user import WebAuthnCredential

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user_id = await _user(db, "race-fido")
        key_a = await _webauthn(db, user_id)
        key_b = await _webauthn(db, user_id)
        await db.commit()

    async def remove(target_id: str, confirmer_id: str) -> bool:
        async with factory() as db:
            async with db.begin():
                user = await lock_user_for_credential_change(db, user_id)
                assert user is not None
                decision = await credential_removal_decision(
                    db, user_id=user_id, credential_type="webauthn", target_id=target_id,
                    evidence=_fido_evidence(confirmer_id),
                )
                if not decision.allowed:
                    return False
                row = await db.get(WebAuthnCredential, target_id)
                assert row is not None
                await db.delete(row)
                return True

    decisions = await asyncio.gather(remove(key_a, key_b), remove(key_b, key_a))
    assert sum(decisions) == 1
    async with factory() as db:
        remaining = await usable_webauthn_credential_ids(db, user_id)
        assert len(remaining) == 1


@pytest.mark.asyncio
async def test_concurrent_totp_removals_cannot_remove_both_remaining_devices(test_engine):
    from arborpress.models.user import MFADevice

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user_id = await _user(db, "race-totp")
        device_a = await _totp(db, user_id)
        device_b = await _totp(db, user_id)
        await db.commit()

    async def remove(target_id: str, confirming_id: str) -> bool:
        async with factory() as db:
            async with db.begin():
                user = await lock_user_for_credential_change(db, user_id)
                assert user is not None
                decision = await credential_removal_decision(
                    db, user_id=user_id, credential_type="totp", target_id=target_id,
                    evidence=_totp_evidence(confirming_id),
                )
                if not decision.allowed:
                    return False
                row = await db.get(MFADevice, target_id)
                assert row is not None
                await db.delete(row)
                return True

    decisions = await asyncio.gather(
        remove(device_a, device_b),
        remove(device_b, device_a),
    )
    assert sum(decisions) == 1
    async with factory() as db:
        remaining = await usable_totp_device_ids(db, user_id)
        assert len(remaining) == 1


@pytest.mark.asyncio
async def test_stepup_grant_schema_migration_preserves_existing_rows():
    from arborpress.core.db import _add_column_if_missing

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.execute(text(
                "CREATE TABLE auth_stepup_grants ("
                "id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NOT NULL, "
                "session_id VARCHAR(36) NOT NULL, action VARCHAR(48) NOT NULL, "
                "target VARCHAR(512) NOT NULL, created_at DATETIME NOT NULL, "
                "expires_at DATETIME NOT NULL, consumed_at DATETIME)"
            ))
            await conn.execute(text(
                "INSERT INTO auth_stepup_grants "
                "(id,user_id,session_id,action,target,created_at,expires_at) "
                "VALUES ('old','user','session','remove_totp_credential','target',"
                "CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
            ))
            await _add_column_if_missing(
                conn, "auth_stepup_grants", "auth_method", "VARCHAR(32) NOT NULL DEFAULT 'unknown'"
            )
            await _add_column_if_missing(
                conn, "auth_stepup_grants", "assurance_level",
                "VARCHAR(32) NOT NULL DEFAULT 'unknown'",
            )
            await _add_column_if_missing(
                conn, "auth_stepup_grants", "confirming_credential_id", "VARCHAR(36)"
            )
            await _add_column_if_missing(
                conn, "auth_stepup_grants", "confirming_mfa_device_id", "VARCHAR(36)"
            )
            row = (await conn.execute(text(
                "SELECT id, auth_method, assurance_level, confirming_credential_id, "
                "confirming_mfa_device_id FROM auth_stepup_grants WHERE id='old'"
            ))).one()
            assert row == ("old", "unknown", "unknown", None, None)
    finally:
        await engine.dispose()
