from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.auth.breakglass import hash_password
from arborpress.auth.stepup import grant_stepup

RECOVERY_TEST_SECRET = "correct horse battery staple"  # noqa: S105 - test fixture


async def _seed_user(test_engine, *, username: str, role: str, password: str | None = None):
    import arborpress.models  # noqa: F401
    from arborpress.models.user import AccountType, User, UserRole, UserSession

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=username,
            display_name=username,
            account_type=AccountType.OPERATIONAL,
            role=UserRole(role),
            is_active=True,
            legacy_password_hash=hash_password(password) if password else None,
            legacy_password_enabled=bool(password),
        )
        db.add(user)
        await db.flush()
        row = None
        if role == "admin":
            row = UserSession(
                user_id=str(user.id),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                last_seen_at=datetime.now(UTC),
                is_valid=True,
                is_tls=False,
                is_cli=False,
                auth_method="webauthn",
                assurance_level="user_verified",
            )
            db.add(row)
        await db.commit()
        return str(user.id), row.id if row else None


def _recovery_settings(monkeypatch):
    from arborpress.core.config import Settings

    cfg = Settings()
    cfg.auth.legacy_password_enabled = True
    cfg.auth.auth_rate_limit = "100/minute"
    cfg.logging.db_audit_log = True
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda *a, **kw: cfg)
    monkeypatch.setattr("arborpress.web.routes.auth.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.web.routes.admin.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

    async def no_csrf():
        return None

    monkeypatch.setattr("arborpress.web.routes.auth.validate_csrf", no_csrf)
    return cfg


class TestRecovery:
    @pytest.mark.asyncio
    async def test_recovery_state_is_user_session_purpose_and_expiry_bound(self, db_session):
        from arborpress.auth.sessions import (
            RECOVERY_PURPOSE,
            RECOVERY_SESSION_PURPOSE,
            get_active_recovery_state,
        )
        from arborpress.models.user import AuthPending, User, UserSession

        user = User(username=f"state-{uuid.uuid4().hex[:8]}", display_name="State")
        db_session.add(user)
        await db_session.flush()
        now = datetime.now(UTC).replace(tzinfo=None)
        session_id = str(uuid.uuid4())
        pending_id = str(uuid.uuid4())
        db_session_row = UserSession(
            id=session_id,
            user_id=str(user.id),
            expires_at=now + timedelta(minutes=15),
            last_seen_at=now,
            is_valid=True,
            is_tls=False,
            is_cli=False,
            auth_method="recovery",
            assurance_level="recovery",
        )
        pending = AuthPending(
            id=pending_id,
            user_id=str(user.id),
            purpose=RECOVERY_SESSION_PURPOSE,
            context=json.dumps({
                "session_id": session_id,
                "recovery_purpose": RECOVERY_PURPOSE,
                "auth_method": "recovery_ticket",
                "authorized_by": "admin-1",
            }),
            created_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        db_session.add_all([db_session_row, pending])
        await db_session.flush()
        cookie = {
            "user_id": str(user.id),
            "session_id": session_id,
            "recovery_id": pending_id,
            "recovery_only": True,
            "auth_method": "recovery",
            "assurance_level": "recovery",
            "recovery_purpose": RECOVERY_PURPOSE,
        }
        assert await get_active_recovery_state(db_session, cookie, db_session_row)

        wrong_user_cookie = {**cookie, "user_id": str(uuid.uuid4())}
        assert await get_active_recovery_state(
            db_session, wrong_user_cookie, db_session_row
        ) is None
        wrong_session_cookie = {**cookie, "session_id": str(uuid.uuid4())}
        assert await get_active_recovery_state(
            db_session, wrong_session_cookie
        ) is None

        pending.expires_at = now - timedelta(seconds=1)
        assert await get_active_recovery_state(db_session, cookie, db_session_row) is None
        assert pending.consumed_at is not None
        assert db_session_row.is_valid is False

    @pytest.mark.asyncio
    async def test_recovery_logout_consumes_state_and_invalidates_session(
        self, client, test_engine, monkeypatch
    ):
        _recovery_settings(monkeypatch)
        user_id, _ = await _seed_user(
            test_engine,
            username=f"logout-recovery-{uuid.uuid4().hex[:8]}",
            role="viewer",
        )
        from arborpress.auth.sessions import RECOVERY_PURPOSE, RECOVERY_SESSION_PURPOSE
        from arborpress.models.user import (
            AuthPending,
            MFADevice,
            MFADeviceType,
            UserSession,
            WebAuthnCredential,
        )

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        now = datetime.now(UTC).replace(tzinfo=None)
        session_id = str(uuid.uuid4())
        pending_id = str(uuid.uuid4())
        async with factory() as db:
            staged_key_id = str(uuid.uuid4())
            staged_totp_id = str(uuid.uuid4())
            staged_key = WebAuthnCredential(
                id=staged_key_id,
                user_id=user_id,
                label="Unfinished recovery key",
                credential_id=uuid.uuid4().bytes,
                public_key=b"staged-public-key",
                uv_capable=True,
                verification_status="recovery_pending",
            )
            staged_totp = MFADevice(
                id=staged_totp_id,
                user_id=user_id,
                device_type=MFADeviceType.TOTP,
                label="Unfinished recovery TOTP",
                secret_enc=b"staged-encrypted-secret",
                is_active=True,
                verification_status="recovery_pending",
            )
            db.add_all([
                staged_key,
                staged_totp,
                UserSession(
                    id=session_id,
                    user_id=user_id,
                    expires_at=now + timedelta(minutes=15),
                    last_seen_at=now,
                    is_valid=True,
                    is_tls=False,
                    is_cli=False,
                    auth_method="recovery",
                    assurance_level="recovery",
                ),
                AuthPending(
                    id=pending_id,
                    user_id=user_id,
                    purpose=RECOVERY_SESSION_PURPOSE,
                    context=json.dumps({
                        "session_id": session_id,
                        "recovery_purpose": RECOVERY_PURPOSE,
                        "auth_method": "recovery_ticket",
                        "authorized_by": "admin-1",
                        "recovery_webauthn_ids": [staged_key_id],
                        "recovery_totp_ids": [staged_totp_id],
                    }),
                    created_at=now,
                    expires_at=now + timedelta(minutes=15),
                ),
            ])
            await db.commit()

        async with client.session_transaction() as browser_session:
            browser_session.update({
                "user_id": user_id,
                "user_name": "recovery user",
                "user_role": "viewer",
                "account_type": "operational",
                "session_id": session_id,
                "recovery_id": pending_id,
                "recovery_only": True,
                "auth_method": "recovery",
                "assurance_level": "recovery",
                "recovery_purpose": RECOVERY_PURPOSE,
                "_csrf_token": "test-token",  # noqa: S105
            })

        response = await client.post(
            "/auth/logout",
            form={"_csrf": "test-token"},
        )
        assert response.status_code == 200
        async with factory() as db:
            pending = await db.get(AuthPending, pending_id)
            db_session_row = await db.get(UserSession, session_id)
            removed_key = await db.get(WebAuthnCredential, staged_key_id)
            removed_totp = await db.get(MFADevice, staged_totp_id)
        assert pending is not None and pending.consumed_at is not None
        assert db_session_row is not None and not db_session_row.is_valid
        assert removed_key is None
        assert removed_totp is None

    @pytest.mark.asyncio
    async def test_breakglass_alone_without_admin_authorization_creates_no_session(
        self, client, test_engine, monkeypatch
    ):
        _recovery_settings(monkeypatch)
        username = f"recovery-{uuid.uuid4().hex[:8]}"
        user_id, _ = await _seed_user(
            test_engine,
            username=username,
            role="viewer",
            password=RECOVERY_TEST_SECRET,
        )

        response = await client.post(
            "/auth/breakglass",
            form={
                "user_name": username,
                "password": RECOVERY_TEST_SECRET,
            },
        )
        assert response.status_code == 403
        async with client.session_transaction() as browser_session:
            assert not browser_session.get("session_id")
            assert not browser_session.get("recovery_only")

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.models.user import UserSession

            rows = (await db.execute(
                select(UserSession).where(UserSession.user_id == user_id)
            )).scalars().all()
        assert rows == []

    @pytest.mark.asyncio
    async def test_admin_ticket_recovery_replaces_pre_recovery_credentials(
        self, client, app, test_engine, monkeypatch
    ):
        import base64
        import hashlib
        import re
        from types import SimpleNamespace

        cfg = _recovery_settings(monkeypatch)
        from arborpress.auth.mfa import get_device_limit as original_totp_limit
        from arborpress.core.site_settings import get_webauthn_settings as original_wa_settings
        from arborpress.models.user import MFADeviceType

        async def capped_wa_settings(db):
            settings = await original_wa_settings(db)
            settings["webauthn_credential_limit"] = 2
            return settings

        async def capped_totp_limit(db, device_type):
            if device_type == MFADeviceType.TOTP:
                return 2
            return await original_totp_limit(db, device_type)

        monkeypatch.setattr(
            "arborpress.core.site_settings.get_webauthn_settings", capped_wa_settings
        )
        monkeypatch.setattr("arborpress.auth.mfa.get_device_limit", capped_totp_limit)
        admin_name = f"recovery-admin-{uuid.uuid4().hex[:8]}"
        target_name = f"recovery-target-{uuid.uuid4().hex[:8]}"
        admin_id, admin_session_id = await _seed_user(
            test_engine, username=admin_name, role="admin"
        )
        target_id, _ = await _seed_user(
            test_engine, username=target_name, role="editor", password=None
        )
        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.models.user import (
                MFADevice,
                MFADeviceType,
                UserSession,
                WebAuthnCredential,
            )

            old_keys = [
                WebAuthnCredential(
                    user_id=target_id,
                    label=f"Old key {index}",
                    credential_id=f"old-recovery-key-{index}-{uuid.uuid4().hex}".encode(),
                    public_key=b"old-public-key",
                    uv_capable=True,
                    verification_status="verified_uv",
                )
                for index in range(2)
            ]
            old_totps = [
                MFADevice(
                    user_id=target_id,
                    device_type=MFADeviceType.TOTP,
                    label=f"Old authenticator {index}",
                    secret_enc=b"existing-encrypted-secret",
                    is_active=True,
                    verification_status="verified",
                )
                for index in range(2)
            ]
            target_session = UserSession(
                user_id=target_id,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                last_seen_at=datetime.now(UTC),
                is_valid=True,
                is_tls=False,
                is_cli=False,
            )
            db.add_all([*old_keys, *old_totps, target_session])
            await db.commit()
            old_key_ids = {str(key.id) for key in old_keys}
            old_key_raw_ids = {key.credential_id for key in old_keys}
            old_totp_ids = {str(device.id) for device in old_totps}
            target_session_id = target_session.id

        async with client.session_transaction() as browser_session:
            browser_session["user_id"] = admin_id
            browser_session["user_name"] = admin_name
            browser_session["user_role"] = "admin"
            browser_session["account_type"] = "operational"
            browser_session["session_id"] = admin_session_id
            browser_session["_csrf_token"] = "test-token"  # noqa: S105
            await grant_stepup(
                browser_session,
                admin_id,
                "admin_credential_reset",
                target_id,
                auth_method="webauthn",
                assurance_level="user_verified",
                confirming_credential_id=str(uuid.uuid4()),
            )

        authorized = await client.post(
            f"/admin/users/{target_id}/auth-reset",
            form={"_csrf": "test-token", "confirm_username": target_name},
        )
        assert authorized.status_code == 200
        html = await authorized.get_data(as_text=True)
        ticket_match = re.search(r"<code>([0-9a-f-]+\.[A-Za-z0-9_-]{43})</code>", html)
        assert ticket_match is not None
        ticket = ticket_match.group(1)
        locator, secret_text = ticket.split(".", 1)
        secret = base64.urlsafe_b64decode(secret_text + "=")
        assert len(secret) == 32
        assert "Break-Glass-Passwort" not in html

        async with factory() as db:
            from arborpress.models.audit import AuditEvent
            from arborpress.models.user import AuthPending, User, UserSession

            authorization = await db.get(AuthPending, locator)
            target_session_row = await db.get(UserSession, target_session_id)
            target_user = await db.get(User, target_id)
            audit_events = (await db.execute(
                select(AuditEvent).where(AuditEvent.target_id == target_id)
            )).scalars().all()
        assert authorization is not None
        assert authorization.challenge == hashlib.sha256(secret).digest()
        assert secret_text not in (authorization.context or "")
        auth_context = json.loads(authorization.context or "{}")
        assert set(auth_context["baseline_webauthn_ids"]) == old_key_ids
        assert set(auth_context["baseline_totp_ids"]) == old_totp_ids
        assert target_session_row is not None and not target_session_row.is_valid
        assert target_user is not None
        assert target_user.legacy_password_enabled is False
        assert target_user.legacy_password_hash is None
        assert "recovery_ticket_issued" in {event.event_type for event in audit_events}
        assert secret_text not in " ".join(event.detail or "" for event in audit_events)

        wrong_secret = secret_text[:-1] + ("A" if secret_text[-1] != "A" else "B")
        rejected_ticket = await client.post(
            "/auth/recovery/redeem",
            form={"_csrf": "test-token", "ticket": f"{locator}.{wrong_secret}"},
        )
        assert rejected_ticket.status_code == 400

        from arborpress.auth.webauthn import WebAuthnService

        wa = WebAuthnService("localhost", "ArborPress", cfg.web.base_url.rstrip("/"))
        wa.verify_authentication = lambda *_args, **_kwargs: SimpleNamespace(
            new_sign_count=1
        )

        async def service():
            return wa

        monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", service)
        monkeypatch.setattr(
            "webauthn.helpers.parse_authentication_credential_json",
            lambda _raw: object(),
        )

        async def normal_login_is_blocked(normal_client):
            begin = await normal_client.post(
                "/auth/login/begin",
                json={"identifier": target_name},
                headers={"Origin": cfg.web.base_url.rstrip("/")},
            )
            assert begin.status_code == 200
            raw_id = next(iter(old_key_raw_ids))
            encoded = base64.urlsafe_b64encode(raw_id).rstrip(b"=").decode()
            assertion = {
                "id": encoded,
                "rawId": encoded,
                "type": "public-key",
                "response": {
                    "authenticatorData": base64.urlsafe_b64encode(
                        b"auth-data"
                    ).decode().rstrip("="),
                    "clientDataJSON": base64.urlsafe_b64encode(b"client-data").decode().rstrip("="),
                    "signature": base64.urlsafe_b64encode(b"signature").decode().rstrip("="),
                    "userHandle": None,
                },
            }
            return await normal_client.post(
                "/auth/login/complete",
                json=assertion,
                headers={"Origin": cfg.web.base_url.rstrip("/")},
            )

        async with app.test_client() as normal_client:
            assert (await normal_login_is_blocked(normal_client)).status_code == 423

        async with client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session["_csrf_token"] = "test-token"  # noqa: S105
        redeemed = await client.post(
            "/auth/recovery/redeem",
            form={"_csrf": "test-token", "ticket": ticket},
        )
        assert redeemed.status_code == 302
        assert redeemed.headers["Location"].endswith("/auth/security")
        async with client.session_transaction() as browser_session:
            recovery_cookie = dict(browser_session)
            assert browser_session["user_id"] == target_id
            assert browser_session["recovery_only"] is True
            assert browser_session["auth_method"] == "recovery"
            assert browser_session["assurance_level"] == "recovery"
            assert browser_session["recovery_id"]

        security = await client.get("/auth/security")
        assert security.status_code == 200
        assert (await client.get("/admin/users")).status_code == 403
        assert (await client.get("/")).status_code == 403
        async with app.test_client() as normal_client:
            assert (await normal_login_is_blocked(normal_client)).status_code == 423

        origin = cfg.web.base_url.rstrip("/")
        headers = {"Origin": origin}
        incomplete = await client.post("/auth/recovery/complete", json={}, headers=headers)
        assert incomplete.status_code == 409

        from urllib.parse import parse_qs, urlparse

        from arborpress.auth.mfa import TOTPService

        pending_totp = await client.post(
            "/auth/totp/begin", json={"label": "Recovery authenticator"}, headers=headers
        )
        assert pending_totp.status_code == 200
        pending_uri = (await pending_totp.get_json())["provisioning_uri"]
        pending_secret = parse_qs(urlparse(pending_uri).query)["secret"][0].encode()
        incomplete = await client.post("/auth/recovery/complete", json={}, headers=headers)
        assert incomplete.status_code == 409
        wrong = await client.post(
            "/auth/totp/complete", json={"code": "00000000"}, headers=headers
        )
        assert wrong.status_code == 400

        totp_begin = await client.post(
            "/auth/totp/begin", json={"label": "Recovery authenticator"}, headers=headers
        )
        totp_uri = (await totp_begin.get_json())["provisioning_uri"]
        new_totp_secret = parse_qs(urlparse(totp_uri).query)["secret"][0].encode()
        new_totp_code = TOTPService().current_token(new_totp_secret)
        totp_complete = await client.post(
            "/auth/totp/complete", json={"code": new_totp_code}, headers=headers
        )
        assert totp_complete.status_code == 201
        async with factory() as db:
            from arborpress.models.user import MFADevice, MFADeviceType

            staged_totp = (await db.execute(select(MFADevice).where(
                MFADevice.user_id == target_id,
                MFADevice.device_type == MFADeviceType.TOTP,
                MFADevice.label == "Recovery authenticator",
            ))).scalar_one()
            assert staged_totp.verification_status == "recovery_pending"
        assert (await client.post(
            "/auth/recovery/complete", json={}, headers=headers
        )).status_code == 409

        new_key_raw_id = b"new-recovery-fido-" + uuid.uuid4().bytes
        wa.verify_registration = lambda *_args, **_kwargs: SimpleNamespace(
            user_verified=True,
            credential_id=new_key_raw_id,
            credential_public_key=b"new-recovery-public-key",
            sign_count=0,
            aaguid="test-aaguid",
            credential_device_type=None,
            credential_backed_up=False,
        )

        async def service():
            return wa

        monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", service)
        monkeypatch.setattr(
            "webauthn.helpers.parse_registration_credential_json", lambda _raw: object()
        )
        register_begin = await client.post(
            "/auth/register/begin",
            json={"enrollment_kind": "security_key", "label": "New FIDO2"},
            headers=headers,
        )
        assert register_begin.status_code == 200
        new_key_b64 = base64.urlsafe_b64encode(new_key_raw_id).rstrip(b"=").decode()
        register_complete = await client.post(
            "/auth/register/complete",
            json={"id": new_key_b64, "rawId": new_key_b64, "label": "New FIDO2"},
            headers=headers,
        )
        assert register_complete.status_code == 201

        # Recovery-staged factors are not offered for a normal WebAuthn login.
        async with app.test_client() as normal_client:
            begin_login = await normal_client.post(
                "/auth/login/begin",
                json={"identifier": target_name},
                headers={"Origin": origin},
            )
            assert begin_login.status_code == 200
            offered = await begin_login.get_json()
            offered_ids = {item["id"] for item in offered["allowCredentials"]}
            assert new_key_b64 not in offered_ids
            assert old_key_raw_ids == {
                base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
                for value in offered_ids
            }

        completed = await client.post("/auth/recovery/complete", json={}, headers=headers)
        assert completed.status_code == 200
        assert (await completed.get_json())["login_required"] is True
        async with factory() as db:
            from sqlalchemy import or_

            from arborpress.auth.policy import usable_webauthn_credential_ids
            from arborpress.models.audit import AuditEvent
            from arborpress.models.user import (
                AuthPending,
                MFADevice,
                User,
                UserSession,
                WebAuthnCredential,
            )

            remaining_keys = (await db.execute(select(WebAuthnCredential).where(
                WebAuthnCredential.user_id == target_id
            ))).scalars().all()
            remaining_totp = (await db.execute(select(MFADevice).where(
                MFADevice.user_id == target_id,
                MFADevice.device_type == MFADeviceType.TOTP,
            ))).scalars().all()
            target_user = await db.get(User, target_id)
            recovery_state = await db.get(AuthPending, recovery_cookie["recovery_id"])
            events = (await db.execute(
                select(AuditEvent).where(or_(
                    AuditEvent.actor_id == target_id,
                    AuditEvent.target_id == target_id,
                ))
            )).scalars().all()
            usable_keys = await usable_webauthn_credential_ids(db, target_id)
        assert len(remaining_keys) == 1
        assert str(remaining_keys[0].id) in usable_keys
        assert remaining_keys[0].verification_status == "verified_uv"
        assert remaining_keys[0].credential_id == new_key_raw_id
        assert len(remaining_totp) == 1
        assert remaining_totp[0].verification_status == "verified"
        assert remaining_totp[0].is_active is True
        assert target_user is not None
        assert target_user.legacy_password_enabled is False
        assert target_user.legacy_password_hash is None
        assert recovery_state is not None and recovery_state.consumed_at is not None
        assert {
            "recovery_ticket_redeemed",
            "recovery_session_created",
            "recovery_credential_added",
            "recovery_credential_removed",
            "recovery_completed",
        }.issubset({event.event_type for event in events})
        audit_details = " ".join(event.detail or "" for event in events)
        assert ticket not in audit_details
        assert secret_text not in audit_details
        assert new_totp_secret.decode() not in audit_details
        assert new_totp_code not in audit_details
        assert pending_secret.decode() not in audit_details

        async with client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session["_csrf_token"] = "test-token"  # noqa: S105
        replay = await client.post(
            "/auth/recovery/redeem",
            form={"_csrf": "test-token", "ticket": ticket},
        )
        assert replay.status_code == 409
        async with factory() as db:
            replay_events = (await db.execute(select(AuditEvent).where(
                AuditEvent.target_id == target_id,
                AuditEvent.event_type == "recovery_ticket_replay",
            ))).scalars().all()
        assert replay_events

        async with client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session.update(recovery_cookie)
        assert (await client.get("/auth/security")).status_code == 401

    @pytest.mark.asyncio
    async def test_breakglass_with_normal_factor_still_requires_mfa(
        self, client, test_engine, monkeypatch
    ):
        _recovery_settings(monkeypatch)
        username = f"normal-mfa-{uuid.uuid4().hex[:8]}"
        user_id, _ = await _seed_user(
            test_engine,
            username=username,
            role="viewer",
            password=RECOVERY_TEST_SECRET,
        )
        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.models.user import WebAuthnCredential

            db.add(WebAuthnCredential(
                user_id=user_id,
                label="Existing key",
                credential_id=uuid.uuid4().bytes,
                public_key=b"existing-test-key",
                uv_capable=True,
                verification_status="verified_uv",
            ))
            await db.commit()

        response = await client.post(
            "/auth/breakglass",
            form={
                "user_name": username,
                "password": RECOVERY_TEST_SECRET,
            },
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/auth/mfa")
        async with client.session_transaction() as browser_session:
            assert browser_session.get("password_mfa_pending_id")
            assert not browser_session.get("session_id")
            assert not browser_session.get("recovery_only")

    @pytest.mark.asyncio
    async def test_breakglass_keeps_migrated_unknown_totp_on_normal_mfa_path(
        self, client, test_engine, monkeypatch
    ):
        _recovery_settings(monkeypatch)
        username = f"legacy-totp-{uuid.uuid4().hex[:8]}"
        user_id, _ = await _seed_user(
            test_engine,
            username=username,
            role="viewer",
            password=RECOVERY_TEST_SECRET,
        )
        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.models.user import MFADevice, MFADeviceType

            db.add(MFADevice(
                user_id=user_id,
                device_type=MFADeviceType.TOTP,
                label="Migrated authenticator",
                secret_enc=b"legacy-encrypted-secret",
                is_active=True,
                verification_status="unknown",
            ))
            await db.commit()

        response = await client.post(
            "/auth/breakglass",
            form={
                "user_name": username,
                "password": RECOVERY_TEST_SECRET,
            },
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/auth/mfa")
        async with client.session_transaction() as browser_session:
            assert browser_session.get("password_mfa_pending_id")
            assert not browser_session.get("session_id")
            assert not browser_session.get("recovery_only")
