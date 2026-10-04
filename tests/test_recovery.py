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
                "auth_method": "breakglass",
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
        from arborpress.models.user import AuthPending, UserSession

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        now = datetime.now(UTC).replace(tzinfo=None)
        session_id = str(uuid.uuid4())
        pending_id = str(uuid.uuid4())
        async with factory() as db:
            db.add_all([
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
                        "auth_method": "breakglass",
                        "authorized_by": "admin-1",
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
        assert pending is not None and pending.consumed_at is not None
        assert db_session_row is not None and not db_session_row.is_valid

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
    async def test_admin_authorized_breakglass_is_limited_and_replace_before_remove(
        self, client, test_engine, monkeypatch
    ):
        cfg = _recovery_settings(monkeypatch)
        admin_name = f"recovery-admin-{uuid.uuid4().hex[:8]}"
        target_name = f"recovery-target-{uuid.uuid4().hex[:8]}"
        admin_id, admin_session_id = await _seed_user(
            test_engine, username=admin_name, role="admin"
        )
        target_id, _ = await _seed_user(
            test_engine,
            username=target_name,
            role="editor",
            password=RECOVERY_TEST_SECRET,
        )
        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.models.user import MFADevice, MFADeviceType

            old_totp = MFADevice(
                user_id=target_id,
                device_type=MFADeviceType.TOTP,
                label="Old authenticator",
                secret_enc=b"existing-encrypted-secret",
                is_active=True,
                verification_status="verified",
            )
            db.add(old_totp)
            await db.commit()
            old_totp_id = str(old_totp.id)

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

        async with client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session["_csrf_token"] = "test-token"  # noqa: S105
        login = await client.post(
            "/auth/breakglass",
            form={
                "user_name": target_name,
                "password": RECOVERY_TEST_SECRET,
            },
        )
        assert login.status_code == 302
        assert login.headers["Location"].endswith("/auth/security")

        async with client.session_transaction() as browser_session:
            recovery_cookie = dict(browser_session)
            assert browser_session["user_id"] == target_id
            assert browser_session["recovery_only"] is True
            assert browser_session["auth_method"] == "recovery"
            assert browser_session["assurance_level"] == "recovery"
            assert browser_session["recovery_id"]

        security = await client.get("/auth/security")
        assert security.status_code == 200
        privileged = await client.get("/admin/users")
        assert privileged.status_code == 403
        body = await client.get("/")
        assert body.status_code == 403

        origin = cfg.web.base_url.rstrip("/")
        incomplete = await client.post(
            "/auth/recovery/complete",
            json={},
            headers={"Origin": origin},
        )
        assert incomplete.status_code == 409

        from urllib.parse import parse_qs, urlparse

        from arborpress.auth.mfa import TOTPService

        pending_enrollment = await client.post(
            "/auth/totp/begin",
            json={"label": "Replacement authenticator"},
            headers={"Origin": origin},
        )
        assert pending_enrollment.status_code == 200
        pending_uri = (await pending_enrollment.get_json())["provisioning_uri"]
        pending_secret = parse_qs(urlparse(pending_uri).query)["secret"][0].encode()
        assert pending_secret
        incomplete_pending_totp = await client.post(
            "/auth/recovery/complete",
            json={},
            headers={"Origin": origin},
        )
        assert incomplete_pending_totp.status_code == 409
        wrong_code = await client.post(
            "/auth/totp/complete",
            json={"code": "00000000"},
            headers={"Origin": origin},
        )
        assert wrong_code.status_code == 400

        verified_enrollment = await client.post(
            "/auth/totp/begin",
            json={"label": "Replacement authenticator"},
            headers={"Origin": origin},
        )
        assert verified_enrollment.status_code == 200
        verified_uri = (await verified_enrollment.get_json())["provisioning_uri"]
        verified_secret = parse_qs(urlparse(verified_uri).query)["secret"][0].encode()
        code = TOTPService().current_token(verified_secret)
        activated = await client.post(
            "/auth/totp/complete",
            json={"code": code},
            headers={"Origin": origin},
        )
        assert activated.status_code == 201

        removed_old = await client.post(
            f"/auth/totp/{old_totp_id}/remove",
            json={},
            headers={"Origin": origin},
        )
        assert removed_old.status_code == 200
        async with factory() as db:
            from arborpress.models.user import MFADevice

            assert await db.get(MFADevice, old_totp_id) is None

        completed = await client.post(
            "/auth/recovery/complete",
            json={},
            headers={"Origin": origin},
        )
        assert completed.status_code == 200
        assert (await completed.get_json())["login_required"] is True

        async with factory() as db:
            from sqlalchemy import or_

            from arborpress.models.audit import AuditEvent

            events = (await db.execute(
                select(AuditEvent).where(or_(
                    AuditEvent.actor_id == target_id,
                    AuditEvent.target_id == target_id,
                ))
            )).scalars().all()
        event_types = {event.event_type for event in events}
        assert {
            "recovery_authorized",
            "recovery_started",
            "recovery_proof_succeeded",
            "recovery_session_created",
            "recovery_credential_added",
            "recovery_credential_removed",
            "recovery_completed",
        }.issubset(event_types)
        audit_details = " ".join(event.detail or "" for event in events)
        assert RECOVERY_TEST_SECRET not in audit_details
        assert verified_secret.decode() not in audit_details
        assert code not in audit_details

        async with client.session_transaction() as browser_session:
            browser_session.clear()
            browser_session.update(recovery_cookie)
        replay = await client.get("/auth/security")
        assert replay.status_code == 401

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
