from __future__ import annotations

import base64
import hashlib
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.auth.breakglass import hash_password
from arborpress.auth.stepup import grant_stepup


async def _seed_admin_user(test_engine, *, username: str = "adminuser") -> tuple[str, str]:
    import arborpress.models  # noqa: F401
    from arborpress.models.user import AccountType, User, UserRole, UserSession

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=username,
            display_name="Admin User",
            account_type=AccountType.OPERATIONAL,
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        user_session = UserSession(
            user_id=user.id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            last_seen_at=datetime.now(UTC),
            is_valid=True,
            is_tls=False,
            is_cli=False,
        )
        db.add(user_session)
        await db.commit()
        return str(user.id), user_session.id


async def _seed_target_user(test_engine, *, username: str = "targetuser") -> str:
    import arborpress.models  # noqa: F401
    from arborpress.models.user import AccountType, User, UserRole

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=username,
            display_name="Target User",
            account_type=AccountType.OPERATIONAL,
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        return str(user.id)


class TestAdminBreakglassUsers:
    @pytest.mark.asyncio
    async def test_admin_can_set_breakglass_password_from_users_page(
        self, client, test_engine, monkeypatch
    ):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

        admin_user_id, session_id = await _seed_admin_user(test_engine)
        target_user_id = await _seed_target_user(test_engine)

        async with client.session_transaction() as sess:
            sess["user_id"] = admin_user_id
            sess["user_name"] = "adminuser"
            sess["user_role"] = "admin"
            sess["account_type"] = "operational"
            sess["session_id"] = session_id
            await grant_stepup(
                sess,
                user_id=admin_user_id,
                action="set_breakglass_password",
                target=target_user_id,
            )
            sess["_csrf_token"] = "test-token"  # noqa: S105 - test-only CSRF fixture

        response = await client.post(
            f"/admin/users/{target_user_id}/breakglass-password",
            form={
                "_csrf": "test-token",
                "mode": "manual",
                "password": "correct horse battery staple",
            },
        )

        assert response.status_code == 200
        text = await response.get_data(as_text=True)
        assert "Break-Glass-Passwort fuer targetuser gesetzt." in text

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.models.user import User

            target_user = await db.get(User, target_user_id)
            assert target_user is not None
            assert target_user.legacy_password_enabled is True
        assert target_user.legacy_password_hash is not None
        assert target_user.legacy_password_hash != hash_password("correct horse battery staple")

    @pytest.mark.asyncio
    async def test_admin_recovery_authorization_works_for_passwordless_accounts(
        self, client, test_engine, monkeypatch
    ):
        from arborpress.core.config import Settings

        cfg = Settings()
        monkeypatch.setattr("arborpress.web.routes.admin.get_settings", lambda: cfg)
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        admin_name = f"reset-admin-{uuid.uuid4().hex[:8]}"
        target_name = f"reset-target-{uuid.uuid4().hex[:8]}"
        admin_user_id, session_id = await _seed_admin_user(test_engine, username=admin_name)
        target_user_id = await _seed_target_user(test_engine, username=target_name)

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.models.user import (
                MFADevice,
                MFADeviceType,
                User,
                UserSession,
                WebAuthnCredential,
            )

            target = await db.get(User, target_user_id)
            credential = WebAuthnCredential(
                user_id=target_user_id,
                label="Lost key",
                credential_id=uuid.uuid4().bytes,
                public_key=b"test-public-key",
            )
            totp = MFADevice(
                user_id=target_user_id,
                device_type=MFADeviceType.TOTP,
                label="Lost phone",
                secret_enc=b"encrypted-secret",
                is_active=True,
                verification_status="verified",
            )
            target_session = UserSession(
                user_id=target_user_id,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
                last_seen_at=datetime.now(UTC),
                is_valid=True,
                is_tls=False,
                is_cli=False,
            )
            db.add_all([credential, totp, target_session])
            await db.commit()
            target_session_id = target_session.id

        async with client.session_transaction() as sess:
            sess["user_id"] = admin_user_id
            sess["user_name"] = admin_name
            sess["user_role"] = "admin"
            sess["account_type"] = "operational"
            sess["session_id"] = session_id
            await grant_stepup(
                sess,
                user_id=admin_user_id,
                action="admin_credential_reset",
                target=target_user_id,
                auth_method="webauthn",
                assurance_level="user_verified",
                confirming_credential_id=str(uuid.uuid4()),
            )
            sess["_csrf_token"] = "test-token"  # noqa: S105 - test-only CSRF fixture

        response = await client.post(
            f"/admin/users/{target_user_id}/auth-reset",
            form={"_csrf": "test-token", "confirm_username": target_name},
        )
        assert response.status_code == 200
        html = await response.get_data(as_text=True)
        ticket_match = re.search(
            r"<code>([0-9a-f-]+\.[A-Za-z0-9_-]{43})</code>", html
        )
        assert ticket_match is not None
        _, secret_text = ticket_match.group(1).split(".", 1)
        ticket_secret = base64.urlsafe_b64decode(secret_text + "=")

        async with factory() as db:
            from sqlalchemy import func, select

            from arborpress.models.user import (
                AuthPending,
                MFADevice,
                UserSession,
                WebAuthnCredential,
            )

            credential_count = (await db.execute(
                select(func.count()).select_from(WebAuthnCredential).where(
                    WebAuthnCredential.user_id == target_user_id
                )
            )).scalar_one()
            revoked_totp = await db.get(MFADevice, str(totp.id))
            revoked_session = await db.get(UserSession, target_session_id)
            recovery_authorization = (await db.execute(
                select(AuthPending).where(
                    AuthPending.user_id == target_user_id,
                    AuthPending.purpose == "recovery_authorization",
                    AuthPending.consumed_at.is_(None),
                )
            )).scalar_one_or_none()
            target = await db.get(User, target_user_id)
        assert credential_count == 1
        assert revoked_totp is not None and revoked_totp.is_active
        assert revoked_totp.verification_status == "verified"
        assert revoked_session is not None and not revoked_session.is_valid
        assert recovery_authorization is not None
        assert recovery_authorization.challenge == hashlib.sha256(ticket_secret).digest()
        assert secret_text not in (recovery_authorization.context or "")
        assert target is not None
        assert target.legacy_password_enabled is False
        assert target.legacy_password_hash is None
