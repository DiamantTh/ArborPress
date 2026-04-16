from __future__ import annotations

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
    async def test_admin_can_set_breakglass_password_from_users_page(self, client, test_engine, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

        admin_user_id, session_id = await _seed_admin_user(test_engine)
        target_user_id = await _seed_target_user(test_engine)

        async with client.session_transaction() as sess:
            sess["user_id"] = admin_user_id
            sess["user_name"] = "adminuser"
            sess["user_role"] = "admin"
            sess["account_type"] = "operational"
            sess["session_id"] = session_id
            grant_stepup(sess, user_id=admin_user_id)
            sess["_csrf_token"] = "test-token"

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