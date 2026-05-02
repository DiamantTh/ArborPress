"""Tests fuer den RP-ID-Lock-Guard (W3C WebAuthn L3 §5.3)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.auth.webauthn import RPIDChangeBlocked, assert_rp_id_locked_match
from arborpress.core import site_settings
from arborpress.models.user import User, WebAuthnCredential


@pytest.fixture(autouse=True)
def _reset_cache():
    site_settings.invalidate_cache()
    yield
    site_settings.invalidate_cache()


async def _add_credential(db) -> None:
    handle = uuid.uuid4().hex[:8]
    user = User(
        id=str(uuid.uuid4()),
        username=f"u_{handle}",
        display_name=f"User {handle}",
        email=f"{handle}@example.test",
    )
    db.add(user)
    await db.flush()
    db.add(
        WebAuthnCredential(
            user_id=user.id,
            label="test-key",
            credential_id=uuid.uuid4().bytes,
            public_key=b"\x00" * 32,
        )
    )
    await db.flush()


def _factory(test_engine):
    return async_sessionmaker(bind=test_engine, expire_on_commit=False)


class TestAssertRpIdLockedMatch:
    async def test_bootstrap_on_empty(self, test_engine):
        factory = _factory(test_engine)
        async with factory() as db:
            await site_settings.save_section(
                "webauthn", {"rp_id_last_known": ""}, db, updated_by="test"
            )
            site_settings.invalidate_cache("webauthn")
            await assert_rp_id_locked_match(db, current_rp_id="example.test")
            wa = await site_settings.get_webauthn_settings(db)
        assert wa["rp_id_last_known"] == "example.test"

    async def test_match_returns_silently(self, test_engine):
        factory = _factory(test_engine)
        async with factory() as db:
            await site_settings.save_section(
                "webauthn",
                {"rp_id_last_known": "example.test", "rp_id_locked": True},
                db,
                updated_by="test",
            )
            site_settings.invalidate_cache("webauthn")
            # Should not raise
            await assert_rp_id_locked_match(db, current_rp_id="example.test")

    async def test_mismatch_no_credentials_adopts(self, test_engine):
        factory = _factory(test_engine)
        async with factory() as db:
            # Wipe any leftover credentials from earlier tests
            from sqlalchemy import delete
            await db.execute(delete(WebAuthnCredential))
            await site_settings.save_section(
                "webauthn",
                {"rp_id_last_known": "old.test", "rp_id_locked": True},
                db,
                updated_by="test",
            )
            site_settings.invalidate_cache("webauthn")
            await assert_rp_id_locked_match(db, current_rp_id="new.test")
            wa = await site_settings.get_webauthn_settings(db)
        assert wa["rp_id_last_known"] == "new.test"

    async def test_mismatch_unlocked_adopts(self, test_engine):
        factory = _factory(test_engine)
        async with factory() as db:
            await _add_credential(db)
            await site_settings.save_section(
                "webauthn",
                {"rp_id_last_known": "old.test", "rp_id_locked": False},
                db,
                updated_by="test",
            )
            site_settings.invalidate_cache("webauthn")
            await assert_rp_id_locked_match(db, current_rp_id="new.test")
            wa = await site_settings.get_webauthn_settings(db)
        assert wa["rp_id_last_known"] == "new.test"
        assert wa["rp_id_locked"] is True

    async def test_mismatch_locked_with_credentials_raises(self, test_engine):
        factory = _factory(test_engine)
        async with factory() as db:
            await _add_credential(db)
            await site_settings.save_section(
                "webauthn",
                {"rp_id_last_known": "old.test", "rp_id_locked": True},
                db,
                updated_by="test",
            )
            site_settings.invalidate_cache("webauthn")
            with pytest.raises(RPIDChangeBlocked) as exc:
                await assert_rp_id_locked_match(db, current_rp_id="new.test")
        assert exc.value.current == "new.test"
        assert exc.value.expected == "old.test"
        assert exc.value.credential_count >= 1
