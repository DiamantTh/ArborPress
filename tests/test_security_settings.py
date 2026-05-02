"""Tests fuer die DB-basierten Security-Settings (HIBP / Break-Glass-Policy)."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.core import site_settings


@pytest.fixture(autouse=True)
def _reset_cache():
    site_settings.invalidate_cache()
    yield
    site_settings.invalidate_cache()


class TestCoerceSecurityPayload:
    def test_coerces_strings(self):
        cleaned = site_settings.coerce_security_payload(
            {
                "legacy_password_min_length": "20",
                "legacy_password_max_length": "200",
                "legacy_password_min_score":  "4",
                "hibp_enabled":   "on",
                "hibp_max_count": "5",
                "hibp_timeout":   "2.5",
                "hibp_fail_open": "false",
            }
        )
        assert cleaned == {
            "legacy_password_min_length": 20,
            "legacy_password_max_length": 200,
            "legacy_password_min_score":  4,
            "hibp_enabled":   True,
            "hibp_max_count": 5,
            "hibp_timeout":   2.5,
            "hibp_fail_open": False,
        }

    def test_drops_unknown_keys(self):
        cleaned = site_settings.coerce_security_payload({"evil_key": "x", "hibp_enabled": True})
        assert cleaned == {"hibp_enabled": True}

    def test_rejects_out_of_bounds(self):
        with pytest.raises(ValueError, match="legacy_password_min_score"):
            site_settings.coerce_security_payload({"legacy_password_min_score": "9"})

    def test_rejects_inverted_length_bounds(self):
        with pytest.raises(ValueError, match="must be greater than or equal"):
            site_settings.coerce_security_payload(
                {"legacy_password_min_length": "100", "legacy_password_max_length": "50"}
            )


class TestGetSecuritySettings:
    async def test_uses_bootstrap_defaults_when_db_empty(self, test_engine):
        import arborpress.models  # noqa: F401

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            sec = await site_settings.get_security_settings(db)
        assert sec["hibp_enabled"] is False
        assert sec["legacy_password_min_length"] >= 8

    async def test_db_overrides_config(self, test_engine):
        import arborpress.models  # noqa: F401

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            await site_settings.save_section(
                "security",
                {"hibp_enabled": True, "hibp_max_count": 3},
                db,
                updated_by="tester",
            )
        site_settings.invalidate_cache("security")
        async with factory() as db:
            sec = await site_settings.get_security_settings(db)
        assert sec["hibp_enabled"] is True
        assert sec["hibp_max_count"] == 3
        # untouched fields keep bootstrap value
        assert sec["legacy_password_min_score"] >= 0
