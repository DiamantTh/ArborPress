"""Tests fuer die DB-basierten WebAuthn-Settings (W3C WebAuthn Level 3)."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.core import site_settings


@pytest.fixture(autouse=True)
def _reset_cache():
    site_settings.invalidate_cache()
    yield
    site_settings.invalidate_cache()


class TestCoerceWebAuthnPayload:
    def test_coerces_strings_and_bools(self):
        cleaned = site_settings.coerce_webauthn_payload(
            {
                "user_verification":         "required",
                "resident_key":              "preferred",
                "attestation":               "none",
                "authenticator_attachment":  "platform",
                "algorithms":                ["-7", "-257"],
                "timeout_ms":                "120000",
                "challenge_ttl_seconds":     "300",
                "conditional_ui_enabled":    "on",
                "signal_api_enabled":        False,
                "require_2fa_after_passkey": "0",
                "counter_strict":            True,
            }
        )
        assert cleaned["user_verification"] == "required"
        assert cleaned["algorithms"] == [-7, -257]
        assert cleaned["timeout_ms"] == 120000
        assert cleaned["conditional_ui_enabled"] is True
        assert cleaned["require_2fa_after_passkey"] is False
        assert cleaned["counter_strict"] is True

    def test_drops_unknown_keys(self):
        cleaned = site_settings.coerce_webauthn_payload(
            {"evil": "x", "user_verification": "preferred"}
        )
        assert cleaned == {"user_verification": "preferred"}

    def test_rejects_invalid_enum(self):
        with pytest.raises(ValueError, match="user_verification"):
            site_settings.coerce_webauthn_payload({"user_verification": "maybe"})

    def test_rejects_out_of_bounds_timeout(self):
        with pytest.raises(ValueError, match="timeout_ms"):
            site_settings.coerce_webauthn_payload({"timeout_ms": 10})

    def test_rejects_unsupported_algorithm(self):
        with pytest.raises(ValueError, match="COSE algorithm"):
            site_settings.coerce_webauthn_payload({"algorithms": [-1]})

    def test_authenticator_attachment_empty_allowed(self):
        cleaned = site_settings.coerce_webauthn_payload({"authenticator_attachment": ""})
        assert cleaned["authenticator_attachment"] == ""


class TestGetWebAuthnSettings:
    async def test_uses_defaults_when_db_empty(self, test_engine):
        import arborpress.models  # noqa: F401

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            wa = await site_settings.get_webauthn_settings(db)

        # W3C / passkeys.dev recommended defaults
        assert wa["user_verification"] == "preferred"
        assert wa["resident_key"] == "preferred"
        assert wa["attestation"] == "none"
        assert wa["algorithms"] == [-7, -257]
        assert wa["rp_id_locked"] is True
        assert wa["counter_strict"] is False

    async def test_db_overrides_defaults(self, test_engine):
        import arborpress.models  # noqa: F401

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db:
            await site_settings.save_section(
                "webauthn",
                {"user_verification": "required", "rp_id_last_known": "example.test"},
                db,
                updated_by="tester",
            )
        site_settings.invalidate_cache("webauthn")
        async with factory() as db:
            wa = await site_settings.get_webauthn_settings(db)

        assert wa["user_verification"] == "required"
        assert wa["rp_id_last_known"] == "example.test"
        # Untouched defaults still present
        assert wa["resident_key"] == "preferred"
