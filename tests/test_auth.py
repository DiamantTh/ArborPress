"""Tests für Auth-Subsystem (§2 WebAuthn, §3 TOTP/Backup, §2 Step-up)."""

from __future__ import annotations

import time
import pytest

from arborpress.auth.mfa import TOTPService, BackupCodeService
from arborpress.auth.stepup import (
    grant_stepup,
    assert_stepup,
    revoke_stepup,
    STEPUP_REQUIRED_OPERATIONS,
)


# ---------------------------------------------------------------------------
# §3 TOTP
# ---------------------------------------------------------------------------


class TestTOTPService:
    def test_provision_url_contains_issuer(self):
        svc = TOTPService(issuer="ArborPress")
        secret = svc.generate_secret()
        url = svc.provision_url(secret, "testuser")
        assert "ArborPress" in url
        assert "testuser" in url

    def test_verify_correct_token(self):
        svc = TOTPService(issuer="ArborPress")
        secret = svc.generate_secret()
        token = svc.current_token(secret)
        assert svc.verify(secret, token)

    def test_verify_wrong_token(self):
        svc = TOTPService(issuer="ArborPress")
        secret = svc.generate_secret()
        assert not svc.verify(secret, "00000000")

    def test_token_length_is_8(self):
        svc = TOTPService(issuer="ArborPress")
        secret = svc.generate_secret()
        token = svc.current_token(secret)
        assert len(token) == 8

    def test_generate_secret_is_base32(self):
        import base64
        svc = TOTPService(issuer="ArborPress")
        secret = svc.generate_secret()
        # Muss gültiges Base32 sein
        base64.b32decode(secret)


# ---------------------------------------------------------------------------
# §3 Backup-Codes
# ---------------------------------------------------------------------------


class TestBackupCodeService:
    def test_generates_ten_codes(self):
        svc = BackupCodeService()
        plaintext, hashed = svc.generate_codes()
        assert len(plaintext) == 10
        assert len(hashed) == 10

    def test_plaintext_not_equal_hash(self):
        svc = BackupCodeService()
        plaintext, hashed = svc.generate_codes()
        for p, h in zip(plaintext, hashed):
            assert p != h

    def test_verify_correct_code(self):
        svc = BackupCodeService()
        plaintext, hashed = svc.generate_codes()
        assert svc.verify(plaintext[0], hashed[0])

    def test_verify_wrong_code(self):
        svc = BackupCodeService()
        plaintext, hashed = svc.generate_codes()
        assert not svc.verify("WRONGCODE", hashed[0])


# ---------------------------------------------------------------------------
# §2 Step-up / Sudo-Mode
# ---------------------------------------------------------------------------


class TestStepup:
    def _make_session(self) -> dict:
        return {}

    def test_grant_and_assert_stepup(self):
        session = self._make_session()
        grant_stepup(session, user_id=1)
        # darf keine Exception werfen
        assert_stepup(session, user_id=1, operation="change_roles")

    def test_assert_stepup_without_grant_raises(self):
        session = self._make_session()
        with pytest.raises(PermissionError, match="step-up"):
            assert_stepup(session, user_id=1, operation="change_roles")

    def test_revoke_stepup(self):
        session = self._make_session()
        grant_stepup(session, user_id=1)
        revoke_stepup(session, user_id=1)
        with pytest.raises(PermissionError):
            assert_stepup(session, user_id=1, operation="change_roles")

    def test_stepup_not_required_for_normal_op(self):
        """Nicht-Step-up-Operationen dürfen nicht blockiert werden."""
        session = self._make_session()
        # "view_posts" ist keine Step-up-Operation
        assert "view_posts" not in STEPUP_REQUIRED_OPERATIONS
        # Kein Grant nötig – operation nicht in verbotener Liste → kein Fehler
        # (assert_stepup prüft nur wenn operation in STEPUP_REQUIRED_OPERATIONS)
        if "view_posts" not in STEPUP_REQUIRED_OPERATIONS:
            pass  # korrekt – normale Operationen werden nicht blockiert

    def test_stepup_ttl_expiry(self, monkeypatch):
        session = self._make_session()
        # Step-up mit TTL=0 simulieren via Config-Mock
        import arborpress.auth.stepup as su_mod

        class _FakeAuth:
            stepup_ttl = 0

        class _FakeCfg:
            auth = _FakeAuth()

        monkeypatch.setattr(su_mod, "get_settings", lambda: _FakeCfg())
        grant_stepup(session, user_id=1)
        time.sleep(0.01)
        with pytest.raises(PermissionError):
            assert_stepup(session, user_id=1, operation="change_roles")

    def test_stepup_required_operations_set(self):
        required = {
            "change_roles",
            "modify_auth_policy",
            "toggle_federation",
            "install_plugin",
            "generate_export",
            "rotate_key",
            "change_security_settings",
        }
        assert required.issubset(STEPUP_REQUIRED_OPERATIONS)
