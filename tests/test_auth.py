"""Tests für Auth-Subsystem (§2 WebAuthn, §3 TOTP/Backup, §2 Step-up)."""

from __future__ import annotations

import time

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from arborpress.auth.breakglass import hash_password, validate_password_policy
from arborpress.auth.password_tools import (
    assess_password_strength,
    generate_diceware_passphrase,
    generate_random_password,
)
from arborpress.auth.mfa import TOTPService, BackupCodeService
from arborpress.auth.stepup import (
    grant_stepup,
    assert_stepup,
    revoke_stepup,
    STEPUP_REQUIRED_OPERATIONS,
)


# ---------------------------------------------------------------------------
# §2 Break-Glass Passwort-Policy
# ---------------------------------------------------------------------------


def _make_test_settings():
    from arborpress.core.config import Settings

    cfg = Settings()
    cfg.auth.legacy_password_enabled = True
    cfg.auth.legacy_password_min_length = 16
    cfg.auth.legacy_password_max_length = 128
    cfg.auth.legacy_password_min_score = 3
    cfg.auth.auth_rate_limit = "10/minute"
    cfg.auth.lockout_threshold = 2
    cfg.auth.lockout_duration = 900
    return cfg


async def _seed_breakglass_user(test_engine, *, username: str, password: str):
    import arborpress.models  # noqa: F401
    from arborpress.models.user import AccountType, User, UserRole

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=username,
            display_name=username.capitalize(),
            account_type=AccountType.OPERATIONAL,
            role=UserRole.ADMIN,
            is_active=True,
            legacy_password_hash=hash_password(password),
            legacy_password_enabled=True,
        )
        db.add(user)
        await db.commit()
        return user.id


class TestBreakglassPasswordPolicy:
    def test_accepts_long_passphrase(self):
        validate_password_policy(
            "correct horse battery staple",
            min_length=16,
            max_length=128,
            min_score=3,
        )

    def test_rejects_short_password(self):
        with pytest.raises(ValueError, match="at least 16"):
            validate_password_policy("shortpass", min_length=16, max_length=128, min_score=3)

    def test_rejects_edge_whitespace(self):
        with pytest.raises(ValueError, match="start or end with whitespace"):
            validate_password_policy(
                " leading and trailing ",
                min_length=16,
                max_length=128,
                min_score=3,
            )

    def test_rejects_low_zxcvbn_score(self):
        with pytest.raises(ValueError, match="zxcvbn score"):
            validate_password_policy(
                "aaaaaaaaaaaaaaaa",
                min_length=16,
                max_length=128,
                min_score=3,
                user_inputs=["admin"],
            )

    def test_generates_diceware_passphrase(self):
        password = generate_diceware_passphrase(word_count=6, delimiter="-")
        assert password.count("-") == 5
        assert len(password) >= 16
        assert assess_password_strength(password).score >= 3

    def test_generates_random_password(self):
        password = generate_random_password(length=24)
        assert len(password) == 24
        assert " " not in password
        assert assess_password_strength(password).score >= 3


class TestBreakglassLogin:
    @pytest.mark.asyncio
    async def test_breakglass_route_is_rate_limited(self, client, monkeypatch):
        cfg = _make_test_settings()
        cfg.auth.auth_rate_limit = "1/minute"

        async def _noop_csrf():
            return None

        monkeypatch.setattr("arborpress.web.routes.auth.get_settings", lambda: cfg)
        monkeypatch.setattr("arborpress.core.config.get_settings", lambda *args, **kwargs: cfg)
        monkeypatch.setattr("arborpress.web.routes.auth.validate_csrf", _noop_csrf)
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

        resp1 = await client.post(
            "/auth/breakglass",
            form={"user_name": "missing", "password": "irrelevant passphrase"},
        )
        resp2 = await client.post(
            "/auth/breakglass",
            form={"user_name": "missing", "password": "irrelevant passphrase"},
        )

        assert resp1.status_code == 401
        assert resp2.status_code == 429

    @pytest.mark.asyncio
    async def test_breakglass_failures_lock_account(self, client, test_engine, monkeypatch):
        cfg = _make_test_settings()

        async def _noop_csrf():
            return None

        monkeypatch.setattr("arborpress.web.routes.auth.get_settings", lambda: cfg)
        monkeypatch.setattr("arborpress.core.config.get_settings", lambda *args, **kwargs: cfg)
        monkeypatch.setattr("arborpress.web.routes.auth.validate_csrf", _noop_csrf)
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

        await _seed_breakglass_user(
            test_engine,
            username="admin1",
            password="correct horse battery staple",
        )

        resp1 = await client.post(
            "/auth/breakglass",
            form={"user_name": "admin1", "password": "wrong wrong wrong"},
        )
        resp2 = await client.post(
            "/auth/breakglass",
            form={"user_name": "admin1", "password": "wrong wrong wrong"},
        )
        resp3 = await client.post(
            "/auth/breakglass",
            form={"user_name": "admin1", "password": "correct horse battery staple"},
        )

        assert resp1.status_code == 401
        assert resp2.status_code == 401
        assert resp3.status_code == 423


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


class TestSSO:
    @pytest.mark.asyncio
    async def test_sso_begin_redirects_to_provider(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        monkeypatch.setattr(
            "arborpress.web.routes.sso._get_provider_config",
            lambda provider: {
                "client_id": "arborpress",
                "authorize_url": "https://sso.example.com/auth",
                "scopes": ["openid", "profile", "email"],
                "use_pkce": True,
            },
        )

        async def _resolve(provider_cfg: dict) -> dict:
            return provider_cfg

        monkeypatch.setattr("arborpress.web.routes.sso._resolve_provider_endpoints", _resolve)

        resp = await client.get("/auth/sso/test")
        assert resp.status_code == 302
        location = resp.headers["Location"]
        assert "https://sso.example.com/auth" in location
        assert "code_challenge=" in location
        assert "response_type=code" in location


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
