"""Tests fuer den Web-Installationspfad (§14)."""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlencode
from pathlib import Path

import pytest
from quart import Quart
from sqlalchemy.ext.asyncio import async_sessionmaker

import arborpress.core.config as config_mod
import arborpress.core.db as db_mod
from arborpress.core.config import Settings
from arborpress.core import site_settings


@pytest.fixture(autouse=True)
def _reset_cache():
    site_settings.invalidate_cache()
    yield
    site_settings.invalidate_cache()


@pytest.fixture()
def install_app(tmp_path, test_engine):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        """
[web]
secret_key = "test-secret-key"
base_url = "http://localhost:8066"
""",
        encoding="utf-8",
    )
    (config_dir / "install.token").write_text(secrets.token_urlsafe(32) + "\n", encoding="utf-8")

    settings = Settings.from_path(config_dir)
    old_settings = config_mod._settings
    old_engine = db_mod._engine
    old_factory = db_mod._session_factory

    config_mod._settings = settings
    db_mod._engine = test_engine
    db_mod._session_factory = None

    from arborpress.web.app import create_app

    app = create_app()
    app.config["TESTING"] = True

    yield app, config_dir

    config_mod._settings = old_settings
    db_mod._engine = old_engine
    db_mod._session_factory = old_factory


class TestWebInstall:
    async def test_install_creates_marker_and_redirects(self, install_app, monkeypatch):
        app, config_dir = install_app
        token_path = config_dir / "install.token"
        marker_path = config_dir / ".installed"

        async def _noop_validate_csrf() -> None:
            return None

        monkeypatch.setattr("arborpress.web.routes.install.validate_csrf", _noop_validate_csrf)

        async with app.test_client() as client:
            response = await client.get("/install")
            assert response.status_code == 200
            token = token_path.read_text(encoding="utf-8").strip()
            initial_username = f"install-{secrets.token_hex(4)}"
            initial_email = f"{initial_username}@example.test"
            body = urlencode(
                {
                    "token": token,
                    "site_name": "ArborPress Test",
                    "admin_username": initial_username,
                    "admin_display_name": "Admin",
                    "admin_email": initial_email,
                }
            )
            response = await client.post(
                "/install",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=False,
            )
            register_page = await client.get("/auth/register")
            assert register_page.status_code == 200

            async def _fake_wa() -> object:
                from arborpress.auth.webauthn import WebAuthnService
                return WebAuthnService("localhost", "ArborPress", "http://localhost:8066")

            monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", _fake_wa)
            begin_response = await client.post(
                "/auth/register/begin",
                json={"enrollment_kind": "security_key", "label": "Initial key"},
                content_type="application/json",
                headers={"Origin": "http://localhost:8066"},
            )
            assert begin_response.status_code == 200
            assert not marker_path.exists()
            assert token_path.exists()

            from types import SimpleNamespace
            from webauthn.helpers.structs import RegistrationCredential

            def _fake_parse(cls, raw):
                return object()

            def _fake_verify(self, credential, expected_challenge):
                assert expected_challenge
                return SimpleNamespace(
                    user_verified=True,
                    credential_id=b"initial-credential-id",
                    credential_public_key=b"initial-public-key",
                    sign_count=0,
                    aaguid="unknown-aaguid",
                    credential_device_type=None,
                    credential_backed_up=False,
                )

            monkeypatch.setattr("arborpress.web.routes.auth._get_webauthn_async", _fake_wa)
            monkeypatch.setattr(RegistrationCredential, "parse_raw", classmethod(_fake_parse))
            monkeypatch.setattr(
                "arborpress.auth.webauthn.WebAuthnService.verify_registration", _fake_verify
            )
            complete = await client.post(
                "/auth/register/complete",
                json={"id": "initial-credential-id", "rawId": "aW5pdGlhbC1jcmVkZW50aWFsLWlk", "label": "Initial key"},
                content_type="application/json",
                headers={"Origin": "http://localhost:8066"},
            )
            assert complete.status_code == 201

        assert response.status_code in (302, 303)
        assert marker_path.exists()
        assert not token_path.exists()

        factory = async_sessionmaker(bind=db_mod._engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.core.site_settings import get_section
            from arborpress.models.user import User, WebAuthnCredential
            from sqlalchemy import func, select
            general = await get_section("general", db)
            user = (await db.execute(select(User).where(
                User.username == initial_username
            ))).scalar_one_or_none()
            user_count = int(user is not None)
            credential_count = 0 if user is None else (await db.execute(
                select(func.count()).select_from(WebAuthnCredential).where(
                    WebAuthnCredential.user_id == str(user.id)
                )
            )).scalar_one()
        assert general["site_title"] == "ArborPress Test"
        assert user_count == 1
        assert credential_count == 1

    async def test_install_page_hidden_after_marker(self, install_app):
        app, config_dir = install_app
        marker_path = config_dir / ".installed"
        marker_path.write_text("installed\n", encoding="utf-8")

        async with app.test_client() as client:
            response = await client.get("/install")

        assert response.status_code == 404
