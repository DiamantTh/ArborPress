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
            body = urlencode(
                {
                    "token": token,
                    "site_name": "ArborPress Test",
                    "admin_username": "admin1",
                    "admin_display_name": "Admin",
                    "admin_email": "admin@example.com",
                }
            )
            response = await client.post(
                "/install",
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=False,
            )

        assert response.status_code in (302, 303)
        assert marker_path.exists()
        assert not token_path.exists()

        factory = async_sessionmaker(bind=db_mod._engine, expire_on_commit=False)
        async with factory() as db:
            from arborpress.core.site_settings import get_section
            general = await get_section("general", db)
        assert general["site_title"] == "ArborPress Test"

    async def test_install_page_hidden_after_marker(self, install_app):
        app, config_dir = install_app
        marker_path = config_dir / ".installed"
        marker_path.write_text("installed\n", encoding="utf-8")

        async with app.test_client() as client:
            response = await client.get("/install")

        assert response.status_code == 404
