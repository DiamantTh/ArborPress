"""Authentication pages retain server-rendered no-JavaScript paths."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from quart import Quart
from quart.testing import QuartClient
from sqlalchemy.ext.asyncio import AsyncEngine


@pytest.mark.asyncio
async def test_login_is_jinja_rendered_and_webauthn_is_only_an_enhancement(
    client: QuartClient, app: Quart, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.web.assets import AssetBundle

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

    def resolve(entry: str) -> AssetBundle:
        if entry == "site":
            return AssetBundle(javascript="dist/assets/site-1122.js", stylesheets=())
        if entry == "webauthn":
            return AssetBundle(
                javascript="dist/assets/webauthn-a1b2.js",
                stylesheets=("dist/assets/webauthn-c3d4.css",),
            )
        raise AssertionError(f"Unexpected browser entry: {entry}")

    monkeypatch.setitem(app.jinja_env.globals, "vite_asset", resolve)

    response = await client.get("/auth/login")

    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert "Benutzername oder E-Mail" in html
    assert "Sicherheitsschlüssel oder Passkey" in html
    assert "Browser-JavaScript erforderlich" in html
    assert 'form method="get" action="/auth/login"' in html
    assert 'type="submit"' in html and "disabled" in html
    assert 'id="user_name" name=' not in html
    assert 'href="/auth/recovery"' in html
    assert "/static/dist/assets/webauthn-a1b2.js" in html
    assert "/static/dist/assets/webauthn-c3d4.css" in html
    assert "webauthn-login.js" not in html


@pytest.mark.asyncio
async def test_public_navigation_logout_has_a_csrf_protected_html_form(
    client: QuartClient, app: Quart, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.web.assets import AssetBundle

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(
            javascript=f"dist/assets/{entry}-1122.js", stylesheets=()
        ),
    )
    async with client.session_transaction() as browser_session:
        browser_session["user_id"] = "public-nav-user"

    response = await client.get("/auth/login")
    html = await response.get_data(as_text=True)

    logout_form = re.search(
        r'<form method="post" action="/auth/logout"[^>]*>\s*'
        r'<input type="hidden" name="_csrf" value="([^"]+)">',
        html,
    )
    assert response.status_code == 200
    assert logout_form is not None
    assert len(logout_form.group(1)) == 64


@pytest.mark.asyncio
async def test_registration_page_keeps_server_html_and_loads_bundled_enhancement(
    client: QuartClient, app: Quart, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.web.assets import AssetBundle

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(javascript=f"dist/assets/{entry}-1234.js", stylesheets=()),
    )
    async with client.session_transaction() as browser_session:
        browser_session["user_name"] = "operator"

    response = await client.get("/auth/register")
    html = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Sicherheitsschlüssel registrieren" in html
    assert 'name="key_label"' in html
    assert "Browser-JavaScript erforderlich" in html
    assert "/static/dist/assets/webauthn-register-1234.js" in html
    assert "webauthn-register.js" not in html


@pytest.mark.asyncio
async def test_mfa_page_keeps_totp_form_and_loads_bundled_enhancement(
    client: QuartClient,
    app: Quart,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.models.user import AuthPending
    from arborpress.web.assets import AssetBundle

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    pending_id = str(uuid.uuid4())
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        db.add(AuthPending(
            id=pending_id,
            purpose='password_mfa',
            user_id=None,
            context='{"methods":["webauthn","totp"]}',
            created_at=datetime.now(UTC).replace(tzinfo=None),
            expires_at=(datetime.now(UTC) + timedelta(minutes=5)).replace(tzinfo=None),
        ))
        await db.commit()

    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(javascript=f"dist/assets/{entry}-1234.js", stylesheets=()),
    )
    async with client.session_transaction() as browser_session:
        browser_session["password_mfa_pending_id"] = pending_id

    response = await client.get("/auth/mfa")
    html = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'id="mfa-totp-form"' in html
    assert 'id="totp-code"' in html
    assert "Browser-JavaScript erforderlich" in html
    assert "/static/dist/assets/auth-mfa-1234.js" in html
