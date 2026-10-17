"""Authentication pages retain server-rendered no-JavaScript paths."""

from __future__ import annotations

import re

import pytest


@pytest.mark.asyncio
async def test_login_is_jinja_rendered_and_webauthn_is_only_an_enhancement(
    client, app, monkeypatch
):
    from arborpress.web.assets import AssetBundle

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

    def resolve(entry: str) -> AssetBundle:
        assert entry == "webauthn"
        return AssetBundle(
            javascript="dist/assets/webauthn-a1b2.js",
            stylesheets=("dist/assets/webauthn-c3d4.css",),
        )

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
    client, app, monkeypatch
):
    from arborpress.web.assets import AssetBundle

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda _entry: AssetBundle(
            javascript="dist/assets/webauthn-a1b2.js", stylesheets=()
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
