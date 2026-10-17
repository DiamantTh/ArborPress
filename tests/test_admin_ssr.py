from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest


async def _seed_admin(test_engine: object) -> tuple[str, str]:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.models  # noqa: F401
    from arborpress.models.user import AccountType, User, UserRole, UserSession

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=f"ssr-admin-{uuid.uuid4().hex[:10]}",
            display_name="SSR Admin",
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


async def _login_admin(
    client: object, test_engine: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    user_id, session_id = await _seed_admin(test_engine)
    async with client.session_transaction() as browser_session:
        browser_session["user_id"] = user_id
        browser_session["user_name"] = "ssr-admin"
        browser_session["user_role"] = "admin"
        browser_session["account_type"] = "operational"
        browser_session["session_id"] = session_id


@pytest.mark.asyncio
async def test_admin_pages_are_server_rendered_and_form_csrf_is_present(
    client: object, test_engine: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _login_admin(client, test_engine, monkeypatch)

    paths = (
        "/admin/",
        "/admin/posts",
        "/admin/posts/new",
        "/admin/pages",
        "/admin/media",
        "/admin/users",
        "/admin/plugins",
        "/admin/security",
        "/admin/webauthn",
        "/admin/comments",
        "/admin/captcha",
        "/admin/settings",
        "/admin/sessions",
    )
    pages: dict[str, str] = {}
    for path in paths:
        response = await client.get(path)
        assert response.status_code == 200, path
        html = await response.get_data(as_text=True)
        assert "<main" in html and "<h" in html, path
        post_forms = re.findall(r"<form\b[^>]*\bmethod=[\"']post[\"']", html, re.IGNORECASE)
        csrf_fields = re.findall(r"<input\b[^>]*\bname=[\"']_csrf[\"']", html, re.IGNORECASE)
        assert len(csrf_fields) == len(post_forms), path
        pages[path] = html

    assert 'name="body"' in pages["/admin/posts/new"]
    assert 'name="_csrf"' in pages["/admin/posts/new"]
    assert 'name="_csrf"' in pages["/admin/settings"]
    assert 'name="_csrf"' in pages["/admin/captcha"]
    assert 'aria-current="page"' in pages["/admin/settings"]
    assert 'data-ap-admin-mount="password-tools"' in pages["/admin/security"]
    assert 'data-ap-admin-mount="captcha-questions"' in pages["/admin/captcha"]
    assert 'type="application/json"' in pages["/admin/captcha"]
    assert ".vite/manifest.json" not in pages["/admin/settings"]
    assert re.search(r"/static/dist/assets/admin-[^\" ]+\.js", pages["/admin/settings"])


@pytest.mark.asyncio
async def test_admin_post_works_from_rendered_form_without_javascript(
    client: object, test_engine: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _login_admin(client, test_engine, monkeypatch)
    response = await client.get("/admin/captcha")
    html = await response.get_data(as_text=True)
    token_match = re.search(r'<input type="hidden" name="_csrf" value="([0-9a-f]+)">', html)
    assert token_match is not None

    saved = await client.post(
        "/admin/captcha",
        form={"_csrf": token_match.group(1), "q_0": "Question?", "a_0": "Answer"},
    )
    assert saved.status_code == 302


@pytest.mark.asyncio
async def test_admin_state_change_rejects_missing_csrf_token(
    client: object, test_engine: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _login_admin(client, test_engine, monkeypatch)
    response = await client.post("/admin/captcha", form={"q_0": "Question?", "a_0": "Answer"})
    assert response.status_code == 403
