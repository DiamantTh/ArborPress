from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from quart import Quart
from quart.testing import QuartClient
from sqlalchemy.ext.asyncio import AsyncEngine


async def _seed_admin(test_engine: AsyncEngine) -> tuple[str, str]:
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
    client: QuartClient, test_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
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
    client: QuartClient,
    app: Quart,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
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
        "/admin/mail",
        "/admin/mail/templates",
        "/admin/mail/templates/comment.guest_confirmation/en-GB",
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
    assert "Mail transport" in pages["/admin/mail"]
    assert "mail template" in pages["/admin/mail"].lower()
    assert "comment.guest_confirmation" in pages["/admin/mail/templates"]
    assert "Subject template" in pages["/admin/mail/templates/comment.guest_confirmation/en-GB"]
    assert 'name="admin_active"' in pages["/admin/settings"]
    assert 'name="_csrf"' in pages["/admin/captcha"]
    assert 'aria-current="page"' in pages["/admin/settings"]
    assert 'data-ap-admin-mount="password-tools"' in pages["/admin/security"]
    assert 'data-ap-admin-mount="captcha-questions"' in pages["/admin/captcha"]
    assert 'type="application/json"' in pages["/admin/captcha"]
    assert ".vite/manifest.json" not in pages["/admin/settings"]
    assert re.search(r"/static/dist/assets/admin-[^\" ]+\.js", pages["/admin/settings"])
    assert re.search(r'href="/static/dist/assets/admin-[^\"]+\.css"', pages["/admin/settings"])
    editor_html = pages["/admin/posts/new"]
    assert 'name="body"' in editor_html
    assert re.search(r'href="/static/dist/assets/editor-[^\"]+\.css"', editor_html)
    assert re.search(r'src="/static/dist/assets/editor-[^\"]+\.js"', editor_html)
    assert "editor-registry.js" not in editor_html
    assert "editor-adapters/" not in editor_html

    security_response = await client.get("/auth/security")
    assert security_response.status_code == 200
    security_html = await security_response.get_data(as_text=True)
    assert "data-ap-auth-security" in security_html
    assert "/static/dist/assets/auth-security-" in security_html
    assert "auth-security.js" not in security_html

    template_config = cast(dict[str, dict[str, object]], app.jinja_env.globals["config"])
    monkeypatch.setitem(template_config["web"], "admin_editor", "easymde")
    fallback_response = await client.get("/admin/posts/new")
    fallback_html = await fallback_response.get_data(as_text=True)
    assert fallback_response.status_code == 200
    assert "Konfigurierter Editor nicht unterstützt" in fallback_html
    assert 'name="body"' in fallback_html
    assert "/static/dist/assets/editor-tiptap-" not in fallback_html


def test_jinja_receives_only_presentation_safe_config(app: Quart) -> None:
    template_config = app.jinja_env.globals["config"]

    assert template_config["web"]["base_url"]
    assert "admin_editor" in template_config["web"]
    assert "legacy_password_enabled" in template_config["auth"]
    assert "db" not in template_config
    assert "secret_key" not in template_config["web"]
    assert "actor_key_enc_key" not in template_config["auth"]


@pytest.mark.asyncio
async def test_admin_post_works_from_rendered_form_without_javascript(
    client: QuartClient, test_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
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
async def test_mail_template_preview_is_ssr_and_save_requires_stepup(
    client: QuartClient, test_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _login_admin(client, test_engine, monkeypatch)
    path = "/admin/mail/templates/notification.generic/en-GB"
    response = await client.get(path)
    html = await response.get_data(as_text=True)
    token_match = re.search(r'<input type="hidden" name="_csrf" value="([0-9a-f]+)">', html)
    assert token_match is not None
    form = {
        "_csrf": token_match.group(1),
        "expected_revision": "0",
        "subject": "{{ notification_title }}",
        "plain": "{{ notification_message }}",
        "html": "<p>{{ notification_message }}</p>",
        "action": "preview",
    }
    preview = await client.post(path, form=form)
    preview_html = await preview.get_data(as_text=True)
    assert preview.status_code == 200
    assert "Preview" in preview_html
    assert 'sandbox=""' in preview_html
    assert "Example notification_message" in preview_html

    form["action"] = "save"
    denied = await client.post(path, form=form)
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_admin_state_change_rejects_missing_csrf_token(
    client: QuartClient, test_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _login_admin(client, test_engine, monkeypatch)
    response = await client.post("/admin/captcha", form={"q_0": "Question?", "a_0": "Answer"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_theme_settings_keep_public_and_admin_selection_types_separate(
    client: QuartClient, test_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _login_admin(client, test_engine, monkeypatch)
    response = await client.get("/admin/settings")
    html = await response.get_data(as_text=True)
    token_match = re.search(r'<input type="hidden" name="_csrf" value="([0-9a-f]+)">', html)
    assert token_match is not None
    token = token_match.group(1)

    saved = await client.post(
        "/admin/settings",
        form={
            "_csrf": token,
            "section": "theme",
            "active": "default",
            "admin_active": "arbor-admin",
        },
    )
    assert saved.status_code == 302

    rejected = await client.post(
        "/admin/settings",
        form={
            "_csrf": token,
            "section": "theme",
            "active": "arbor-admin",
            "admin_active": "default",
        },
    )
    assert rejected.status_code == 400


@pytest.mark.asyncio
async def test_theme_management_is_server_rendered_and_role_gated(
    client: QuartClient,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _login_admin(client, test_engine, monkeypatch)

    overview = await client.get("/admin/themes")
    assert overview.status_code == 200
    overview_html = await overview.get_data(as_text=True)
    assert "Public Themes" in overview_html
    assert "Admin Themes" in overview_html
    assert "default-local" in overview_html or "Theme-Verwaltung" in overview_html
    assert 'name="theme_type" value="public"' in overview_html
    assert 'name="_csrf"' in overview_html

    detail = await client.get("/admin/themes/default")
    assert detail.status_code == 200
    detail_html = await detail.get_data(as_text=True)
    assert "Validierung" in detail_html
    assert "Themeoptionen" in detail_html
    assert "index.html" in detail_html
    assert "Derived Theme" in detail_html

    async with client.session_transaction() as browser_session:
        user_id = browser_session["user_id"]
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.models.user import User, UserRole

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = await db.get(User, user_id)
        assert user is not None
        user.role = UserRole.AUTHOR
        await db.commit()
    async with client.session_transaction() as browser_session:
        browser_session["user_role"] = "admin"
    forbidden = await client.get("/admin/themes")
    assert forbidden.status_code == 403


@pytest.mark.asyncio
async def test_theme_options_form_saves_and_rejects_stale_concurrent_edit(
    client: QuartClient,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _login_admin(client, test_engine, monkeypatch)
    from arborpress.runtime.paths import get_runtime_paths
    from arborpress.themes.manifest import get_theme_registry

    theme_root = get_runtime_paths().themes / "options-ssr"
    theme_root.mkdir(parents=True)
    (theme_root / "theme.toml").write_text(
        """name = "Options SSR"
version = "1.0.0"
type = "public"
[options.accent]
type = "color"
label = "Accent"
default = "#123456"
""",
        encoding="utf-8",
    )
    get_theme_registry().load()

    detail = await client.get("/admin/themes/options-ssr")
    assert detail.status_code == 200
    html = await detail.get_data(as_text=True)
    token = re.search(r'<input type="hidden" name="_csrf" value="([0-9a-f]+)">', html)
    expected = re.search(r'<input type="hidden" name="expected_hash" value="([0-9a-f]+)">', html)
    assert token is not None and expected is not None
    assert 'name="option_accent"' in html

    saved = await client.post(
        "/admin/themes/options-ssr/options",
        form={
            "_csrf": token.group(1),
            "expected_hash": expected.group(1),
            "option_accent": "#abcdef",
        },
    )
    assert saved.status_code == 302
    stale = await client.post(
        "/admin/themes/options-ssr/options",
        form={
            "_csrf": token.group(1),
            "expected_hash": expected.group(1),
            "option_accent": "#fedcba",
        },
    )
    assert stale.status_code == 409

    from arborpress.themes.management import list_revisions

    revision = next(item for item in list_revisions("options-ssr") if item["kind"] == "options")
    restored = await client.post(
        f"/admin/themes/options-ssr/revisions/{revision['id']}/restore",
        form={"_csrf": token.group(1)},
    )
    assert restored.status_code == 302
    reset_detail = await client.get("/admin/themes/options-ssr")
    reset_html = await reset_detail.get_data(as_text=True)
    assert 'value="#123456"' in reset_html


@pytest.mark.asyncio
async def test_broken_admin_theme_preview_recovers_to_builtin_fallback(
    client: QuartClient,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    import shutil

    await _login_admin(client, test_engine, monkeypatch)
    from arborpress.runtime.paths import get_runtime_paths
    from arborpress.themes.manifest import get_theme_registry

    theme_root = get_runtime_paths().themes / "broken-admin-preview"
    request.addfinalizer(lambda: shutil.rmtree(theme_root, ignore_errors=True))
    (theme_root / "templates/admin").mkdir(parents=True)
    (theme_root / "theme.toml").write_text(
        """name = "Broken admin preview"
version = "1.0.0"
type = "admin"
capabilities = ["templates"]
templates = ["admin/dashboard.html"]
""",
        encoding="utf-8",
    )
    (theme_root / "templates/admin/dashboard.html").write_text(
        "{{ missing_template_callable() }}", encoding="utf-8"
    )
    get_theme_registry().load()

    detail = await client.get("/admin/themes/broken-admin-preview")
    html = await detail.get_data(as_text=True)
    token = re.search(r'<input type="hidden" name="_csrf" value="([0-9a-f]+)">', html)
    assert token is not None
    preview = await client.post(
        "/admin/themes/broken-admin-preview/preview", form={"_csrf": token.group(1)}
    )
    assert preview.status_code == 302

    recovered = await client.get("/admin/")
    recovered_html = await recovered.get_data(as_text=True)
    assert recovered.status_code == 500
    assert "Admin-Theme konnte diese Seite nicht rendern" in recovered_html
    assert "Dashboard" in recovered_html
    async with client.session_transaction() as browser_session:
        assert "_theme_preview" not in browser_session


def test_settings_passed_to_theme_templates_are_secret_redacted() -> None:
    from arborpress.web.routes.admin import _template_safe_settings

    source = {
        "mail": {"smtp_password": "mail-secret", "smtp_user": "operator"},
        "search": {"meilisearch_api_key": "search-secret"},
        "nested": [{"private_key": "key-secret", "label": "safe"}],
    }
    safe = _template_safe_settings(source)
    assert safe == {
        "mail": {"smtp_password": "", "smtp_user": "operator"},
        "search": {"meilisearch_api_key": ""},
        "nested": [{"private_key": "", "label": "safe"}],
    }
    assert safe["mail"]["smtp_password"] != source["mail"]["smtp_password"]


@pytest.mark.asyncio
async def test_comment_moderation_queue_detail_and_decision_are_server_rendered(
    client: QuartClient,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus

    await _login_admin(client, test_engine, monkeypatch)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    suffix = uuid.uuid4().hex[:10]
    async with factory() as db:
        post = Post(
            short_id=uuid.uuid4().hex[:8],
            slug=f"moderate-{suffix}",
            title="Moderation detail article",
            body_md="",
            body_html="",
            status=PostStatus.PUBLISHED,
        )
        db.add(post)
        await db.flush()
        comment = Comment(
            post_id=post.id,
            author_name="<script>guest()</script>",
            author_email="private@example.test",
            body="<script>comment()</script>",
            status=CommentStatus.PENDING_MODERATION,
        )
        db.add(comment)
        await db.commit()
        comment_id = str(comment.id)

    queue_response = await client.get("/admin/comments?type=comments")
    assert queue_response.status_code == 200
    queue = await queue_response.get_data(as_text=True)
    assert "Ausstehende Kommentare" in queue
    assert "&lt;script&gt;guest()&lt;/script&gt;" in queue
    assert "private@example.test" not in queue

    detail_response = await client.get(f"/admin/comments/{comment_id}")
    assert detail_response.status_code == 200
    detail = await detail_response.get_data(as_text=True)
    assert "Moderation detail article" in detail
    assert "&lt;script&gt;comment()&lt;/script&gt;" in detail
    assert "private@example.test" in detail
    csrf = re.search(r'<input type="hidden" name="_csrf" value="([0-9a-f]+)">', detail)
    assert csrf is not None

    rejected_csrf = await client.post(
        f"/admin/comments/{comment_id}/decision",
        form={"outcome": "approve", "reason_code": "no_violation"},
    )
    assert rejected_csrf.status_code == 403

    response = await client.post(
        f"/admin/comments/{comment_id}/decision",
        form={
            "_csrf": csrf.group(1),
            "outcome": "approve",
            "reason_code": "no_violation",
        },
    )
    assert response.status_code == 303
    async with factory() as db:
        updated = await db.get(Comment, comment_id)
        assert updated is not None and updated.status == CommentStatus.APPROVED


@pytest.mark.asyncio
async def test_post_author_and_relation_forms_are_server_rendered_without_javascript(
    client: QuartClient,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.models.authorization import ObjectRelation, ObjectRelationName
    from arborpress.models.content import Post, PostStatus
    from arborpress.models.user import AccountType, User, UserRole

    await _login_admin(client, test_engine, monkeypatch)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    suffix = uuid.uuid4().hex[:10]
    primary = User(
        username=f"ui-primary-{suffix}",
        display_name="UI Primary",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    coauthor = User(
        username=f"ui-coauthor-{suffix}",
        display_name="UI Coauthor",
        account_type=AccountType.PUBLIC,
        role=UserRole.AUTHOR,
        is_active=True,
    )
    post = Post(
        short_id=uuid.uuid4().hex[:8],
        slug=f"author-ui-{suffix}",
        title="Authored editor page",
        body_md="",
        body_html="",
        status=PostStatus.DRAFT,
    )
    async with factory() as db:
        db.add_all([primary, coauthor, post])
        await db.flush()
        from arborpress.content.authors import replace_post_authors

        await replace_post_authors(
            db,
            post_id=str(post.id),
            primary_user_id=str(primary.id),
            coauthor_user_ids=[str(coauthor.id)],
            actor_user_id=str(primary.id),
        )
        db.add(
            ObjectRelation(
                subject_user_id=str(coauthor.id),
                object_type="content",
                object_id=str(post.id),
                relation=ObjectRelationName.EDITOR,
            )
        )
        await db.commit()
        slug = post.slug

    response = await client.get(f"/admin/posts/{slug}/edit")
    html = await response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'name="primary_user_id"' in html
    assert 'name="coauthor_ids"' in html
    assert 'name="coauthor_position_' in html
    assert "UI Primary" in html and "UI Coauthor" in html
    assert 'name="subject_user_id"' in html
    assert 'name="relation"' in html
    assert 'name="_csrf"' in html


@pytest.mark.asyncio
async def test_mail_admin_omits_credentials_recipient_localpart_and_body_and_requires_csrf(
    client: QuartClient,
    test_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.mail.profiles import save_profile
    from arborpress.mail.queue import enqueue_mail

    await _login_admin(client, test_engine, monkeypatch)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        await save_profile(
            db,
            {
                "id": "admin-mail-profile",
                "host": "smtp.example.test",
                "port": 465,
                "transport": "implicit_tls",
                "username": "smtp-user-secret",
                "secret": "smtp-password-secret",
                "from_address": "noreply@example.test",
            },
        )
        await db.commit()
    from arborpress.core import db as db_module

    db_module._engine = test_engine
    db_module._session_factory = factory
    job_id = await enqueue_mail(
        "private-localpart@example.test",
        "hidden-subject-marker",
        "hidden-body-marker",
        profile_id="admin-mail-profile",
    )
    response = await client.get("/admin/mail")
    html = await response.get_data(as_text=True)
    assert response.status_code == 200
    for private_value in (
        "smtp-user-secret",
        "smtp-password-secret",
        "private-localpart",
        "hidden-subject-marker",
        "hidden-body-marker",
    ):
        assert private_value not in html
    assert "example.test" in html
    csrf_match = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert csrf_match is not None

    rejected = await client.post(f"/admin/mail/queue/{job_id}/cancel", form={})
    assert rejected.status_code == 403
    cancelled = await client.post(
        f"/admin/mail/queue/{job_id}/cancel",
        form={"_csrf": csrf_match.group(1)},
    )
    assert cancelled.status_code == 302
