"""Phase 12C operational readiness and diagnostic safety regressions."""

from __future__ import annotations

import json

import pytest


def test_doctor_origin_rejects_credentials_paths_and_non_http_schemes() -> None:
    from arborpress.core.doctor import _safe_origin

    assert _safe_origin("https://blog.example.test")[0] is True
    assert _safe_origin("http://localhost:8066")[0] is True
    assert _safe_origin("https://user:secret@example.test")[0] is False
    assert _safe_origin("https://example.test/path")[0] is False
    assert _safe_origin("file:///etc/passwd")[0] is False


def test_doctor_fails_closed_for_untraceable_production_build() -> None:
    from arborpress.core.doctor import DoctorCheck, _check

    checks: list[DoctorCheck] = []
    _check(
        checks,
        "build_sha",
        False,
        "Build SHA unavailable.",
        production=True,
        production_blocker=True,
    )
    assert checks[0].level == "blocker"
    assert checks[0].status == "failed"


@pytest.mark.asyncio
async def test_readiness_reports_schema_head_and_is_no_store(client) -> None:
    from arborpress.core.config import installed_marker_path

    marker = installed_marker_path()
    marker.write_text("test installation", encoding="utf-8")
    try:
        response = await client.get("/_ready")
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        payload = await response.get_json()
        assert payload["db"] == "ok"
        assert payload["schema"] == "current"
        assert payload["status"] == "ready"
    finally:
        marker.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_readiness_blocks_restore_journal_without_leaking_details(client) -> None:
    from arborpress.runtime.paths import get_runtime_paths

    marker = get_runtime_paths().run / "restore-journal.json"
    marker.write_text('{"secret":"do-not-return"}', encoding="utf-8")
    try:
        liveness = await client.get("/_health")
        assert liveness.status_code == 200
        response = await client.get("/_ready")
        assert response.status_code == 503
        assert response.headers["Cache-Control"] == "no-store"
        body = (await response.get_data()).decode()
        assert "do-not-return" not in body
        assert "secret" not in body
    finally:
        marker.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_doctor_report_is_json_safe_and_contains_no_connection_secret(client) -> None:
    from arborpress.core.config import get_settings
    from arborpress.core.doctor import collect_doctor_report

    cfg = get_settings()
    report = await collect_doctor_report(production=False)
    encoded = json.dumps(report, sort_keys=True)
    secret = cfg.web.secret_key.get_secret_value()
    assert "checks" in report
    assert "summary" in report
    assert secret not in encoded
    assert cfg.db.url not in encoded
    assert "private_key" not in encoded


@pytest.mark.asyncio
async def test_admin_system_status_is_admin_only(client) -> None:
    response = await client.get("/admin/system")
    assert response.status_code in {302, 303, 401, 403}



@pytest.mark.asyncio
async def test_sitemap_uses_canonical_origin_and_excludes_private_content(db_session, monkeypatch):
    import uuid

    from quart import Quart

    from arborpress.models.content import Post, PostStatus, PostVisibility
    from arborpress.models.user import User
    from arborpress.web.routes import discovery

    user = User(id=str(uuid.uuid4()), username='sitemap-author', display_name='Author')
    db_session.add(user)
    await db_session.flush()
    for slug, status, visibility in (
        ('public-entry', PostStatus.PUBLISHED, PostVisibility.PUBLIC),
        ('private-entry', PostStatus.PUBLISHED, PostVisibility.PRIVATE),
        ('draft-entry', PostStatus.DRAFT, PostVisibility.PUBLIC),
    ):
        db_session.add(Post(
            id=str(uuid.uuid4()), short_id=uuid.uuid4().hex[:12], author_id=user.id,
            slug=slug, title=slug, body_md='Body', body_html='<p>Body</p>',
            status=status, visibility=visibility,
        ))
    await db_session.flush()

    async def database():
        yield db_session

    monkeypatch.setattr(discovery, 'get_db_session', database)
    app = Quart(__name__)
    app.register_blueprint(discovery.discovery_bp)
    response = await app.test_client().get('/sitemap.xml', headers={'Host': 'attacker.invalid'})
    body = (await response.get_data()).decode()
    assert response.status_code == 200
    assert 'public-entry' in body
    assert 'private-entry' not in body and 'draft-entry' not in body
    assert 'attacker.invalid' not in body
