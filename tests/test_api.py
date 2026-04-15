"""API v1 Tests – öffentliche Endpunkte und Admin-Endpunkte (§8)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _seed_post(engine, *, slug="hello-world", title="Hello World",
                     published=True, public=True, username="alice"):
    """Erzeugt User + Post direkt in der DB und gibt beide zurück."""
    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from arborpress.models.user import AccountType, User, UserRole

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username=username,
            display_name=username.capitalize(),
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
        db.add(user)
        await db.flush()

        from datetime import UTC, datetime
        import secrets
        post = Post(
            short_id=secrets.token_urlsafe(6)[:8],
            author_id=user.id,
            slug=slug,
            title=title,
            body_md="# Hello\n\nBody text.",
            body_html="<h1>Hello</h1><p>Body text.</p>",
            status=PostStatus.PUBLISHED if published else PostStatus.DRAFT,
            visibility=PostVisibility.PUBLIC if public else PostVisibility.PRIVATE,
            published_at=datetime.now(UTC) if published else None,
        )
        db.add(post)
        await db.commit()
    return user, post


# ---------------------------------------------------------------------------
# Public API – GET /api/v1/posts
# ---------------------------------------------------------------------------


class TestAPIPostsList:
    @pytest.mark.asyncio
    async def test_returns_json_envelope(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/posts")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "items" in data
        assert "total" in data
        assert "page" in data

    @pytest.mark.asyncio
    async def test_per_page_capped_at_50(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/posts?per_page=999")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["per_page"] == 50

    @pytest.mark.asyncio
    async def test_invalid_page_returns_400(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/posts?page=abc")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_lists_published_post(self, test_engine, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        await _seed_post(test_engine, slug="api-test-post", username="api_tester")

        import arborpress.core.db as _db
        _db._engine = test_engine
        monkeypatch.setattr(_db, "_engine", test_engine)

        resp = await client.get("/api/v1/posts")
        assert resp.status_code == 200
        data = await resp.get_json()
        slugs = [p["slug"] for p in data["items"]]
        assert "api-test-post" in slugs


# ---------------------------------------------------------------------------
# Public API – GET /api/v1/posts/<slug>
# ---------------------------------------------------------------------------


class TestAPIPostDetail:
    @pytest.mark.asyncio
    async def test_returns_body_html(self, test_engine, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        await _seed_post(test_engine, slug="detail-post", username="detail_user")

        import arborpress.core.db as _db
        _db._engine = test_engine

        resp = await client.get("/api/v1/posts/detail-post")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "body_html" in data
        assert data["slug"] == "detail-post"

    @pytest.mark.asyncio
    async def test_unknown_slug_is_404(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/posts/this-does-not-exist-xyz")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_private_post_is_404(self, test_engine, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        await _seed_post(test_engine, slug="private-post", public=False, username="priv_user")

        import arborpress.core.db as _db
        _db._engine = test_engine

        resp = await client.get("/api/v1/posts/private-post")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Public API – GET /api/v1/tags
# ---------------------------------------------------------------------------


class TestAPITags:
    @pytest.mark.asyncio
    async def test_returns_items_and_total(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/tags")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "items" in data
        assert "total" in data


# ---------------------------------------------------------------------------
# Public API – GET /api/v1/users/<handle>
# ---------------------------------------------------------------------------


class TestAPIUserProfile:
    @pytest.mark.asyncio
    async def test_unknown_handle_is_404(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/users/nobody_xyz")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_public_user_returns_profile(self, test_engine, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        await _seed_post(test_engine, slug="u-profile-post", username="profile_alice")

        import arborpress.core.db as _db
        _db._engine = test_engine

        resp = await client.get("/api/v1/users/profile_alice")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["username"] == "profile_alice"
        assert "post_count" in data


# ---------------------------------------------------------------------------
# Public API – GET /api/v1/search
# ---------------------------------------------------------------------------


class TestAPISearch:
    @pytest.mark.asyncio
    async def test_empty_q_returns_zero(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/search")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_search_returns_envelope(self, client, monkeypatch):
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        resp = await client.get("/api/v1/search?q=hello")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "items" in data
        assert data["q"] == "hello"


# ---------------------------------------------------------------------------
# Admin API – Serialiser helpers (unit-level)
# ---------------------------------------------------------------------------


class TestAPISerialiser:
    """_post_summary returns expected keys."""

    def test_post_summary_keys(self):
        from arborpress.web.routes.api import _post_summary
        from types import SimpleNamespace
        from datetime import datetime, UTC

        post = SimpleNamespace(
            short_id="abc123",
            slug="test",
            title="Test",
            excerpt=None,
            published_at=datetime.now(UTC),
            reading_time_min=1,
            lang=None,
            is_pinned=False,
            is_featured=False,
            tags=[],
        )
        summary = _post_summary(post)
        for key in ("id", "slug", "title", "tags", "url", "published_at"):
            assert key in summary, f"Missing key: {key}"

    def test_user_public_keys(self):
        from arborpress.web.routes.api import _user_public
        from types import SimpleNamespace

        user = SimpleNamespace(
            username="bob",
            display_name="Bob",
            bio=None,
            website=None,
        )
        result = _user_public(user, post_count=3)
        assert result["post_count"] == 3
        assert result["profile_url"] == "/@bob"
