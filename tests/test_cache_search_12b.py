"""Phase 12B regression coverage for the existing cache/search services."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


class _RedisFixture:
    def __init__(self) -> None:
        self.keys = [b"owned:a", b"owned:b", b"other:c"]
        self.deleted: list[bytes] = []
        self.key_calls = 0

    async def scan_iter(self, *, match: str, count: int):
        assert count == 250
        prefix = match.removesuffix("*").encode()
        for key in self.keys:
            if key.startswith(prefix):
                yield key

    async def delete(self, *keys: bytes) -> None:
        self.deleted.extend(keys)

    async def keys(self, _pattern: str):
        self.key_calls += 1
        raise AssertionError("blocking KEYS must not be used")


class _MemcachedFixture:
    def __init__(self) -> None:
        self.items: dict[bytes, bytes] = {}
        self.flush_all_called = False

    async def get(self, key: bytes) -> bytes | None:
        return self.items.get(key)

    async def add(self, key: bytes, value: bytes, exptime: int) -> None:
        self.items.setdefault(key, value)

    async def set(self, key: bytes, value: bytes, exptime: int) -> None:
        self.items[key] = value

    async def delete(self, key: bytes) -> None:
        self.items.pop(key, None)

    async def flush_all(self) -> None:
        self.flush_all_called = True
        self.items.clear()


@pytest.mark.asyncio
async def test_redis_flush_scans_only_owned_prefix_in_batches() -> None:
    from arborpress.core.cache import RedisBackend

    backend = RedisBackend("redis://ignored", prefix="owned:")
    client = _RedisFixture()
    backend._client = client
    await backend.flush()
    assert client.deleted == [b"owned:a", b"owned:b"]
    assert client.key_calls == 0


@pytest.mark.asyncio
async def test_memcached_flush_rotates_only_instance_generation() -> None:
    from arborpress.core.cache import MemcachedBackend

    backend = MemcachedBackend("localhost", 11211, prefix="ap:instance:")
    client = _MemcachedFixture()
    backend._client = client
    await backend.set("key", {"value": 1}, 60)
    assert await backend.get("key") == {"value": 1}
    client.items[b"another-app:unrelated"] = b"preserve"
    await backend.flush()
    assert await backend.get("key") is None
    assert not client.flush_all_called
    assert client.items[b"another-app:unrelated"] == b"preserve"


@pytest.mark.asyncio
async def test_cache_namespace_and_file_purge_are_instance_scoped(tmp_path) -> None:
    from arborpress.core.cache import FileBackend, NamespacedBackend

    backend = FileBackend(str(tmp_path), prefix="instance-a_")
    scoped = NamespacedBackend(backend, "arborpress:cache:v1:instance-a:")
    await scoped.set("safe", {"ok": True}, 30)
    (tmp_path / "instance-b_foreign.cache").write_text("{}", encoding="utf-8")
    await scoped.flush()
    assert await scoped.get("safe") is None
    assert (tmp_path / "instance-b_foreign.cache").exists()


def test_configured_cache_prefix_is_bounded_and_does_not_truncate_collisions() -> None:
    from arborpress.core.cache import _instance_prefix

    first = _instance_prefix("x" * 1_000)
    second = _instance_prefix(("x" * 999) + "y")
    assert len(first) < 100
    assert first != second
    assert first == _instance_prefix("x" * 1_000)


@pytest.mark.asyncio
async def test_l1_ttl_is_bounded_for_cross_worker_staleness() -> None:
    import time

    from arborpress.core.cache import MemoryBackend, TwoLevelBackend

    backend = TwoLevelBackend(MemoryBackend(), MemoryBackend(), l1_ttl=300)
    assert backend._l1_ttl == 5
    await backend.set("key", "old", 30)
    await backend._l2.set("key", "new", 30)
    assert await backend.get("key") == "old"
    value, _expires = backend._l1._store["key"]
    backend._l1._store["key"] = (value, time.monotonic() - 1)
    assert await backend.get("key") == "new"


@pytest.mark.asyncio
async def test_cache_facade_fails_open_when_optional_backend_errors(caplog) -> None:
    from arborpress.core.cache import CacheBackend, cache_get, cache_set, reset_backend

    class Broken(CacheBackend):
        async def get(self, _key: str):
            raise RuntimeError("redis://secret-user:secret@example.invalid")

        async def set(self, _key: str, _value, _ttl: int) -> None:
            raise RuntimeError("secret")

        async def delete(self, _key: str) -> None:
            raise RuntimeError("secret")

        async def flush(self) -> None:
            raise RuntimeError("secret")

    reset_backend(Broken())
    try:
        assert await cache_get("db-is-authoritative") is None
        await cache_set("optional", "value")
        assert "secret-user" not in caplog.text
    finally:
        reset_backend(None)


def test_search_provider_diagnostics_do_not_claim_health_only_external_adapter():
    from arborpress.core.db_capabilities import DBCapabilities
    from arborpress.core.search import _provider

    provider, degraded, why = _provider(
        DBCapabilities(engine_name="sqlite", fts_provider="sqlite_fts5"), "meilisearch"
    )
    assert provider == "like"
    assert degraded
    assert why == "external_adapter_unavailable_using_database_search"


@pytest.mark.asyncio
async def test_shared_search_applies_same_visibility_to_posts_and_pages(db_session) -> None:
    from arborpress.core.db_capabilities import DBCapabilities
    from arborpress.core.search import search_public_content
    from arborpress.models.content import Page, Post, PostStatus, PostVisibility

    now = datetime.now(UTC).replace(tzinfo=None)
    db_session.add_all(
        [
            Post(
                short_id="s12public",
                slug="visible-search-post",
                title="Public Arbor Search",
                body_md="body needle",
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
                noindex=False,
                published_at=now,
            ),
            Post(
                short_id="s12hidden",
                slug="hidden-search-post",
                title="Hidden Arbor Search",
                body_md="needle",
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.HIDDEN,
                noindex=False,
                published_at=now,
            ),
            Post(
                short_id="s12draft",
                slug="draft-search-post",
                title="Draft Arbor Search",
                body_md="needle",
                status=PostStatus.DRAFT,
                visibility=PostVisibility.PUBLIC,
                noindex=False,
            ),
            Post(
                short_id="s12noindex",
                slug="noindex-search-post",
                title="Noindex Arbor Search",
                body_md="needle",
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
                noindex=True,
                published_at=now,
            ),
            Page(
                slug="visible-search-page",
                title="Public Arbor Page",
                body_md="page needle",
                is_published=True,
                visibility=PostVisibility.PUBLIC,
                noindex=False,
            ),
            Page(
                slug="private-search-page",
                title="Private Arbor Page",
                body_md="needle",
                is_published=True,
                visibility=PostVisibility.PRIVATE,
                noindex=False,
            ),
        ]
    )
    await db_session.flush()

    result = await search_public_content(
        db_session,
        "needle",
        capabilities=DBCapabilities(engine_name="sqlite", fts_provider="fallback"),
    )
    assert {item.slug for item in result.items} == {
        "visible-search-post",
        "visible-search-page",
    }
    assert result.total == 2
    assert result.provider == "like"

    # Simulate a Postgres capability against SQLite: the native SQL function
    # fails, the savepoint rolls back, and the shared service uses LIKE.
    native_fallback = await search_public_content(
        db_session,
        "needle",
        capabilities=DBCapabilities(engine_name="postgresql", fts_provider="pg_fts"),
    )
    assert native_fallback.provider == "like"
    assert native_fallback.degraded
    assert {item.slug for item in native_fallback.items} == {
        "visible-search-post",
        "visible-search-page",
    }


@pytest.mark.asyncio
async def test_search_query_and_pagination_are_bounded(db_session) -> None:
    from arborpress.core.search import search_public_content

    with pytest.raises(ValueError, match="at most"):
        await search_public_content(db_session, "x" * 201)
    with pytest.raises(ValueError, match="page must"):
        await search_public_content(db_session, "term", page=0)
    with pytest.raises(ValueError, match="per_page"):
        await search_public_content(db_session, "term", per_page=0)


@pytest.mark.asyncio
async def test_feed_etag_returns_304(client, monkeypatch) -> None:
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    for path in ("/feed.xml", "/feed/atom.xml"):
        first = await client.get(path)
        assert first.status_code == 200
        etag = first.headers["ETag"]
        second = await client.get(path, headers={"If-None-Match": etag})
        assert second.status_code == 304
        assert await second.get_data() == b""


@pytest.mark.asyncio
async def test_ssr_and_api_search_share_public_post_and_page_visibility(
    test_engine, client, monkeypatch
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.core.db as db_module
    from arborpress.models.content import Page, PostVisibility
    from tests.test_api import _seed_post

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    term = "SharedSearchPhaseTwelveB"
    await _seed_post(
        test_engine,
        slug="shared-visible-search-result",
        title=term,
        username="shared_search_author",
    )
    await _seed_post(
        test_engine,
        slug="shared-private-search-result",
        title=term,
        public=False,
        username="private_search_author",
    )
    async with async_sessionmaker(bind=test_engine, expire_on_commit=False)() as db:
        db.add(
            Page(
                slug="shared-visible-search-page",
                title=term,
                body_md="shared search page",
                is_published=True,
                visibility=PostVisibility.PUBLIC,
                noindex=False,
            )
        )
        await db.commit()
    db_module._engine = test_engine

    api_response = await client.get(f"/api/v1/search?q={term}")
    assert api_response.status_code == 200
    api_slugs = {item["slug"] for item in (await api_response.get_json())["items"]}
    assert api_slugs == {"shared-visible-search-result", "shared-visible-search-page"}

    ssr_response = await client.get(f"/search?q={term}")
    assert ssr_response.status_code == 200
    ssr_html = await ssr_response.get_data(as_text=True)
    assert "shared-visible-search-result" in ssr_html
    assert "shared-visible-search-page" in ssr_html
    assert "shared-private-search-result" not in ssr_html


@pytest.mark.asyncio
async def test_public_api_etag_and_cookie_response_are_not_shared(
    test_engine, client, monkeypatch
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.core.db as db_module
    from tests.test_api import _seed_post

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    await _seed_post(test_engine, slug="etag-content", username="etag_user")
    db_module._engine = test_engine

    first = await client.get("/api/v1/posts/etag-content")
    assert first.status_code == 200
    assert first.headers.get("ETag")
    second = await client.get(
        "/api/v1/posts/etag-content", headers={"If-None-Match": first.headers["ETag"]}
    )
    assert second.status_code == 304

    from sqlalchemy import select

    from arborpress.models.content import Post

    async with async_sessionmaker(bind=test_engine, expire_on_commit=False)() as db:
        post = (await db.execute(select(Post).where(Post.slug == "etag-content"))).scalar_one()
        post.title = "Updated ETag Content"
        await db.commit()
    changed = await client.get("/api/v1/posts/etag-content")
    assert changed.headers["ETag"] != first.headers["ETag"]

    private = await client.get("/api/v1/oauth/me", headers={"Cookie": "session=anything"})
    assert private.headers["Cache-Control"].startswith("no-store")


@pytest.mark.asyncio
async def test_media_etag_and_last_modified_return_304(tmp_path, client, monkeypatch) -> None:
    from types import SimpleNamespace

    media_dir = tmp_path / "media"
    target = media_dir / "2026" / "11" / "asset.txt"
    target.parent.mkdir(parents=True)
    target.write_text("public image payload", encoding="utf-8")
    monkeypatch.setattr(
        "arborpress.web.routes.public.get_settings",
        lambda: SimpleNamespace(web=SimpleNamespace(media_dir=media_dir)),
    )
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

    first = await client.get("/media/2026/11/asset.txt")
    assert first.status_code == 200
    assert first.headers.get("ETag", "").startswith("W/")
    assert first.headers["Cache-Control"] == "public, max-age=31536000, immutable"
    second = await client.get(
        "/media/2026/11/asset.txt", headers={"If-None-Match": first.headers["ETag"]}
    )
    assert second.status_code == 304
    assert await second.get_data() == b""
    last_modified = await client.get(
        "/media/2026/11/asset.txt",
        headers={"If-Modified-Since": first.headers["Last-Modified"]},
    )
    assert last_modified.status_code == 304


@pytest.mark.asyncio
async def test_site_settings_cache_expires_for_other_workers(monkeypatch) -> None:
    import arborpress.core.site_settings as settings

    clock = [100.0]
    monkeypatch.setattr(settings.time, "monotonic", lambda: clock[0])
    settings.invalidate_cache()
    settings._cache["general"] = {"site_title": "cached"}
    settings._cache_deadline["general"] = 105.0
    assert settings.get_cached("general") == {"site_title": "cached"}
    clock[0] = 105.1
    assert settings.get_cached("general") is None


@pytest.mark.asyncio
async def test_optional_cache_failure_does_not_fail_readiness(client, monkeypatch) -> None:
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setattr(
        "arborpress.core.cache.cache_health",
        lambda: _unhealthy_cache(),
    )
    response = await client.get("/_ready")
    assert response.status_code == 200
    data = await response.get_json()
    assert data["status"] == "ready"
    assert data["cache"]["healthy"] is False


async def _unhealthy_cache() -> tuple[bool, str]:
    return False, "fixture_unavailable"
