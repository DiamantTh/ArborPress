"""Routing, canonical identity and discovery contracts for public locales."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker


def test_supported_language_normalization_and_configured_default():
    from pydantic import ValidationError

    from arborpress.core.config import WebSettings
    from arborpress.core.i18n import normalize_language, supported_languages

    assert normalize_language("en_gb") == "en-GB"
    assert normalize_language("en") == "en-GB"
    assert normalize_language("xx-YY") is None
    assert WebSettings(default_lang="FR_fr").default_lang == "fr-FR"
    with pytest.raises(ValidationError):
        WebSettings(default_lang="xx-YY")
    assert "de-DE" in supported_languages()


@pytest.mark.asyncio
async def test_legacy_null_language_is_served_under_default_prefix(
    test_engine, client, app, monkeypatch
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.models  # noqa: F401
    from arborpress.core.config import Settings
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from arborpress.web.assets import AssetBundle

    cfg = Settings().model_copy(
        update={"web": Settings().web.model_copy(update={"i18n_mode": "prefix"})}
    )
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.web.routes.public.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "config",
        {
            **app.jinja_env.globals["config"],
            "web": {**app.jinja_env.globals["config"]["web"], "i18n_mode": "prefix"},
        },
    )
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(javascript="dist/assets/public-test.js", stylesheets=()),
    )
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        db.add(
            Post(
                short_id=uuid.uuid4().hex[:8],
                slug="legacy-default-language",
                title="Legacy language",
                body_md="Body",
                body_html="<p>Body</p>",
                lang=None,
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
                published_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
        await db.flush()
        from arborpress.core.db_capabilities import DBCapabilities
        from arborpress.core.search import search_public_content

        search_result = await search_public_content(
            db,
            "Legacy language",
            language="de-DE",
            default_language="de-DE",
            capabilities=DBCapabilities(engine_name="sqlite"),
        )
        assert [item.slug for item in search_result.items] == ["legacy-default-language"]
        await db.commit()
    response = await client.get("/de-DE/p/legacy-default-language")
    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert '<html lang="de-DE">' in html
    assert "http://localhost:8066/de-DE/p/legacy-default-language" in html
    sitemap = await client.get("/sitemap.xml")
    assert "http://localhost:8066/de-DE/p/legacy-default-language" in await sitemap.get_data(
        as_text=True
    )


async def _translated_posts(engine) -> tuple[str, str, str]:
    import arborpress.models  # noqa: F401
    from arborpress.models.content import (
        ContentTranslationGroup,
        Post,
        PostStatus,
        PostVisibility,
    )

    suffix = uuid.uuid4().hex[:10]
    group_id = str(uuid.uuid4())
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as db:
        db.add(ContentTranslationGroup(id=group_id, content_kind="post"))
        now = datetime.now(UTC).replace(tzinfo=None)
        for lang in ("en-GB", "de-DE"):
            db.add(
                Post(
                    short_id=uuid.uuid4().hex[:8],
                    slug=f"i18n-{suffix}-{lang[:2].lower()}",
                    title=f"Localized {lang}",
                    body_md="Body",
                    body_html="<p>Localized body</p>",
                    lang=lang,
                    translation_group_id=group_id,
                    status=PostStatus.PUBLISHED,
                    visibility=PostVisibility.PUBLIC,
                    noindex=False,
                    published_at=now,
                )
            )
        await db.commit()
    return suffix, group_id, f"i18n-{suffix}-en"


async def _translated_pages(engine) -> str:
    import arborpress.models  # noqa: F401
    from arborpress.models.content import ContentTranslationGroup, Page, PageType, PostVisibility

    suffix = uuid.uuid4().hex[:10]
    group_id = str(uuid.uuid4())
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as db:
        db.add(ContentTranslationGroup(id=group_id, content_kind="page"))
        for lang in ("en-GB", "de-DE"):
            db.add(
                Page(
                    slug=f"legal-{suffix}-{lang[:2].lower()}",
                    title=f"Legal {lang}",
                    body_md="Body",
                    body_html="<p>Legal body</p>",
                    page_type=PageType.CUSTOM,
                    lang=lang,
                    translation_group_id=group_id,
                    is_published=True,
                    visibility=PostVisibility.PUBLIC,
                )
            )
        await db.commit()
    return f"legal-{suffix}-en"


@pytest.mark.asyncio
async def test_prefix_content_canonical_hreflang_and_host_independence(
    test_engine, client, app, monkeypatch
):
    from arborpress.core.config import Settings
    from arborpress.web.assets import AssetBundle

    cfg = Settings().model_copy(
        update={"web": Settings().web.model_copy(update={"i18n_mode": "prefix"})}
    )
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setattr("arborpress.web.routes.public.get_settings", lambda: cfg)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "config",
        {
            **app.jinja_env.globals["config"],
            "web": {**app.jinja_env.globals["config"]["web"], "i18n_mode": "prefix"},
        },
    )
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(javascript="dist/assets/public-test.js", stylesheets=()),
    )
    _suffix, _group, english_slug = await _translated_posts(test_engine)

    legacy = await client.get(f"/p/{english_slug}")
    assert legacy.status_code == 301
    assert legacy.headers["Location"] == f"/en-GB/p/{english_slug}"
    response = await client.get(f"/en-GB/p/{english_slug}", headers={"Host": "attacker.invalid"})
    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert '<html lang="en-GB">' in html
    assert f"https://example.invalid/en-GB/p/{english_slug}" not in html
    assert 'href="http://localhost:8066/en-GB/p/' + english_slug + '"' in html
    assert 'hreflang="de-DE"' in html
    assert 'hreflang="en-GB"' in html


@pytest.mark.asyncio
async def test_single_language_index_filter_is_not_a_canonical_variant(client, app, monkeypatch):
    from arborpress.core.config import Settings
    from arborpress.web.assets import AssetBundle

    cfg = Settings()
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.web.routes.public.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(javascript="dist/assets/public-test.js", stylesheets=()),
    )
    response = await client.get("/?lang=en-GB")
    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert '<link rel="canonical" href="http://localhost:8066/">' in html


@pytest.mark.asyncio
async def test_prefix_rejects_unsupported_language_and_wrong_translation(
    test_engine, client, monkeypatch
):
    from arborpress.core.config import Settings

    cfg = Settings().model_copy(
        update={"web": Settings().web.model_copy(update={"i18n_mode": "prefix"})}
    )
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.web.routes.public.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    _suffix, _group, english_slug = await _translated_posts(test_engine)

    assert (await client.get(f"/xx/p/{english_slug}")).status_code == 404
    assert (await client.get(f"/de-DE/p/{english_slug}")).status_code == 404


@pytest.mark.asyncio
async def test_prefix_page_canonical_and_hreflang(test_engine, client, app, monkeypatch):
    from arborpress.core.config import Settings
    from arborpress.web.assets import AssetBundle

    cfg = Settings().model_copy(
        update={"web": Settings().web.model_copy(update={"i18n_mode": "prefix"})}
    )
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.web.routes.public.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setitem(
        app.jinja_env.globals,
        "config",
        {
            **app.jinja_env.globals["config"],
            "web": {**app.jinja_env.globals["config"]["web"], "i18n_mode": "prefix"},
        },
    )
    monkeypatch.setitem(
        app.jinja_env.globals,
        "vite_asset",
        lambda entry: AssetBundle(javascript="dist/assets/public-test.js", stylesheets=()),
    )
    english_slug = await _translated_pages(test_engine)
    response = await client.get(f"/en-GB/page/{english_slug}")
    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert f"http://localhost:8066/en-GB/page/{english_slug}" in html
    assert 'hreflang="de-DE"' in html
    assert 'hreflang="en-GB"' in html


@pytest.mark.asyncio
async def test_prefix_root_is_deterministic_and_protocol_routes_stay_unprefixed(
    client, monkeypatch
):
    from arborpress.core.config import Settings

    cfg = Settings().model_copy(
        update={"web": Settings().web.model_copy(update={"i18n_mode": "prefix"})}
    )
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.web.routes.public.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

    root = await client.get("/", headers={"Accept-Language": "de-DE"})
    assert root.status_code == 302
    assert root.headers["Location"] == "/de-DE/"
    slashless = await client.get("/en-GB")
    assert slashless.status_code == 301
    assert slashless.headers["Location"] == "/en-GB/"
    localized_root = await client.get("/en-GB/")
    assert localized_root.status_code == 200
    assert localized_root.headers.get("Location") != "/en-GB/"
    protocol = await client.get("/api/v1/oauth/me")
    assert protocol.status_code == 401
    assert protocol.headers.get("Location") is None


@pytest.mark.asyncio
async def test_sitemap_honors_noindex_and_uses_configured_origin(client, monkeypatch):
    from arborpress.core.config import Settings

    cfg = Settings().model_copy(
        update={"web": Settings().web.model_copy(update={"base_url": "https://canonical.example"})}
    )
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    response = await client.get("/sitemap.xml", headers={"Host": "attacker.invalid"})
    assert response.status_code == 200
    body = await response.get_data(as_text=True)
    assert "https://canonical.example/" in body
    assert "attacker.invalid" not in body


@pytest.mark.asyncio
async def test_public_feeds_exclude_noindex_posts(test_engine, client, monkeypatch):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.models  # noqa: F401
    from arborpress.core.config import Settings
    from arborpress.models.content import Post, PostStatus, PostVisibility

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    cfg = Settings()
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    now = datetime.now(UTC).replace(tzinfo=None)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        db.add(
            Post(
                short_id=uuid.uuid4().hex[:8],
                slug="excluded-noindex-feed-item",
                title="Private search hint",
                body_md="body",
                body_html="<p>body</p>",
                lang="en-GB",
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
                noindex=True,
                published_at=now,
            )
        )
        await db.commit()

    for feed_path in ("/feed.xml", "/feed/atom.xml"):
        response = await client.get(feed_path)
        assert response.status_code == 200
        assert b"excluded-noindex-feed-item" not in await response.get_data()


@pytest.mark.asyncio
async def test_slug_history_redirects_and_short_id_does_not_disclose_drafts(
    test_engine, client, monkeypatch
):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.models  # noqa: F401
    from arborpress.content.public_identity import remember_old_slugs
    from arborpress.core.config import Settings
    from arborpress.models.content import Post, PostStatus, PostVisibility

    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    cfg = Settings().model_copy(
        update={"web": Settings().web.model_copy(update={"i18n_mode": "prefix"})}
    )
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.web.routes.public.get_settings", lambda: cfg)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        post = Post(
            short_id=uuid.uuid4().hex[:8],
            slug="current-seo-slug",
            title="Current",
            body_md="body",
            body_html="<p>body</p>",
            lang="en-GB",
            status=PostStatus.PUBLISHED,
            visibility=PostVisibility.PUBLIC,
            published_at=datetime.now(UTC).replace(tzinfo=None),
        )
        draft = Post(
            short_id=uuid.uuid4().hex[:8],
            slug="seo-private-draft",
            title="Draft",
            body_md="body",
            body_html="<p>body</p>",
            lang="en-GB",
            status=PostStatus.DRAFT,
            visibility=PostVisibility.PUBLIC,
        )
        db.add_all([post, draft])
        await db.flush()
        await remember_old_slugs(
            db,
            kind="post",
            content_id=str(post.id),
            language=post.lang,
            slugs=("older-seo-slug",),
        )
        draft_short_id = draft.short_id
        await db.commit()

    old = await client.get("/en-GB/p/older-seo-slug")
    assert old.status_code == 301
    assert old.headers["Location"].endswith("/en-GB/p/current-seo-slug")
    hidden_target = await client.get(f"/o/{draft_short_id}")
    assert hidden_target.status_code == 404


@pytest.mark.asyncio
async def test_sitemap_switches_to_bounded_index_when_content_exceeds_limit(
    test_engine, client, monkeypatch
):
    from arborpress.core.config import Settings

    cfg = Settings()
    monkeypatch.setattr("arborpress.core.config.get_settings", lambda: cfg)
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setattr("arborpress.web.routes.discovery.SITEMAP_LIMIT", 1)
    await _translated_posts(test_engine)
    index = await client.get("/sitemap.xml")
    assert index.status_code == 200
    assert b"<sitemapindex" in await index.get_data()
    first = await client.get("/sitemap/0.xml")
    assert first.status_code == 200
    assert b"<urlset" in await first.get_data()
    assert (await client.get("/sitemap/99.xml")).status_code == 404
