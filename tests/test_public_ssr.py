"""Public pages render their useful content through Quart and Jinja."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker


async def _seed_public_posts(engine, *, language: str = "p4btest") -> tuple[str, str]:
    import arborpress.models  # noqa: F401
    from arborpress.models.content import Comment, CommentStatus, Post, PostStatus, PostVisibility
    from arborpress.models.user import AccountType, User, UserRole

    suffix = uuid.uuid4().hex[:12]
    now = datetime.now(UTC).replace(tzinfo=None)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as db:
        author = User(
            username=f"ssr-{suffix}",
            display_name=f"SSR Author {suffix}",
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
        db.add(author)
        await db.flush()
        posts = [
            Post(
                short_id=uuid.uuid4().hex[:8],
                author_id=str(author.id),
                slug=f"ssr-{suffix}-{number}",
                title=f"SSR Article {suffix} {number}",
                body_md="Server rendered body",
                body_html=f"<p>Server rendered article body {suffix} {number}</p>",
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
                lang=language,
                published_at=now + timedelta(seconds=number),
            )
            for number in (1, 2)
        ]
        db.add_all(posts)
        await db.flush()
        db.add(
            Comment(
                post_id=posts[0].id,
                author_name='Visitor "One" & <tag>',
                author_email="visitor@example.test",
                body="Quoted <script>alert(1)</script> text",
                status=CommentStatus.APPROVED,
            )
        )
        await db.commit()
    return posts[0].slug, posts[1].slug


def _install_asset_stub(app, monkeypatch) -> None:
    from arborpress.web.assets import AssetBundle

    def resolve(entry: str) -> AssetBundle:
        if entry == "site":
            return AssetBundle(javascript="dist/assets/site-a1b2.js", stylesheets=())
        if entry == "public":
            return AssetBundle(javascript="dist/assets/public-e5f6.js", stylesheets=())
        raise AssertionError(f"Unexpected browser entry: {entry}")

    monkeypatch.setitem(app.jinja_env.globals, "vite_asset", resolve)


@pytest.mark.asyncio
async def test_packaged_public_and_webauthn_entries_are_served_by_quart(client):
    from arborpress.web.assets import AssetResolver

    resolver = AssetResolver()
    for entry in ("public", "webauthn"):
        bundle = resolver.resolve(entry)
        response = await client.get(f"/static/{bundle.javascript}")
        assert response.status_code == 200
        assert await response.get_data()
        for stylesheet in bundle.stylesheets:
            css_response = await client.get(f"/static/{stylesheet}")
            assert css_response.status_code == 200
            assert await css_response.get_data()


@pytest.mark.asyncio
async def test_theme_static_route_serves_only_declared_assets(client):
    css = await client.get("/static/themes/default/css/style.css")
    assert css.status_code == 200
    assert b"--color-bg" in await css.get_data()

    undeclared = await client.get("/static/themes/default/secret.txt")
    assert undeclared.status_code == 404


@pytest.mark.asyncio
async def test_public_index_is_server_rendered_and_preserves_filtered_pagination(
    test_engine, client, app, monkeypatch
):
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    monkeypatch.setattr("arborpress.web.routes.public._PER_PAGE", 1)
    _install_asset_stub(app, monkeypatch)
    first_slug, _ = await _seed_public_posts(test_engine)

    response = await client.get("/?lang=p4btest&page=2")

    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert "<main" in html
    assert 'aria-label="Hauptnavigation"' in html
    suffix = first_slug.removeprefix("ssr-").removesuffix("-1")
    assert f"SSR Article {suffix} 1" in html
    assert f"SSR Article {suffix} 2" not in html
    assert "2 / 2" in html
    assert "lang=p4btest" in html


@pytest.mark.asyncio
async def test_article_and_comment_form_are_complete_without_javascript(
    test_engine, client, app, monkeypatch
):
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
    _install_asset_stub(app, monkeypatch)
    first_slug, _ = await _seed_public_posts(test_engine)

    response = await client.get(f"/p/{first_slug}")

    assert response.status_code == 200
    html = await response.get_data(as_text=True)
    assert '<article class="post"' in html
    assert "Server rendered article body" in html
    assert "SSR Author" in html
    suffix = first_slug.removeprefix("ssr-").removesuffix("-1")
    assert f'href="/@ssr-{suffix}"' in html
    assert 'method="POST"' in html
    assert f'action="/p/{first_slug}/comment"' in html
    assert 'name="_csrf"' in html
    assert "data-comment-quote" in html
    assert "ohne JavaScript über die Links am Kommentar" in html
    assert 'aria-live="polite"' in html
    assert "onclick=" not in html
    assert "Visitor &#34;One&#34; &amp; &lt;tag&gt;" in html
    assert ">Antworten</a>" in html
    assert ">Zitieren</a>" in html
    assert "/static/dist/assets/public-e5f6.js" in html
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html


@pytest.mark.asyncio
async def test_public_not_found_and_invalid_pagination_are_html_errors(client, monkeypatch):
    monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)

    missing = await client.get("/p/no-such-public-post")
    invalid_page = await client.get("/?page=not-a-number")

    assert missing.status_code == 404
    assert missing.content_type.startswith("text/html")
    assert invalid_page.status_code == 400
    assert invalid_page.content_type.startswith("text/html")
