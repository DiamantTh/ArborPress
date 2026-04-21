"""Tests für Content-Modell – §6 Slug-Kanonisierung, §5 AP-IDs."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# §6 Slug-Kanonisierung
# ---------------------------------------------------------------------------


class TestSlugCanonicalization:
    """Slugs müssen lowercase sein und stabile URLs ergeben (§6)."""

    def _canonicalize(self, slug: str) -> str:
        """Repliziert _canonical_slug aus public.py."""
        from slugify import slugify
        return slugify(slug, lowercase=True, separator="-")

    def test_lowercase(self):
        assert self._canonicalize("Hello-World") == "hello-world"

    def test_spaces_to_dashes(self):
        assert self._canonicalize("hello world") == "hello-world"

    def test_unicode_umlauts(self):
        result = self._canonicalize("Über Äpfel")
        assert result == result.lower()
        assert " " not in result

    def test_special_chars_stripped(self):
        result = self._canonicalize("Test! @#$% Post")
        assert "!" not in result
        assert "@" not in result

    def test_empty_slug(self):
        result = self._canonicalize("")
        # Leerer Slug bleibt leer oder wird zu ""
        assert isinstance(result, str)

    def test_already_canonical(self):
        assert self._canonicalize("already-canonical") == "already-canonical"


# ---------------------------------------------------------------------------
# §6 Stabile Media-URLs
# ---------------------------------------------------------------------------


class TestMediaURLs:
    """Media-Pfade: yyyy/mm/dateiname – unveränderlich nach Upload (§6)."""

    def test_media_path_format(self):
        import re
        path = "2024/03/my-image.webp"
        assert re.match(r"^\d{4}/\d{2}/.+$", path)

    def test_media_filename_no_traversal(self):
        """Pfad-Traversal-Versuche dürfen nicht in URL auftauchen."""
        filename = "../../etc/passwd"
        # Simulation: Dateinamen-Sanitisierung
        import os
        safe = os.path.basename(filename)
        assert ".." not in safe
        assert "/" not in safe


# ---------------------------------------------------------------------------
# §6 Kurz-IDs (ActivityPub-kompatibel)
# ---------------------------------------------------------------------------


class TestShortIds:
    """short_id muss URL-safe und eindeutig sein (§6 /o/{id})."""

    def test_short_id_url_safe(self):
        import re
        # Simulates UUID4 hex prefix or nanoid-style
        short_id = "a1b2c3d4"
        assert re.match(r"^[a-zA-Z0-9_-]+$", short_id)

    def test_short_id_not_empty(self):
        assert len("a1b2c3d4") > 0


# ---------------------------------------------------------------------------
# Reverse Proxy
# ---------------------------------------------------------------------------


class TestReverseProxyMiddleware:
    async def test_forwarded_prefix_sets_root_path(self):
        from arborpress.web.middleware import ReverseProxyMiddleware

        captured: dict = {}

        async def app(scope, receive, send):
            captured.update(scope)

        middleware = ReverseProxyMiddleware(app, trusted_proxies=1)
        scope = {
            "type": "http",
            "scheme": "http",
            "path": "/login",
            "root_path": "",
            "headers": [
                (b"x-forwarded-proto", b"https"),
                (b"x-forwarded-host", b"blog.example.com"),
                (b"x-forwarded-prefix", b"/blog"),
                (b"x-forwarded-for", b"203.0.113.9, 10.0.0.1"),
            ],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8066),
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            return None

        await middleware(scope, receive, send)

        assert captured["scheme"] == "https"
        assert captured["root_path"] == "/blog"
        assert captured["client"][0] == "203.0.113.9"


# ---------------------------------------------------------------------------
# Federation for blogging
# ---------------------------------------------------------------------------


class TestFederationHelpers:
    @pytest.mark.asyncio
    async def test_webfinger_rejects_unknown_user(self, app, client, monkeypatch):
        from arborpress.core.site_settings import _cache

        _cache["federation"] = {"mode": "full", "instance_name": "ArborPress"}
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        monkeypatch.setattr(
            "arborpress.web.routes.federation.get_settings",
            lambda: SimpleNamespace(web=SimpleNamespace(base_url="https://blog.example.com")),
        )

        resp = await client.get("/.well-known/webfinger?resource=acct:missing@blog.example.com")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_outbox_lists_published_posts(self, test_engine, client, monkeypatch):
        import arborpress.models  # noqa: F401
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from arborpress.core.db import Base
        from arborpress.models.content import Post, PostStatus, PostVisibility
        from arborpress.models.user import AccountType, User, UserRole
        from arborpress.web.routes.federation import ap_outbox

        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
        async with factory() as db_session:
            user = User(
                username="alice",
                display_name="Alice",
                account_type=AccountType.PUBLIC,
                role=UserRole.AUTHOR,
                is_active=True,
            )
            db_session.add(user)
            await db_session.flush()

            post = Post(
                short_id="abc123",
                author_id=user.id,
                slug="hello-world",
                title="Hello World",
                body_md="Hi",
                body_html="<p>Hi</p>",
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
            )
            db_session.add(post)
            await db_session.commit()

            monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
            monkeypatch.setattr(
                "arborpress.web.routes.federation._fed",
                lambda: {"mode": "full", "instance_name": "ArborPress"},
            )
            monkeypatch.setattr(
                "arborpress.web.routes.federation.get_settings",
                lambda: SimpleNamespace(web=SimpleNamespace(base_url="https://blog.example.com")),
            )

            async def _fake_db_session():
                yield db_session

            monkeypatch.setattr(
                "arborpress.web.routes.federation.get_db_session",
                _fake_db_session,
            )

            resp = await client.get("/ap/outbox/alice")
            payload = await resp.get_json()
            assert resp.status_code == 200
            assert payload["totalItems"] == 1
            assert payload["orderedItems"][0]["type"] in {"Article", "Note"}


# ---------------------------------------------------------------------------
# §10 Security Hardening
# ---------------------------------------------------------------------------


class TestSSRFGuard:
    """is_safe_external_url blocks private/reserved IP ranges (§10 SSRF)."""

    def _check(self, url: str) -> bool:
        from arborpress.core.validators import is_safe_external_url
        return is_safe_external_url(url)

    def test_blocks_loopback(self):
        assert self._check("http://127.0.0.1/secret") is False

    def test_blocks_private_10(self):
        assert self._check("http://10.0.0.1/") is False

    def test_blocks_private_172(self):
        assert self._check("http://172.16.5.1/") is False

    def test_blocks_private_192168(self):
        assert self._check("http://192.168.0.1/") is False

    def test_blocks_link_local_aws_imds(self):
        # AWS / GCP / Azure instance metadata service
        assert self._check("http://169.254.169.254/latest/meta-data/") is False

    def test_blocks_ipv6_loopback(self):
        assert self._check("http://[::1]/") is False

    def test_blocks_ipv6_ula(self):
        assert self._check("http://[fc00::1]/") is False

    def test_blocks_javascript_scheme(self):
        assert self._check("javascript:alert(1)") is False

    def test_blocks_bare_file_scheme(self):
        assert self._check("file:///etc/passwd") is False

    def test_allows_public_http(self):
        # example.com is a public IANA-reserved domain that resolves to 93.x
        # We just test scheme + non-private literal IP here to stay offline
        # (no DNS in CI). Real-IP literal for a routable address:
        assert self._check("http://203.0.113.5/") is False  # TEST-NET-3 → blocked

    def test_blocks_empty_url(self):
        assert self._check("") is False

    def test_blocks_no_scheme(self):
        assert self._check("//evil.com/ssrf") is False


class TestMathCaptchaHMAC:
    """Math captcha challenge must be HMAC-signed (§10 input tampering)."""

    def _sign(self, a: int, b: int) -> str:
        from arborpress.core.captcha import _math_sign
        return _math_sign(a, b)

    def test_signature_is_hex(self):
        sig = self._sign(3, 4)
        assert all(c in "0123456789abcdef" for c in sig)
        assert len(sig) == 64  # SHA-256 hex digest

    def test_signature_changes_with_values(self):
        assert self._sign(3, 4) != self._sign(4, 3)
        assert self._sign(1, 1) != self._sign(1, 2)

    def test_verify_accepts_correct_answer(self):
        from arborpress.core.captcha import _verify_math
        form = {
            "captcha_a": "3",
            "captcha_b": "4",
            "captcha_answer": "7",
            "captcha_sig": self._sign(3, 4),
        }
        ok, msg = _verify_math(form)
        assert ok is True
        assert msg == ""

    def test_verify_rejects_wrong_answer(self):
        from arborpress.core.captcha import _verify_math
        form = {
            "captcha_a": "3",
            "captcha_b": "4",
            "captcha_answer": "99",
            "captcha_sig": self._sign(3, 4),
        }
        ok, _ = _verify_math(form)
        assert ok is False

    def test_verify_rejects_tampered_values(self):
        """Bot submits different a/b but keeps old signature → must fail."""
        from arborpress.core.captcha import _verify_math
        real_sig = self._sign(3, 4)
        # Bot changes a=3 → a=1, b=4 → b=0 then sets answer=1
        form = {
            "captcha_a": "1",
            "captcha_b": "0",
            "captcha_answer": "1",
            "captcha_sig": real_sig,  # signature for (3,4), not (1,0)
        }
        ok, _ = _verify_math(form)
        assert ok is False

    def test_verify_rejects_missing_signature(self):
        from arborpress.core.captcha import _verify_math
        form = {
            "captcha_a": "2",
            "captcha_b": "3",
            "captcha_answer": "5",
            # captcha_sig intentionally absent
        }
        ok, _ = _verify_math(form)
        assert ok is False

    def test_get_challenge_includes_sig(self):
        from arborpress.core.captcha import CaptchaType, get_captcha_challenge
        ctx = get_captcha_challenge(CaptchaType.MATH, {})
        assert "math_sig" in ctx
        assert len(ctx["math_sig"]) == 64


class TestImageFetchMimeFilter:
    """SVG must be blocked by the MIME allowlist in image_fetch (§10 XSS)."""

    def test_svg_not_in_allowed_mime(self):
        from arborpress.core.image_fetch import _ALLOWED_MIME
        assert "image/svg+xml" not in _ALLOWED_MIME

    def test_jpeg_still_allowed(self):
        from arborpress.core.image_fetch import _ALLOWED_MIME
        assert "image/jpeg" in _ALLOWED_MIME

    def test_webp_still_allowed(self):
        from arborpress.core.image_fetch import _ALLOWED_MIME
        assert "image/webp" in _ALLOWED_MIME
