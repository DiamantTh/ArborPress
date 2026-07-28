"""Tests fuer rp.id / origin-Auflösung (W3C WebAuthn L3 §5.3, §7.1)."""

from __future__ import annotations

from arborpress.auth import webauthn as wa


class TestResolveRpId:
    def test_strips_scheme_and_path(self):
        assert wa.resolve_rp_id("https://blog.example.com/path") == "blog.example.com"

    def test_strips_port(self):
        assert wa.resolve_rp_id("https://example.com:8443/") == "example.com"

    def test_localhost_passthrough(self):
        # localhost is a valid registrable domain per W3C §5.3 step 7
        assert wa.resolve_rp_id("http://localhost:5000") == "localhost"

    def test_idn_punycode(self):
        # W3C §5.3 requires ASCII (Punycode) form for rp.id
        rp_id = wa.resolve_rp_id("https://bücher.example/")
        assert rp_id.startswith("xn--")
        assert rp_id.endswith(".example")

    def test_lowercases_host(self):
        assert wa.resolve_rp_id("https://EXAMPLE.com/") == "example.com"

    def test_unicode_dot_and_trailing_dot(self):
        # U+3002 IDEOGRAPHIC FULL STOP and trailing dot should canonicalize.
        assert wa.resolve_rp_id("https://bücher。example./") == "xn--bcher-kva.example"


class TestResolveOrigin:
    def test_omits_default_https_port(self):
        assert wa.resolve_origin("https://example.com:443/x") == "https://example.com"

    def test_omits_default_http_port(self):
        assert wa.resolve_origin("http://example.com:80/") == "http://example.com"

    def test_keeps_non_default_port(self):
        assert wa.resolve_origin("https://example.com:8443/") == "https://example.com:8443"

    def test_idn_origin_punycode(self):
        origin = wa.resolve_origin("https://bücher.example/")
        assert origin.startswith("https://xn--")

    def test_origin_canonicalizes_trailing_dot(self):
        assert wa.resolve_origin("https://EXAMPLE.COM.:443/path") == "https://example.com"
