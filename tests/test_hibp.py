"""Tests fuer den HIBP (Have I Been Pwned) Pwned-Passwords Helper."""

from __future__ import annotations

import hashlib

import httpx
import pytest

from arborpress.auth import hibp
from arborpress.auth.password_tools import validate_password_policy


def _sha1(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


def _range_response_for(password: str, count: int) -> str:
    sha1 = _sha1(password)
    suffix = sha1[5:]
    # Mix in unrelated suffixes to ensure parser picks the right one.
    return (
        "0000000000000000000000000000000000A:1\r\n"
        f"{suffix}:{count}\r\n"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB:7\r\n"
    )


def _make_mock_transport(password: str, count: int) -> httpx.MockTransport:
    expected_prefix = _sha1(password)[:5]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/range/{expected_prefix}"
        assert request.headers.get("Add-Padding") == "true"
        return httpx.Response(200, text=_range_response_for(password, count))

    return httpx.MockTransport(handler)


def _patch_httpx_client(monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
    original_client = httpx.Client

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original_client(*args, **kwargs)

    monkeypatch.setattr(hibp.httpx, "Client", factory)


class TestCheckPwned:
    def test_returns_count_when_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        password = "hunter2-leaked-example"
        _patch_httpx_client(monkeypatch, _make_mock_transport(password, 42))
        assert hibp.check_pwned(password) == 42

    def test_returns_zero_when_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        password = "untouched-passphrase-xyz"

        def handler(_request: httpx.Request) -> httpx.Response:
            # Suffix not in body -> count = 0
            return httpx.Response(200, text="ABCDEFABCDEFABCDEFABCDEFABCDEFABCDE:9\r\n")

        _patch_httpx_client(monkeypatch, httpx.MockTransport(handler))
        assert hibp.check_pwned(password) == 0

    def test_empty_password_short_circuits(self) -> None:
        assert hibp.check_pwned("") == 0

    def test_network_error_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("offline")

        _patch_httpx_client(monkeypatch, httpx.MockTransport(handler))
        with pytest.raises(hibp.HIBPCheckError):
            hibp.check_pwned("anything-here-1234")


class TestEnforcePolicy:
    def test_rejects_breached_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        password = "leaked-passphrase-9999"
        _patch_httpx_client(monkeypatch, _make_mock_transport(password, 5))
        with pytest.raises(ValueError, match="data breaches"):
            hibp.enforce_hibp_policy(password)

    def test_accepts_when_below_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        password = "tolerated-passphrase-0001"
        _patch_httpx_client(monkeypatch, _make_mock_transport(password, 3))
        assert hibp.enforce_hibp_policy(password, max_count=3) == 3

    def test_fail_open_swallows_network_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("offline")

        _patch_httpx_client(monkeypatch, httpx.MockTransport(handler))
        assert hibp.enforce_hibp_policy("any-password-here-12345", fail_open=True) == 0

    def test_fail_closed_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("offline")

        _patch_httpx_client(monkeypatch, httpx.MockTransport(handler))
        with pytest.raises(hibp.HIBPCheckError):
            hibp.enforce_hibp_policy("any-password-here-12345", fail_open=False)


class TestPolicyIntegration:
    def test_validate_password_policy_runs_hibp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        password = "correct horse battery staple extra"
        _patch_httpx_client(monkeypatch, _make_mock_transport(password, 99))
        with pytest.raises(ValueError, match="data breaches"):
            validate_password_policy(
                password,
                min_length=16,
                max_length=128,
                min_score=3,
                check_hibp=True,
                hibp_fail_open=False,
            )

    def test_validate_password_policy_skips_hibp_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called: dict[str, int] = {"n": 0}

        def handler(_request: httpx.Request) -> httpx.Response:
            called["n"] += 1
            return httpx.Response(200, text="")

        _patch_httpx_client(monkeypatch, httpx.MockTransport(handler))
        validate_password_policy(
            "correct horse battery staple extra",
            min_length=16,
            max_length=128,
            min_score=3,
        )
        assert called["n"] == 0
