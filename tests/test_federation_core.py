"""Security and identity contracts for the ActivityPub foundation."""

from __future__ import annotations

import base64
import hashlib
import json
from email.utils import formatdate
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def test_federation_master_switch_is_explicit() -> None:
    from arborpress.core.site_settings import get_defaults
    from arborpress.federation.policy import federation_is_enabled

    defaults = get_defaults("federation")
    assert defaults["enabled"] is False
    assert federation_is_enabled({"mode": "full"}) is False
    assert federation_is_enabled({"enabled": True, "mode": "full"}) is True
    assert federation_is_enabled({"enabled": True, "mode": "disabled"}) is False


@pytest.mark.asyncio
async def test_local_actor_is_explicit_stable_and_gets_encrypted_rsa_key(
    test_engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptography.fernet import Fernet
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base
    from arborpress.federation.actors import enable_local_actor
    from arborpress.models.federation import FederationInstanceIdentity
    from arborpress.models.user import AccountType, ActorKeypair, User, UserRole

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    fernet_key = Fernet.generate_key()
    monkeypatch.setattr(
        "arborpress.federation.policy.get_settings",
        lambda: SimpleNamespace(web=SimpleNamespace(base_url="https://blog.example.com")),
    )
    monkeypatch.setattr(
        "arborpress.federation.actors.get_settings",
        lambda: SimpleNamespace(
            auth=SimpleNamespace(
                actor_key_enc_key=SimpleNamespace(get_secret_value=lambda: fernet_key.decode())
            )
        ),
    )
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username="stable-author",
            display_name="Stable Author",
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        first = await enable_local_actor(db, user)
        first_uri = first.actor_uri
        first.enabled = False
        user.username = "renamed-author"
        second = await enable_local_actor(db, user)
        key = await db.get(ActorKeypair, second.current_keypair_id)
        identity = await db.get(FederationInstanceIdentity, 1)
        assert second.actor_uri == first_uri
        assert second.preferred_username == "renamed-author"
        assert second.enabled is True
        assert identity.canonical_origin == "https://blog.example.com"
        assert key.algorithm == "rsa-sha256"
        private_pem = Fernet(fernet_key).decrypt(key.private_key_enc)
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        assert private_key.key_size >= 3072
        monkeypatch.setattr(
            "arborpress.federation.policy.get_settings",
            lambda: SimpleNamespace(web=SimpleNamespace(base_url="https://new.example.com")),
        )
        with pytest.raises(
            RuntimeError, match="canonical_origin_change_requires_explicit_migration"
        ):
            await enable_local_actor(db, user)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org/actor",
        "https://user:secret@example.org/actor",
        "file:///etc/passwd",
        "https://127.0.0.1/actor",
        "https://[::1]/actor",
        "https://[::ffff:127.0.0.1]/actor",
        "https://169.254.169.254/latest/meta-data",
    ],
)
def test_remote_url_syntax_fails_closed(url: str) -> None:
    from arborpress.federation.security import FederationFetchError, validate_remote_url_syntax

    with pytest.raises(FederationFetchError):
        validate_remote_url_syntax(url)


@pytest.mark.asyncio
async def test_remote_dns_addresses_must_all_be_public(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    from arborpress.federation.security import FederationFetchError, validate_remote_url

    loop = __import__("asyncio").get_running_loop()

    async def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(FederationFetchError, match="blocked_address"):
        await validate_remote_url("https://remote.example/actor")


@pytest.mark.asyncio
async def test_fetcher_revalidates_redirect_target(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from arborpress.federation import security
    from arborpress.federation.security import FederationFetchError

    calls: list[str] = []

    async def allowed(url: str) -> tuple[str, ...]:
        calls.append(url)
        if "127.0.0.1" in url:
            raise FederationFetchError("blocked_address")
        return ("93.184.216.34",)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://127.0.0.1/private"})

    monkeypatch.setattr(security, "validate_remote_url", allowed)
    with pytest.raises(FederationFetchError, match="blocked_address"):
        await security.fetch_remote(
            "https://remote.example/actor", transport=httpx.MockTransport(handler)
        )
    assert calls == ["https://remote.example/actor", "https://127.0.0.1/private"]


def _signed_headers(private_key, body: bytes) -> dict[str, str]:
    date = formatdate(usegmt=True)
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    headers = {"host": "local.example", "date": date, "digest": f"SHA-256={digest}"}
    lines = [
        "(request-target): post /ap/inbox/alice",
        f"host: {headers['host']}",
        f"date: {date}",
        f"digest: {headers['digest']}",
    ]
    signature = private_key.sign("\n".join(lines).encode(), padding.PKCS1v15(), hashes.SHA256())
    headers["signature"] = (
        'keyId="https://remote.example/actor#main-key",algorithm="rsa-sha256",'
        'headers="(request-target) host date digest",'
        f'signature="{base64.b64encode(signature).decode()}"'
    )
    return headers


def test_legacy_rsa_signature_requires_and_binds_digest() -> None:
    from arborpress.auth.http_signatures import verify_legacy_signature_with_pem

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    body = b'{"type":"Follow"}'
    headers = _signed_headers(private_key, body)
    valid, reason = verify_legacy_signature_with_pem(
        method="POST", path="/ap/inbox/alice", headers=headers, body=body, pem=pem
    )
    assert valid and reason == "ok"
    valid, reason = verify_legacy_signature_with_pem(
        method="POST", path="/ap/inbox/alice", headers=headers, body=body + b" ", pem=pem
    )
    assert not valid and reason == "digest_mismatch"
    headers["signature"] = headers["signature"].replace(' digest",', '",')
    valid, reason = verify_legacy_signature_with_pem(
        method="POST", path="/ap/inbox/alice", headers=headers, body=body, pem=pem
    )
    assert not valid and reason == "required_component_not_covered"


def test_inbox_activity_projection_sanitizes_html_and_never_fetches_context() -> None:
    from arborpress.web.routes.federation import _sanitize_activity

    result = _sanitize_activity(
        {
            "@context": [
                "https://evil.example/context.jsonld",
                "https://www.w3.org/ns/activitystreams",
            ],
            "content": (
                '<p onclick="alert(1)">Hi<script>bad()</script>'
                '<a href="javascript:alert(1)">x</a></p>'
            ),
            "actor": "https://remote.example/actor",
        }
    )
    assert result["@context"] == ["https://www.w3.org/ns/activitystreams"]
    assert "<script>" not in result["content"]
    assert "onclick" not in result["content"]
    assert "javascript:" not in result["content"]


@pytest.mark.asyncio
async def test_explicit_local_actor_and_webfinger_omit_private_account_fields(
    test_engine, client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.models  # noqa: F401
    from arborpress.core.db import Base
    from arborpress.models.content import (
        Post,
        PostAuthorRelation,
        PostAuthorRole,
        PostStatus,
        PostVisibility,
    )
    from arborpress.models.federation import FederationInstanceIdentity, LocalFederationActor
    from arborpress.models.user import AccountType, ActorKeypair, User, UserRole

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    actor_uri = "https://blog.example.com/ap/actor/public-author"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    async with factory() as db:
        user = User(
            username="public-author",
            display_name="Public Author",
            email="private@example.test",
            bio="A short profile",
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        post = Post(
            short_id="federated-post",
            author_id=user.id,
            slug="public-article",
            title="Public article",
            body_md="An article",
            body_html="<p>An article</p>",
            status=PostStatus.PUBLISHED,
            visibility=PostVisibility.PUBLIC,
        )
        db.add(post)
        key = ActorKeypair(
            user_id=str(user.id),
            key_id_url=f"{actor_uri}#main-key",
            public_key_pem=public_pem,
            private_key_enc=b"not exposed",
            algorithm="rsa-sha256",
        )
        db.add(key)
        await db.flush()
        db.add(
            PostAuthorRelation(
                post_id=str(post.id),
                user_id=str(user.id),
                role=PostAuthorRole.PRIMARY,
                position=0,
            )
        )
        db.add(FederationInstanceIdentity(id=1, canonical_origin="https://blog.example.com"))
        db.add(
            LocalFederationActor(
                user_id=str(user.id),
                actor_uri=actor_uri,
                preferred_username=user.username,
                enabled=True,
                current_keypair_id=key.id,
            )
        )
        await db.commit()

        monkeypatch.setattr(
            "arborpress.web.routes.federation._fed",
            lambda: {"enabled": True, "mode": "full"},
        )
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        monkeypatch.setattr(
            "arborpress.federation.policy.get_settings",
            lambda: SimpleNamespace(web=SimpleNamespace(base_url="https://blog.example.com")),
        )

        async def route_db_session():
            async with factory() as route_db:
                yield route_db

        monkeypatch.setattr("arborpress.web.routes.federation.get_db_session", route_db_session)

        actor_response = await client.get("/ap/actor/public-author")
        actor_payload = await actor_response.get_json()
        assert actor_response.status_code == 200
        assert actor_payload["id"] == actor_uri
        assert actor_payload["publicKey"]["owner"] == actor_uri
        assert actor_payload["preferredUsername"] == "public-author"
        assert "email" not in actor_payload
        assert "private_key_enc" not in actor_payload

        webfinger_response = await client.get(
            "/.well-known/webfinger?resource=acct:public-author@blog.example.com"
        )
        webfinger_payload = await webfinger_response.get_json()
        assert webfinger_response.status_code == 200
        assert webfinger_payload["links"][0]["href"] == actor_uri

        object_response = await client.get("/ap/object/federated-post")
        object_payload = await object_response.get_json()
        assert object_response.status_code == 200
        assert object_payload["type"] == "Article"
        assert object_payload["attributedTo"] == actor_uri


@pytest.mark.asyncio
async def test_signed_intake_deduplicates_and_has_no_comment_side_effects(
    test_engine, client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import func, select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    import arborpress.models  # noqa: F401
    from arborpress.auth.http_signatures import SignatureResult
    from arborpress.core.db import Base
    from arborpress.models.content import Comment
    from arborpress.models.federation import FederationInboxActivity, LocalFederationActor
    from arborpress.models.user import AccountType, User, UserRole

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with factory() as db:
        user = User(
            username="federated-owner",
            display_name="Federated Owner",
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        actor = LocalFederationActor(
            user_id=str(user.id),
            actor_uri="https://blog.example.com/ap/actor/federated-owner",
            preferred_username="federated-owner",
            enabled=True,
        )
        db.add(actor)
        await db.commit()
        comments_before = (await db.execute(select(func.count()).select_from(Comment))).scalar_one()

        monkeypatch.setattr(
            "arborpress.web.routes.federation._fed",
            lambda: {"enabled": True, "mode": "full"},
        )
        monkeypatch.setattr("arborpress.core.config.is_installed", lambda: True)
        monkeypatch.setattr(
            "arborpress.federation.policy.get_settings",
            lambda: type(
                "Settings", (), {"web": type("Web", (), {"base_url": "https://blog.example.com"})()}
            )(),
        )

        async def route_db_session():
            async with factory() as route_db:
                yield route_db

        monkeypatch.setattr("arborpress.web.routes.federation.get_db_session", route_db_session)

        async def domain_allowed(_db, _domain, _settings):
            return True

        async def signature_ok(**_kwargs):
            return SignatureResult(
                True,
                "ok",
                actor_uri="https://remote.example/actor",
                key_id="https://remote.example/actor#main-key",
            )

        monkeypatch.setattr("arborpress.federation.policy.domain_allowed", domain_allowed)
        monkeypatch.setattr(
            "arborpress.auth.http_signatures.verify_request_signature", signature_ok
        )
        activity = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://remote.example/activities/one",
            "type": "Follow",
            "actor": "https://remote.example/actor",
            "object": "https://blog.example.com/ap/actor/federated-owner",
        }
        body = json.dumps(activity).encode()
        first = await client.post(
            "/ap/inbox/federated-owner",
            scheme="https",
            headers={"Content-Type": "application/activity+json", "Host": "blog.example.com"},
            data=body,
        )
        duplicate = await client.post(
            "/ap/inbox/federated-owner",
            scheme="https",
            headers={"Content-Type": "application/activity+json", "Host": "blog.example.com"},
            data=body,
        )
        activity["object"] = "https://blog.example.com/ap/actor/someone-else"
        conflict = await client.post(
            "/ap/inbox/federated-owner",
            scheme="https",
            headers={"Content-Type": "application/activity+json", "Host": "blog.example.com"},
            data=json.dumps(activity).encode(),
        )
        assert first.status_code == 202
        assert duplicate.status_code == 202
        assert conflict.status_code == 409
        assert (
            await db.execute(select(func.count()).select_from(FederationInboxActivity))
        ).scalar_one() == 1
        assert (
            await db.execute(select(func.count()).select_from(Comment))
        ).scalar_one() == comments_before
