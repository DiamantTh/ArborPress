from __future__ import annotations

import asyncio
import shutil
from email import message_from_bytes, policy

import pytest

from arborpress.mail.openpgp import (
    OpenPGPError,
    _private_home,
    _run,
    _write_private,
    build_pgp_message,
    create_instance_key_material,
    encrypt_secret,
    import_instance_key_material,
    inspect_public_key,
    make_current,
    save_instance_key,
)
from arborpress.mail.smtp import MailMessage, SMTPBackend, compose_message_content
from arborpress.models.mail import InstanceOpenPGPKey

requires_gpg = pytest.mark.skipif(
    shutil.which("gpg") is None, reason="GnuPG runtime is not installed"
)


def _stored_instance(material: dict[str, object]) -> InstanceOpenPGPKey:
    return InstanceOpenPGPKey(
        id="instance-test-key",
        fingerprint=str(material["fingerprint"]),
        openpgp_user_id=str(material["openpgp_user_id"]),
        algorithm=str(material["algorithm"]),
        public_key_armored=str(material["public_key_armored"]),
        private_key_enc=encrypt_secret(material["private_key"]),  # type: ignore[arg-type]
        passphrase_enc=encrypt_secret(material["passphrase"]),  # type: ignore[arg-type]
        status="active",
        is_current=True,
    )


def _recipient_key(user_id: str) -> dict[str, object]:
    """Create an isolated synthetic recipient with an encryption subkey."""
    import base64
    import os

    passphrase = base64.urlsafe_b64encode(os.urandom(30)).decode("ascii")
    with _private_home() as home:
        args = ("--pinentry-mode", "loopback", "--passphrase-fd", "0")
        _run(
            home,
            *args,
            "--quick-generate-key",
            user_id,
            "ed25519",
            "sign",
            "2y",
            data=(passphrase + "\n").encode(),
        )
        listing = _run(home, "--with-colons", "--fingerprint", "--list-secret-keys").decode()
        fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
        )
        _run(
            home,
            *args,
            "--quick-add-key",
            fingerprint,
            "cv25519",
            "encr",
            "2y",
            data=(passphrase + "\n").encode(),
        )
        public = _run(home, "--armor", "--export", fingerprint).decode()
        private = _run(
            home,
            *args,
            "--armor",
            "--export-secret-keys",
            fingerprint,
            data=(passphrase + "\n").encode(),
        )
    return {"public_key_armored": public, "private_key": private, "passphrase": passphrase.encode()}


@requires_gpg
def test_real_pgp_mime_sign_encrypt_and_smtp_capture(monkeypatch):
    signing = create_instance_key_material("ArborPress Test <instance@arborpress.invalid>")
    recipient = _recipient_key("Recipient <recipient@arborpress.invalid>")
    wrong_recipient = _recipient_key("Wrong Recipient <wrong@arborpress.invalid>")
    recipient_key = inspect_public_key(recipient["public_key_armored"])
    message = MailMessage(
        "recipient@arborpress.invalid",
        "Geschützt – Grüße",
        "Plain text body: Grüße aus ArborPress.",
        "<p>HTML body: <strong>Grüße</strong></p>",
        message_id="<openpgp-test@arborpress.invalid>",
        attachments=[
            {
                "filename": "test.txt",
                "content_type": "text/plain",
                "content": b"attachment payload",
            }
        ],
    )
    profile = {
        "from_address": "mail@arborpress.invalid",
        "from_name": "ArborPress",
        "enabled": True,
    }
    pgp = build_pgp_message(
        message,
        profile,
        recipient_public_key=str(recipient["public_key_armored"]),
        recipient_fingerprint=str(recipient_key["fingerprint"]),
        instance_key=_stored_instance(signing),
        sign=True,
    )
    assert pgp.get_content_type() == "multipart/encrypted"
    assert pgp.get_param("protocol") == "application/pgp-encrypted"
    encrypted_part = list(pgp.iter_parts())[1]
    encrypted = encrypted_part.get_payload(decode=True)
    assert encrypted and b"BEGIN PGP MESSAGE" in encrypted

    with _private_home() as home:
        secret_path = _write_private(home, "recipient-secret.asc", recipient["private_key"])
        passphrase_path = _write_private(home, "recipient-passphrase", recipient["passphrase"])
        _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passphrase_path),
            "--import",
            str(secret_path),
        )
        signer_path = _write_private(
            home, "signer-public.asc", signing["public_key_armored"].encode()
        )
        _run(home, "--import", str(signer_path))
        encrypted_path = _write_private(home, "message.asc", encrypted)
        status_path = home / "gpg-status"
        plaintext = _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passphrase_path),
            "--status-file",
            str(status_path),
            "--decrypt",
            str(encrypted_path),
        )
        assert b"[GNUPG:] VALIDSIG " in status_path.read_bytes()
    with _private_home() as wrong_home:
        wrong_secret_path = _write_private(
            wrong_home, "wrong-secret.asc", wrong_recipient["private_key"]
        )
        wrong_passphrase = _write_private(
            wrong_home, "wrong-passphrase", wrong_recipient["passphrase"]
        )
        _run(
            wrong_home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(wrong_passphrase),
            "--import",
            str(wrong_secret_path),
        )
        ciphertext_path = _write_private(wrong_home, "message.asc", encrypted)
        with pytest.raises(OpenPGPError):
            _run(wrong_home, "--decrypt", str(ciphertext_path))
    inner = message_from_bytes(plaintext, policy=policy.default)
    assert inner.get_content_type() == "multipart/mixed"
    parts = list(inner.walk())
    assert any(
        "Grüße aus ArborPress" in str(part.get_content())
        for part in parts
        if part.get_content_type() == "text/plain"
    )
    assert any(
        "Grüße" in str(part.get_content())
        for part in parts
        if part.get_content_type() == "text/html"
    )
    assert any(
        part.get_filename() == "test.txt" and part.get_payload(decode=True) == b"attachment payload"
        for part in parts
    )

    captured: dict[str, object] = {}

    class FakeSMTP:
        esmtp_extensions: dict[str, str] = {"starttls": ""}
        is_connected = True

        def __init__(self, **kwargs):
            captured["config"] = kwargs

        async def connect(self):
            return None

        async def starttls(self, **kwargs):
            return None

        async def ehlo(self):
            return None

        async def send_message(self, outgoing, **kwargs):
            captured["message"] = outgoing
            captured["kwargs"] = kwargs

        async def quit(self, **kwargs):
            self.is_connected = False

        def close(self):
            self.is_connected = False

    monkeypatch.setattr("arborpress.mail.smtp.aiosmtplib.SMTP", FakeSMTP)
    asyncio.run(
        SMTPBackend().send(
            pgp,
            {
                **profile,
                "host": "127.0.0.1",
                "port": 587,
                "transport": "starttls",
                "timeout_seconds": 3,
                "from_address": "mail@arborpress.invalid",
            },
        )
    )
    captured_message = captured["message"]
    assert captured_message is pgp
    assert captured_message.get_content_type() == "multipart/encrypted"
    assert captured["kwargs"]["recipients"] == ["recipient@arborpress.invalid"]  # type: ignore[index]


@requires_gpg
@pytest.mark.asyncio
async def test_instance_key_import_storage_rotation_and_retained_history(db_session):
    first_material = create_instance_key_material("ArborPress First <first@example.invalid>")
    imported = import_instance_key_material(
        first_material["private_key"], first_material["passphrase"].decode("ascii")
    )
    first = await save_instance_key(db_session, imported)
    assert first.is_current
    assert first.fingerprint == imported["fingerprint"]
    assert first.private_key_enc != imported["private_key"]
    assert first.passphrase_enc != imported["passphrase"]

    second_material = create_instance_key_material("ArborPress Second <second@example.invalid>")
    second = await save_instance_key(db_session, second_material)
    assert second.is_current
    await db_session.flush()
    assert first.is_current is False
    assert first.status == "retired"
    assert (await make_current(db_session, first.id)).is_current
    assert second.is_current is False
    assert second.status == "retired"


@requires_gpg
def test_public_recipient_key_rejects_private_material():
    material = create_instance_key_material("Recipient <recipient@arborpress.invalid>")
    with pytest.raises(OpenPGPError, match="Only a public key"):
        inspect_public_key(material["private_key"])


@requires_gpg
def test_instance_import_rejects_decryption_capable_private_key():
    recipient = _recipient_key("Not an instance signer <recipient@example.invalid>")
    with pytest.raises(OpenPGPError, match="must not contain a usable message-decryption key"):
        import_instance_key_material(
            recipient["private_key"], recipient["passphrase"].decode("ascii")
        )


@requires_gpg
def test_sign_only_pgp_mime_signature_verifies():
    signing = create_instance_key_material("ArborPress Signer <signer@example.invalid>")
    message = MailMessage(
        "external@example.invalid", "Signed only", "Signed body"
    )
    signed = build_pgp_message(
        message,
        {"from_address": "mail@example.invalid"},
        recipient_public_key=None,
        recipient_fingerprint=None,
        instance_key=_stored_instance(signing),
        sign=True,
    )
    assert signed.get_content_type() == "multipart/signed"
    assert signed.get_param("micalg") == "pgp-sha256"
    parts = list(signed.iter_parts())
    with _private_home() as home:
        signer = _write_private(home, "signer.asc", signing["public_key_armored"].encode())
        _run(home, "--import", str(signer))
        content_path = _write_private(
            home,
            "signed-content.mime",
            compose_message_content(message).as_bytes(policy=policy.SMTP),
        )
        signature_path = _write_private(
            home, "signature.asc", str(parts[1].get_payload()).encode()
        )
        _run(home, "--verify", str(signature_path), str(content_path))


@requires_gpg
def test_encryption_only_pgp_mime_decrypts_without_signer():
    recipient = _recipient_key("Recipient <recipient@example.invalid>")
    details = inspect_public_key(recipient["public_key_armored"])
    message = MailMessage("recipient@example.invalid", "Encrypted", "Encrypted body")
    encrypted = build_pgp_message(
        message,
        {"from_address": "mail@example.invalid"},
        recipient_public_key=str(recipient["public_key_armored"]),
        recipient_fingerprint=str(details["fingerprint"]),
        instance_key=None,
        sign=False,
    )
    assert encrypted.get_content_type() == "multipart/encrypted"
    with _private_home() as home:
        secret = _write_private(home, "recipient-secret.asc", recipient["private_key"])
        passphrase = _write_private(home, "passphrase", recipient["passphrase"])
        _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passphrase),
            "--import",
            str(secret),
        )
        content = _write_private(
            home,
            "ciphertext.asc",
            list(encrypted.iter_parts())[1].get_payload(decode=True),
        )
        plaintext = _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passphrase),
            "--decrypt",
            str(content),
        )
    assert b"Encrypted body" in plaintext
    assert b"BEGIN PGP SIGNATURE" not in plaintext


def test_unsigned_plaintext_is_only_the_unprotected_policy_path():
    message = MailMessage("external@example.invalid", "Hello", "body")
    plain = build_pgp_message(
        message,
        {"from_address": "mail@example.invalid"},
        recipient_public_key=None,
        recipient_fingerprint=None,
        instance_key=None,
        sign=False,
    )
    assert plain.get_content_type() == "text/plain"


@pytest.mark.asyncio
async def test_user_opt_in_fails_closed_without_active_public_key(db_session):
    import uuid

    from arborpress.mail.openpgp import build_for_user
    from arborpress.models.user import User

    user = User(
        username=f"pgp-{uuid.uuid4().hex[:12]}",
        display_name="PGP User",
        email="pgp-user@example.invalid",
        is_active=True,
        pgp_encryption_enabled=True,
    )
    db_session.add(user)
    await db_session.flush()
    with pytest.raises(OpenPGPError, match="no active public key"):
        await build_for_user(
            MailMessage(user.email, "Test", "content"),
            {"from_address": "mail@example.invalid"},
            db=db_session,
            user_id=str(user.id),
            user_email=user.email,
            encryption_required=False,
            signing_enabled=False,
        )


@pytest.mark.asyncio
async def test_expired_or_revoked_recipient_key_never_downgrades(db_session):
    import uuid
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import delete

    from arborpress.mail.openpgp import build_for_user
    from arborpress.models.user import User, UserPGPKey

    user = User(
        username=f"pgp-{uuid.uuid4().hex[:12]}",
        display_name="PGP User",
        email="pgp-user@example.invalid",
        is_active=True,
        pgp_encryption_enabled=True,
    )
    db_session.add(user)
    await db_session.flush()
    now = datetime.now(UTC).replace(tzinfo=None)
    db_session.add(
        UserPGPKey(
            id=str(uuid.uuid4()),
            user_id=str(user.id),
            label="expired",
            public_key_armored="not inspected after expiry rejection",
            fingerprint="A" * 40,
            use_for_encryption=True,
            expires_at=now - timedelta(days=1),
            status="active",
        )
    )
    await db_session.flush()
    with pytest.raises(OpenPGPError, match="key has expired"):
        await build_for_user(
            MailMessage(user.email, "Test", "content"),
            {"from_address": "mail@example.invalid"},
            db=db_session,
            user_id=str(user.id),
            user_email=user.email,
            encryption_required=False,
            signing_enabled=False,
        )

    await db_session.execute(
        delete(UserPGPKey).where(UserPGPKey.user_id == user.id)
    )
    db_session.add(
        UserPGPKey(
            id=str(uuid.uuid4()),
            user_id=str(user.id),
            label="revoked",
            public_key_armored="not selected after revocation",
            fingerprint="B" * 40,
            use_for_encryption=True,
            status="revoked",
            revoked_at=now,
        )
    )
    await db_session.flush()
    with pytest.raises(OpenPGPError, match="no active public key"):
        await build_for_user(
            MailMessage(user.email, "Test", "content"),
            {"from_address": "mail@example.invalid"},
            db=db_session,
            user_id=str(user.id),
            user_email=user.email,
            encryption_required=False,
            signing_enabled=False,
        )


@pytest.mark.asyncio
async def test_account_email_change_blocks_queued_old_address(db_session):
    import uuid

    from arborpress.mail.openpgp import build_for_user
    from arborpress.models.user import User

    user = User(
        username=f"pgp-{uuid.uuid4().hex[:12]}",
        display_name="PGP User",
        email="new-address@example.invalid",
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    with pytest.raises(OpenPGPError, match="no longer the account email"):
        await build_for_user(
            MailMessage("old-address@example.invalid", "Queued", "content"),
            {"from_address": "mail@example.invalid"},
            db=db_session,
            user_id=str(user.id),
            user_email=user.email,
            encryption_required=False,
            signing_enabled=False,
        )


@requires_gpg
@pytest.mark.asyncio
async def test_normal_outbox_applies_user_encryption_policy(test_engine, monkeypatch):
    from contextlib import asynccontextmanager

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from arborpress.core import db as db_module
    from arborpress.core.site_settings import invalidate_cache
    from arborpress.mail.profiles import save_profile
    from arborpress.mail.queue import enqueue_mail, process_queue
    from arborpress.mail.smtp import SMTPBackend
    from arborpress.models.mail import MailQueue, MailStatus
    from arborpress.models.user import User, UserPGPKey

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    db_module._engine = test_engine
    db_module._session_factory = factory
    invalidate_cache("mail")
    recipient = _recipient_key("Outbox Recipient <outbox-recipient@example.invalid>")
    details = inspect_public_key(recipient["public_key_armored"])
    async with factory() as db:
        await save_profile(
            db,
            {
                "id": "openpgp-outbox-test",
                "host": "smtp.example.invalid",
                "port": 587,
                "transport": "starttls",
                "from_address": "mail@example.invalid",
            },
        )
        user = User(
            username="openpgp-outbox-user",
            display_name="Outbox Recipient",
            email="outbox-recipient@example.invalid",
            is_active=True,
            pgp_encryption_enabled=True,
        )
        db.add(user)
        await db.flush()
        db.add(
            UserPGPKey(
                id="openpgp-outbox-key",
                user_id=str(user.id),
                label="Mail encryption",
                public_key_armored=str(details["public_key_armored"]),
                fingerprint=str(details["fingerprint"]),
                use_for_signing=False,
                use_for_encryption=True,
                is_primary_signing=False,
                expires_at=details["expires_at"],
                openpgp_user_id=str(details["openpgp_user_id"]),
                status="active",
            )
        )
        await db.commit()

    sent = []

    async def fake_send(self, message, profile):
        sent.append(message)

    @asynccontextmanager
    async def worker_lock():
        yield True

    monkeypatch.setattr(SMTPBackend, "send", fake_send)
    monkeypatch.setattr("arborpress.mail.queue._worker_lock", worker_lock)
    job_id = await enqueue_mail(
        "outbox-recipient@example.invalid",
        "Protected outbox message",
        "Body sent through the standard mail queue.",
        profile_id="openpgp-outbox-test",
        idempotency_key="openpgp-outbox-integration",
        purpose="test",
        visible_to=["outbox-recipient@example.invalid", "other@example.invalid"],
        visible_cc=["copy@example.invalid"],
    )
    async with factory() as db:
        user = await db.scalar(
            select(User).where(User.username == "openpgp-outbox-user")
        )
        assert user is not None
        # An explicit opt-out after queueing must not silently downgrade a
        # message which was queued under the user's protected-mail policy.
        user.pgp_encryption_enabled = False
        await db.commit()
    assert await process_queue(batch_size=1, worker_id="openpgp-test-worker") == 1
    assert len(sent) == 1
    assert sent[0].get_content_type() == "multipart/encrypted"
    assert str(sent[0]["To"]) == "outbox-recipient@example.invalid"
    assert sent[0].get("Cc") is None
    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        assert row is not None
        assert row.status == MailStatus.SENT
        assert row.pgp_encrypted is True


@pytest.mark.asyncio
async def test_user_opt_out_does_not_encrypt_plaintext(db_session):
    import uuid

    from arborpress.mail.openpgp import build_for_user
    from arborpress.models.user import User

    user = User(
        username=f"pgp-{uuid.uuid4().hex[:12]}",
        display_name="PGP User",
        email="pgp-user@example.invalid",
        is_active=True,
        pgp_encryption_enabled=False,
    )
    db_session.add(user)
    await db_session.flush()
    message, encrypted = await build_for_user(
        MailMessage(user.email, "Test", "content"),
        {"from_address": "mail@example.invalid"},
        db=db_session,
        user_id=str(user.id),
        user_email=user.email,
        encryption_required=False,
        signing_enabled=False,
    )
    assert not encrypted
    assert isinstance(message, MailMessage)
