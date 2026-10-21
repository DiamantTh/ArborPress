"""Regression tests for the durable mail outbox and strict SMTP transport."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker


@pytest.mark.asyncio
async def test_profile_secret_is_encrypted_and_safe_view_omits_it(test_engine):
    from arborpress.core import db as db_module
    from arborpress.mail.profiles import (
        profile_transport_data,
        safe_profile_data,
        save_profile,
    )
    from arborpress.models.mail import SMTPProfile

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    db_module._engine = test_engine
    db_module._session_factory = factory
    async with factory() as db:
        row = await save_profile(
            db,
            {
                "id": "test-profile",
                "host": "smtp.example.test",
                "port": 465,
                "transport": "implicit_tls",
                "username": "operator",
                "secret": "never-log-this-secret",
                "from_address": "noreply@example.test",
            },
        )
        await db.commit()
        assert b"never-log-this-secret" not in row.secret_enc
        assert safe_profile_data(row)["has_secret"] is True
        assert "secret" not in safe_profile_data(row)
        assert profile_transport_data(row)["password"] == "never-log-this-secret"  # noqa: S105
        assert await db.get(SMTPProfile, row.id) is row


@pytest.mark.asyncio
async def test_outbox_idempotency_send_and_manual_retry(test_engine, monkeypatch):
    from sqlalchemy import update

    from arborpress.core import db as db_module
    from arborpress.mail.profiles import save_profile
    from arborpress.mail.queue import enqueue_mail, process_queue, retry_mail
    from arborpress.mail.smtp import SMTPBackend
    from arborpress.models.mail import MailQueue, MailStatus

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    db_module._engine = test_engine
    db_module._session_factory = factory
    async with factory() as db:
        await db.execute(
            update(MailQueue)
            .where(MailQueue.status.in_([MailStatus.PENDING, MailStatus.RETRY]))
            .values(status=MailStatus.CANCELLED)
        )
        await save_profile(
            db,
            {
                "id": "outbox-test",
                "host": "smtp.example.test",
                "port": 465,
                "transport": "implicit_tls",
                "from_address": "noreply@example.test",
            },
        )
        await db.commit()

    job_id = await enqueue_mail(
        "recipient@example.test",
        "Hello",
        "body",
        profile_id="outbox-test",
        idempotency_key="domain-event-1",
        purpose="notice",
    )
    assert (
        await enqueue_mail(
            "recipient@example.test",
            "Hello",
            "body",
            profile_id="outbox-test",
            idempotency_key="domain-event-1",
            purpose="notice",
        )
        == job_id
    )
    sent = []

    async def fake_send(self, message, profile):
        await asyncio.sleep(0.02)
        sent.append((message.message_id, profile["id"]))

    monkeypatch.setattr(SMTPBackend, "send", fake_send)
    outcomes = await asyncio.gather(
        process_queue(batch_size=1, worker_id="test-worker-a"),
        process_queue(batch_size=1, worker_id="test-worker-b"),
    )
    assert sum(outcomes) == 1
    assert sent and sent[0][1] == "outbox-test"
    assert len(sent) == 1
    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        assert row is not None
        assert row.status == MailStatus.SENT
        assert row.message_id == sent[0][0]
        assert row.lease_owner is None

    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        row.status = MailStatus.DEAD
        row.last_error = "smtp_550"
        await db.commit()
    assert await retry_mail(job_id) is True
    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        assert row.status == MailStatus.PENDING
        assert row.attempts == 0


@pytest.mark.asyncio
async def test_concurrent_idempotent_enqueue_returns_one_delivery(test_engine):
    from sqlalchemy import select

    from arborpress.core import db as db_module
    from arborpress.mail.queue import enqueue_mail
    from arborpress.models.mail import MailQueue

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    db_module._engine = test_engine
    db_module._session_factory = factory
    results = await asyncio.gather(
        enqueue_mail(
            "race@example.test",
            "subject",
            "body",
            profile_id="transactional",
            idempotency_key="race-key",
            purpose="race-test",
        ),
        enqueue_mail(
            "race@example.test",
            "subject",
            "body",
            profile_id="transactional",
            idempotency_key="race-key",
            purpose="race-test",
        ),
    )
    assert results[0] == results[1]
    async with factory() as db:
        rows = (
            (await db.execute(select(MailQueue).where(MailQueue.recipient == "race@example.test")))
            .scalars()
            .all()
        )
        assert len(rows) == 1


def test_header_injection_and_bcc_are_handled_without_leaking_bcc():
    from arborpress.mail.smtp import MailMessage, SMTPBackend

    with pytest.raises(ValueError, match="header"):
        MailMessage("user@example.test", "subject\r\nBcc: victim@example.test", "body")
    message = MailMessage("blind@example.test", "private delivery", "body", recipient_kind="bcc")
    built = SMTPBackend._build_message(
        message,
        {"from_address": "sender@example.test", "from_name": "ArborPress"},
    )
    assert "Bcc" not in built
    assert str(built["To"]) == "undisclosed-recipients:;"


@pytest.mark.asyncio
async def test_starttls_downgrade_is_rejected_before_auth_or_message(monkeypatch):
    import arborpress.mail.smtp as smtp_module
    from arborpress.mail.smtp import MailMessage, SMTPBackend, SMTPConfigurationError

    class FakeSMTP:
        is_connected = True
        esmtp_extensions = {"size": "1000"}
        calls: list[str] = []

        def __init__(self, **kwargs):
            self.calls.append("init")

        async def connect(self):
            self.calls.append("connect")

        async def login(self, *args, **kwargs):
            self.calls.append("login")

        async def starttls(self, **kwargs):
            self.calls.append("starttls")

        async def send_message(self, *args, **kwargs):
            self.calls.append("send")

        async def quit(self, **kwargs):
            self.calls.append("quit")

        def close(self):
            self.calls.append("close")

    monkeypatch.setattr(smtp_module.aiosmtplib, "SMTP", FakeSMTP)
    with pytest.raises(SMTPConfigurationError, match="STARTTLS"):
        await SMTPBackend().send(
            MailMessage("user@example.test", "subject", "body"),
            {
                "host": "smtp.example.test",
                "port": 587,
                "transport": "starttls",
                "username": "user",
                "password": "password",
                "from_address": "noreply@example.test",
            },
        )
    assert "login" not in FakeSMTP.calls
    assert "send" not in FakeSMTP.calls


@pytest.mark.asyncio
async def test_starttls_authentication_and_delivery_follow_validated_upgrade(monkeypatch):
    import arborpress.mail.smtp as smtp_module
    from arborpress.mail.smtp import MailMessage, SMTPBackend

    calls: list[object] = []

    class FakeSMTP:
        is_connected = True
        esmtp_extensions = {"starttls": "", "dsn": ""}

        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        async def connect(self):
            calls.append("connect")

        async def starttls(self, **kwargs):
            calls.append(("starttls", kwargs))

        async def ehlo(self):
            calls.append("ehlo")

        async def login(self, username, password, **kwargs):
            calls.append(("login", username, password))

        async def send_message(self, message, **kwargs):
            calls.append(("send", kwargs))
            return {}, "250 accepted"

        async def quit(self, **kwargs):
            calls.append("quit")

        def close(self):
            calls.append("close")

    monkeypatch.setattr(smtp_module.aiosmtplib, "SMTP", FakeSMTP)
    await SMTPBackend().send(
        MailMessage("user@example.test", "subject", "body"),
        {
            "host": "smtp.example.test",
            "port": 587,
            "transport": "starttls",
            "username": "mailer",
            "password": "secret",
            "from_address": "noreply@example.test",
        },
    )
    login_index = next(
        i for i, item in enumerate(calls) if isinstance(item, tuple) and item[0] == "login"
    )
    send_index = next(
        i for i, item in enumerate(calls) if isinstance(item, tuple) and item[0] == "send"
    )
    tls_index = next(
        i for i, item in enumerate(calls) if isinstance(item, tuple) and item[0] == "starttls"
    )
    tls = next(item for item in calls if isinstance(item, tuple) and item[0] == "starttls")
    assert tls[1]["validate_certs"] is True
    assert calls.index("connect") < tls_index < calls.index("ehlo")
    assert calls.index("ehlo") < login_index < send_index


@pytest.mark.asyncio
async def test_dnssec_status_is_not_overclaimed(monkeypatch):
    from types import SimpleNamespace

    import dns.flags

    from arborpress.mail.dns import SMTPDNSResolver

    resolver = SMTPDNSResolver(dnssec_policy="own_validation")

    async def answer(*args, **kwargs):
        return SimpleNamespace(
            rrset=["3 1 1 abcdef"],
            response=SimpleNamespace(flags=dns.flags.AD),
        )

    monkeypatch.setattr(resolver.resolver, "resolve", answer)
    tlsa = await resolver.query("_465._tcp.smtp.example.test", "TLSA")
    assert tlsa.dnssec == "indeterminate"
    assert resolver.resolver.ednsflags & dns.flags.DO

    trusted = SMTPDNSResolver(dnssec_policy="trusted_ad")
    monkeypatch.setattr(trusted.resolver, "resolve", answer)
    assert (await trusted.query("_465._tcp.smtp.example.test", "TLSA")).dnssec == "secure"


def test_verp_tokens_are_opaque_and_domain_bound():
    from arborpress.mail.delivery import new_verp_token, verp_address

    token = new_verp_token()
    assert len(token) == 32
    assert verp_address(token, "bounce.example.test") == f"bounce+{token}@bounce.example.test"
    with pytest.raises(ValueError):
        verp_address("../../alice@example.test", "bounce.example.test")


@pytest.mark.asyncio
async def test_apply_dsn_records_only_normalized_state(test_engine):
    from arborpress.core import db as db_module
    from arborpress.mail.delivery import apply_dsn, new_verp_token
    from arborpress.mail.queue import enqueue_mail
    from arborpress.models.mail import MailQueue

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    db_module._engine = test_engine
    db_module._session_factory = factory
    job_id = await enqueue_mail("recipient@example.test", "Subject", "body")
    token = new_verp_token()
    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        row.verp_token = token
        assert await apply_dsn(db, token=token, status="bounced", enhanced_code="5.1.1")
        await db.commit()
        refreshed = await db.get(MailQueue, job_id)
        assert refreshed.dsn_status == "bounced"
        assert refreshed.dsn_enhanced_code == "5.1.1"


@pytest.mark.asyncio
async def test_enqueue_can_share_and_rollback_producer_transaction(test_engine):
    from arborpress.core import db as db_module
    from arborpress.mail.queue import enqueue_mail
    from arborpress.models.mail import MailQueue

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    db_module._engine = test_engine
    db_module._session_factory = factory
    async with factory() as db:
        job_id = await enqueue_mail("atomic@example.test", "subject", "body", session=db)
        await db.rollback()
    async with factory() as db:
        assert await db.get(MailQueue, job_id) is None


@pytest.mark.asyncio
async def test_transient_failure_sets_retry_and_expired_lease_is_recovered(
    test_engine, monkeypatch
):
    from datetime import timedelta

    from sqlalchemy import update

    from arborpress.core import db as db_module
    from arborpress.mail.profiles import save_profile
    from arborpress.mail.queue import _now, enqueue_mail, process_queue
    from arborpress.mail.smtp import SMTPBackend
    from arborpress.models.mail import MailQueue, MailStatus

    factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    db_module._engine = test_engine
    db_module._session_factory = factory
    async with factory() as db:
        await db.execute(
            update(MailQueue)
            .where(MailQueue.status.in_([MailStatus.PENDING, MailStatus.RETRY]))
            .values(status=MailStatus.CANCELLED)
        )
        await save_profile(
            db,
            {
                "id": "retry-test",
                "host": "smtp.example.test",
                "port": 465,
                "transport": "implicit_tls",
                "from_address": "noreply@example.test",
            },
        )
        await db.commit()
    job_id = await enqueue_mail("retry@example.test", "Retry", "body", profile_id="retry-test")

    async def timeout_send(self, message, profile):
        raise TimeoutError

    monkeypatch.setattr(SMTPBackend, "send", timeout_send)
    assert await process_queue(batch_size=1, worker_id="retry-worker") == 0
    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        assert row is not None
        assert row.status == MailStatus.RETRY
        assert row.attempts == 1
        assert row.next_attempt_at is not None and row.next_attempt_at > _now()

    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        assert row is not None
        row.status = MailStatus.LEASED
        row.lease_owner = "crashed-worker"
        row.lease_until = _now() - timedelta(seconds=1)
        row.next_attempt_at = None
        await db.commit()

    async def successful_send(self, message, profile):
        return None

    monkeypatch.setattr(SMTPBackend, "send", successful_send)
    assert await process_queue(batch_size=1, worker_id="recovery-worker") == 1
    async with factory() as db:
        row = await db.get(MailQueue, job_id)
        assert row is not None
        assert row.status == MailStatus.SENT
        assert row.attempts == 2
