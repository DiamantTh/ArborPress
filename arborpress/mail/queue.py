"""Durable, lease-based DB outbox and worker shared by embedded and CLI modes."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import socket
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError

from arborpress.mail.smtp import MailMessage, SMTPBackend

log = logging.getLogger("arborpress.mail.queue")
LEASE_SECONDS = 90
DEFAULT_MAX_ATTEMPTS = 5
_worker_stopping = False


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _scoped_key(key: str | None, purpose: str | None, recipient: str) -> str:
    if not key:
        return uuid.uuid4().hex
    material = f"{purpose or 'transactional'}\0{recipient.casefold()}\0{key}".encode()
    return hashlib.sha256(material).hexdigest()


def _message_id(row_id: str) -> str:
    from arborpress.core.config import get_settings

    host = urlsplit(get_settings().web.base_url).hostname or ""
    try:
        domain = (
            host.encode("idna").decode("ascii")
            if host and ":" not in host
            else "arborpress.invalid"
        )
    except UnicodeError:
        domain = "arborpress.invalid"
    return f"<{row_id}@{domain}>"


async def enqueue_mail(
    to: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
    idempotency_key: str | None = None,
    *,
    profile_id: str | None = None,
    purpose: str | None = None,
    recipient_kind: str = "to",
    visible_to: list[str] | None = None,
    visible_cc: list[str] | None = None,
    headers: dict[str, str] | None = None,
    envelope_sender: str | None = None,
    session: Any = None,
    template_id: str | None = None,
    template_locale: str | None = None,
    template_revision: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
) -> str:
    """Persist one envelope delivery. Passing ``session`` makes it transactional
    with the producer's domain write; otherwise the function owns its transaction.
    """
    from arborpress.core.db import get_session_factory
    from arborpress.mail.smtp import normalize_attachments, validate_address, validate_header_value
    from arborpress.models.mail import MailQueue, MailStatus

    recipient = validate_address(to)
    validate_header_value(subject, "subject")
    if recipient_kind not in {"to", "cc", "bcc"}:
        raise ValueError("recipient_kind must be to, cc, or bcc")
    for address in visible_to or []:
        validate_address(address)
    for address in visible_cc or []:
        validate_address(address)
    if envelope_sender:
        validate_address(envelope_sender)
    if headers:
        protected = {
            "from",
            "to",
            "cc",
            "bcc",
            "return-path",
            "received",
            "message-id",
            "content-type",
            "content-transfer-encoding",
            "mime-version",
            "subject",
            "reply-to",
            "sender",
            "date",
            "resent-to",
            "resent-from",
            "delivered-to",
            "authentication-results",
        }
        for name, value in headers.items():
            if name.lower() in protected:
                raise ValueError("Protected email header cannot be supplied by producer.")
            if not name.isascii() or not name.replace("-", "").isalnum() or len(name) > 64:
                raise ValueError("Invalid email header name.")
            validate_header_value(value, name)
    key = _scoped_key(idempotency_key, purpose, recipient)
    stored_attachments = normalize_attachments(attachments or [])
    owns_session = session is None
    if owns_session:
        factory = get_session_factory()
        session = factory()
    try:
        from arborpress.core.site_settings import get_section_authoritative

        mail_settings = await get_section_authoritative("mail", session)
        if profile_id is None:
            configured = (
                mail_settings.get("bulk_profile")
                if purpose == "bulk"
                else mail_settings.get("transactional_profile")
            )
            profile_id = str(configured or "transactional")
        existing = (
            await session.execute(select(MailQueue).where(MailQueue.idempotency_key == key))
        ).scalar_one_or_none()
        if existing:
            return str(existing.id)
        from sqlalchemy import func

        from arborpress.models.user import User

        account_matches = (
            await session.execute(
                select(User.id, User.pgp_encryption_enabled)
                .where(func.lower(User.email) == recipient.casefold())
                .with_for_update()
                .limit(2)
            )
        ).all()
        if len(account_matches) > 1:
            raise ValueError("Recipient email maps ambiguously to multiple local accounts.")
        recipient_user_id = str(account_matches[0][0]) if account_matches else None
        recipient_encryption_required = bool(
            mail_settings.get("pgp_require_encryption", False)
        ) or (bool(account_matches[0][1]) if account_matches else False)
        row_id = str(uuid.uuid4())
        entry = MailQueue(
            id=row_id,
            idempotency_key=key,
            recipient=recipient,
            recipient_user_id=recipient_user_id,
            recipient_identity_checked=True,
            recipient_encryption_required=recipient_encryption_required,
            recipient_kind=recipient_kind,
            visible_to=(
                visible_to
                if visible_to is not None
                else ([recipient] if recipient_kind == "to" else [])
            ),
            visible_cc=(
                visible_cc
                if visible_cc is not None
                else ([recipient] if recipient_kind == "cc" else [])
            ),
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            attachments=stored_attachments,
            headers=headers or {},
            profile_id=profile_id,
            message_type=purpose,
            template_id=template_id,
            template_locale=template_locale,
            template_revision=template_revision,
            message_id=_message_id(row_id),
            envelope_sender=envelope_sender,
            status=MailStatus.PENDING,
            max_attempts=DEFAULT_MAX_ATTEMPTS,
            updated_at=_now(),
        )
        try:
            # The unique constraint is the cross-process race arbiter. A
            # transaction supplied by a domain producer must fail as a whole
            # on a concurrent duplicate, so its domain write cannot commit
            # without the matching mail delivery.
            session.add(entry)
            await session.flush()
        except IntegrityError:
            if not owns_session:
                raise
            await session.rollback()
            existing = (
                await session.execute(select(MailQueue).where(MailQueue.idempotency_key == key))
            ).scalar_one_or_none()
            if existing is None:
                raise
            return str(existing.id)
        if owns_session:
            await session.commit()
        log.info("Mail queued id=%s profile=%s", row_id, entry.profile_id)
        return row_id
    except Exception:
        if owns_session:
            await session.rollback()
        raise
    finally:
        if owns_session:
            await session.close()


async def _legacy_profile(session: Any, profile_id: str) -> dict[str, Any] | None:
    """One-time secure bridge for deployments configured before named profiles."""
    from arborpress.core.site_settings import get_section, invalidate_cache
    from arborpress.mail.profiles import profile_transport_data, save_profile
    from arborpress.models.settings import SiteSetting

    settings = await get_section("mail", session)
    if settings.get("backend") not in {"smtp", "queue"} or profile_id != "transactional":
        return None
    row = await save_profile(
        session,
        {
            "id": "transactional",
            "display_name": "Transactional",
            "host": settings.get("smtp_host", "localhost"),
            "port": settings.get("smtp_port", 587),
            "transport": "implicit_tls" if settings.get("smtp_tls") else "starttls",
            "username": settings.get("smtp_user") or None,
            "secret": settings.get("smtp_password") or None,
            "from_address": settings.get("from_address", "noreply@example.com"),
            "from_name": settings.get("from_name", "ArborPress"),
            "enabled": True,
        },
    )
    # Remove the plaintext legacy credential from the settings row once the
    # encrypted profile has been flushed successfully.
    setting = await session.get(SiteSetting, "mail")
    if setting is not None:
        import json

        value = json.loads(setting.value or "{}")
        value.pop("smtp_password", None)
        setting.value = json.dumps(value)
    await session.commit()
    invalidate_cache("mail")
    return profile_transport_data(row)


async def _profile_data(session: Any, profile_id: str) -> dict[str, Any] | None:
    from arborpress.mail.profiles import profile_transport_data
    from arborpress.models.mail import SMTPProfile

    result = await session.execute(select(SMTPProfile).where(SMTPProfile.id == profile_id))
    row = result.scalar_one_or_none()
    if row is None:
        return await _legacy_profile(session, profile_id)
    return profile_transport_data(row)


def _is_transient(exc: Exception) -> bool:
    from aiosmtplib.errors import (
        SMTPConnectError,
        SMTPConnectTimeoutError,
        SMTPReadTimeoutError,
        SMTPResponseException,
        SMTPServerDisconnected,
        SMTPTimeoutError,
    )

    if isinstance(
        exc,
        (
            TimeoutError,
            asyncio.TimeoutError,
            OSError,
            socket.gaierror,
            SMTPConnectError,
            SMTPConnectTimeoutError,
            SMTPReadTimeoutError,
            SMTPServerDisconnected,
            SMTPTimeoutError,
        ),
    ):
        return True
    if isinstance(exc, SMTPResponseException):
        return int(exc.code) < 500
    code = getattr(exc, "code", None)
    return isinstance(code, int) and code < 500


def _safe_error(exc: Exception) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code.isidentifier():
        return code[:120]
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return f"smtp_{code}"
    name = type(exc).__name__.lower()
    return name[:120] if name.isidentifier() else "delivery_error"


async def _claim_one(session: Any, worker_id: str, now: datetime) -> Any | None:
    from arborpress.models.mail import MailQueue, MailStatus

    # A worker may have crashed after using its final allowed attempt. Such an
    # expired lease is terminal rather than claimable forever.
    terminalized = await session.execute(
        update(MailQueue)
        .where(
            MailQueue.status == MailStatus.LEASED,
            MailQueue.lease_until <= now,
            MailQueue.attempts >= MailQueue.max_attempts,
        )
        .values(
            status=MailStatus.DEAD,
            lease_owner=None,
            lease_until=None,
            last_error="lease_expired",
            updated_at=now,
        )
    )
    ready = MailQueue.status.in_([MailStatus.PENDING, MailStatus.RETRY]) & (
        MailQueue.next_attempt_at.is_(None) | (MailQueue.next_attempt_at <= now)
    )
    expired = (MailQueue.status == MailStatus.LEASED) & (MailQueue.lease_until <= now)
    candidate = (
        await session.execute(
            select(MailQueue.id)
            .where(
                MailQueue.attempts < MailQueue.max_attempts,
                or_(ready, expired),
            )
            .order_by(MailQueue.priority.desc(), MailQueue.created_at, MailQueue.id)
            .limit(1)
        )
    ).scalar_one_or_none()
    if candidate is None:
        if terminalized.rowcount:
            await session.commit()
        return None
    claimed = await session.execute(
        update(MailQueue)
        .where(
            MailQueue.id == candidate,
            MailQueue.attempts < MailQueue.max_attempts,
            or_(ready, expired),
        )
        .values(
            status=MailStatus.LEASED,
            lease_owner=worker_id,
            lease_until=now + timedelta(seconds=LEASE_SECONDS),
            attempts=MailQueue.attempts + 1,
            updated_at=now,
        )
    )
    if claimed.rowcount != 1:
        return None
    await session.commit()
    return (await session.execute(select(MailQueue).where(MailQueue.id == candidate))).scalar_one()


async def process_queue(batch_size: int = 10, *, worker_id: str | None = None) -> int:
    """Claim, send, and finalize deliveries under the instance worker lock."""
    async with _worker_lock() as acquired:
        if not acquired:
            return 0
        return await _process_queue_locked(batch_size, worker_id=worker_id)


async def _process_queue_locked(batch_size: int, *, worker_id: str | None = None) -> int:
    """Process a batch after the instance-wide POSIX worker lock is acquired."""
    from arborpress.core.db import get_session_factory
    from arborpress.models.mail import MailQueue, MailStatus

    factory = get_session_factory()
    backend = SMTPBackend()
    worker_id = worker_id or f"worker-{uuid.uuid4().hex}"
    sent = 0
    for _ in range(max(0, batch_size)):
        async with factory() as session:
            row = await _claim_one(session, worker_id, _now())
            if row is None:
                break
            payload = {
                "id": row.id,
                "recipient": row.recipient,
                "recipient_user_id": row.recipient_user_id,
                "recipient_identity_checked": row.recipient_identity_checked,
                "recipient_encryption_required": row.recipient_encryption_required,
                "recipient_kind": row.recipient_kind,
                "subject": row.subject,
                "body_text": row.body_text,
                "body_html": row.body_html,
                "attachments": row.attachments or [],
                "visible_to": row.visible_to or [],
                "visible_cc": row.visible_cc or [],
                "headers": row.headers or {},
                "message_id": row.message_id,
                "envelope_sender": row.envelope_sender,
                "dsn_envid": row.dsn_envid or row.id.replace("-", ""),
                "profile_id": row.profile_id,
                "attempts": row.attempts,
                "max_attempts": row.max_attempts,
            }
        try:
            async with factory() as session:
                profile = await _profile_data(session, payload["profile_id"])
            if not profile or not profile.get("enabled"):
                raise SMTPProfileUnavailable("smtp_profile_unavailable")
            from arborpress.core.site_settings import get_section_authoritative
            from arborpress.mail.openpgp import (
                build_for_user,
                build_pgp_message,
                current_instance_key,
            )
            from arborpress.models.user import User

            async with factory() as session:
                row = await session.get(MailQueue, payload["id"])
                if row is None or row.lease_owner != worker_id:
                    continue
                user_id = row.recipient_user_id
                if not row.recipient_identity_checked:
                    from sqlalchemy import func

                    from arborpress.mail.openpgp import OpenPGPError

                    matches = (
                        (
                            await session.execute(
                                select(User.id)
                                .where(func.lower(User.email) == row.recipient.casefold())
                                .limit(2)
                            )
                        )
                        .scalars()
                        .all()
                    )
                    if len(matches) > 1:
                        raise OpenPGPError(
                            "recipient_identity_ambiguous",
                            "The queued recipient matches more than one local account.",
                        )
                    if matches:
                        # Pre-Phase-15 rows lack a durable account reference. A
                        # current email match cannot prove which account owned
                        # that address when the message was queued.
                        raise OpenPGPError(
                            "recipient_identity_unbound",
                            "A legacy queued message targets a local account but has no stable "
                            "account association; create a new message through its producer.",
                        )
                    row.recipient_identity_checked = True
                    await session.commit()
                settings = await get_section_authoritative("mail", session)
                require_encryption = bool(settings.get("pgp_require_encryption", False)) or bool(
                    row.recipient_encryption_required
                )
                signing_enabled = bool(settings.get("pgp_sign_enabled", False))
                if user_id:
                    row_user = await session.get(User, user_id)
                    if row_user is None or not row_user.is_active or row_user.email is None:
                        from arborpress.mail.openpgp import OpenPGPError

                        raise OpenPGPError(
                            "recipient_account_unavailable",
                            "The registered mail recipient is unavailable.",
                        )
                    if row_user.email.casefold() != payload["recipient"].casefold():
                        from arborpress.mail.openpgp import OpenPGPError

                        raise OpenPGPError(
                            "recipient_address_changed",
                            "The account email changed after this message was queued.",
                        )
                    mail_message = MailMessage(
                        payload["recipient"],
                        payload["subject"],
                        payload["body_text"],
                        payload["body_html"],
                        message_id=payload["message_id"],
                        recipient_kind=payload["recipient_kind"],
                        visible_to=payload["visible_to"],
                        visible_cc=payload["visible_cc"],
                        headers=payload["headers"],
                        envelope_sender=payload["envelope_sender"],
                        dsn_envid=payload["dsn_envid"],
                        attachments=payload["attachments"],
                    )
                    prepared_message, encrypted = await build_for_user(
                        mail_message,
                        profile,
                        db=session,
                        user_id=user_id,
                        user_email=row_user.email,
                        encryption_required=require_encryption,
                        signing_enabled=signing_enabled,
                    )
                else:
                    if require_encryption:
                        from arborpress.mail.openpgp import OpenPGPError

                        raise OpenPGPError(
                            "external_recipient_encryption_unavailable",
                            "Instance policy requires encryption, but external recipients "
                            "have no local key.",
                        )
                    msg = MailMessage(
                        payload["recipient"],
                        payload["subject"],
                        payload["body_text"],
                        payload["body_html"],
                        message_id=payload["message_id"],
                        recipient_kind=payload["recipient_kind"],
                        visible_to=payload["visible_to"],
                        visible_cc=payload["visible_cc"],
                        headers=payload["headers"],
                        envelope_sender=payload["envelope_sender"],
                        dsn_envid=payload["dsn_envid"],
                        attachments=payload["attachments"],
                    )
                    current_key = await current_instance_key(session) if signing_enabled else None
                    if signing_enabled and current_key is None:
                        from arborpress.mail.openpgp import OpenPGPError

                        raise OpenPGPError(
                            "instance_signing_key_missing",
                            "Mail signing is enabled but no usable instance key exists.",
                        )
                    prepared_message = (
                        await asyncio.to_thread(
                            build_pgp_message,
                            msg,
                            profile,
                            recipient_public_key=None,
                            recipient_fingerprint=None,
                            instance_key=current_key,
                            sign=signing_enabled,
                        )
                        if signing_enabled
                        else msg
                    )
                    encrypted = False
                row.pgp_encrypted = encrypted
                await session.commit()
            envelope_sender = payload["envelope_sender"]
            if not envelope_sender and profile.get("envelope_domain"):
                from arborpress.mail.delivery import new_verp_token, verp_address

                async with factory() as session:
                    row = await session.get(MailQueue, payload["id"])
                    if row is not None:
                        if not row.verp_token:
                            row.verp_token = new_verp_token()
                        envelope_sender = verp_address(row.verp_token, profile["envelope_domain"])
                        row.envelope_sender = envelope_sender
                        await session.commit()
            if isinstance(prepared_message, EmailMessage):
                object.__setattr__(prepared_message, "_arborpress_envelope_sender", envelope_sender)
                object.__setattr__(prepared_message, "_arborpress_recipient", payload["recipient"])
                object.__setattr__(prepared_message, "_arborpress_dsn_envid", payload["dsn_envid"])
            await backend.send(
                prepared_message,
                profile,
            )
            async with factory() as session:
                await session.execute(
                    update(MailQueue)
                    .where(MailQueue.id == payload["id"], MailQueue.lease_owner == worker_id)
                    .values(
                        status=MailStatus.SENT,
                        sent_at=_now(),
                        updated_at=_now(),
                        lease_owner=None,
                        lease_until=None,
                        last_error=None,
                    )
                )
                await session.commit()
            sent += 1
            log.info("Mail accepted by SMTP id=%s profile=%s", payload["id"], payload["profile_id"])
        except Exception as exc:
            transient = _is_transient(exc)
            delay = min(86_400, 30 * (2 ** max(0, payload["attempts"] - 1)))
            delay = int(delay * secrets.SystemRandom().uniform(0.8, 1.2))
            new_status = (
                MailStatus.RETRY
                if transient and payload["attempts"] < payload["max_attempts"]
                else MailStatus.DEAD
            )
            error = _safe_error(exc)
            async with factory() as session:
                await session.execute(
                    update(MailQueue)
                    .where(MailQueue.id == payload["id"], MailQueue.lease_owner == worker_id)
                    .values(
                        status=new_status,
                        next_attempt_at=(
                            _now() + timedelta(seconds=delay)
                            if new_status == MailStatus.RETRY
                            else None
                        ),
                        lease_owner=None,
                        lease_until=None,
                        last_error=error,
                        updated_at=_now(),
                    )
                )
                await session.commit()
            log.warning(
                "Mail delivery failed id=%s status=%s error=%s",
                payload["id"],
                new_status,
                error,
            )
    return sent


class SMTPProfileUnavailable(RuntimeError):
    pass


async def retry_mail(job_id: str) -> bool:
    from arborpress.core.db import get_session_factory
    from arborpress.models.mail import MailQueue, MailStatus

    async with get_session_factory()() as session:
        row = await session.get(MailQueue, job_id)
        if row is None or row.status not in {MailStatus.DEAD, MailStatus.RETRY}:
            return False
        row.status = MailStatus.PENDING
        row.attempts = 0
        row.next_attempt_at = None
        row.lease_owner = None
        row.lease_until = None
        row.last_error = None
        row.updated_at = _now()
        await session.commit()
        return True


async def cancel_mail(job_id: str) -> bool:
    from arborpress.core.db import get_session_factory
    from arborpress.models.mail import MailQueue, MailStatus

    async with get_session_factory()() as session:
        result = await session.execute(
            update(MailQueue)
            .where(
                MailQueue.id == job_id,
                MailQueue.status.in_([MailStatus.PENDING, MailStatus.RETRY, MailStatus.DEAD]),
            )
            .values(status=MailStatus.CANCELLED, updated_at=_now(), last_error=None)
        )
        await session.commit()
        return bool(getattr(result, "rowcount", 0) == 1)


async def run_queue_worker(interval: int = 5, *, stop_event: asyncio.Event | None = None) -> None:
    """Embedded/separate worker loop. Durable leases recover after process death."""
    log.info("Mail outbox worker started interval=%ds", interval)
    while stop_event is None or not stop_event.is_set():
        try:
            await process_queue()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("Mail outbox worker error type=%s", type(exc).__name__)
        try:
            if stop_event:
                await asyncio.wait_for(stop_event.wait(), timeout=max(1, interval))
            else:
                await asyncio.sleep(max(1, interval))
        except TimeoutError:
            pass


@asynccontextmanager
async def _worker_lock() -> AsyncIterator[bool]:
    """Allow only one embedded/separate worker owner per instance on POSIX."""
    from arborpress.runtime.paths import ensure_instance_layout, get_runtime_paths

    paths = get_runtime_paths()
    ensure_instance_layout(paths)
    lock_path = paths.run / "mail-worker.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        try:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except ImportError:
            # DB leases remain race-safe on platforms without flock.
            acquired = True
        except BlockingIOError:
            acquired = False
        yield acquired
    finally:
        if acquired:
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
            except ImportError:
                pass
        os.close(fd)
