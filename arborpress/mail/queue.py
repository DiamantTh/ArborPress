"""Async Mail-Queue-Worker (§13 – outbox queue with retries).

§13:
- Retries mit Backoff
- Idempotenz
- Minimales sensibles Logging
"""

from __future__ import annotations

import asyncio
import logging
import math
import secrets
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from arborpress.mail.smtp import MailMessage, SMTPBackend

if TYPE_CHECKING:
    pass

log = logging.getLogger("arborpress.mail.queue")


def _make_idempotency_key() -> str:
    return secrets.token_hex(16)


async def enqueue_mail(
    to: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
    idempotency_key: str | None = None,
) -> str:
    """Reiht eine Mail in die Warteschlange ein (§13 async outbox).

    Gibt die ID des Queue-Eintrags zurück.
    """
    from arborpress.core.db import get_session_factory
    from arborpress.models.mail import MailQueue, MailStatus

    key = idempotency_key or _make_idempotency_key()
    factory = get_session_factory()

    async with factory() as session:
        # Idempotenz-Check
        from sqlalchemy import select
        existing = (await session.execute(
            select(MailQueue).where(MailQueue.idempotency_key == key)
        )).scalar_one_or_none()

        if existing:
            log.debug("Mail already queued: %s", key)
            return str(existing.id)

        entry = MailQueue(
            idempotency_key=key,
            recipient=to,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            status=MailStatus.PENDING,
        )
        session.add(entry)
        await session.commit()
        log.debug("Mail queued: to=%s key=%s", to, key)
        return str(entry.id)


async def process_queue(batch_size: int = 10) -> int:
    """Verarbeitet ausstehende Mails aus der Queue (§13).

    Gibt Anzahl erfolgreich gesendeter Mails zurück.
    """
    from sqlalchemy import select

    from arborpress.core.db import get_session_factory
    from arborpress.core.site_settings import get_section
    from arborpress.models.mail import MailQueue, MailStatus

    factory = get_session_factory()
    backend = SMTPBackend()
    sent = 0

    async with factory() as session:
        mail_section = await get_section("mail", session)
        if mail_section.get("backend", "none") == "none":
            return 0

        max_retries        = mail_section.get("max_retries", 3)
        retry_backoff_base = mail_section.get("retry_backoff_base", 60)
        now = datetime.utcnow()
        rows = (
            await session.execute(
                select(MailQueue)
                .where(
                    MailQueue.status == MailStatus.PENDING,
                    (MailQueue.next_attempt_at == None) | (MailQueue.next_attempt_at <= now),  # noqa: E711
                )
                .limit(batch_size)
            )
        ).scalars().all()

        for entry in rows:
            try:
                await backend.send(
                    MailMessage(
                        to=entry.recipient,
                        subject=entry.subject,
                        body_text=entry.body_text,
                        body_html=entry.body_html,
                        idempotency_key=entry.idempotency_key,
                    ),
                    mail_section,
                )
                entry.status = MailStatus.SENT
                entry.sent_at = datetime.utcnow()
                sent += 1
            except Exception as exc:
                entry.attempts += 1
                entry.last_error = str(exc)[:512]  # §13: kein sensibles Logging
                if entry.attempts >= max_retries:
                    entry.status = MailStatus.FAILED
                else:
                    # Exponentielles Backoff
                    delay = retry_backoff_base * int(math.pow(2, entry.attempts - 1))
                    entry.next_attempt_at = datetime.utcnow() + timedelta(seconds=delay)
                log.warning("Mail send failed (attempt %d): %s", entry.attempts, exc)

        await session.commit()

    return sent


async def run_queue_worker(interval: int = 30) -> None:
    """Dauerhafter Background-Worker (für CLI-Befehl / Quart-Startup)."""
    log.info("Mail-Queue-Worker gestartet (Intervall: %ds)", interval)
    while True:
        try:
            sent = await process_queue()
            if sent:
                log.info("Mail-Queue: %d Mails gesendet", sent)
        except Exception as exc:
            log.error("Mail-Queue-Worker Fehler: %s", exc)
        await asyncio.sleep(interval)
