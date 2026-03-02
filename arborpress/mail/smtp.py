"""Mail-SMTP-Backend (§13).

- SMTP universal
- Async mit aiosmtplib
- OpenPGP-Signierung wenn aktiviert (§13)
- Kein sensibles Logging
"""

from __future__ import annotations

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import aiosmtplib

log = logging.getLogger("arborpress.mail")


class MailMessage:
    """Einfaches Mail-DTO."""

    def __init__(
        self,
        to: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> None:
        self.to = to
        self.subject = subject
        self.body_text = body_text
        self.body_html = body_html
        self.idempotency_key = idempotency_key


class SMTPBackend:
    """SMTP-Backend (§13 – universal mail backend)."""

    async def send(self, msg: MailMessage, mail_section: dict) -> None:
        """Sendet eine E-Mail über SMTP. Erhält Mail-Einstellungen als dict."""
        mime = MIMEMultipart("alternative") if msg.body_html else MIMEText(msg.body_text, "plain")
        mime["From"] = f"{mail_section.get('from_name', '')} <{mail_section.get('from_address', '')}>"
        mime["To"] = msg.to
        mime["Subject"] = msg.subject

        if msg.body_html:
            mime.attach(MIMEText(msg.body_text, "plain"))
            mime.attach(MIMEText(msg.body_html, "html"))

        smtp_port = mail_section.get("smtp_port", 587)

        # §13: Private Keys werden hier nie geloggt
        log.debug("Sending mail to %s subject=%r", msg.to, msg.subject)

        await aiosmtplib.send(
            mime,
            hostname=mail_section.get("smtp_host", "localhost"),
            port=smtp_port,
            username=mail_section.get("smtp_user") or None,
            password=mail_section.get("smtp_password", "") or None,
            use_tls=(smtp_port == 465),
            start_tls=(smtp_port in (587, 25) and mail_section.get("smtp_tls", True)),
        )
        log.info("Mail sent to %s", msg.to)
