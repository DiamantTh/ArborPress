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

import aiosmtplib

log = logging.getLogger("arborpress.mail")


def _to_ascii_hostname(host: str) -> str:
    """Converts IDN hostnames to IDNA-ASCII/Punycode (§13, RFC 5321)."""
    if not host or host in ("localhost", "127.0.0.1", "::1"):
        return host
    # Leave pure IPv4 addresses unchanged
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    try:
        import idna as _idna  # idna>=3.7 (IDNA 2008)
        return _idna.encode(host, alg="TRANSITIONAL").decode("ascii")
    except Exception:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return host


class MailMessage:
    """Simple mail DTO."""

    def __init__(
        self,
        to: str,
        subject: str,
        body_text: str,
        body_html: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        self.to = to
        self.subject = subject
        self.body_text = body_text
        self.body_html = body_html
        self.idempotency_key = idempotency_key


class SMTPBackend:
    """SMTP-Backend (§13 – universal mail backend)."""

    async def send(self, msg: MailMessage, mail_section: dict) -> None:
        """Sends an email via SMTP. Receives mail settings as dict."""
        mime = MIMEMultipart("alternative") if msg.body_html else MIMEText(msg.body_text, "plain")
        mime["From"] = (
            f"{mail_section.get('from_name', '')} <{mail_section.get('from_address', '')}>"
        )
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
            hostname=_to_ascii_hostname(mail_section.get("smtp_host", "localhost")),
            port=smtp_port,
            username=mail_section.get("smtp_user") or None,
            password=mail_section.get("smtp_password", "") or None,
            use_tls=(smtp_port == 465),
            start_tls=(smtp_port in (587, 25) and mail_section.get("smtp_tls", True)),
        )
        log.info("Mail sent to %s", msg.to)
