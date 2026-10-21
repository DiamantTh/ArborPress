"""Strict-TLS SMTP transport for the database mail outbox."""

from __future__ import annotations

import logging
import re
import uuid
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Any

import aiosmtplib

log = logging.getLogger("arborpress.mail")
_ADDRESS = re.compile(r"^[^\s<>@]+@[^\s<>@]+$")


def validate_header_value(value: str, field: str = "header") -> str:
    if "\r" in value or "\n" in value or "\0" in value:
        raise ValueError(f"Invalid {field} header value.")
    if len(value) > 998:
        raise ValueError(f"{field} header value exceeds the RFC line limit.")
    return value


def validate_address(value: str) -> str:
    value = validate_header_value(value, "address").strip()
    if not _ADDRESS.fullmatch(value):
        raise ValueError("Invalid email address.")
    return value


class MailMessage:
    """Structured delivery DTO; SMTP envelope recipient is never inferred from headers."""

    def __init__(
        self,
        to: str,
        subject: str,
        body_text: str,
        body_html: str | None = None,
        idempotency_key: str | None = None,
        *,
        message_id: str | None = None,
        recipient_kind: str = "to",
        visible_to: list[str] | None = None,
        visible_cc: list[str] | None = None,
        headers: dict[str, str] | None = None,
        envelope_sender: str | None = None,
        reply_to: str | None = None,
        dsn_envid: str | None = None,
    ) -> None:
        self.to = validate_address(to)
        self.subject = validate_header_value(subject, "subject")
        self.body_text = body_text
        self.body_html = body_html
        self.idempotency_key = idempotency_key
        self.message_id = message_id or make_msgid(domain="arborpress.invalid")
        self.recipient_kind = recipient_kind
        self.visible_to = (
            visible_to if visible_to is not None else ([self.to] if recipient_kind == "to" else [])
        )
        self.visible_cc = visible_cc or []
        self.headers = headers or {}
        self.envelope_sender = validate_address(envelope_sender) if envelope_sender else None
        self.reply_to = validate_address(reply_to) if reply_to else None
        self.dsn_envid = dsn_envid or uuid.uuid4().hex


class SMTPBackend:
    """Async SMTP with implicit TLS or mandatory STARTTLS and default CA validation."""

    async def send(self, msg: MailMessage, profile: dict[str, Any]) -> None:
        if not profile.get("enabled", True):
            raise SMTPConfigurationError("SMTP profile is disabled.")
        transport = profile.get("transport", "starttls")
        if transport not in {"implicit_tls", "starttls"}:
            raise SMTPConfigurationError("Unsupported SMTP transport mode.")
        host = str(profile["host"])
        port = int(profile["port"])
        timeout = float(profile.get("timeout_seconds", 20))
        smtp = aiosmtplib.SMTP(
            hostname=host,
            port=port,
            timeout=timeout,
            use_tls=transport == "implicit_tls",
            start_tls=False,
            validate_certs=True,
        )
        try:
            await smtp.connect()
            if transport == "starttls":
                extensions = {key.lower() for key in getattr(smtp, "esmtp_extensions", {})}
                if "starttls" not in extensions:
                    raise SMTPConfigurationError("SMTP server did not offer required STARTTLS.")
                await smtp.starttls(server_hostname=host, validate_certs=True, timeout=timeout)
                await smtp.ehlo()
            # Authentication is deliberately delayed until after the transport has
            # reached its required TLS state.
            username, password = profile.get("username"), profile.get("password")
            if username or password:
                if not username or not password:
                    raise SMTPConfigurationError("Both SMTP username and secret are required.")
                await smtp.login(username, password, timeout=timeout)

            message = self._build_message(msg, profile)
            mail_options: list[str] = []
            rcpt_options: list[str] = []
            extensions = {key.lower() for key in getattr(smtp, "esmtp_extensions", {})}
            if "dsn" in extensions:
                mail_options.extend(["RET=HDRS", f"ENVID={msg.dsn_envid}"])
                rcpt_options.append("NOTIFY=FAILURE,DELAY")
            await smtp.send_message(
                message,
                sender=msg.envelope_sender or profile["from_address"],
                recipients=[msg.to],
                mail_options=mail_options,
                rcpt_options=rcpt_options,
                timeout=timeout,
            )
        finally:
            if smtp.is_connected:
                try:
                    await smtp.quit(timeout=timeout)
                except Exception:
                    smtp.close()

    @staticmethod
    def _build_message(msg: MailMessage, profile: dict[str, Any]) -> EmailMessage:
        message = EmailMessage()
        display = profile.get("from_name") or ""
        message["From"] = formataddr((display, profile["from_address"]))
        visible_to = msg.visible_to
        visible_cc = msg.visible_cc
        if visible_to:
            message["To"] = ", ".join(validate_address(value) for value in visible_to)
        elif msg.recipient_kind == "bcc":
            message["To"] = "undisclosed-recipients:;"
        if visible_cc:
            message["Cc"] = ", ".join(validate_address(value) for value in visible_cc)
        message["Subject"] = validate_header_value(msg.subject, "subject")
        message["Message-ID"] = validate_header_value(msg.message_id, "message id")
        if msg.reply_to or profile.get("reply_to"):
            message["Reply-To"] = validate_address(msg.reply_to or profile["reply_to"])
        for key, value in msg.headers.items():
            if key.lower() in {
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
            }:
                raise ValueError("Protected email header cannot be supplied by producer.")
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key):
                raise ValueError("Invalid email header name.")
            message[key] = validate_header_value(value, key)
        message.set_content(msg.body_text)
        if msg.body_html:
            message.add_alternative(msg.body_html, subtype="html")
        return message


class SMTPConfigurationError(RuntimeError):
    """SMTP profile or required transport capability is unavailable."""


async def test_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """Probe DNS/TCP/TLS/EHLO/AUTH without sending a message or logging secrets."""
    host = str(profile["host"])
    transport = str(profile.get("transport", "starttls"))
    smtp = aiosmtplib.SMTP(
        hostname=host,
        port=int(profile["port"]),
        timeout=float(profile.get("timeout_seconds", 20)),
        use_tls=transport == "implicit_tls",
        start_tls=False,
        validate_certs=True,
    )
    try:
        await smtp.connect()
        if transport == "starttls":
            extensions = {key.lower() for key in getattr(smtp, "esmtp_extensions", {})}
            if "starttls" not in extensions:
                raise SMTPConfigurationError("SMTP server did not offer required STARTTLS.")
            await smtp.starttls(server_hostname=host, validate_certs=True)
            await smtp.ehlo()
        if profile.get("username") or profile.get("password"):
            if not profile.get("username") or not profile.get("password"):
                raise SMTPConfigurationError("Both SMTP username and secret are required.")
            await smtp.login(profile["username"], profile["password"])
        return {
            "ok": True,
            "host": host,
            "port": int(profile["port"]),
            "transport": transport,
            "authenticated": bool(profile.get("username")),
            "dsn": "dsn" in {key.lower() for key in getattr(smtp, "esmtp_extensions", {})},
        }
    except Exception as exc:
        return {
            "ok": False,
            "host": host,
            "port": int(profile["port"]),
            "transport": transport,
            "error": type(exc).__name__,
        }
    finally:
        if smtp.is_connected:
            try:
                await smtp.quit(timeout=3)
            except Exception:
                smtp.close()
