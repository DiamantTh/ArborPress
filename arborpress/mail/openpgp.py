"""OpenPGP key validation, encrypted instance-key storage, and PGP/MIME.

GnuPG is invoked without a shell in a private temporary home. ArborPress stores
the protected secret-key export and its passphrase encrypted with the existing
application secret; GnuPG temporary state is removed after each operation.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.mime.base import MIMEBase
from pathlib import Path
from typing import Any, cast

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.config import get_settings
from arborpress.mail.smtp import MailMessage, SMTPBackend, compose_message_content
from arborpress.models.mail import InstanceOpenPGPKey
from arborpress.models.user import UserPGPKey

log = logging.getLogger("arborpress.mail.openpgp")
MAX_PUBLIC_KEY_BYTES = 128 * 1024
MAX_SECRET_KEY_BYTES = 2 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
_EMAIL_IN_UID = re.compile(r"<([^<>\s]+@[^<>\s]+)>")


class OpenPGPError(ValueError):
    """Safe, user-displayable OpenPGP validation or policy error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _binary() -> str:
    executable = shutil.which("gpg")
    if executable is None:
        raise OpenPGPError("openpgp_unavailable", "OpenPGP service is unavailable.")
    return executable


@contextmanager
def _private_home() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="arborpress-pgp-"))
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        # GnuPG agents are per-home processes and otherwise outlive the temporary
        # directory while retaining imported secret material in their cache.
        try:
            subprocess.run(  # noqa: S603 - fixed system binary and private temporary home
                [
                    shutil.which("gpgconf") or "gpgconf",
                    "--homedir",
                    str(path),
                    "--kill",
                    "gpg-agent",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
                env={"PATH": os.defpath, "HOME": str(path), "GNUPGHOME": str(path), "LC_ALL": "C"},
                shell=False,
            )  # noqa: S603 - fixed system binary with fixed flags and a private temp path
        except OSError, subprocess.TimeoutExpired:
            pass
        shutil.rmtree(path, ignore_errors=True)


def _run(home: Path, *args: str, data: bytes | None = None, timeout: int = 20) -> bytes:
    env = {"PATH": os.defpath, "HOME": str(home), "GNUPGHOME": str(home), "LC_ALL": "C"}
    try:
        result = subprocess.run(  # noqa: S603 - fixed GnuPG binary; data stays in isolated arguments/files
            [_binary(), "--homedir", str(home), "--batch", "--no-tty", *args],
            input=data,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=env,
            shell=False,
        )  # noqa: S603 - fixed GnuPG executable; arguments are validated data and private temp paths
    except subprocess.TimeoutExpired as exc:
        raise OpenPGPError("openpgp_timeout", "OpenPGP operation timed out.") from exc
    except OSError as exc:
        raise OpenPGPError("openpgp_unavailable", "OpenPGP service could not start.") from exc
    if result.returncode:
        raise OpenPGPError("openpgp_invalid", "OpenPGP key or message is invalid.")
    return result.stdout


def _fernet() -> Fernet:
    root = get_settings().web.secret_key.get_secret_value().encode()
    key = hashlib.sha256(b"arborpress:instance-openpgp:v1\0" + root).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(value: bytes) -> bytes:
    return _fernet().encrypt(value)


def decrypt_secret(value: bytes) -> bytes:
    try:
        return _fernet().decrypt(value)
    except InvalidToken as exc:
        raise OpenPGPError(
            "openpgp_key_unavailable",
            "Stored OpenPGP key cannot be decrypted with this instance secret.",
        ) from exc


def _decode_uid(value: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)


def _algorithm_acceptable(algorithm: str, bits: str) -> bool:
    """Allow only established GnuPG key families at conservative key sizes."""
    if not bits.isdigit():
        return False
    strength = int(bits)
    if algorithm in {"1", "2", "3", "16", "17"}:
        return strength >= 2048
    if algorithm in {"18", "19"}:
        return strength >= 255
    if algorithm == "22":
        return strength >= 255
    return False


def inspect_public_key(armored: str | bytes, *, require_encryption: bool = True) -> dict[str, Any]:
    raw = armored.encode("utf-8") if isinstance(armored, str) else armored
    if not raw or len(raw) > MAX_PUBLIC_KEY_BYTES:
        raise OpenPGPError("openpgp_key_size", "Public key is empty or exceeds the 128 KiB limit.")
    with _private_home() as home:
        key_file = home / "public.asc"
        key_file.write_bytes(raw)
        os.chmod(key_file, 0o600)
        _run(home, "--import", str(key_file))
        listing = _run(home, "--with-colons", "--fingerprint", "--list-keys").decode(
            "utf-8", "replace"
        )
        secret_listing = _run(home, "--with-colons", "--list-secret-keys").decode(
            "utf-8", "replace"
        )
    if any(line.startswith("sec:") for line in secret_listing.splitlines()):
        raise OpenPGPError(
            "openpgp_private_key_rejected", "Only a public key may be stored for a mail recipient."
        )
    primary: dict[str, str] | None = None
    current: dict[str, str] | None = None
    fingerprints: list[str] = []
    primary_count = 0
    user_ids: list[str] = []
    usable_key_expiries: list[int] = []
    has_encryption_capability = False
    for line in listing.splitlines():
        fields = line.split(":")
        kind = fields[0]
        if kind in {"pub", "sub"}:
            current = {
                "kind": kind,
                "validity": fields[1] if len(fields) > 1 else "",
                "bits": fields[2] if len(fields) > 2 else "",
                "algo": fields[3] if len(fields) > 3 else "",
                "expires": fields[6] if len(fields) > 6 else "",
                "capabilities": fields[11] if len(fields) > 11 else "",
            }
            if kind == "pub":
                primary_count += 1
                primary = current
        elif kind == "fpr" and len(fields) > 9:
            fingerprints.append(fields[9].upper())
        elif kind == "uid" and len(fields) > 9:
            user_ids.append(_decode_uid(fields[9]))
        if current and current.get("kind") in {"pub", "sub"}:
            expiry = int(current["expires"]) if current["expires"].isdigit() else 0
            valid = current["validity"] not in {"r", "e", "d", "i"}
            capability = "e" if require_encryption else "s"
            has_encryption_capability = has_encryption_capability or (
                valid
                and "e" in current["capabilities"]
                and _algorithm_acceptable(current["algo"], current["bits"])
            )
            if (
                valid
                and capability in current["capabilities"]
                and _algorithm_acceptable(current["algo"], current["bits"])
            ):
                usable_key_expiries.append(expiry)
    if primary is None or primary_count != 1 or not fingerprints or not user_ids:
        raise OpenPGPError("openpgp_invalid", "No parseable OpenPGP public key was found.")
    if primary["validity"] in {"r", "e", "d"}:
        raise OpenPGPError("openpgp_key_invalid", "The OpenPGP primary key is revoked or expired.")
    if not usable_key_expiries:
        raise OpenPGPError(
            "openpgp_no_encryption_subkey" if require_encryption else "openpgp_no_signing_key",
            "The key has no current suitable encryption-capable key or subkey."
            if require_encryption
            else "The key has no current suitable signing-capable key.",
        )
    expiries = [item for item in usable_key_expiries if item > 0]
    expires_at = (
        datetime.fromtimestamp(min(expiries), UTC).replace(tzinfo=None) if expiries else None
    )
    algorithm = {"1": "RSA", "18": "ECDH", "22": "EdDSA", "19": "ECDSA"}.get(
        primary["algo"], f"OpenPGP-{primary['algo']}"
    )
    with _private_home() as home:
        key_file = _write_private(home, "public.asc", raw)
        _run(home, "--import", str(key_file))
        public_armored = _run(home, "--armor", "--export", fingerprints[0]).decode("ascii")
    return {
        "fingerprint": fingerprints[0],
        "openpgp_user_id": user_ids[0][:512],
        "user_ids": user_ids,
        "emails": [
            match.group(1).casefold() for uid in user_ids for match in _EMAIL_IN_UID.finditer(uid)
        ],
        "algorithm": f"{algorithm}-{primary['bits']}",
        "has_encryption_capability": has_encryption_capability,
        "expires_at": expires_at,
        "public_key_armored": public_armored,
    }


def create_instance_key_material(user_id: str) -> dict[str, Any]:
    """Create a sign-only Ed25519 identity; no instance decryption key exists."""
    user_id = user_id.strip()
    if (
        not user_id
        or user_id.startswith("-")
        or len(user_id) > 512
        or any(ch in user_id for ch in "\r\n\0")
    ):
        raise OpenPGPError("openpgp_user_id", "OpenPGP identity is invalid.")
    passphrase = base64.urlsafe_b64encode(os.urandom(36)).decode("ascii")
    with _private_home() as home:
        pinentry = ("--pinentry-mode", "loopback", "--passphrase-fd", "0")
        _run(
            home,
            *pinentry,
            "--quick-generate-key",
            user_id,
            "ed25519",
            "sign",
            "2y",
            data=(passphrase + "\n").encode(),
        )
        secret_listing = _run(home, "--with-colons", "--fingerprint", "--list-secret-keys").decode()
        fingerprint = _first_fingerprint(secret_listing)
        public = _run(home, "--armor", "--export", fingerprint)
        private = _run(
            home,
            *pinentry,
            "--armor",
            "--export-secret-keys",
            fingerprint,
            data=(passphrase + "\n").encode(),
        )
    details = inspect_public_key(public, require_encryption=False)
    return {
        **details,
        "private_key": private,
        "passphrase": passphrase.encode(),
    }


def _first_fingerprint(listing: str) -> str:
    for line in listing.splitlines():
        fields = line.split(":")
        if fields[0] == "fpr" and len(fields) > 9:
            return fields[9].upper()
    raise OpenPGPError("openpgp_invalid", "OpenPGP key fingerprint is unavailable.")


def import_instance_key_material(armored: bytes, passphrase: str) -> dict[str, Any]:
    if not armored or len(armored) > MAX_SECRET_KEY_BYTES:
        raise OpenPGPError("openpgp_key_size", "Private key is empty or exceeds the 2 MiB limit.")
    if len(passphrase) > 4096:
        raise OpenPGPError("openpgp_passphrase", "Private-key passphrase is too large.")
    with _private_home() as home:
        key_file = home / "secret.asc"
        pass_file = home / "passphrase"
        key_file.write_bytes(armored)
        pass_file.write_bytes(passphrase.encode())
        os.chmod(key_file, 0o600)
        os.chmod(pass_file, 0o600)
        _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(pass_file),
            "--import",
            str(key_file),
        )
        listing = _run(home, "--with-colons", "--fingerprint", "--list-secret-keys").decode()
        fingerprint = _first_fingerprint(listing)
        _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(pass_file),
            "--local-user",
            fingerprint,
            "--detach-sign",
            "--output",
            "-",
            data=b"ArborPress OpenPGP key validation",
        )
        public = _run(home, "--armor", "--export", fingerprint)
        private = _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(pass_file),
            "--armor",
            "--export-secret-keys",
            fingerprint,
        )
    details = inspect_public_key(public, require_encryption=False)
    if details["has_encryption_capability"]:
        raise OpenPGPError(
            "openpgp_instance_decryption_key_rejected",
            "Instance signing keys must not contain a usable message-decryption key.",
        )
    if details["fingerprint"] != fingerprint:
        raise OpenPGPError(
            "openpgp_key_mismatch", "Private and public key fingerprints do not match."
        )
    return {
        **details,
        "private_key": private,
        "passphrase": passphrase.encode(),
    }


async def save_instance_key(
    db: AsyncSession, material: dict[str, Any], *, activate: bool = True
) -> InstanceOpenPGPKey:
    existing = await db.scalar(
        select(InstanceOpenPGPKey).where(InstanceOpenPGPKey.fingerprint == material["fingerprint"])
    )
    if existing is not None:
        raise OpenPGPError("openpgp_duplicate_key", "This instance key is already registered.")
    now = datetime.now(UTC).replace(tzinfo=None)
    if activate:
        await db.execute(
            update(InstanceOpenPGPKey)
            .where(InstanceOpenPGPKey.is_current.is_(True))
            .values(is_current=False, status="retired", retired_at=now)
        )
    row = InstanceOpenPGPKey(
        id=str(uuid.uuid4()),
        fingerprint=material["fingerprint"],
        openpgp_user_id=material["openpgp_user_id"],
        algorithm=material["algorithm"],
        public_key_armored=material["public_key_armored"],
        private_key_enc=encrypt_secret(material["private_key"]),
        passphrase_enc=encrypt_secret(material["passphrase"]),
        expires_at=material["expires_at"],
        status="active" if activate else "inactive",
        is_current=activate,
        created_at=now,
    )
    db.add(row)
    await db.flush()
    return row


async def make_current(db: AsyncSession, key_id: str) -> InstanceOpenPGPKey:
    now = datetime.now(UTC).replace(tzinfo=None)
    row = await db.get(InstanceOpenPGPKey, key_id)
    if (
        row is None
        or row.status not in {"active", "retired"}
        or (row.expires_at is not None and row.expires_at <= now)
    ):
        raise OpenPGPError("openpgp_key_unavailable", "The selected instance key is not usable.")
    await validate_stored_instance_key(row)
    await db.execute(
        update(InstanceOpenPGPKey)
        .where(InstanceOpenPGPKey.is_current.is_(True))
        .values(is_current=False, status="retired", retired_at=now)
    )
    row.status = "active"
    row.is_current = True
    row.retired_at = None
    await db.flush()
    return row


async def validate_stored_instance_key(row: InstanceOpenPGPKey) -> None:
    """Verify encrypted-at-rest material, passphrase, signing ability and fingerprint."""
    material = await asyncio.to_thread(
        import_instance_key_material,
        decrypt_secret(row.private_key_enc),
        decrypt_secret(row.passphrase_enc).decode("ascii"),
    )
    if material["fingerprint"] != row.fingerprint:
        raise OpenPGPError(
            "openpgp_key_mismatch", "Stored signing key fingerprint does not match its metadata."
        )


def _write_private(home: Path, name: str, value: bytes) -> Path:
    path = home / name
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _build_signed_content(msg: MailMessage, signature: bytes) -> EmailMessage:
    content = compose_message_content(msg)
    wrapper = EmailMessage()
    wrapper.set_type("multipart/signed")
    wrapper.set_param("protocol", "application/pgp-signature")
    wrapper.set_param("micalg", "pgp-sha256")
    wrapper.attach(content)
    sig = MIMEBase("application", "pgp-signature")
    sig.set_payload(signature.decode("ascii"))
    sig["Content-Transfer-Encoding"] = "7bit"
    sig.set_param("name", "signature.asc")
    sig.add_header("Content-Disposition", "attachment", filename="signature.asc")
    wrapper.attach(sig)  # type: ignore[arg-type]  # Legacy MIMEBase is valid MIME content.
    return wrapper


def build_pgp_message(
    msg: MailMessage,
    profile: dict[str, Any],
    *,
    recipient_public_key: str | None,
    recipient_fingerprint: str | None,
    instance_key: InstanceOpenPGPKey | None,
    sign: bool,
) -> EmailMessage:
    """Build a standards-based PGP/MIME entity; never plaintext-fallback on error."""
    if sign and instance_key is None:
        raise OpenPGPError(
            "openpgp_signing_key_missing", "Instance signing is enabled but no current key exists."
        )
    if recipient_public_key and not recipient_fingerprint:
        raise OpenPGPError("openpgp_recipient_key_invalid", "Recipient encryption key is invalid.")
    if recipient_public_key is None and not sign:
        return SMTPBackend._build_message(msg, profile)

    content = compose_message_content(msg)
    content_bytes = content.as_bytes(policy=policy.SMTP)
    with _private_home() as home:
        recipient_fpr = None
        if recipient_public_key:
            key_path = _write_private(home, "recipient.asc", recipient_public_key.encode())
            _run(home, "--import", str(key_path))
            info = _run(home, "--with-colons", "--fingerprint", "--list-keys").decode()
            recipient_fpr = _first_fingerprint(info)
            if recipient_fpr != recipient_fingerprint:
                raise OpenPGPError("openpgp_key_mismatch", "Recipient key fingerprint changed.")
        passphrase_path: Path | None = None
        local_fpr: str | None = None
        if sign:
            assert instance_key is not None
            secret = decrypt_secret(instance_key.private_key_enc)
            passphrase = decrypt_secret(instance_key.passphrase_enc)
            private_path = _write_private(home, "instance-secret.asc", secret)
            passphrase_path = _write_private(home, "instance-passphrase", passphrase)
            _run(
                home,
                "--pinentry-mode",
                "loopback",
                "--passphrase-file",
                str(passphrase_path),
                "--import",
                str(private_path),
            )
            local_fpr = instance_key.fingerprint
        if recipient_fpr:
            plaintext = _write_private(home, "content.mime", content_bytes)
            args = ["--armor", "--trust-model", "always"]
            if sign:
                assert local_fpr is not None and passphrase_path is not None
                args.extend(
                    [
                        "--pinentry-mode",
                        "loopback",
                        "--passphrase-file",
                        str(passphrase_path),
                        "--local-user",
                        local_fpr,
                        "--digest-algo",
                        "SHA256",
                        "--sign",
                    ]
                )
            args.extend(
                ["--encrypt", "--recipient", recipient_fpr or "", "--output", "-", str(plaintext)]
            )
            encrypted = _run(home, *args, timeout=30)
            wrapper = EmailMessage()
            wrapper.set_type("multipart/encrypted")
            wrapper.set_param("protocol", "application/pgp-encrypted")
            version = MIMEBase("application", "pgp-encrypted")
            version.set_payload("Version: 1")
            version["Content-Transfer-Encoding"] = "7bit"
            data = MIMEBase("application", "octet-stream")
            data.set_payload(encrypted.decode("ascii"))
            data["Content-Transfer-Encoding"] = "7bit"
            data.add_header("Content-Disposition", "inline", filename="encrypted.asc")
            wrapper.attach(version)  # type: ignore[arg-type]  # Legacy MIMEBase is valid MIME content.
            wrapper.attach(data)  # type: ignore[arg-type]  # Legacy MIMEBase is valid MIME content.
            return _outer_headers(msg, profile, wrapper)

        assert local_fpr is not None and passphrase_path is not None
        content_path = _write_private(home, "content.mime", content_bytes)
        signature = _run(
            home,
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            str(passphrase_path),
            "--armor",
            "--detach-sign",
            "--local-user",
            local_fpr,
            "--digest-algo",
            "SHA256",
            "--output",
            "-",
            str(content_path),
        )
        return _outer_headers(msg, profile, _build_signed_content(msg, signature))


def _outer_headers(
    msg: MailMessage, profile: dict[str, Any], content: EmailMessage
) -> EmailMessage:
    outer = SMTPBackend._build_message(msg, profile)
    outer.clear_content()
    content_type = content.get_content_type()
    params = content.get_params(header="content-type", failobj=[])[1:]
    outer.set_type(content_type)
    for name, value in params:
        outer.set_param(name, value)
    if content.is_multipart():
        for part in content.iter_parts():
            outer.attach(part)  # type: ignore[arg-type]  # MIMEPart is an EmailMessage at runtime.
    else:
        outer.set_payload(content.get_payload())
        for name, value in content.items():
            if name.lower() not in {"content-type", "mime-version"}:
                outer[name] = value
    return outer


async def selected_recipient_key(db: AsyncSession, user_id: str) -> UserPGPKey | None:
    return cast(UserPGPKey | None, await db.scalar(
        select(UserPGPKey)
        .where(
            UserPGPKey.user_id == user_id,
            UserPGPKey.use_for_encryption.is_(True),
            UserPGPKey.status == "active",
            UserPGPKey.revoked_at.is_(None),
        )
        .order_by(UserPGPKey.created_at.desc())
        .limit(1)
    ))


async def current_instance_key(db: AsyncSession) -> InstanceOpenPGPKey | None:
    row = await db.scalar(
        select(InstanceOpenPGPKey).where(
            InstanceOpenPGPKey.is_current.is_(True), InstanceOpenPGPKey.status == "active"
        )
    )
    if (
        row is not None
        and row.expires_at is not None
        and row.expires_at <= datetime.now(UTC).replace(tzinfo=None)
    ):
        return None
    return row


async def build_for_user(
    msg: MailMessage,
    profile: dict[str, Any],
    *,
    db: AsyncSession,
    user_id: str,
    user_email: str | None,
    encryption_required: bool,
    signing_enabled: bool,
) -> tuple[MailMessage | EmailMessage, bool]:
    from arborpress.models.user import User

    user = await db.get(User, user_id)
    if user is None or not user.is_active or not user_email or user.email is None:
        raise OpenPGPError(
            "recipient_account_unavailable", "The registered mail recipient is unavailable."
        )
    if user.email.casefold() != user_email.casefold():
        raise OpenPGPError(
            "recipient_address_changed", "The account email changed after this message was queued."
        )
    if msg.to.casefold() != user.email.casefold():
        raise OpenPGPError(
            "recipient_address_changed", "The queued recipient is no longer the account email."
        )
    key = await selected_recipient_key(db, user_id)
    opted_in = bool(user.pgp_encryption_enabled)
    must_encrypt = encryption_required or opted_in
    if must_encrypt and key is None:
        raise OpenPGPError(
            "recipient_key_missing",
            "Required encryption is unavailable: the account has no active public key.",
        )
    if key is not None and must_encrypt:
        if key.expires_at is not None and key.expires_at <= datetime.now(UTC).replace(tzinfo=None):
            raise OpenPGPError(
                "recipient_key_expired",
                "Required encryption is unavailable: the account key has expired.",
            )
        details = await asyncio.to_thread(inspect_public_key, key.public_key_armored)
        if user.email.casefold() not in details["emails"]:
            if must_encrypt:
                raise OpenPGPError(
                    "recipient_key_identity_mismatch",
                    "Required encryption is unavailable: key identity does not match "
                    "the current account email.",
                )
            key = None
    instance_key = await current_instance_key(db) if signing_enabled else None
    if signing_enabled and instance_key is None:
        raise OpenPGPError(
            "instance_signing_key_missing",
            "Mail signing is enabled but no usable instance key exists.",
        )
    if not must_encrypt and not signing_enabled:
        return msg, False
    if must_encrypt:
        # Each queued row has one SMTP envelope recipient. Do not reveal the
        # other members of a producer's To/Cc list in a protected user's headers.
        msg.visible_to = [msg.to] if msg.recipient_kind == "to" else []
        msg.visible_cc = [msg.to] if msg.recipient_kind == "cc" else []
    try:
        built = await asyncio.to_thread(
            build_pgp_message,
            msg,
            profile,
            recipient_public_key=key.public_key_armored if must_encrypt and key else None,
            recipient_fingerprint=key.fingerprint if must_encrypt and key else None,
            instance_key=instance_key,
            sign=signing_enabled,
        )
    except OpenPGPError:
        raise
    except Exception as exc:
        log.error("PGP/MIME construction failed code=%s", type(exc).__name__)
        raise OpenPGPError("openpgp_processing_failed", "OpenPGP mail processing failed.") from exc
    return built, must_encrypt
