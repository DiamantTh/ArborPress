"""TOTP/HOTP service (§3 – system-level MFA module).

SHA-256 minimum, 6–8 digits configurable.
Multiple MFA devices per account supported (named, max. MFA_MAX_DEVICES).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets

import pyotp

from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.mfa")
audit = get_audit_logger()

# §3: SHA-256 minimum; 8 digits as default
_DIGITS = 8
_DIGEST = hashlib.sha256
_INTERVAL = 30  # TOTP window in seconds

# Maximum number of MFA devices (TOTP+HOTP+plugin) per account
MFA_MAX_DEVICES: int = 20


class TOTPService:
    """TOTP enrollment and verification (§3)."""

    def __init__(self, issuer: str = "Arbor Press") -> None:
        self.issuer = issuer

    def _totp(self, secret: bytes) -> pyotp.TOTP:
        return pyotp.TOTP(
            secret.decode(),
            digits=_DIGITS,
            digest=_DIGEST,
            interval=_INTERVAL,
        )

    def generate_secret(self) -> bytes:
        """Generate a new TOTP secret (32 bytes, Base32-encoded)."""
        return base64.b32encode(os.urandom(32))

    def provisioning_uri(
        self,
        secret: bytes,
        account_name: str,
        issuer: str | None = None,
    ) -> str:
        totp = self._totp(secret)
        return totp.provisioning_uri(name=account_name, issuer_name=issuer or self.issuer)

    def provision_url(self, secret: bytes, account_name: str) -> str:
        """Backward-compatible alias used by tests and older callers."""
        return self.provisioning_uri(secret, account_name)

    def current_token(self, secret: bytes) -> str:
        """Return the current TOTP token for the given secret."""
        return self._totp(secret).now()

    def verify(
        self,
        secret: bytes,
        code: str,
        *,
        user_id: str = "unknown",
        valid_window: int = 1,
    ) -> bool:
        totp = self._totp(secret)
        result = totp.verify(code, valid_window=valid_window)
        if result:
            audit.info("TOTP verify OK | user=%s", user_id)
        else:
            audit.warning("TOTP verify FAILED | user=%s", user_id)
        return result


class HOTPService:
    """HOTP enrollment and verification (§3).

    HOTP (HMAC-based One-Time Password, RFC 4226) is particularly suited for
    hardware tokens without a real-time clock (e.g. YubiKey in HOTP mode).
    The counter is stored per device in the DB and incremented by 1 after each
    successful verify (stored in `MFADevice` as extra_data JSON).

    Important: the counter in the backend must be persisted after each successful
    verify before a response is sent.
    """

    def generate_secret(self) -> bytes:
        """Generate a new HOTP secret (32 bytes, Base32-encoded)."""
        return base64.b32encode(os.urandom(32))

    def provisioning_uri(
        self,
        secret: bytes,
        account_name: str,
        initial_count: int = 0,
        issuer: str = "Arbor Press",
    ) -> str:
        hotp = pyotp.HOTP(secret.decode(), digits=_DIGITS, digest=_DIGEST)
        return hotp.provisioning_uri(
            name=account_name, issuer_name=issuer, initial_count=initial_count
        )

    def verify(
        self,
        secret: bytes,
        code: str,
        counter: int,
        *,
        user_id: str,
        look_ahead: int = 10,
    ) -> tuple[bool, int]:
        """Verify an HOTP code.

        Args:
            counter:    Current counter value (from DB).
            look_ahead: Number of future counter values to check (drift tolerance).

        Returns:
            (ok, new_counter) – new counter must be persisted by the caller.
        """
        hotp = pyotp.HOTP(secret.decode(), digits=_DIGITS, digest=_DIGEST)
        for offset in range(look_ahead + 1):
            if hotp.verify(code, counter + offset):
                new_counter = counter + offset + 1
                audit.info(
                    "HOTP verify OK | user=%s counter=%d->%d",
                    user_id, counter, new_counter,
                )
                return True, new_counter
        audit.warning("HOTP verify FAILED | user=%s counter=%d", user_id, counter)
        return False, counter


class BackupCodeService:
    """Backup code management (§2 / §3 – one-time recovery)."""

    def generate_codes(self, count: int = 10) -> tuple[list[str], list[str]]:
        """Return (plaintext_codes, hashed_codes).

        Plaintext is shown to the user once and then discarded.
        """
        from argon2 import PasswordHasher

        ph = PasswordHasher()
        plain: list[str] = []
        hashed: list[str] = []
        for _ in range(count):
            # Format: XXXX-XXXX-XXXX (URL-safe, lesbar)
            code = "-".join(
                secrets.token_hex(2).upper() for _ in range(3)
            )
            plain.append(code)
            hashed.append(ph.hash(code))
        return plain, hashed

    def verify(
        self,
        code: str,
        stored_hash: str,
        *,
        user_id: str = "unknown",
    ) -> bool:
        """Backward-compatible verify helper for backup codes."""
        return self.verify_code(code, stored_hash, user_id=user_id)

    def verify_code(
        self,
        code: str,
        stored_hash: str,
        *,
        user_id: str = "unknown",
    ) -> bool:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerificationError

        ph = PasswordHasher()
        try:
            result = ph.verify(stored_hash, code)
            if result:
                audit.warning("BACKUP-CODE used | user=%s", user_id)
            return result
        except VerificationError:
            audit.warning("BACKUP-CODE invalid attempt | user=%s", user_id)
            return False
