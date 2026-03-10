"""TOTP/HOTP-Service (§3 – system-level MFA module).

SHA-256 minimum, 6–8 Stellen konfigurierbar.
Mehrere MFA-Geräte pro Account möglich (benannt, max. MFA_MAX_DEVICES).
"""

from __future__ import annotations

import base64
import logging
import os
import secrets

import pyotp

from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.mfa")
audit = get_audit_logger()

# §3: SHA-256 minimum; 8 Digits als Default
_DIGITS = 8
_DIGEST = "sha256"
_INTERVAL = 30  # Sekunden TOTP-Fenster

# Maximale Anzahl MFA-Geräte (TOTP+HOTP+Plugin) pro Account
MFA_MAX_DEVICES: int = 20


class TOTPService:
    """TOTP-Enrollment und -Verification (§3)."""

    def generate_secret(self) -> bytes:
        """Erzeugt ein neues TOTP-Secret (32 Bytes, Base32-codiert)."""
        return base64.b32encode(os.urandom(32))

    def provisioning_uri(
        self,
        secret: bytes,
        account_name: str,
        issuer: str = "Arbor Press",
    ) -> str:
        totp = pyotp.TOTP(
            secret.decode(),
            digits=_DIGITS,
            digest=_DIGEST,
            interval=_INTERVAL,
        )
        return totp.provisioning_uri(name=account_name, issuer_name=issuer)

    def verify(
        self,
        secret: bytes,
        code: str,
        *,
        user_id: str,
        valid_window: int = 1,
    ) -> bool:
        totp = pyotp.TOTP(
            secret.decode(),
            digits=_DIGITS,
            digest=_DIGEST,
            interval=_INTERVAL,
        )
        result = totp.verify(code, valid_window=valid_window)
        if result:
            audit.info("TOTP verify OK | user=%s", user_id)
        else:
            audit.warning("TOTP verify FAILED | user=%s", user_id)
        return result


class HOTPService:
    """HOTP-Enrollment und -Verification (§3).

    HOTP (HMAC-based One-Time Password, RFC 4226) eignet sich besonders für
    Hardware-Token ohne Echtzeituhr (z. B. YubiKey im HOTP-Modus).
    Der Counter-Stand wird pro Gerät in der DB gespeichert und bei jedem
    erfolgreichen Verify um 1 erhöht (im `MFADevice` als extra_data-JSON).

    Wichtig: Der Counter im Backend muss nach jedem erfolgreichen Verify
    persistiert werden, bevor eine Antwort gesendet wird.
    """

    def generate_secret(self) -> bytes:
        """Erzeugt ein neues HOTP-Secret (32 Bytes, Base32-codiert)."""
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
        """Verifiziert einen HOTP-Code.

        Args:
            counter:    Aktueller Counter-Stand (aus DB).
            look_ahead: Anzahl zukünftiger Counter-Werte prüfen (Drift-Toleranz).

        Returns:
            (ok, new_counter) – neuer Counter muss von Caller persistiert werden.
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
    """Backup-Code-Verwaltung (§2 / §3 – one-time recovery)."""

    def generate_codes(self, count: int = 10) -> tuple[list[str], list[str]]:
        """Gibt (plaintext_codes, hashed_codes) zurück.

        Plaintext wird dem Benutzer einmalig gezeigt und danach verworfen.
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

    def verify_code(
        self,
        code: str,
        stored_hash: str,
        *,
        user_id: str,
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
