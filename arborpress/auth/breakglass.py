"""Break-Glass Legacy-Passwort-Auth (Spec §17).

WICHTIG: Nur als versteckter Notfall-Zugang gedacht.
- Nicht in UI exponiert
- Nur für dedizierte Admin-Identitäten
- Audit-Log bei jeder Nutzung obligatorisch
"""

from __future__ import annotations

import logging

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.breakglass")
audit = get_audit_logger()

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Erzeugt einen Argon2id-Hash des Passworts."""
    return _hasher.hash(password)


def verify_password(hashed: str, password: str, *, admin_id: str) -> bool:
    """Überprüft das Passwort und schreibt immer ins Audit-Log."""
    try:
        result = _hasher.verify(hashed, password)
        if result:
            audit.warning(
                "BREAK-GLASS login erfolgreich | admin=%s", admin_id
            )
        return result
    except VerificationError:
        audit.warning(
            "BREAK-GLASS login fehlgeschlagen | admin=%s", admin_id
        )
        return False


def needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)
