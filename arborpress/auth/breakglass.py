"""Break-glass legacy password auth (spec §17).

IMPORTANT: Intended only as a hidden emergency access path.
- Not exposed in UI
- Only for dedicated admin identities
- Audit log on every use is mandatory
"""

from __future__ import annotations

import logging

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.breakglass")
audit = get_audit_logger()

# OWASP 2024 recommendation Argon2id (interactive): t=3, m=64 MiB, p=4
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,      # raised from 2 to follow OWASP recommendation
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _hasher.hash(password)


def verify_password(hashed: str, password: str, *, admin_id: str) -> bool:
    """Verify a password and always write to the audit log."""
    try:
        result = _hasher.verify(hashed, password)
        if result:
            audit.warning(
                "BREAK-GLASS login successful | admin=%s", admin_id
            )
        return result
    except VerificationError:
        audit.warning(
            "BREAK-GLASS login failed | admin=%s", admin_id
        )
        return False


def needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)
