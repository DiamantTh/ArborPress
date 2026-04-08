"""Step-up / sudo mode (§2 – step-up mechanism).

Protects high-risk operations via short-lived re-authentication.
Uses WebAuthn with UV (preferred) or backup code.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from arborpress.core.config import get_settings
from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.stepup")
audit = get_audit_logger()

# Session key for step-up timestamp
_STEPUP_KEY = "_arborpress_stepup_at"
_STEPUP_USER_KEY = "_arborpress_stepup_uid"

# §2 – Operationen die Step-up erfordern
STEPUP_REQUIRED_OPERATIONS = frozenset(
    {
        "change_roles",
        "modify_auth_policy",
        "toggle_federation",
        "install_plugin",
        "enable_plugin",
        "generate_export",
        "rotate_key",
        "change_security_settings",
    }
)


def require_stepup(operation: str) -> bool:
    """Return True if the operation requires step-up."""
    return operation in STEPUP_REQUIRED_OPERATIONS


def is_stepup_active(session: dict[str, Any], user_id: str) -> bool:
    """Check whether the step-up session is still valid (§2 TTL)."""
    cfg = get_settings()
    stepup_at = session.get(_STEPUP_KEY)
    stepup_uid = session.get(_STEPUP_USER_KEY)

    if not stepup_at or stepup_uid != user_id:
        return False

    age = time.time() - stepup_at
    return age < cfg.auth.stepup_ttl


def grant_stepup(session: dict[str, Any], user_id: str) -> None:
    """Grant step-up and write audit log."""
    session[_STEPUP_KEY] = time.time()
    session[_STEPUP_USER_KEY] = user_id
    audit.info("STEP-UP granted | user=%s", user_id)


def revoke_stepup(session: dict[str, Any], user_id: str) -> None:
    """Revoke an active step-up."""
    session.pop(_STEPUP_KEY, None)
    session.pop(_STEPUP_USER_KEY, None)
    audit.info("STEP-UP revoked | user=%s", user_id)


def assert_stepup(session: dict[str, Any], user_id: str, operation: str) -> None:
    """Raise PermissionError if step-up is not active (helper for views)."""
    if not is_stepup_active(session, user_id):
        audit.warning(
            "STEP-UP required but not active | user=%s op=%s", user_id, operation
        )
        raise PermissionError(
            f"Step-up authentication required for operation: {operation}"
        )
