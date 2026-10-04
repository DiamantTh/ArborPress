"""Action-, target-, session-bound, one-shot WebAuthn step-up grants."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, or_, update

from arborpress.core.config import get_settings
from arborpress.logging.config import get_audit_logger

log = logging.getLogger("arborpress.auth.stepup")
audit = get_audit_logger()

_GRANTS_KEY = "_arborpress_stepup_grants"

# Every operation passed to assert_stepup is registered here. Unknown names
# fail closed so a typo at a sensitive call site cannot disable protection.
STEPUP_POLICIES: dict[str, str] = {
    "change_roles": "target",
    "modify_auth_policy": "instance",
    "toggle_federation": "instance",
    "install_plugin": "target",
    "enable_plugin": "target",
    "disable_plugin": "target",
    "generate_export": "instance",
    "rotate_key": "target",
    "change_security_settings": "instance",
    "change_webauthn_settings": "instance",
    "unlock_webauthn_rp_id": "instance",
    "lock_webauthn_rp_id": "instance",
    "delete_post": "target",
    "add_webauthn_credential": "target",
    "remove_webauthn_credential": "target",
    "add_totp_credential": "target",
    "remove_totp_credential": "target",
    "change_password": "target",
    "enable_password": "target",
    "disable_password": "target",
    "set_breakglass_password": "target",
    "admin_credential_reset": "target",
}
STEPUP_REQUIRED_OPERATIONS = frozenset(STEPUP_POLICIES)


def _effective_stepup_ttl() -> int:
    """Keep step-up grants brief even when a legacy config requested longer."""
    configured = int(get_settings().auth.stepup_ttl)
    return min(300, max(0, configured))


def require_stepup(operation: str) -> bool:
    """Return whether a known operation requires step-up; reject unknown names."""
    if operation not in STEPUP_POLICIES:
        raise ValueError(f"unregistered step-up operation: {operation}")
    return True


def _validate_scope(action: str, target: str | None) -> None:
    if STEPUP_POLICIES[action] == "target" and not target:
        raise ValueError(f"step-up operation {action!r} requires a target")
    if STEPUP_POLICIES[action] == "instance" and target not in (None, "instance"):
        raise ValueError(f"step-up operation {action!r} is scoped to the instance")


def _target_key(target: str | None) -> str:
    return target or "instance"


def _session_grant_ids(session: dict[str, Any]) -> list[str]:
    value = session.get(_GRANTS_KEY, [])
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


async def _open_db_session():
    from arborpress.core.db import get_db_session

    async for db in get_db_session():
        yield db


async def _audit_stepup(
    db: Any,
    *,
    event_type: str,
    outcome: str,
    user_id: str,
    action: str,
    target: str,
) -> None:
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type=event_type,
        outcome=outcome,
        actor_id=user_id,
        target_id=target if len(target) <= 36 else None,
        detail=f"action={action};target={target}",
        db=db,
    )


async def is_stepup_active(
    session: dict[str, Any],
    user_id: str,
    action: str = "change_security_settings",
    target: str | None = None,
    *,
    db: Any = None,
) -> bool:
    """Check for a matching, unexpired server-side grant without consuming it."""
    if action not in STEPUP_POLICIES:
        return False
    _validate_scope(action, target)
    ids = _session_grant_ids(session)
    session_id = str(session.get("session_id") or "")
    if not ids or not session_id or _effective_stepup_ttl() <= 0:
        return False

    if db is None:
        async for owned_db in _open_db_session():
            return await is_stepup_active(
                session, user_id, action, target, db=owned_db
            )
        return False

    from sqlalchemy import select
    from arborpress.models.user import StepUpGrant

    row = await db.execute(
        select(StepUpGrant.id).where(
            StepUpGrant.id.in_(ids),
            StepUpGrant.user_id == str(user_id),
            StepUpGrant.session_id == session_id,
            StepUpGrant.action == action,
            StepUpGrant.target == _target_key(target),
            StepUpGrant.consumed_at.is_(None),
            StepUpGrant.expires_at > datetime.now(UTC).replace(tzinfo=None),
        ).limit(1)
    )
    return row.scalar_one_or_none() is not None


async def grant_stepup(
    session: dict[str, Any],
    user_id: str,
    action: str,
    target: str | None = None,
    *,
    db: Any = None,
) -> None:
    """Issue a short, one-shot grant scoped to user, browser session, action, and target."""
    require_stepup(action)
    _validate_scope(action, target)
    session_id = str(session.get("session_id") or "")
    if not session_id:
        raise ValueError("step-up grant requires an authenticated database session")

    if db is None:
        async for owned_db in _open_db_session():
            await grant_stepup(
                session, user_id, action, target, db=owned_db
            )
            await owned_db.commit()
            return
        raise RuntimeError("database session unavailable for step-up grant")

    from arborpress.models.user import StepUpGrant

    now = datetime.now(UTC).replace(tzinfo=None)
    ttl = _effective_stepup_ttl()
    if ttl <= 0:
        raise PermissionError("step-up grants are disabled by policy")
    # Expired and consumed grants are no longer useful.
    await db.execute(
        delete(StepUpGrant).where(
            or_(StepUpGrant.expires_at <= now, StepUpGrant.consumed_at.is_not(None))
        )
    )
    grant = StepUpGrant(
        id=str(uuid.uuid4()),
        user_id=str(user_id),
        session_id=session_id,
        action=action,
        target=_target_key(target),
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    db.add(grant)
    ids = _session_grant_ids(session)
    ids.append(grant.id)
    session[_GRANTS_KEY] = ids[-12:]
    await _audit_stepup(
        db, event_type="sensitive_stepup_granted", outcome="success",
        user_id=str(user_id), action=action, target=_target_key(target),
    )
    audit.info(
        "STEP-UP granted | user=%s action=%s target=%s",
        user_id, action, _target_key(target),
    )


async def assert_stepup(
    session: dict[str, Any],
    user_id: str,
    operation: str,
    target: str | None = None,
    *,
    consume: bool = True,
    db: Any = None,
) -> None:
    """Validate a matching grant and atomically consume it by default."""
    try:
        require_stepup(operation)
        _validate_scope(operation, target)
    except ValueError as exc:
        from arborpress.core.audit import write_audit_event

        await write_audit_event(
            event_type="sensitive_stepup_failed",
            outcome="failure",
            actor_id=str(user_id),
            target_id=target if target and len(target) <= 36 else None,
            detail=f"unregistered_or_invalid_action={operation}",
        )
        audit.error("STEP-UP rejected unknown operation | user=%s op=%s", user_id, operation)
        raise PermissionError(str(exc)) from exc

    if db is None:
        async for owned_db in _open_db_session():
            try:
                await assert_stepup(
                    session, user_id, operation, target, consume=consume, db=owned_db
                )
            except PermissionError:
                await owned_db.commit()
                raise
            else:
                # Persist consumption before the caller performs the protected action.
                await owned_db.commit()
            return
        raise RuntimeError("database session unavailable for step-up validation")

    from arborpress.models.user import StepUpGrant

    user_id = str(user_id)
    session_id = str(session.get("session_id") or "")
    expected_target = _target_key(target)
    ids = _session_grant_ids(session)
    now = datetime.now(UTC).replace(tzinfo=None)
    if session_id and ids and _effective_stepup_ttl() > 0:
        for grant_id in ids:
            if consume:
                result = await db.execute(
                    update(StepUpGrant)
                    .where(
                        StepUpGrant.id == grant_id,
                        StepUpGrant.user_id == user_id,
                        StepUpGrant.session_id == session_id,
                        StepUpGrant.action == operation,
                        StepUpGrant.target == expected_target,
                        StepUpGrant.consumed_at.is_(None),
                        StepUpGrant.expires_at > now,
                    )
                    .values(consumed_at=now)
                )
                matched = result.rowcount == 1
            else:
                from sqlalchemy import select

                result = await db.execute(
                    select(StepUpGrant.id).where(
                        StepUpGrant.id == grant_id,
                        StepUpGrant.user_id == user_id,
                        StepUpGrant.session_id == session_id,
                        StepUpGrant.action == operation,
                        StepUpGrant.target == expected_target,
                        StepUpGrant.consumed_at.is_(None),
                        StepUpGrant.expires_at > now,
                    )
                )
                matched = result.scalar_one_or_none() is not None
            if matched:
                if consume:
                    session[_GRANTS_KEY] = [item for item in ids if item != grant_id]
                    await _audit_stepup(
                        db, event_type="sensitive_stepup_consumed", outcome="success",
                        user_id=user_id, action=operation, target=expected_target,
                    )
                    audit.info(
                        "STEP-UP consumed | user=%s action=%s target=%s",
                        user_id, operation, expected_target,
                    )
                return

    await _audit_stepup(
        db, event_type="sensitive_stepup_failed", outcome="failure",
        user_id=user_id, action=operation, target=expected_target,
    )
    audit.warning(
        "STEP-UP failed | user=%s action=%s target=%s",
        user_id, operation, expected_target,
    )
    raise PermissionError(f"step-up authentication required for operation: {operation}")


async def revoke_stepup(
    session: dict[str, Any], user_id: str, *, db: Any = None
) -> None:
    """Revoke every step-up grant for a user in this browser session."""
    if db is None:
        async for owned_db in _open_db_session():
            await revoke_stepup(session, user_id, db=owned_db)
            await owned_db.commit()
            return
        return
    from arborpress.models.user import StepUpGrant

    ids = _session_grant_ids(session)
    if ids:
        now = datetime.now(UTC).replace(tzinfo=None)
        await db.execute(
            update(StepUpGrant)
            .where(
                StepUpGrant.id.in_(ids),
                StepUpGrant.user_id == str(user_id),
                StepUpGrant.session_id == str(session.get("session_id") or ""),
                StepUpGrant.consumed_at.is_(None),
            )
            .values(consumed_at=now)
        )
    session[_GRANTS_KEY] = []
    audit.info("STEP-UP revoked | user=%s", user_id)
