"""Authentication-policy and lockout checks shared by routes and CLI."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import func, select, update

from arborpress.models.user import MFADevice, MFADeviceType, User, WebAuthnCredential

log = logging.getLogger("arborpress.auth.policy")


@dataclass(frozen=True)
class CredentialRemovalDecision:
    allowed: bool
    reason: str | None
    usable_count: int


async def lock_user_for_credential_change(db: Any, user_id: str) -> User | None:
    """Serialize credential removals for one user on all supported databases.

    ``FOR UPDATE`` is ignored by SQLite. The no-op row update obtains a SQLite
    write lock while also taking a row lock on PostgreSQL and MariaDB/MySQL.
    Credential counts and deletion must stay in this same transaction.
    """
    user_id = str(user_id)
    await db.execute(
        update(User)
        .where(User.id == user_id)
        .values(id=User.id, updated_at=User.updated_at)
    )
    return (await db.execute(
        select(User).where(User.id == user_id).with_for_update()
    )).scalar_one_or_none()


async def usable_webauthn_credential_ids(db: Any, user_id: str) -> set[str]:
    """Credentials that can be offered for an UV-required WebAuthn assertion.

    Old credentials with unknown enrollment assurance are retained. UV is
    checked on every assertion; a credential explicitly known not to support
    UV is excluded from the available-factor count.
    """
    rows = await db.execute(
        select(WebAuthnCredential.id).where(
            WebAuthnCredential.user_id == str(user_id),
            WebAuthnCredential.uv_capable.is_not(False),
            WebAuthnCredential.verification_status != "recovery_pending",
        )
    )
    return {str(value) for value in rows.scalars().all()}


async def usable_totp_device_ids(db: Any, user_id: str) -> set[str]:
    """Only confirmed, active TOTP devices count as available credentials."""
    rows = await db.execute(
        select(MFADevice.id).where(
            MFADevice.user_id == str(user_id),
            MFADevice.device_type == MFADeviceType.TOTP,
            MFADevice.is_active.is_(True),
            MFADevice.verification_status == "verified",
        )
    )
    return {str(value) for value in rows.scalars().all()}


async def recovery_has_new_auth_path(
    db: Any,
    user: User,
    recovery_context: dict[str, Any],
    *,
    exclude_webauthn_id: str | None = None,
    exclude_mfa_id: str | None = None,
) -> bool:
    """Require a verified WebAuthn credential staged by this recovery only."""
    from arborpress.models.user import WebAuthnCredential

    baseline = {
        str(value) for value in recovery_context.get("baseline_webauthn_ids", [])
    }
    recovery_ids = {
        str(value) for value in recovery_context.get("recovery_webauthn_ids", [])
    }
    if exclude_webauthn_id:
        recovery_ids.discard(str(exclude_webauthn_id))
    if not recovery_ids or recovery_ids.intersection(baseline):
        return False
    return (await db.execute(
        select(WebAuthnCredential.id).where(
            WebAuthnCredential.id.in_(recovery_ids),
            WebAuthnCredential.user_id == str(user.id),
            WebAuthnCredential.uv_capable.is_(True),
            WebAuthnCredential.verification_status == "recovery_pending",
        ).limit(1)
    )).scalar_one_or_none() is not None


async def credential_removal_decision(
    db: Any,
    *,
    user_id: str,
    credential_type: Literal["webauthn", "totp"],
    target_id: str,
    evidence: Any,
) -> CredentialRemovalDecision:
    """Apply the per-type self-service removal and confirming-factor policy."""
    webauthn_ids = await usable_webauthn_credential_ids(db, user_id)
    totp_ids = await usable_totp_device_ids(db, user_id)
    auth_method = getattr(evidence, "auth_method", None)
    assurance = getattr(evidence, "assurance_level", None)

    if credential_type == "webauthn":
        confirming_id = getattr(evidence, "confirming_credential_id", None)
        if (
            auth_method != "webauthn"
            or assurance != "user_verified"
            or confirming_id not in webauthn_ids
        ):
            return CredentialRemovalDecision(
                False, "webauthn_uv_stepup_required", len(webauthn_ids)
            )
        if target_id in webauthn_ids and len(webauthn_ids) == 1:
            return CredentialRemovalDecision(False, "last_webauthn_credential", 1)
        if (
            target_id in webauthn_ids
            and len(webauthn_ids) == 2
            and confirming_id == target_id
        ):
            return CredentialRemovalDecision(False, "different_webauthn_required", 2)
        return CredentialRemovalDecision(True, None, len(webauthn_ids))

    if (
        auth_method == "webauthn"
        and assurance == "user_verified"
        and getattr(evidence, "confirming_credential_id", None) in webauthn_ids
    ):
        confirmed_by_webauthn = True
        confirmed_by_totp = False
    elif (
        auth_method == "totp"
        and assurance == "otp_verified"
        and getattr(evidence, "confirming_mfa_device_id", None) in totp_ids
    ):
        confirmed_by_webauthn = False
        confirmed_by_totp = True
    else:
        return CredentialRemovalDecision(False, "totp_or_webauthn_stepup_required", len(totp_ids))

    if target_id in totp_ids:
        if len(totp_ids) == 1 and not confirmed_by_webauthn:
            return CredentialRemovalDecision(False, "last_totp_requires_webauthn", 1)
        if (
            len(totp_ids) == 2
            and confirmed_by_totp
            and getattr(evidence, "confirming_mfa_device_id", None) == target_id
        ):
            return CredentialRemovalDecision(False, "different_totp_required", 2)
    return CredentialRemovalDecision(True, None, len(totp_ids))


def requires_second_factor(
    user: User,
    authentication_method: str,
    available_factors: set[str],
    *,
    auth_settings: Any,
    webauthn_settings: dict[str, Any],
) -> bool:
    """Apply the shared login MFA policy to password and SSO authentication."""
    if authentication_method == "password":
        # Password-only access remains a restricted recovery session.
        return bool(available_factors)
    if authentication_method == "sso":
        return bool(
            user.require_uv
            or auth_settings.require_uv
            or webauthn_settings.get("require_mfa_after_sso", False)
            or webauthn_settings.get("require_2fa_after_passkey", False)
        )
    return False


async def usable_auth_paths(
    db: Any,
    user: User,
    *,
    exclude_webauthn_id: str | None = None,
    exclude_mfa_id: str | None = None,
    exclude_password: bool = False,
) -> set[str]:
    """Return normal, currently usable ways to authenticate this account."""
    credential_stmt = select(func.count()).select_from(WebAuthnCredential).where(
        WebAuthnCredential.user_id == str(user.id),
        WebAuthnCredential.uv_capable.is_not(False),
        WebAuthnCredential.verification_status != "recovery_pending",
    )
    if exclude_webauthn_id:
        credential_stmt = credential_stmt.where(WebAuthnCredential.id != exclude_webauthn_id)
    credential_count = (await db.execute(credential_stmt)).scalar_one() or 0

    totp_stmt = select(func.count()).select_from(MFADevice).where(
        MFADevice.user_id == str(user.id),
        MFADevice.device_type == MFADeviceType.TOTP,
        MFADevice.is_active.is_(True),
        MFADevice.verification_status == "verified",
    )
    if exclude_mfa_id:
        totp_stmt = totp_stmt.where(MFADevice.id != exclude_mfa_id)
    totp_count = (await db.execute(totp_stmt)).scalar_one() or 0

    paths: set[str] = set()
    available_factors: set[str] = set()
    if credential_count:
        paths.add("webauthn")
        available_factors.add("webauthn")
    if totp_count:
        paths.add("totp")
        available_factors.add("totp")
    has_second_factor = bool(available_factors)
    from arborpress.core.config import get_settings

    auth_settings = get_settings().auth
    if (
        auth_settings.legacy_password_enabled
        and user.legacy_password_enabled
        and user.legacy_password_hash
        and not exclude_password
    ):
        paths.add("password+second_factor" if has_second_factor else "password_recovery")
    # Existing SSO can be a login path if an operator has configured one and
    # the account itself has not opted out. Import lazily to avoid config IO.
    if not user.sso_disabled:
        try:
            from arborpress.web.routes.sso import get_configured_providers
            if get_configured_providers():
                from arborpress.core.site_settings import get_webauthn_settings

                wa_policy = await get_webauthn_settings(db)
                sso_requires_mfa = requires_second_factor(
                    user,
                    "sso",
                    available_factors,
                    auth_settings=auth_settings,
                    webauthn_settings=wa_policy,
                )
                if not sso_requires_mfa or available_factors:
                    paths.add("sso")
        except Exception:  # pragma: no cover - SSO is optional
            log.debug("Could not evaluate the optional SSO authentication path", exc_info=True)
    return paths


async def assert_auth_path_remains(
    db: Any,
    user: User,
    *,
    exclude_webauthn_id: str | None = None,
    exclude_mfa_id: str | None = None,
    exclude_password: bool = False,
) -> set[str]:
    paths = await usable_auth_paths(
        db, user,
        exclude_webauthn_id=exclude_webauthn_id,
        exclude_mfa_id=exclude_mfa_id,
        exclude_password=exclude_password,
    )
    if not paths:
        raise ValueError(
            "Dieser Vorgang würde den letzten nutzbaren Authentifizierungspfad entfernen."
        )
    return paths


async def is_last_active_admin(db: Any, user: User) -> bool:
    """Whether disabling/demoting this user would leave no active admin."""
    if user.role.value != "admin" or not user.is_active:
        return False
    count = (await db.execute(
        select(func.count()).select_from(User).where(
            User.role == user.role,
            User.is_active.is_(True),
            User.id != str(user.id),
        )
    )).scalar_one() or 0
    return count == 0
