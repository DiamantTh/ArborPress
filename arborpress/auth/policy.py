"""Authentication-policy and lockout checks shared by routes and CLI."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from arborpress.models.user import MFADevice, MFADeviceType, User, WebAuthnCredential


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
        WebAuthnCredential.user_id == str(user.id)
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
            pass
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
        raise ValueError("Dieser Vorgang würde den letzten nutzbaren Authentifizierungspfad entfernen.")
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
