"""WebAuthn/FIDO2 authentication (spec §17).

Primary auth path. Legacy password is a separate break-glass module
and is NEVER enabled by default.

The `rp.id`, `rp.name` and `origin` values are derived from the
deployment URL ([web].base_url in config.toml) and the site title in
the general site_settings section. Per W3C Web Authentication Level 3
§5.3 (RP ID), changing the registrable domain suffix invalidates every
existing credential, so the resolver enforces an explicit ``rp_id_locked``
guard managed via the admin UI.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import webauthn
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
)

log = logging.getLogger("arborpress.auth.webauthn")
audit = logging.getLogger("arborpress.audit")


class RPIDChangeBlocked(RuntimeError):
    """Raised when the resolved rp.id differs from the locked value.

    Per W3C WebAuthn L3 §5.3, every credential is bound to the rp.id
    at registration time. Changing it silently would lock all users
    out, so the operator must confirm the change via /admin/webauthn.
    """

    def __init__(self, current: str, expected: str, credential_count: int) -> None:
        super().__init__(
            f"WebAuthn RP ID changed: resolved={current!r} locked={expected!r} "
            f"({credential_count} credential(s) would be invalidated)."
        )
        self.current = current
        self.expected = expected
        self.credential_count = credential_count


# ---------------------------------------------------------------------------
# Resolver helpers (rp.id, rp.name, origin)
# ---------------------------------------------------------------------------

def _to_punycode(host: str) -> str:
    """Encode IDN hostnames as ASCII (W3C WebAuthn L3 §5.3 requires
    rp.id to be a registrable domain in ASCII)."""
    if host in ("localhost", "127.0.0.1", "::1"):
        return host
    try:
        import idna as _idna
        return _idna.encode(host, alg="TRANSITIONAL").decode("ascii")
    except Exception:
        try:
            return host.encode("idna").decode("ascii")
        except Exception:
            return host


def resolve_origin(base_url: str) -> str:
    """Return the canonical origin (scheme://host[:port]) for WebAuthn
    response verification. W3C WebAuthn L3 §7.1 step 9 requires an
    exact origin match – no substring tricks."""
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    host = _to_punycode(parsed.hostname or "localhost")
    if parsed.port and not (
        (scheme == "https" and parsed.port == 443)
        or (scheme == "http" and parsed.port == 80)
    ):
        return f"{scheme}://{host}:{parsed.port}"
    return f"{scheme}://{host}"


def resolve_rp_id(base_url: str) -> str:
    """Return the rp.id (host without port/path/scheme), Punycode-encoded."""
    parsed = urlparse(base_url)
    return _to_punycode(parsed.hostname or "localhost")


async def resolve_rp_name(db: Any) -> str:
    """Return the human-readable RP name (W3C WebAuthn L3 §5.4.1)."""
    from arborpress.core.site_settings import get_section
    general = await get_section("general", db)
    return str(general.get("site_title") or "ArborPress")


# ---------------------------------------------------------------------------
# RP-ID change guard
# ---------------------------------------------------------------------------

async def assert_rp_id_locked_match(
    db: Any,
    *,
    current_rp_id: str,
) -> dict[str, Any]:
    """Verify that the resolved rp.id still matches the locked value.

    On the very first run (no ``rp_id_last_known`` stored) the current
    value is silently adopted. If the rp.id changed and at least one
    WebAuthn credential exists in the database, raises
    :class:`RPIDChangeBlocked` so the caller can refuse to issue new
    registration / authentication options.
    """
    from sqlalchemy import func, select

    from arborpress.core.site_settings import (
        get_webauthn_settings,
        save_section,
    )
    from arborpress.models.user import WebAuthnCredential

    settings = await get_webauthn_settings(db)
    last_known = (settings.get("rp_id_last_known") or "").strip()

    if not last_known:
        # First boot – record the value and continue.
        await save_section(
            "webauthn",
            {**settings, "rp_id_last_known": current_rp_id},
            db,
            updated_by="system:bootstrap",
        )
        audit.info("WEBAUTHN rp_id bootstrap | rp_id=%s", current_rp_id)
        return settings

    if last_known == current_rp_id:
        return settings

    # Mismatch.
    count_stmt = select(func.count()).select_from(WebAuthnCredential)
    count = (await db.execute(count_stmt)).scalar_one() or 0

    if count == 0 or not settings.get("rp_id_locked", True):
        # No credentials at risk OR operator already unlocked → adopt.
        await save_section(
            "webauthn",
            {**settings, "rp_id_last_known": current_rp_id, "rp_id_locked": True},
            db,
            updated_by="system:rp-id-adopt",
        )
        audit.warning(
            "WEBAUTHN rp_id changed | old=%s new=%s credentials=%d locked=%s",
            last_known, current_rp_id, count, settings.get("rp_id_locked", True),
        )
        return {**settings, "rp_id_last_known": current_rp_id}

    audit.error(
        "WEBAUTHN rp_id change BLOCKED | old=%s new=%s credentials=%d",
        last_known, current_rp_id, count,
    )
    raise RPIDChangeBlocked(current_rp_id, last_known, count)


class WebAuthnService:
    """Kapselt WebAuthn-Registrierung und -Authentifizierung.

    All policy parameters (UV, RK, attestation, algorithms, timeout)
    flow in from the ``webauthn`` site_settings section so an operator
    can adjust them without redeploying.
    """

    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        origin: str,
        *,
        user_verification: str = "preferred",
        resident_key: str = "preferred",
        attestation: str = "none",
        authenticator_attachment: str = "",
        algorithms: list[int] | None = None,
        timeout_ms: int = 60_000,
    ) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.user_verification = user_verification
        self.resident_key = resident_key
        self.attestation = attestation
        self.authenticator_attachment = authenticator_attachment or None
        self.algorithms = algorithms or [-7, -257]
        self.timeout_ms = timeout_ms

    # ------------------------------------------------------------------
    # Registrierung
    # ------------------------------------------------------------------

    def generate_registration_options(
        self,
        user_id: bytes,
        user_name: str,
        user_display_name: str,
        existing_credentials: list[bytes] | None = None,
    ) -> PublicKeyCredentialCreationOptions:
        kwargs: dict[str, Any] = dict(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_display_name,
            exclude_credentials=[
                {"id": cred, "type": "public-key"}
                for cred in (existing_credentials or [])
            ],
            timeout=self.timeout_ms,
        )
        # py_webauthn accepts these as enums or strings; pass through
        # only when set so library defaults still apply otherwise.
        try:
            from webauthn.helpers.structs import (
                AttestationConveyancePreference,
                AuthenticatorSelectionCriteria,
                ResidentKeyRequirement,
                UserVerificationRequirement,
            )
            kwargs["attestation"] = AttestationConveyancePreference(self.attestation)
            kwargs["authenticator_selection"] = AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement(self.resident_key),
                user_verification=UserVerificationRequirement(self.user_verification),
            )
        except Exception as exc:  # pragma: no cover – fall back to library defaults
            log.warning("WebAuthn enum mapping unavailable, using defaults: %s", exc)
        return webauthn.generate_registration_options(**kwargs)

    def verify_registration(
        self,
        credential: RegistrationCredential,
        expected_challenge: bytes,
    ) -> webauthn.VerifiedRegistration:
        return webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
            require_user_verification=(self.user_verification == "required"),
        )

    # ------------------------------------------------------------------
    # Authentifizierung
    # ------------------------------------------------------------------

    def generate_authentication_options(
        self,
        allowed_credentials: list[bytes] | None = None,
    ) -> PublicKeyCredentialRequestOptions:
        return webauthn.generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=[
                {"id": cred, "type": "public-key"}
                for cred in (allowed_credentials or [])
            ],
            user_verification=self.user_verification,
            timeout=self.timeout_ms,
        )

    def verify_authentication(
        self,
        credential: AuthenticationCredential,
        expected_challenge: bytes,
        credential_public_key: bytes,
        current_sign_count: int,
    ) -> webauthn.VerifiedAuthentication:
        return webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=current_sign_count,
            require_user_verification=(self.user_verification == "required"),
        )


# ---------------------------------------------------------------------------
# Service factory
# ---------------------------------------------------------------------------

async def build_webauthn_service(db: Any, base_url: str) -> WebAuthnService:
    """Resolve rp.id/origin/name + load policy from the DB.

    Raises :class:`RPIDChangeBlocked` if the deployment URL changed and
    the change has not yet been confirmed by an operator.
    """
    from arborpress.core.site_settings import get_webauthn_settings

    rp_id = resolve_rp_id(base_url)
    origin = resolve_origin(base_url)
    rp_name = await resolve_rp_name(db)

    # Guard – may raise RPIDChangeBlocked.
    await assert_rp_id_locked_match(db, current_rp_id=rp_id)

    settings = await get_webauthn_settings(db)
    return WebAuthnService(
        rp_id=rp_id,
        rp_name=rp_name,
        origin=origin,
        user_verification=settings.get("user_verification", "preferred"),
        resident_key=settings.get("resident_key", "preferred"),
        attestation=settings.get("attestation", "none"),
        authenticator_attachment=settings.get("authenticator_attachment", ""),
        algorithms=settings.get("algorithms", [-7, -257]),
        timeout_ms=int(settings.get("timeout_ms", 60_000)),
    )

