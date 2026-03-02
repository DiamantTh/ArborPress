"""WebAuthn/FIDO2-Authentifizierung (Spec §17).

Primärer Auth-Pfad. Legacy-Passwort ist separates Break-Glass-Modul
und NIE standardmäßig aktiviert.
"""

from __future__ import annotations

import logging

import webauthn
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
)

log = logging.getLogger("arborpress.auth.webauthn")


class WebAuthnService:
    """Kapselt WebAuthn-Registrierung und -Authentifizierung."""

    def __init__(self, rp_id: str, rp_name: str, origin: str) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin

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
        return webauthn.generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_display_name,
            exclude_credentials=[
                {"id": cred, "type": "public-key"}
                for cred in (existing_credentials or [])
            ],
        )

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
            require_user_verification=True,
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
            user_verification="required",
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
            require_user_verification=True,
        )
