"""Deklarierte Plugin-Capabilities (Spec §15)."""

from enum import StrEnum


class Capability(StrEnum):
    """Alle von Core erkannten Capability-Typen.

    Ein Plugin deklariert genau die Capabilities, die es implementiert.
    Core validiert beim Laden, dass die entsprechenden Entry-Points
    vorhanden sind.
    """

    # --- Auth & MFA -------------------------------------------------------
    MFA_PROVIDER = "mfa_provider"
    AUTH_PROVIDER = "auth_provider"

    # --- Daten-Import/-Export ---------------------------------------------
    IMPORTER = "importer"
    EXPORTER = "exporter"

    # --- Föderations-Erweiterungen ----------------------------------------
    FEDERATION_EXTENSION = "federation_extension"

    # --- Optionale Konzepte -----------------------------------------------
    COMMENTS_EXTENSION = "comments_extension"
    MAIL_BACKEND = "mail_backend"
