"""Beispiel-Importer für CSV-Dateien."""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("arborpress.plugins.example_importer")


@dataclass
class ImportedUser:
    username: str
    display_name: str
    email: str


class CsvImporter:
    """Implementiert die ``importer``-Capability.

    Erwartet eine CSV mit den Spalten: username, display_name, email
    """

    def import_from(self, source: str) -> list[ImportedUser]:
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Datei nicht gefunden: {path}")

        users: list[ImportedUser] = []
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                users.append(
                    ImportedUser(
                        username=row["username"].strip(),
                        display_name=row.get("display_name", row["username"]).strip(),
                        email=row["email"].strip(),
                    )
                )

        log.info("CSV-Import: %d Nutzer aus %s gelesen", len(users), path)
        return users
