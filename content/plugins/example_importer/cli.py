"""CLI-Erweiterung des example_importer-Plugins (Spec §15 – CLI design rules)."""

from pathlib import Path

import typer

plugin_app = typer.Typer(help="CSV-Importer Plugin")


@plugin_app.command("run")
def run_import(
    file: Path = typer.Argument(..., help="Pfad zur CSV-Datei"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Nur anzeigen, nicht speichern"),
) -> None:
    """Importiert Nutzer aus einer CSV-Datei."""
    from plugins.example_importer.importer import CsvImporter

    importer = CsvImporter()
    users = importer.import_from(str(file))

    typer.echo(f"Gefunden: {len(users)} Nutzer")
    for u in users:
        typer.echo(f"  {u.username} <{u.email}>")

    if dry_run:
        typer.echo("[dry-run] Nichts gespeichert.")
        return

    # TODO: Nutzer in DB schreiben (Core-Service nutzen)
    typer.echo("Import abgeschlossen (DB-Schreiben noch nicht implementiert).")
