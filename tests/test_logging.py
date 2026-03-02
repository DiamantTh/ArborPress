"""Tests für Logging-Konfiguration."""

from __future__ import annotations

import logging
from pathlib import Path

from arborpress.core.config import LoggingSettings
from arborpress.logging.config import AUDIT_LOGGER_NAME, get_audit_logger, setup_logging


def test_setup_logging_stdout(capfd) -> None:
    cfg = LoggingSettings(level="WARNING", audit_log=False, access_log=False)
    setup_logging(cfg)
    root = logging.getLogger("arborpress")
    root.warning("Test-Warnung")
    out, _ = capfd.readouterr()
    assert "Test-Warnung" in out


def test_audit_logger_is_isolated() -> None:
    audit = get_audit_logger()
    assert audit.name == AUDIT_LOGGER_NAME
    # Audit soll nicht in Root propagiert werden
    assert not audit.propagate


def test_file_logging_creates_file(tmp_path: Path) -> None:
    log_file = tmp_path / "app.log"
    cfg = LoggingSettings(level="DEBUG", file=log_file, audit_log=False)
    setup_logging(cfg)
    logging.getLogger("arborpress").info("Datei-Test")
    assert log_file.exists()
