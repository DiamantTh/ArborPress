"""Logging setup per spec §16.

Default: stdout/stderr.
Optional file logging when enabled in configuration.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

from arborpress.core.config import LoggingSettings

# Structured format (machine-readable + human-readable)
_FMT_STD = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_FMT_AUDIT = "%(asctime)s [AUDIT] %(name)s: %(message)s"

# Dedicated logger for security/audit events
AUDIT_LOGGER_NAME = "arborpress.audit"


def setup_logging(cfg: LoggingSettings) -> None:
    """Initialize the logging system.

    Categories (spec §16):
    - arborpress.app    – errors/warnings/info
    - arborpress.access – optional access log
    - arborpress.audit  – credential/policy/admin events
    """
    root = logging.getLogger("arborpress")
    root.setLevel(cfg.level)

    # --- App log → stdout -------------------------------------------------
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter(_FMT_STD))
    root.addHandler(stdout_handler)

    # --- Optional app file log --------------------------------------------
    if cfg.file:
        _add_file_handler(root, cfg.file, _FMT_STD)

    # --- Audit log --------------------------------------------------------
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    audit_logger.propagate = False  # Do not mix into root log

    if cfg.audit_log:
        audit_stderr = logging.StreamHandler(sys.stderr)
        audit_stderr.setFormatter(logging.Formatter(_FMT_AUDIT))
        audit_logger.addHandler(audit_stderr)

        if cfg.audit_file:
            _add_file_handler(audit_logger, cfg.audit_file, _FMT_AUDIT)

    # --- Optional access log ----------------------------------------------
    if cfg.access_log:
        access_logger = logging.getLogger("arborpress.access")
        access_logger.propagate = False
        access_handler = logging.StreamHandler(sys.stdout)
        access_handler.setFormatter(logging.Formatter(_FMT_STD))
        access_logger.addHandler(access_handler)


def _add_file_handler(
    logger: logging.Logger, path: Path, fmt: str
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.WatchedFileHandler(path)
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)


def get_audit_logger() -> logging.Logger:
    return logging.getLogger(AUDIT_LOGGER_NAME)
