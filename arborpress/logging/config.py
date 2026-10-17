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
    # File paths supplied directly by callers receive the same semantics as
    # paths loaded through get_settings(): relative paths are instance-local.
    file_path = _resolve_log_path(cfg.file) if cfg.file is not None else None
    audit_file_path = (
        _resolve_log_path(cfg.audit_file) if cfg.audit_file is not None else None
    )
    if cfg.file is not None or cfg.audit_file is not None:
        from arborpress.runtime.paths import ensure_instance_layout, get_runtime_paths

        ensure_instance_layout(get_runtime_paths())

    root = logging.getLogger("arborpress")
    root.setLevel(cfg.level)

    # --- App log → stdout -------------------------------------------------
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter(_FMT_STD))
    root.addHandler(stdout_handler)

    # --- Optional app file log --------------------------------------------
    if file_path is not None:
        _add_file_handler(root, file_path, _FMT_STD)

    # --- Audit log --------------------------------------------------------
    audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
    audit_logger.propagate = False  # Do not mix into root log

    if cfg.audit_log:
        audit_stderr = logging.StreamHandler(sys.stderr)
        audit_stderr.setFormatter(logging.Formatter(_FMT_AUDIT))
        audit_logger.addHandler(audit_stderr)

        if audit_file_path is not None:
            _add_file_handler(audit_logger, audit_file_path, _FMT_AUDIT)

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
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handler = logging.handlers.WatchedFileHandler(path)
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)


def _resolve_log_path(path: Path) -> Path:
    """Resolve relative log paths under the active instance log directory."""
    candidate = path.expanduser()
    if candidate.is_absolute():
        return candidate

    from arborpress.runtime.paths import get_runtime_paths

    root = get_runtime_paths().log.resolve(strict=False)
    resolved = (root / candidate).resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise ValueError(f"Relative log paths must remain inside {root}")
    return resolved


def get_audit_logger() -> logging.Logger:
    return logging.getLogger(AUDIT_LOGGER_NAME)


def reset_logging_for_tests() -> None:
    """Remove ArborPress handlers between tests using different prefixes."""
    for name in ("arborpress", "arborpress.access", AUDIT_LOGGER_NAME):
        logger = logging.getLogger(name)
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()
        logger.propagate = True
