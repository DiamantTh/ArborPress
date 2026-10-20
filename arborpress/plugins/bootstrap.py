"""Apply modest POSIX/Linux process defaults before loading the plugin host."""

from __future__ import annotations

import os
import runpy
import sys
from typing import Any


def apply_process_limits() -> dict[str, bool]:
    """Apply portable best-effort limits without failing plugin startup."""
    result = {"umask": False, "core_dumps_disabled": False, "open_files_limited": False}
    os.umask(0o077)
    result["umask"] = True
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result["core_dumps_disabled"] = True
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        ceiling = 1024
        limited = min(soft, ceiling)
        resource.setrlimit(resource.RLIMIT_NOFILE, (limited, min(hard, ceiling)))
        result["open_files_limited"] = True
    except ImportError, OSError, ValueError:
        pass
    return result


def apply_linux_no_new_privs() -> bool:
    """Set Linux PR_SET_NO_NEW_PRIVS, or report unsupported without failing."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes

        libc: Any = ctypes.CDLL(None, use_errno=True)
        return int(libc.prctl(38, 1, 0, 0, 0)) == 0  # PR_SET_NO_NEW_PRIVS
    except AttributeError, OSError:
        return False


def main() -> None:
    limits = apply_process_limits()
    nnp = apply_linux_no_new_privs()
    os.environ["ARBORPRESS_PLUGIN_HARDENING"] = ",".join(
        [key for key, enabled in limits.items() if enabled] + (["no_new_privs"] if nnp else [])
    )
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    sys.argv = ["arborpress.plugins.host", *arguments]
    runpy.run_module("arborpress.plugins.host", run_name="__main__")


if __name__ == "__main__":
    main()
