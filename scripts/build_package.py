"""Build Python artifacts with immutable Git commit build metadata."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "arborpress" / "_build_info.py"


def main() -> int:
    git_executable = shutil.which("git")
    poetry_executable = shutil.which("poetry")
    if git_executable is None or poetry_executable is None:
        print("Both git and poetry must be available to build artifacts.", file=sys.stderr)
        return 2
    try:
        commit = subprocess.run(  # noqa: S603 - executable resolved from the trusted PATH
            [git_executable, "rev-parse", "--verify", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = "unknown"
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        commit = "unknown"
    original = TARGET.read_bytes() if TARGET.exists() else None
    try:
        TARGET.write_text(
            f'"""Generated immutable build identity."""\n\nBUILD_SHA = "{commit}"\n',
            encoding="utf-8",
        )
        return subprocess.call(  # noqa: S603
            [poetry_executable, "build", *sys.argv[1:]], cwd=ROOT
        )
    finally:
        if original is None:
            TARGET.unlink(missing_ok=True)
        else:
            TARGET.write_bytes(original)


if __name__ == "__main__":
    raise SystemExit(main())
