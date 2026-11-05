"""Fail when repository-wide mypy findings exceed the committed baseline."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_FILE = ROOT / "scripts" / "mypy_baseline.json"


def main() -> int:
    baseline = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    command = [sys.executable, "-m", "mypy", "arborpress/", "--no-error-summary"]
    result = subprocess.run(  # noqa: S603 - fixed local interpreter and arguments
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    sys.stdout.write(output)
    count = len(re.findall(r": error: .+ \[[a-z0-9-]+\]$", output, flags=re.MULTILINE))
    allowed = int(baseline["max_errors"])
    print(
        f"mypy repository baseline: {count} findings; allowed maximum {allowed} "
        f"(captured from {baseline['baseline_commit']})."
    )
    if result.returncode not in {0, 1} or (result.returncode == 1 and count == 0):
        print("mypy failed without a valid diagnostic result.", file=sys.stderr)
        return 2
    if count > allowed:
        print("Repository-wide mypy baseline regressed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
