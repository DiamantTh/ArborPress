"""Export exact locked runtime/optional-runtime pins for advisory lookup only."""
import tomllib
from pathlib import Path

lock = tomllib.loads(Path('poetry.lock').read_text())
pins = {
    f"{p['name']}=={p['version']}"
    for p in lock["package"] if "main" in p.get("groups", [])
}
for pin in sorted(pins):
    print(pin)
