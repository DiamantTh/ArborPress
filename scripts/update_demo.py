#!/usr/bin/env python3
"""
ArborPress – Demo-Aktualisierungs-Skript
=========================================
Liest alle Theme-CSS-Dateien aus arborpress/themes/ und aktualisiert
die THEMES- und DARK_PAIRS-Konstanten in docs/demo.html automatisch.

Aufruf:
    python scripts/update_demo.py
    # oder via Makefile:
    make demo

Das Skript ändert NUR die JS-Datenstrukturen in demo.html.
Die eingebettete Basis-CSS und das Layout bleiben unberührt.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
THEMES_DIR = ROOT / "arborpress" / "themes"
DEMO_FILE  = ROOT / "docs" / "demo.html"

# CSS-Variablen die ins THEMES-Objekt aufgenommen werden
WANTED_VARS = [
    "--color-bg", "--color-bg-alt", "--color-surface", "--color-border",
    "--color-text", "--color-text-muted",
    "--color-accent", "--color-accent-hover",
    "--color-danger", "--color-success",
    "--radius", "--radius-sm",
    "--shadow", "--shadow-md",
    "--font-sans",
]


def parse_toml_value(line: str) -> str:
    """Sehr einfacher TOML-Inline-Wert-Parser (nur Strings und Booleans)."""
    line = line.strip()
    if "=" not in line:
        return ""
    val = line.split("=", 1)[1].strip()
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    if val.startswith("'") and val.endswith("'"):
        return val[1:-1]
    return val


def read_toml(path: Path) -> dict[str, str]:
    """Liest theme.toml (nur flache [theme]-Sektion)."""
    result: dict[str, str] = {}
    in_theme = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line == "[theme]":
            in_theme = True
            continue
        if line.startswith("[") and line != "[theme]":
            in_theme = False
            continue
        if in_theme and "=" in line:
            key = line.split("=", 1)[0].strip()
            result[key] = parse_toml_value(line)
    return result


def find_css_file(theme_dir: Path) -> Path | None:
    """Findet die primäre Theme-CSS-Datei (Full oder Saison-Stil)."""
    full = theme_dir / "static" / "css" / "style.css"
    if full.exists():
        return full
    simple = theme_dir / "static" / "style.css"
    if simple.exists():
        return simple
    return None


def extract_root_vars(css: str) -> dict[str, str]:
    """Extrahiert CSS-Variablen aus dem :root { ... } Block."""
    m = re.search(r':root\s*\{([^}]+)\}', css, re.DOTALL)
    if not m:
        return {}
    block = m.group(1)
    result: dict[str, str] = {}
    for match in re.finditer(r'(--[\w-]+)\s*:\s*([^;]+);', block):
        key   = match.group(1).strip()
        value = " ".join(match.group(2).split())   # normalise whitespace
        result[key] = value
    return result


def vars_to_js_object(theme_id: str, vars_: dict[str, str], indent: str = "    ") -> str:
    """Wandelt CSS-Variablen-Dict in einen JS-Object-Literal-String um."""
    lines: list[str] = []
    for k in WANTED_VARS:
        v = vars_.get(k)
        if v:
            lines.append(f"{indent}'{k}': '{v}',")
    # WICHTIG: normaler String-Ausdruck – kein f-String, also kein {{ }}
    return f"'{theme_id}': {{\n" + "\n".join(lines) + "\n    }"


def build_dark_pairs(themes: dict[str, dict]) -> str:
    """Baut das DARK_PAIRS JS-Objekt."""
    pairs: list[str] = []
    for tid, meta in sorted(themes.items()):
        companion = meta.get("dark_companion")
        if companion and companion in themes:
            pairs.append(f"    '{tid}': '{companion}',")
    return "const DARK_PAIRS = {\n" + "\n".join(pairs) + "\n  };"


def build_themes_obj(themes: dict[str, dict], css_vars: dict[str, dict[str, str]]) -> str:
    """Baut das THEMES JS-Objekt."""
    # Sortierung: zuerst Hell-Themes, dann Dark-Themes
    light = [t for t in themes if not themes[t].get("light_companion")]
    dark  = [t for t in themes if themes[t].get("light_companion")]
    ordered = sorted(light) + sorted(dark)

    entries: list[str] = []
    for tid in ordered:
        if tid not in css_vars:
            print(f"  ⚠  Keine CSS-Variablen für '{tid}' – übersprungen", file=sys.stderr)
            continue
        entries.append("    " + vars_to_js_object(tid, css_vars[tid], indent="      "))

    return "const THEMES = {\n" + ",\n".join(entries) + "\n  };"


def update_demo_html(demo_path: Path, dark_pairs_js: str, themes_js: str) -> None:
    """Ersetzt DARK_PAIRS und THEMES in demo.html."""
    content = demo_path.read_text(encoding="utf-8")

    # DARK_PAIRS ersetzen - alles zwischen 'const DARK_PAIRS = {' und '};'
    content, n1 = re.subn(
        r'const DARK_PAIRS = \{[^}]*\};',
        dark_pairs_js,
        content,
        count=1,
        flags=re.DOTALL,
    )
    if n1 == 0:
        print("  ⚠  DARK_PAIRS-Block nicht in demo.html gefunden – nicht ersetzt", file=sys.stderr)

    # THEMES ersetzen - alles zwischen 'const THEMES = {' und gematchter schließender };
    # Da THEMES verschachtelt ist, suchen wir bis zum ersten '};' nach dem Block-Start
    content, n2 = re.subn(
        r'const THEMES = \{.*?\n  \};',
        themes_js,
        content,
        count=1,
        flags=re.DOTALL,
    )
    if n2 == 0:
        print("  ⚠  THEMES-Block nicht in demo.html gefunden – nicht ersetzt", file=sys.stderr)

    demo_path.write_text(content, encoding="utf-8")
    print(f"  ✅  {demo_path.name} aktualisiert (DARK_PAIRS: {n1}, THEMES: {n2})")


def main() -> None:
    print("ArborPress Demo-Updater")
    print("=" * 40)

    if not DEMO_FILE.exists():
        print(f"❌  demo.html nicht gefunden: {DEMO_FILE}", file=sys.stderr)
        sys.exit(1)

    themes: dict[str, dict] = {}         # theme_id → toml-Metadaten
    css_vars: dict[str, dict[str, str]]  = {}  # theme_id → CSS-Variablen

    for theme_dir in sorted(THEMES_DIR.iterdir()):
        if not theme_dir.is_dir():
            continue
        toml_file = theme_dir / "theme.toml"
        if not toml_file.exists():
            continue

        meta = read_toml(toml_file)
        tid  = meta.get("id") or theme_dir.name
        themes[tid] = meta

        css_file = find_css_file(theme_dir)
        if css_file is None:
            print(f"  ⚠  Kein CSS für '{tid}'", file=sys.stderr)
            continue

        css_text = css_file.read_text(encoding="utf-8")
        vars_    = extract_root_vars(css_text)

        # Falls Saison-Theme (nur :root-Override), Basis-Vars aus Default-Theme mergen
        if not vars_.get("--color-bg"):
            print(f"  ℹ  '{tid}' hat kein eigenes bg – übersprungen (Basis-Theme nötig)", file=sys.stderr)
            continue

        css_vars[tid] = vars_
        companion = meta.get("dark_companion") or meta.get("light_companion") or ""
        print(f"  ✓  {tid:<28} CSS-Variablen eingelesen  {('→ '+companion) if companion else ''}")

    dark_pairs_js = build_dark_pairs(themes)
    themes_js     = build_themes_obj(themes, css_vars)

    print()
    update_demo_html(DEMO_FILE, dark_pairs_js, themes_js)
    print()
    print(f"Fertig! {len(css_vars)} Themes verarbeitet.")
    print("→ Öffne docs/demo.html im Browser. F5 lädt ohne Flackern dank Anti-FOUC-Preload.")


if __name__ == "__main__":
    main()
