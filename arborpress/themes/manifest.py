"""Theme-Manifest-Schema, Validierung und Loader (§9).

Jedes Theme liegt in ``arborpress/themes/<id>/`` mit einer ``theme.toml``:

    [theme]
    id          = "my-theme"
    name        = "My Theme"
    version     = "1.0.0"
    author      = "..."
    description = "..."

    [theme.features]
    dark_mode_toggle  = false
    code_highlight    = true
    reading_time      = true

    [assets]           # optional, falls Custom-JS/CSS neben style.css
    css   = []
    js    = []

    [overrides]
    templates = []     # nur öffentliche Templates – NIE Login/Security (§9)
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

log = logging.getLogger("arborpress.themes")

# Seiten die NIE durch Themes überschrieben werden dürfen (§9)
_PROTECTED_TEMPLATES: frozenset[str] = frozenset({
    "auth/login.html",
    "auth/register.html",
    "auth/stepup.html",
    "admin/login.html",
    "admin/security.html",
    "admin/mfa.html",
})

# Verzeichnis aller eingebauten Themes
_BUILTIN_THEMES_DIR = Path(__file__).parent


class ThemeFeatures(BaseModel):
    dark_mode_toggle:  bool = False
    code_highlight:    bool = True
    reading_time:      bool = True
    table_of_contents: bool = False


class ThemeAssets(BaseModel):
    css:   list[str] = []
    fonts: list[str] = []
    icons: list[str] = []
    js:    list[str] = []


class ThemeOverrides(BaseModel):
    templates: list[str] = []

    @field_validator("templates")
    @classmethod
    def _no_security_overrides(cls, v: list[str]) -> list[str]:
        forbidden = [t for t in v if t in _PROTECTED_TEMPLATES]
        if forbidden:
            raise ValueError(
                f"Theme darf folgende Templates nicht überschreiben: {forbidden}"
            )
        return v


class ThemeMeta(BaseModel):
    id:               str = "default"
    name:             str
    version:          str = "1.0.0"
    license:          str = "unknown"
    description:      str = ""
    min_core:         str = "0.1.0"
    author:           str = ""
    url:              str = ""
    preview:          str = "preview.png"
    features:         ThemeFeatures = Field(default_factory=ThemeFeatures)
    dark_companion:   str | None = None  # ID des zugehörigen Dark-Themes
    light_companion:  str | None = None  # ID des zugehörigen Light-Themes (für Dark-Themes)


class ThemeManifest(BaseModel):
    theme:     ThemeMeta
    assets:    ThemeAssets    = Field(default_factory=ThemeAssets)
    overrides: ThemeOverrides = Field(default_factory=ThemeOverrides)

    # Pfad-Felder, nicht aus TOML – werden vom Loader gesetzt
    _path: Path | None = None

    @classmethod
    def from_file(cls, path: Path) -> ThemeManifest:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        obj = cls.model_validate(data)
        obj._path = path.parent
        return obj

    # ------------------------------------------------------------------
    # Komfort-Properties
    # ------------------------------------------------------------------

    @property
    def theme_dir(self) -> Path | None:
        return self._path

    @property
    def css_url(self) -> str:
        """Haupt-CSS-URL für dieses Theme.

        Full-Themes (default, minimal, dark, …) legen ihr CSS unter
        ``static/css/style.css`` ab; Saison-Themes direkt unter
        ``static/style.css``.  Wir wählen den Pfad nach tatsächlicher
        Existenz der Datei; fällt sonst auf den flachen Pfad zurück.
        """
        if self._path:
            if (self._path / "static" / "css" / "style.css").exists():
                return f"/static/themes/{self.theme.id}/css/style.css"
        return f"/static/themes/{self.theme.id}/style.css"

    @property
    def static_dir(self) -> Path | None:
        if self._path:
            return self._path / "static"
        return None

    @property
    def template_dir(self) -> Path | None:
        d = self._path / "templates" if self._path else None
        return d if d and d.exists() else None


# ---------------------------------------------------------------------------
# Theme-Registry / Loader
# ---------------------------------------------------------------------------


def _scan_dir(directory: Path) -> dict[str, ThemeManifest]:
    themes: dict[str, ThemeManifest] = {}
    for toml_file in sorted(directory.glob("*/theme.toml")):
        try:
            m = ThemeManifest.from_file(toml_file)
            themes[m.theme.id] = m
        except Exception as exc:
            log.warning("Ungültiges Theme in %s: %s", toml_file, exc)
    return themes


class ThemeRegistry:
    """Lädt und verwaltet alle verfügbaren Themes."""

    def __init__(self) -> None:
        self._themes: dict[str, ThemeManifest] = {}
        self._loaded = False

    def load(self, extra_dirs: list[Path] | None = None) -> None:
        # Externe Themes zuerst einlesen (niedrigere Priorität)
        merged: dict[str, ThemeManifest] = {}
        for d in (extra_dirs or []):
            merged.update(_scan_dir(d))
        # Eingebaute Themes überschreiben externe mit gleicher ID
        # (stellt sicher, dass Built-in-Themes vollständig inkl. CSS bleiben)
        merged.update(_scan_dir(_BUILTIN_THEMES_DIR))
        self._themes = merged
        self._loaded = True
        log.debug("Themes geladen: %s", list(self._themes))

    def all(self) -> list[ThemeManifest]:
        return list(self._themes.values())

    def get(self, theme_id: str) -> ThemeManifest | None:
        if not self._loaded:
            self.load()
        return self._themes.get(theme_id)

    def get_or_default(self, theme_id: str) -> ThemeManifest:
        m = self.get(theme_id)
        if m is None:
            log.warning("Theme '%s' nicht gefunden, nutze 'default'.", theme_id)
            m = self.get("default")
        if m is None:
            raise RuntimeError("Kein Theme verfügbar (weder angefragt noch 'default').")
        return m


_registry: ThemeRegistry | None = None


def get_theme_registry() -> ThemeRegistry:
    global _registry
    if _registry is None:
        _registry = ThemeRegistry()
        # Externe Themes aus content/themes/ einlesen
        extra: list[Path] = []
        external = Path("content/themes")
        if external.is_dir():
            extra.append(external)
        _registry.load(extra_dirs=extra or None)
    return _registry


def get_active_theme() -> ThemeManifest:
    """Gibt das aktive Theme zurück (aus DB-Settings oder Fallback 'default')."""
    from arborpress.core.site_settings import get_cached, get_defaults
    theme_s = get_cached("theme") or get_defaults("theme")
    theme_id = theme_s.get("active", "default") or "default"
    return get_theme_registry().get_or_default(theme_id)
