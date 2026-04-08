"""Theme manifest schema, validation and loader (§9).

Each theme lives in ``arborpress/themes/<id>/`` with a ``theme.toml``:

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

    [assets]           # optional, if custom JS/CSS alongside style.css
    css   = []
    js    = []

    [overrides]
    templates = []     # public templates only – NEVER login/security (§9)
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

log = logging.getLogger("arborpress.themes")

# Pages that MUST NEVER be overridden by themes (§9)
_PROTECTED_TEMPLATES: frozenset[str] = frozenset({
    "auth/login.html",
    "auth/register.html",
    "auth/stepup.html",
    "admin/login.html",
    "admin/security.html",
    "admin/mfa.html",
})

# Directory of all built-in themes
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
                f"Theme must not override these templates: {forbidden}"
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
    dark_companion:   str | None = None  # ID of the associated dark theme
    light_companion:  str | None = None  # ID of the associated light theme (for dark themes)


class ThemeManifest(BaseModel):
    theme:     ThemeMeta
    assets:    ThemeAssets    = Field(default_factory=ThemeAssets)
    overrides: ThemeOverrides = Field(default_factory=ThemeOverrides)

    # Path fields, not from TOML – set by the loader
    _path: Path | None = None

    @classmethod
    def from_file(cls, path: Path) -> ThemeManifest:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        obj = cls.model_validate(data)
        obj._path = path.parent
        return obj

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def theme_dir(self) -> Path | None:
        return self._path

    @property
    def css_url(self) -> str:
        """Main CSS URL for this theme.

        Full themes (default, minimal, dark, …) store their CSS under
        ``static/css/style.css``; seasonal themes directly under
        ``static/style.css``.  We select the path based on actual file
        existence; otherwise falls back to the flat path.
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
# Theme registry / loader
# ---------------------------------------------------------------------------


def _scan_dir(directory: Path) -> dict[str, ThemeManifest]:
    themes: dict[str, ThemeManifest] = {}
    for toml_file in sorted(directory.glob("*/theme.toml")):
        try:
            m = ThemeManifest.from_file(toml_file)
            themes[m.theme.id] = m
        except Exception as exc:
            log.warning("Invalid theme in %s: %s", toml_file, exc)
    return themes


class ThemeRegistry:
    """Loads and manages all available themes."""

    def __init__(self) -> None:
        self._themes: dict[str, ThemeManifest] = {}
        self._loaded = False

    def load(self, extra_dirs: list[Path] | None = None) -> None:
        # Load external themes first (lower priority)
        merged: dict[str, ThemeManifest] = {}
        for d in (extra_dirs or []):
            merged.update(_scan_dir(d))
        # Built-in themes override external ones with the same ID
        # (ensures built-in themes remain complete including CSS)
        merged.update(_scan_dir(_BUILTIN_THEMES_DIR))
        self._themes = merged
        self._loaded = True
        log.debug("Themes loaded: %s", list(self._themes))

    def all(self) -> list[ThemeManifest]:
        return list(self._themes.values())

    def get(self, theme_id: str) -> ThemeManifest | None:
        if not self._loaded:
            self.load()
        return self._themes.get(theme_id)

    def get_or_default(self, theme_id: str) -> ThemeManifest:
        m = self.get(theme_id)
        if m is None:
            log.warning("Theme '%s' not found, using 'default'.", theme_id)
            m = self.get("default")
        if m is None:
            raise RuntimeError("No theme available (neither requested nor 'default').")
        return m


_registry: ThemeRegistry | None = None


def get_theme_registry() -> ThemeRegistry:
    global _registry
    if _registry is None:
        _registry = ThemeRegistry()
        # Load external themes from content/themes/
        extra: list[Path] = []
        external = Path("content/themes")
        if external.is_dir():
            extra.append(external)
        _registry.load(extra_dirs=extra or None)
    return _registry


def get_active_theme() -> ThemeManifest:
    """Return the active theme (from DB settings or fallback 'default')."""
    from arborpress.core.site_settings import get_cached, get_defaults
    theme_s = get_cached("theme") or get_defaults("theme")
    theme_id = theme_s.get("active", "default") or "default"
    return get_theme_registry().get_or_default(theme_id)
