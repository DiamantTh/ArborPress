"""Jinja loader for explicitly declared, type-scoped theme overrides."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from jinja2 import BaseLoader, TemplateNotFound, TemplateSyntaxError
from jinja2.environment import Environment

from arborpress.themes.manifest import ThemeManifest, ThemeMetaView, ThemeRegistry, ThemeType


@dataclass(frozen=True, slots=True)
class ThemeContextView:
    """Presentation metadata only; never exposes a theme filesystem path."""

    theme: ThemeMetaView
    type: ThemeType
    source: str
    parent: str | None

    @property
    def id(self) -> str:
        return self.theme.id

    @property
    def name(self) -> str:
        return self.theme.name

    @property
    def version(self) -> str:
        return self.theme.version


def theme_context_view(theme: ThemeManifest) -> ThemeContextView:
    return ThemeContextView(
        theme=theme.theme,
        type=theme.type,
        source=theme.source,
        parent=theme.parent,
    )


def template_theme_type() -> ThemeType:
    """Resolve Public/Admin from the Quart endpoint, never from the URL/CWD."""
    try:
        from quart import request

        endpoint = request.endpoint or ""
    except RuntimeError:
        endpoint = ""
    return "admin" if endpoint.startswith("admin.") else "public"


def active_theme_for_request(registry: ThemeRegistry) -> ThemeManifest:
    theme_type = template_theme_type()
    try:
        from quart import session

        if theme_type == "admin" and session.get("_theme_admin_safe_fallback"):
            return registry.get_or_default("arbor-admin", "admin")
        preview = session.get("_theme_preview")
    except RuntimeError:
        preview = None
    if isinstance(preview, dict):
        try:
            from time import time

            if (
                session.get("user_role") == "admin"
                and preview.get("type") == theme_type
                and float(preview.get("expires", 0)) > time()
            ):
                selected_preview = registry.get(str(preview.get("theme_id", "")))
                if selected_preview is not None and selected_preview.type == theme_type:
                    from arborpress.themes.management import theme_preview_fingerprint

                    expected = preview.get("fingerprint")
                    try:
                        current = theme_preview_fingerprint(registry, selected_preview.id)
                    except ValueError:
                        current = None
                    if isinstance(expected, str) and current == expected:
                        return selected_preview
        except TypeError, ValueError:
            pass
        session.pop("_theme_preview", None)
    selected = registry.active(theme_type)
    if theme_type == "public":
        try:
            from quart import request

            cookie_id = request.cookies.get("ap-theme")
        except RuntimeError:
            cookie_id = None
        if cookie_id:
            from arborpress.core.site_settings import get_cached, get_defaults

            demo = get_cached("demo") or get_defaults("demo")
            override = registry.get(cookie_id) if demo.get("enabled") else None
            if override is not None and override.type == "public":
                return override
    return selected


def template_overrides_trusted(theme: ThemeManifest) -> bool:
    """Package templates are trusted as code; instance templates need local trust."""
    if theme.source == "builtin":
        return True
    from arborpress.core.site_settings import get_cached, get_defaults

    settings = None
    try:
        from quart import g

        settings = getattr(g, "_theme_runtime_settings", None)
    except RuntimeError:
        pass
    if not isinstance(settings, dict):
        settings = get_cached("theme") or get_defaults("theme")
    trusted_ids = settings.get("trusted_themes", [])
    return isinstance(trusted_ids, list) and theme.id in trusted_ids


class ThemeTemplateLoader(BaseLoader):
    """Theme overrides precede core templates, constrained by manifest allowlists."""

    def __init__(self, registry: ThemeRegistry, core_loader: BaseLoader) -> None:
        self.registry = registry
        self.core_loader = core_loader

    def _selection(
        self, template: str, environment: Environment | None = None
    ) -> tuple[str, Path | None]:
        theme_type = template_theme_type()
        theme = active_theme_for_request(self.registry)
        for candidate in self.registry.chain(theme.id):
            if template not in candidate.templates:
                continue
            path = candidate.template_dir / template
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(candidate.template_dir.resolve(strict=True))
            except OSError, ValueError:
                continue
            if not resolved.is_file() or resolved.stat().st_size > 256 * 1024:
                continue
            try:
                source = resolved.read_text(encoding="utf-8")
                if environment is not None:
                    environment.parse(source)
            except OSError, UnicodeDecodeError, TemplateSyntaxError:
                # A broken child override falls through to the next validated
                # parent/core template instead of breaking the entire site.
                continue
            return f"{theme_type}:{theme.id}:{candidate.id}:{resolved}", resolved
        return f"{theme_type}:{theme.id}:core", None

    def get_source(
        self, environment: Environment, template: str
    ) -> tuple[str, str | None, Callable[[], bool] | None]:
        selection, path = self._selection(template, environment)
        if path is None:
            try:
                source, filename, core_uptodate = self.core_loader.get_source(environment, template)
            except TemplateNotFound:
                raise

            def uptodate_core() -> bool:
                current, current_path = self._selection(template, environment)
                return (
                    current == selection
                    and current_path is None
                    and (core_uptodate is None or core_uptodate())
                )

            return source, filename, uptodate_core

        try:
            source = path.read_text(encoding="utf-8")
            loaded_stat = path.stat()
        except OSError as exc:
            raise TemplateNotFound(template) from exc

        def uptodate_theme() -> bool:
            current, current_path = self._selection(template, environment)
            if current != selection or current_path != path:
                return False
            try:
                current_stat = path.stat()
            except OSError:
                return False
            return current_stat.st_mtime_ns == loaded_stat.st_mtime_ns

        return source, str(path), uptodate_theme


def install_theme_template_loader(environment: Environment, registry: ThemeRegistry) -> None:
    core_loader = environment.loader
    if core_loader is None:
        raise RuntimeError("Jinja has no core package template loader")
    environment.loader = ThemeTemplateLoader(registry, core_loader)
    # Jinja caches by template name, not by selected theme. The wrapped
    # uptodate check invalidates the entry when a setting or request type changes.
    environment.auto_reload = True
