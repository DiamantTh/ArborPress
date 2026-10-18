"""Jinja loader for explicitly declared, type-scoped theme overrides."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from jinja2 import BaseLoader, TemplateNotFound
from jinja2.environment import Environment

from arborpress.themes.manifest import ThemeManifest, ThemeRegistry, ThemeType


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


class ThemeTemplateLoader(BaseLoader):
    """Theme overrides precede core templates, constrained by manifest allowlists."""

    def __init__(self, registry: ThemeRegistry, core_loader: BaseLoader) -> None:
        self.registry = registry
        self.core_loader = core_loader

    def _selection(self, template: str) -> tuple[str, Path | None]:
        theme_type = template_theme_type()
        theme = active_theme_for_request(self.registry)
        for candidate in self.registry.chain(theme.id):
            if template not in candidate.templates:
                continue
            path = candidate.template_dir / template
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(candidate.template_dir.resolve(strict=True))
            except (OSError, ValueError):
                continue
            if resolved.is_file():
                return f"{theme_type}:{theme.id}:{candidate.id}:{resolved}", resolved
        return f"{theme_type}:{theme.id}:core", None

    def get_source(
        self, environment: Environment, template: str
    ) -> tuple[str, str | None, Callable[[], bool] | None]:
        selection, path = self._selection(template)
        if path is None:
            try:
                source, filename, core_uptodate = self.core_loader.get_source(
                    environment, template
                )
            except TemplateNotFound:
                raise

            def uptodate_core() -> bool:
                current, current_path = self._selection(template)
                return current == selection and current_path is None and (
                    core_uptodate is None or core_uptodate()
                )

            return source, filename, uptodate_core

        try:
            source = path.read_text(encoding="utf-8")
            loaded_stat = path.stat()
        except OSError as exc:
            raise TemplateNotFound(template) from exc

        def uptodate_theme() -> bool:
            current, current_path = self._selection(template)
            if current != selection or current_path != path:
                return False
            try:
                current_stat = path.stat()
            except OSError:
                return False
            return current_stat.st_mtime_ns == loaded_stat.st_mtime_ns

        return source, str(path), uptodate_theme


def install_theme_template_loader(
    environment: Environment, registry: ThemeRegistry
) -> None:
    core_loader = environment.loader
    if core_loader is None:
        raise RuntimeError("Jinja has no core package template loader")
    environment.loader = ThemeTemplateLoader(registry, core_loader)
    # Jinja caches by template name, not by selected theme. The wrapped
    # uptodate check invalidates the entry when a setting or request type changes.
    environment.auto_reload = True
