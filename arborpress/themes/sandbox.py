"""Jinja environment used by built-in and operator-provided theme templates."""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from datetime import date, datetime
from pathlib import Path
from typing import Any

from jinja2.environment import Template
from jinja2.runtime import BlockReference, Macro
from jinja2.sandbox import SandboxedEnvironment

_restrict_theme_model_access: ContextVar[bool] = ContextVar(
    "arborpress_restrict_theme_model_access", default=False
)


class ArborPressThemeTemplate(Template):
    """Apply stricter model access only while rendering an instance theme file."""

    async def render_async(self, *args: Any, **kwargs: Any) -> str:
        token = _restrict_theme_model_access.set(_is_instance_theme_source(self.filename))
        try:
            return await super().render_async(*args, **kwargs)
        finally:
            _restrict_theme_model_access.reset(token)

    def render(self, *args: Any, **kwargs: Any) -> str:
        token = _restrict_theme_model_access.set(_is_instance_theme_source(self.filename))
        try:
            return super().render(*args, **kwargs)
        finally:
            _restrict_theme_model_access.reset(token)


def _is_instance_theme_source(filename: str | None) -> bool:
    if not filename:
        return False
    from arborpress.runtime.paths import get_runtime_paths

    try:
        Path(filename).resolve().relative_to(get_runtime_paths().themes.resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


class ArborPressSandboxedEnvironment(SandboxedEnvironment):
    """Quart-compatible async sandbox with a narrow callable-attribute policy."""

    def __init__(self, app: Any, **options: Any) -> None:
        options.setdefault("loader", app.create_global_jinja_loader())
        options["enable_async"] = True
        super().__init__(**options)
        self.template_class = ArborPressThemeTemplate

    def is_safe_attribute(self, obj: Any, attr: str, value: Any) -> bool:
        if attr.startswith("_") or any(
            marker in attr.lower()
            for marker in ("password", "secret", "token", "private_key", "signing_key")
        ):
            return False
        if _restrict_theme_model_access.get():
            from sqlalchemy import inspect as sqlalchemy_inspect

            state = sqlalchemy_inspect(obj, raiseerr=False)
            mapper = getattr(state, "mapper", None)
            if mapper is not None:
                if attr in mapper.column_attrs:
                    return not any(
                        marker in attr.lower()
                        for marker in ("email", "password", "secret", "token", "private_key")
                    )
                if attr in mapper.relationships:
                    return attr not in state.unloaded
                return (
                    type(obj).__module__ == "arborpress.models.content"
                    and type(obj).__name__ in {"Post", "Page"}
                    and attr == "rendered_html"
                )
        if callable(value):
            if isinstance(obj, Mapping) and attr in {"get", "items", "keys", "values"}:
                return True
            if isinstance(obj, (date, datetime)) and attr in {"replace", "strftime", "isoformat"}:
                return True
            if isinstance(obj, str) and attr in {
                "capitalize",
                "casefold",
                "center",
                "count",
                "endswith",
                "find",
                "format",
                "format_map",
                "isalnum",
                "isalpha",
                "isdigit",
                "islower",
                "isspace",
                "istitle",
                "isupper",
                "join",
                "ljust",
                "lower",
                "lstrip",
                "partition",
                "replace",
                "rfind",
                "rjust",
                "rpartition",
                "rsplit",
                "rstrip",
                "split",
                "splitlines",
                "startswith",
                "strip",
                "title",
                "upper",
                "zfill",
            }:
                return True
            return False
        return super().is_safe_attribute(obj, attr, value)

    def is_safe_callable(self, obj: Any) -> bool:
        """Allow framework globals and narrow presentation helpers only."""
        if obj in self.globals.values():
            return True
        if isinstance(obj, (BlockReference, Macro)):
            return True
        if getattr(obj, "__arborpress_safe_template_callable__", False):
            return True
        owner = getattr(obj, "__self__", None)
        name = getattr(obj, "__name__", "")
        if isinstance(owner, Mapping) and name in {"get", "items", "keys", "values"}:
            return True
        if isinstance(owner, (date, datetime, str)):
            return self.is_safe_attribute(owner, name, obj)
        return False
