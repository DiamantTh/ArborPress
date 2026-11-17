"""Canonical URL construction for public content.

URLs are always rooted in the configured public origin. Request Host and
forwarded headers never participate in canonical identity.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from quart import url_for
from werkzeug.routing import BuildError

_LANGUAGE_ENDPOINTS = {
    "public.index",
    "public.post_detail",
    "public.page_detail",
    "public.tag_archive",
    "public.search",
    "public.author_profile",
    "public.author_post",
}


def public_path(endpoint: str, *, lang: str | None = None, **values: Any) -> str:
    """Build a safe route path, optionally under a supported language prefix."""
    if endpoint not in _LANGUAGE_ENDPOINTS:
        raise ValueError("Only public content routes have canonical language-aware paths")
    from arborpress.core.config import get_settings
    from arborpress.core.i18n import normalize_language

    mode = get_settings().web.i18n_mode
    if mode == "single" and endpoint == "public.index" and lang:
        # Preserve the existing explicit single-language index filter.
        return url_for(endpoint, lang=lang, **values)
    try:
        path = url_for(endpoint, **values)
    except (RuntimeError, BuildError):
        # Serializers are also used in app-independent unit tests and command
        # contexts. Keep the same route mapping without requiring a request.
        if endpoint == "public.index":
            path = "/"
        elif endpoint in {"public.post_detail", "public.page_detail", "public.tag_archive"}:
            key = "slug" if endpoint != "public.tag_archive" else "tag"
            segment = (
                "p"
                if endpoint == "public.post_detail"
                else ("page" if endpoint == "public.page_detail" else "tag")
            )
            path = f"/{segment}/{quote(str(values[key]), safe='-._~')}"
        elif endpoint == "public.search":
            path = "/search"
        elif endpoint == "public.author_profile":
            path = f"/@{quote(str(values['handle']), safe='-._~')}"
        elif endpoint == "public.author_post":
            handle = quote(str(values["handle"]), safe="-._~")
            slug = quote(str(values["slug"]), safe="-._~")
            path = f"/@{handle}/p/{slug}"
        else:
            raise
    if mode != "prefix" or endpoint not in _LANGUAGE_ENDPOINTS:
        return path
    selected = normalize_language(lang)
    if selected is None:
        from quart import request

        selected = normalize_language(request.path.lstrip("/").split("/", 1)[0])
    if selected is None:
        selected = normalize_language(get_settings().web.default_lang)
    return f"/{selected}{path}" if selected else path


def canonical_url(endpoint: str, *, lang: str | None = None, **values: Any) -> str:
    """Return an absolute canonical URL from configured base_url + route path."""
    from arborpress.core.config import get_settings

    origin = get_settings().web.base_url.rstrip("/")
    if get_settings().web.i18n_mode == "single" and endpoint == "public.index":
        # The optional single-mode `?lang=` view is a UI filter, not a distinct
        # indexable representation.
        return origin + url_for(endpoint, **values)
    return origin + public_path(endpoint, lang=lang, **values)


def register_public_url_helper(app: object) -> None:
    """Expose a narrow, theme-safe URL builder to SSR templates."""
    from quart import Quart

    if isinstance(app, Quart):
        setattr(  # noqa: B010 - the theme sandbox reads this explicit marker.
            public_path, "__arborpress_safe_template_callable__", True
        )
        app.jinja_env.globals["public_url"] = public_path
        setattr(  # noqa: B010 - the theme sandbox reads this explicit marker.
            canonical_url, "__arborpress_safe_template_callable__", True
        )
        app.jinja_env.globals["canonical_url"] = canonical_url
