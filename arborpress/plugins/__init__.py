"""Plugin runtime public package namespace.

Keep this package initializer dependency-light so a clean per-plugin venv can
bootstrap the stdlib-only isolated host. Core discovery is imported lazily.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arborpress.plugins.registry import PluginRegistry


def get_registry() -> PluginRegistry:
    """Return the Core metadata registry without loading it in plugin hosts."""
    from arborpress.plugins.registry import get_registry as _get_registry

    return _get_registry()


__all__ = ["get_registry"]
