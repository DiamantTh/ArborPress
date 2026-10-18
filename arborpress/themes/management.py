"""Local, server-authoritative theme administration primitives.

Theme source files are never edited in-place by the web UI. Writes are routed
to a deterministic child theme under the active prefix and checked against the
parent's declared resources. SiteSetting remains the source of active theme,
option and local trust choices; file revisions live under instance/data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from jinja2 import Environment, TemplateSyntaxError

from arborpress.runtime.paths import get_runtime_paths
from arborpress.themes.manifest import (
    ThemeManifest,
    ThemeOptionDefinition,
    ThemeRegistry,
    _resolve_inside,
    _validate_theme_relative_path,
)

MAX_TEMPLATE_BYTES = 256 * 1024
MAX_CSS_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 32 * 1024
MAX_REVISION_BYTES = 2 * MAX_CSS_BYTES + 4096
_TEMPLATE_NAMES = {
    "public": frozenset(
        {
            "index.html",
            "post.html",
            "page.html",
            "tag.html",
            "search.html",
            "comment_confirmed.html",
        }
    ),
    "admin": frozenset(
        {
            "admin/dashboard.html",
            "admin/posts.html",
            "admin/post_edit.html",
            "admin/pages.html",
            "admin/media.html",
            "admin/comments.html",
            "admin/plugins.html",
            "admin/settings.html",
            "admin/captcha.html",
        }
    ),
}
_OPTION_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class ThemeManagementError(ValueError):
    """A safe, user-displayable theme management error."""


class ThemeConflictError(ThemeManagementError):
    """The underlying theme file changed since the editor was loaded."""


def content_hash(content: str | None) -> str:
    return hashlib.sha256((content or "").encode("utf-8")).hexdigest()


def option_values_hash(values: Mapping[str, Any] | None) -> str:
    serialized = json.dumps(values or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return content_hash(serialized)


def theme_preview_fingerprint(registry: ThemeRegistry, theme_id: str) -> str:
    """Bind a preview to the current manifest/template/style revisions in its chain."""
    chain = registry.chain(theme_id)
    if not chain:
        raise ThemeManagementError("Theme parent chain is unavailable for preview.")
    digest = hashlib.sha256()
    for theme in chain:
        resources = [(theme.theme_dir / "theme.toml", True, MAX_MANIFEST_BYTES)]
        resources.extend(
            (theme.template_dir / name, True, MAX_TEMPLATE_BYTES) for name in theme.templates
        )
        resources.extend(
            (theme.theme_dir / name, False, MAX_CSS_BYTES) for name in theme.assets.css
        )
        for resource, hash_content, size_limit in resources:
            try:
                resolved = resource.resolve(strict=True)
                resolved.relative_to(theme.theme_dir.resolve(strict=True))
                if not resolved.is_file():
                    raise OSError("not a regular file")
                stat = resolved.stat()
                if stat.st_size > size_limit:
                    raise OSError("resource exceeds its size limit")
                digest.update(theme.id.encode("utf-8"))
                digest.update(resolved.relative_to(theme.theme_dir.resolve()).as_posix().encode())
                if hash_content:
                    with resolved.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(64 * 1024), b""):
                            digest.update(chunk)
                else:
                    digest.update(f"{stat.st_ino}:{stat.st_mtime_ns}:{stat.st_size}".encode())
            except (OSError, ValueError) as exc:
                raise ThemeManagementError(
                    "Theme changed or escaped its root during preview."
                ) from exc
    return digest.hexdigest()


def _normalised_relative(value: str, kind: Literal["template", "css"]) -> str:
    try:
        _validate_theme_relative_path(value)
    except ValueError as exc:
        raise ThemeManagementError("The requested theme path is not a safe relative path.") from exc
    if kind == "template":
        if value not in _TEMPLATE_NAMES["public"] | _TEMPLATE_NAMES["admin"]:
            raise ThemeManagementError("This template is not editable through the theme UI.")
        return value
    if not value.startswith("static/") or not value.endswith(".css"):
        raise ThemeManagementError("Only declared local CSS files can be edited.")
    return value


def _read_text(path: Path, limit: int) -> str:
    if path.is_symlink() or not path.is_file():
        raise ThemeManagementError("Theme resource is not a regular file.")
    if path.stat().st_size > limit:
        raise ThemeManagementError("Theme resource exceeds the editor size limit.")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ThemeManagementError("Theme text files must use valid UTF-8.") from exc


def _resolve_declared_file(
    registry: ThemeRegistry,
    theme_id: str,
    relative: str,
    kind: Literal["template", "css"],
) -> tuple[ThemeManifest, Path] | None:
    theme = registry.get(theme_id)
    if theme is None:
        raise ThemeManagementError("Theme is unavailable or invalid.")
    theme = local_derived_theme(registry, theme_id) or theme
    relative = _normalised_relative(relative, kind)
    chain = registry.chain(theme.id)
    for candidate in chain:
        declared = (
            relative in candidate.templates
            if kind == "template"
            else relative in candidate.assets.css
        )
        if declared:
            try:
                root = candidate.template_dir if kind == "template" else candidate.theme_dir
                path = _resolve_inside(root, relative)
                return candidate, path
            except (OSError, ValueError):
                raise ThemeManagementError("Theme resource escapes its declared root.") from None
    if kind == "template":
        core_root = Path(__file__).resolve().parents[1] / "templates"
        if relative in _TEMPLATE_NAMES[theme.type]:
            try:
                return theme, _resolve_inside(core_root, relative)
            except (OSError, ValueError):
                pass
    return None


def load_editable_file(
    registry: ThemeRegistry,
    theme_id: str,
    relative: str,
    kind: Literal["template", "css"],
) -> tuple[str, str]:
    resolved = _resolve_declared_file(registry, theme_id, relative, kind)
    if resolved is None:
        raise ThemeManagementError("The requested resource does not exist in the theme chain.")
    _owner, path = resolved
    limit = MAX_TEMPLATE_BYTES if kind == "template" else MAX_CSS_BYTES
    content = _read_text(path, limit)
    return content, content_hash(content)


def editable_templates(theme: ThemeManifest) -> list[str]:
    return sorted(_TEMPLATE_NAMES[theme.type])


def editable_styles(registry: ThemeRegistry, theme_id: str) -> list[str]:
    styles: set[str] = set()
    for candidate in registry.chain(theme_id):
        styles.update(candidate.assets.css)
    return sorted(styles)


def merged_option_definitions(
    registry: ThemeRegistry, theme_id: str
) -> dict[str, ThemeOptionDefinition]:
    chain = registry.chain(theme_id)
    if not chain:
        raise ThemeManagementError("Theme parent chain is unavailable.")
    result: dict[str, ThemeOptionDefinition] = {}
    for theme in reversed(chain):
        for key, definition in theme.options.items():
            previous = result.get(key)
            if previous and previous.type != definition.type:
                raise ThemeManagementError(f"Theme option {key!r} changes type in the child theme.")
            if previous and previous.type == "select" and previous.choices != definition.choices:
                raise ThemeManagementError(
                    f"Theme option {key!r} changes choices in the child theme."
                )
            result[key] = definition
    return result


def resolve_option_values(
    registry: ThemeRegistry,
    theme_id: str,
    stored: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    definitions = merged_option_definitions(registry, theme_id)
    stored = stored or {}
    chain = registry.chain(theme_id)
    values: dict[str, Any] = {}
    for theme in reversed(chain):
        for key, definition in theme.options.items():
            if definition.default is not None:
                values[key] = definition.default
            theme_values = stored.get(theme.id, {})
            if isinstance(theme_values, Mapping) and key in theme_values:
                try:
                    values[key] = definition.validate_value(theme_values[key])
                except ValueError:
                    # A stale value from a previous manifest falls back to the
                    # newly validated schema default rather than breaking SSR.
                    values.pop(key, None)
                    if definition.default is not None:
                        values[key] = definition.default
    target_values = stored.get(theme_id, {})
    if isinstance(target_values, Mapping):
        for key, value in target_values.items():
            target_definition = definitions.get(key)
            if target_definition is not None:
                try:
                    values[key] = target_definition.validate_value(value)
                except ValueError:
                    pass
    return values


def validate_option_values(
    registry: ThemeRegistry, theme_id: str, submitted: Mapping[str, Any]
) -> dict[str, Any]:
    definitions = merged_option_definitions(registry, theme_id)
    unknown = set(submitted) - set(definitions)
    if unknown:
        raise ThemeManagementError("Unknown theme option submitted.")
    values: dict[str, Any] = {}
    for key, definition in definitions.items():
        if key not in submitted:
            if definition.type == "boolean":
                values[key] = False
            elif definition.required:
                raise ThemeManagementError(f"Required theme option {key!r} is missing.")
            continue
        raw = submitted[key]
        try:
            if definition.type == "integer":
                value: Any = int(raw)
            elif definition.type == "number":
                value = float(raw)
            elif definition.type == "boolean":
                if raw is True or raw in ("1", "true"):
                    value = True
                elif raw is False or raw in ("0", "false"):
                    value = False
                else:
                    raise ValueError("boolean option must be true or false")
            else:
                value = raw
            values[key] = definition.validate_value(value)
        except (ValueError, TypeError) as exc:
            raise ThemeManagementError(f"Invalid value for theme option {key!r}.") from exc
        if definition.type == "asset" and values[key]:
            allowed_assets = {
                asset
                for candidate in registry.chain(theme_id)
                for asset in candidate.assets.all_paths()
            }
            if values[key] not in allowed_assets:
                raise ThemeManagementError(
                    f"Theme option {key!r} must reference an asset declared in its parent chain."
                )
    return values


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_document(value: Mapping[str, Any]) -> str:
    lines: list[str] = []

    def emit(table: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> None:
        scalars = [
            (key, item) for key, item in table.items() if isinstance(item, (str, int, float, bool))
        ]
        arrays = [(key, item) for key, item in table.items() if isinstance(item, list)]
        nested: list[tuple[str, Mapping[str, Any]]] = [
            (key, item) for key, item in table.items() if isinstance(item, Mapping)
        ]
        if prefix:
            if lines:
                lines.append("")
            lines.append("[" + ".".join(prefix) + "]")
        for key, item in scalars:
            rendered = (
                _quote(item)
                if isinstance(item, str)
                else str(item).lower()
                if isinstance(item, bool)
                else str(item)
            )
            lines.append(f"{key} = {rendered}")
        for key, items in arrays:
            rendered_items = [
                _quote(item)
                if isinstance(item, str)
                else str(item).lower()
                if isinstance(item, bool)
                else str(item)
                for item in items
                if isinstance(item, (str, int, float, bool))
            ]
            lines.append(f"{key} = [{', '.join(rendered_items)}]")
        for table_key, nested_table in nested:
            emit(nested_table, (*prefix, table_key))

    emit(value)
    return "\n".join(lines) + "\n"


def _safe_theme_root(path: Path) -> Path:
    paths = get_runtime_paths()
    root = paths.themes.resolve(strict=False)
    candidate = path.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ThemeManagementError("Managed themes must stay under instance/themes.") from exc
    return candidate


def _atomic_write(root: Path, relative: str, content: str) -> Path:
    _validate_theme_relative_path(relative)
    root = _safe_theme_root(root)
    destination = root.joinpath(*PurePosixPath(relative).parts)
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved_parent = parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ThemeManagementError("Theme file path escapes its local theme root.") from exc
    if destination.is_symlink():
        raise ThemeManagementError("Theme editor refuses symbolic-link targets.")
    temporary = parent / f".ap-theme-{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def _create_revision(
    *,
    theme_id: str,
    kind: str,
    relative: str,
    before: str | None,
    after: str | None,
    actor_id: str,
    actor_name: str,
) -> str:
    from arborpress.themes.manifest import THEME_ID_RE

    if not THEME_ID_RE.fullmatch(theme_id):
        raise ThemeManagementError("Invalid theme ID for revision storage.")
    paths = get_runtime_paths()
    revisions_root = (paths.data / "theme-revisions").resolve(strict=False)
    data_root = paths.data.resolve(strict=False)
    try:
        revisions_root.relative_to(data_root)
    except ValueError as exc:
        raise ThemeManagementError("Theme revision path is outside instance data.") from exc
    revision_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    payload = {
        "id": revision_id,
        "created_at": datetime.now(UTC).isoformat(),
        "actor_id": actor_id[:36],
        "actor_name": actor_name[:32],
        "theme_id": theme_id,
        "kind": kind,
        "path": relative,
        "before": before,
        "after": after,
        "before_sha256": content_hash(before),
        "after_sha256": content_hash(after),
    }
    theme_revisions = revisions_root / theme_id
    theme_revisions.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        resolved_theme_revisions = theme_revisions.resolve(strict=True)
        resolved_theme_revisions.relative_to(revisions_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ThemeManagementError("Theme revision path escapes instance data.") from exc
    target = resolved_theme_revisions / f"{revision_id}.json"
    # Revision payload size is bounded by the largest editable file plus JSON.
    encoded = json.dumps(payload, ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_REVISION_BYTES:
        raise ThemeManagementError("Theme revision exceeds the storage limit.")
    temporary = target.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return revision_id


def record_change_revision(
    *,
    theme_id: str,
    kind: str,
    relative: str,
    before: str | None,
    after: str | None,
    actor_id: str,
    actor_name: str,
) -> str:
    """Record a non-file change such as validated theme option values."""
    return _create_revision(
        theme_id=theme_id,
        kind=kind,
        relative=relative,
        before=before,
        after=after,
        actor_id=actor_id,
        actor_name=actor_name,
    )


def _derived_id(registry: ThemeRegistry, parent_id: str) -> str:
    base = f"{parent_id}-local"
    if len(base) > 63:
        base = f"local-{hashlib.sha256(parent_id.encode()).hexdigest()[:16]}"
    for suffix in range(1, 1000):
        candidate = base if suffix == 1 else f"{base[: 62 - len(str(suffix))]}-{suffix}"
        record = registry.record(candidate)
        if record is None:
            return candidate
        if (
            record.status == "valid"
            and record.manifest is not None
            and record.manifest.derived
            and record.manifest.parent == parent_id
        ):
            return candidate
    raise ThemeManagementError("No collision-free derived theme ID is available.")


def local_derived_theme(registry: ThemeRegistry, theme_id: str) -> ThemeManifest | None:
    """Return the deterministic local child, if one already exists."""
    selected = registry.get(theme_id)
    if selected is None:
        return None
    if selected.derived and selected.source == "instance":
        return selected
    candidate = registry.get(_derived_id(registry, selected.id))
    if (
        candidate is not None
        and candidate.source == "instance"
        and candidate.derived
        and candidate.parent == selected.id
    ):
        return candidate
    return None


def _derived_manifest(parent: ThemeManifest, theme_id: str) -> dict[str, Any]:
    return {
        "name": f"{parent.name} (Local)",
        "version": parent.version,
        "type": parent.type,
        "author": "Local ArborPress administrator",
        "license": "UNLICENSED",
        "description": f"Local overrides derived from {parent.id}.",
        "requires_arborpress": parent.requires_arborpress,
        "tested_with": parent.tested_with,
        "parent": parent.id,
        "derived": True,
        "capabilities": ["templates", "styles", "public_assets"],
        "templates": [],
        "assets": {"css": [], "fonts": [], "images": [], "icons": []},
        "entry_points": {},
        "options": {},
    }


def derived_manifest_source(registry: ThemeRegistry, theme_id: str) -> tuple[str, str]:
    """Return an existing or prospective local child manifest for the editor."""
    theme = registry.get(theme_id)
    if theme is None:
        raise ThemeManagementError("Theme is unavailable or invalid.")
    derived = local_derived_theme(registry, theme_id)
    if derived is not None:
        source = _read_text(derived.theme_dir / "theme.toml", MAX_MANIFEST_BYTES)
        return source, content_hash(source)
    child_id = _derived_id(registry, theme_id)
    source = _toml_document(_derived_manifest(theme, child_id))
    return source, content_hash(source)


def ensure_derived_theme(registry: ThemeRegistry, parent_id: str) -> ThemeManifest:
    parent = registry.get(parent_id)
    if parent is None:
        raise ThemeManagementError("Parent theme is unavailable or invalid.")
    if parent.derived and parent.source == "instance":
        return parent
    theme_id = _derived_id(registry, parent_id)
    existing = registry.get(theme_id)
    if existing is not None:
        return existing
    root = _safe_theme_root(get_runtime_paths().themes / theme_id)
    try:
        root.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError:
        registry.load()
        raced = registry.get(theme_id)
        if raced is not None and raced.derived and raced.parent == parent_id:
            return raced
        raise ThemeManagementError(
            "A conflicting theme appeared while creating the local child."
        ) from None
    manifest = _derived_manifest(parent, theme_id)
    _atomic_write(root, "theme.toml", _toml_document(manifest))
    registry.load()
    result = registry.get(theme_id)
    if result is None:
        raise ThemeManagementError("Derived theme failed manifest validation.")
    return result


def _update_derived_declaration(
    registry: ThemeRegistry,
    derived: ThemeManifest,
    relative: str,
    kind: Literal["template", "css"],
    entry_point: str | None = None,
) -> None:
    manifest_before = _read_text(derived.theme_dir / "theme.toml", MAX_MANIFEST_BYTES)
    data = tomllib.loads(manifest_before)
    if kind == "template":
        templates = list(data.get("templates", []))
        if relative not in templates:
            templates.append(relative)
        data["templates"] = sorted(templates)
    else:
        assets = data.setdefault("assets", {})
        styles = list(assets.get("css", []))
        if relative not in styles:
            styles.append(relative)
        assets["css"] = sorted(styles)
        if entry_point:
            data.setdefault("entry_points", {})[
                "admin_css" if derived.type == "admin" else "public_css"
            ] = relative
    _atomic_write(derived.theme_dir, "theme.toml", _toml_document(data))
    registry.load()
    if registry.get(derived.id) is None:
        raise ThemeManagementError("Derived theme manifest failed validation.")


def save_override(
    registry: ThemeRegistry,
    theme_id: str,
    relative: str,
    kind: Literal["template", "css"],
    content: str,
    expected_hash: str,
    *,
    actor_id: str,
    actor_name: str,
) -> tuple[ThemeManifest, str]:
    relative = _normalised_relative(relative, kind)
    limit = MAX_TEMPLATE_BYTES if kind == "template" else MAX_CSS_BYTES
    if len(content.encode("utf-8")) > limit:
        raise ThemeManagementError("Edited theme resource exceeds the size limit.")
    if kind == "template":
        try:
            Environment(autoescape=True).parse(content)
        except TemplateSyntaxError as exc:
            raise ThemeManagementError(
                f"Template syntax error at line {exc.lineno}: {exc.message}"
            ) from exc
    current, current_hash = load_editable_file(registry, theme_id, relative, kind)
    if current_hash != expected_hash:
        raise ThemeConflictError(
            "Theme resource changed while it was being edited; reload before saving."
        )
    source_theme = registry.get(theme_id)
    if source_theme is None:
        raise ThemeManagementError("Theme is unavailable or invalid.")
    # A local derived theme can be edited directly; all other sources get a
    # newly created child so package and third-party parents remain untouched.
    derived = ensure_derived_theme(registry, theme_id)
    if kind == "template":
        target_relative = f"templates/{relative}"
        entry_point = None
    else:
        target_relative = relative
        parent_chain = registry.chain(theme_id)
        css_names = {
            theme.entry_points.get("public_css" if theme.type == "public" else "admin_css")
            for theme in parent_chain
        }
        entry_point = "public_css" if source_theme.type == "public" else "admin_css"
        if relative not in css_names:
            entry_point = None
    target_path = derived.theme_dir.joinpath(*PurePosixPath(target_relative).parts)
    manifest_before = _read_text(derived.theme_dir / "theme.toml", MAX_MANIFEST_BYTES)
    if target_path.is_symlink():
        raise ThemeManagementError("Theme editor refuses symbolic-link targets.")
    if target_path.exists():
        try:
            target_path = _resolve_inside(derived.theme_dir, target_relative)
        except (OSError, ValueError) as exc:
            raise ThemeManagementError("Theme file path escapes its local theme root.") from exc
        local_before = _read_text(target_path, limit)
    else:
        local_before = None
    try:
        # The declaration is written after content. Roll back both files if
        # validation or revision storage fails before the save is complete.
        _atomic_write(derived.theme_dir, target_relative, content)
        _update_derived_declaration(registry, derived, relative, kind, entry_point)
        registry.load()
        saved = registry.get(derived.id)
        if saved is None or any(
            issue["level"] == "error" for issue in validate_theme(registry, derived.id)
        ):
            raise ThemeManagementError("Saved override did not pass theme validation.")
        revision = _create_revision(
            theme_id=derived.id,
            kind=kind,
            relative=relative,
            before=local_before,
            after=content,
            actor_id=actor_id,
            actor_name=actor_name,
        )
        return saved, revision
    except Exception:
        _atomic_write(derived.theme_dir, "theme.toml", manifest_before)
        if local_before is None:
            if target_path.is_symlink():
                raise ThemeManagementError(
                    "Theme editor refuses symbolic-link targets."
                ) from None
            target_path.unlink(missing_ok=True)
        else:
            _atomic_write(derived.theme_dir, target_relative, local_before)
        registry.load()
        raise


def reset_override(
    registry: ThemeRegistry,
    theme_id: str,
    relative: str,
    kind: Literal["template", "css"],
    expected_hash: str,
    *,
    actor_id: str,
    actor_name: str,
) -> str:
    derived = registry.get(theme_id)
    if derived is None or derived.source != "instance" or not derived.derived:
        raise ThemeManagementError("Only a local Derived Theme override can be reset.")
    relative = _normalised_relative(relative, kind)
    local_relative = f"templates/{relative}" if kind == "template" else relative
    local_path = _resolve_inside(derived.theme_dir, local_relative)
    if local_path.is_symlink():
        raise ThemeManagementError("Theme editor refuses symbolic-link targets.")
    if not local_path.is_file():
        raise ThemeManagementError("This theme has no local override for that resource.")
    before = _read_text(local_path, MAX_TEMPLATE_BYTES if kind == "template" else MAX_CSS_BYTES)
    if content_hash(before) != expected_hash:
        raise ThemeConflictError(
            "Theme resource changed while it was being edited; reload before reset."
        )
    data = tomllib.loads((derived.theme_dir / "theme.toml").read_text(encoding="utf-8"))
    manifest_before = _read_text(derived.theme_dir / "theme.toml", MAX_MANIFEST_BYTES)
    if kind == "template":
        data["templates"] = [item for item in data.get("templates", []) if item != relative]
    else:
        assets = data.setdefault("assets", {})
        assets["css"] = [item for item in assets.get("css", []) if item != relative]
        entry_points = data.setdefault("entry_points", {})
        for key in ("public_css", "admin_css"):
            if entry_points.get(key) == relative:
                entry_points.pop(key)
    try:
        # Remove the declaration first, then unlink. Until revision storage is
        # complete, the previous manifest and file can still be restored.
        _atomic_write(derived.theme_dir, "theme.toml", _toml_document(data))
        registry.load()
        if registry.get(derived.id) is None or any(
            issue["level"] == "error" for issue in validate_theme(registry, derived.id)
        ):
            raise ThemeManagementError("Reset did not pass theme validation.")
        local_path.unlink(missing_ok=True)
        revision = _create_revision(
            theme_id=derived.id,
            kind=f"{kind}-reset",
            relative=relative,
            before=before,
            after=None,
            actor_id=actor_id,
            actor_name=actor_name,
        )
        registry.load()
        return revision
    except Exception:
        _atomic_write(derived.theme_dir, "theme.toml", manifest_before)
        if not local_path.exists():
            _atomic_write(derived.theme_dir, local_relative, before)
        registry.load()
        raise


def validate_theme(registry: ThemeRegistry, theme_id: str) -> list[dict[str, str]]:
    record = registry.record(theme_id)
    if record is None:
        return [{"level": "error", "file": "theme.toml", "message": "Theme not found."}]
    issues = [
        {"level": "error", "file": "theme.toml", "message": message}
        for message in record.diagnostics
    ]
    theme = record.manifest
    if theme is None:
        return issues or [
            {"level": "error", "file": "theme.toml", "message": "Manifest is invalid."}
        ]
    for candidate in registry.chain(theme_id):
        for item in candidate.templates:
            try:
                source = _read_text(
                    _resolve_inside(candidate.template_dir, item), MAX_TEMPLATE_BYTES
                )
                Environment(autoescape=True).parse(source)
            except TemplateSyntaxError as exc:
                issues.append(
                    {
                        "level": "error",
                        "file": f"{candidate.id}/{item}",
                        "message": f"Template syntax error at line {exc.lineno}.",
                    }
                )
            except (OSError, ValueError, ThemeManagementError) as exc:
                issues.append(
                    {"level": "error", "file": f"{candidate.id}/{item}", "message": str(exc)[:300]}
                )
    try:
        merged_option_definitions(registry, theme_id)
    except ThemeManagementError as exc:
        issues.append({"level": "error", "file": "theme.toml", "message": str(exc)[:300]})
    return issues or [
        {
            "level": "info",
            "file": "theme.toml",
            "message": "Theme manifest, compatibility and declared templates are valid.",
        }
    ]


def list_revisions(theme_id: str) -> list[dict[str, Any]]:
    from arborpress.themes.manifest import THEME_ID_RE

    if not THEME_ID_RE.fullmatch(theme_id):
        raise ThemeManagementError("Invalid theme ID.")
    root = get_runtime_paths().data / "theme-revisions" / theme_id
    try:
        resolved_root = root.resolve(strict=True)
        resolved_root.relative_to(get_runtime_paths().data.resolve(strict=True))
    except OSError, ValueError:
        return []
    revisions: list[dict[str, Any]] = []
    for path in sorted(resolved_root.glob("*.json"), reverse=True):
        if path.is_symlink() or path.stat().st_size > MAX_REVISION_BYTES + 4096:
            continue
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(item, dict) and item.get("theme_id") == theme_id:
                revisions.append(item)
        except OSError, ValueError, UnicodeDecodeError:
            continue
    return revisions


def write_manifest_override(
    registry: ThemeRegistry,
    theme_id: str,
    content: str,
    expected_hash: str,
    *,
    actor_id: str,
    actor_name: str,
) -> tuple[ThemeManifest, str]:
    if len(content.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ThemeManagementError("Theme manifest exceeds the size limit.")
    try:
        parsed = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ThemeManagementError(f"Invalid TOML at line {exc.lineno}.") from exc
    selected = registry.get(theme_id)
    if selected is None:
        raise ThemeManagementError("Theme is unavailable or invalid.")
    expected_parent_id = selected.parent if selected.derived else selected.id
    if expected_parent_id is None:
        raise ThemeManagementError("A local override must retain its parent relationship.")
    expected_type = selected.type
    if parsed.get("parent") != expected_parent_id or parsed.get("type") != expected_type:
        raise ThemeManagementError("A local override cannot change its parent or theme type.")
    if parsed.get("derived") is not True:
        raise ThemeManagementError("A local override manifest must retain derived = true.")
    try:
        validated = ThemeManifest.model_validate(parsed)
    except Exception as exc:
        raise ThemeManagementError(f"Theme manifest validation failed: {str(exc)[:300]}") from exc
    if selected.derived and selected.source == "instance":
        expected_derived_id = selected.id
        existing: ThemeManifest | None = selected
        current = _read_text(selected.theme_dir / "theme.toml", MAX_MANIFEST_BYTES)
    else:
        expected_derived_id = _derived_id(registry, selected.id)
        existing = registry.get(expected_derived_id)
        current = (
            _read_text(existing.theme_dir / "theme.toml", MAX_MANIFEST_BYTES)
            if existing is not None
            else _toml_document(_derived_manifest(selected, expected_derived_id))
        )
    if content_hash(current) != expected_hash:
        raise ThemeConflictError("Theme manifest changed while it was being edited; reload first.")
    if existing is None:
        if validated.templates or validated.assets.all_paths():
            raise ThemeManagementError(
                "Declare only local files that already exist in the Derived Theme."
            )
    else:
        validated._path = existing.theme_dir.resolve(strict=True)
        validated._id = existing.id
        validated._source = "instance"
        try:
            validated._validate_filesystem_references()
        except Exception as exc:
            raise ThemeManagementError(
                f"Theme manifest validation failed: {str(exc)[:300]}"
            ) from exc
    derived = ensure_derived_theme(registry, theme_id)
    if derived.id != expected_derived_id:
        raise ThemeManagementError("Derived theme identity changed while editing.")
    try:
        validated._path = derived.theme_dir.resolve(strict=True)
        validated._id = derived.id
        validated._source = "instance"
        validated._validate_filesystem_references()
    except Exception as exc:
        raise ThemeManagementError(f"Theme manifest validation failed: {str(exc)[:300]}") from exc
    try:
        _atomic_write(derived.theme_dir, "theme.toml", content)
        registry.load()
        saved = registry.get(derived.id)
        validation_errors = validate_theme(registry, derived.id)
        if saved is None or any(issue["level"] == "error" for issue in validation_errors):
            raise ThemeManagementError("Manifest or inherited options failed validation.")
        revision = _create_revision(
            theme_id=derived.id,
            kind="manifest",
            relative="theme.toml",
            before=current,
            after=content,
            actor_id=actor_id,
            actor_name=actor_name,
        )
        return saved, revision
    except Exception:
        # Keep the last known-good manifest if any validation or revision step fails.
        _atomic_write(derived.theme_dir, "theme.toml", current)
        registry.load()
        raise


def parent_children(registry: ThemeRegistry, theme_id: str) -> list[str]:
    return sorted(manifest.id for manifest in registry.all() if manifest.parent == theme_id)
