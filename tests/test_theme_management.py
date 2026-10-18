from __future__ import annotations

from pathlib import Path

import pytest

from arborpress.runtime.paths import ensure_instance_layout, get_runtime_paths
from arborpress.themes.management import (
    ThemeConflictError,
    ThemeManagementError,
    content_hash,
    derived_manifest_source,
    ensure_derived_theme,
    list_revisions,
    load_editable_file,
    merged_option_definitions,
    reset_override,
    resolve_option_values,
    save_override,
    validate_option_values,
    write_manifest_override,
)
from arborpress.themes.manifest import ThemeRegistry, get_theme_registry, reset_theme_registry


def _write_theme(root: Path, theme_id: str, manifest: str) -> Path:
    theme_dir = root / theme_id
    theme_dir.mkdir(parents=True)
    (theme_dir / "theme.toml").write_text(manifest, encoding="utf-8")
    return theme_dir


def test_builtin_edit_creates_minimal_derived_theme_and_reset_restores_parent(
    tmp_path: Path,
) -> None:
    from arborpress.runtime.paths import initialize_runtime

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    reset_theme_registry()
    registry = get_theme_registry()
    parent, expected = load_editable_file(registry, "default", "index.html", "template")
    changed = "<main><h1>Local view</h1></main>"
    derived, revision_id = save_override(
        registry,
        "default",
        "index.html",
        "template",
        changed,
        expected,
        actor_id="actor-1",
        actor_name="operator",
    )

    assert derived.id == "default-local"
    assert derived.parent == "default"
    assert derived.derived is True
    assert derived.templates == ["index.html"]
    assert list((derived.theme_dir / "templates").rglob("*")) == [
        derived.theme_dir / "templates" / "index.html"
    ]
    assert load_editable_file(registry, derived.id, "index.html", "template")[0] == changed
    assert load_editable_file(registry, "default", "index.html", "template")[0] == changed
    assert (
        get_runtime_paths().data / "theme-revisions" / derived.id / f"{revision_id}.json"
    ).is_file()
    revision = next(item for item in list_revisions(derived.id) if item["id"] == revision_id)
    assert revision["before"] is None
    assert revision["after"] == changed
    with pytest.raises(ThemeConflictError):
        save_override(
            registry,
            "default",
            "index.html",
            "template",
            "<main>stale concurrent save</main>",
            expected,
            actor_id="actor-2",
            actor_name="second operator",
        )

    reset_revision = reset_override(
        registry,
        derived.id,
        "index.html",
        "template",
        content_hash(changed),
        actor_id="actor-1",
        actor_name="operator",
    )
    restored, _ = load_editable_file(registry, derived.id, "index.html", "template")
    assert restored == parent
    assert reset_revision
    assert (derived.theme_dir / "templates" / "index.html").exists() is False


def test_override_save_rolls_back_files_when_revision_storage_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.runtime.paths import initialize_runtime
    from arborpress.themes import management

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    reset_theme_registry()
    registry = get_theme_registry()
    _, expected = load_editable_file(registry, "default", "index.html", "template")

    def fail_revision(**_kwargs):
        raise OSError("simulated revision storage failure")

    monkeypatch.setattr(management, "_create_revision", fail_revision)
    with pytest.raises(OSError, match="simulated"):
        save_override(
            registry,
            "default",
            "index.html",
            "template",
            "<main>not committed</main>",
            expected,
            actor_id="actor",
            actor_name="admin",
        )

    child = registry.get("default-local")
    assert child is not None
    assert child.templates == []
    assert not (child.theme_dir / "templates/index.html").exists()
    original, _ = load_editable_file(registry, "default", "index.html", "template")
    assert original != "<main>not committed</main>"


def test_override_save_rejects_stale_hash_and_jinja_syntax(tmp_path: Path) -> None:
    from arborpress.runtime.paths import initialize_runtime

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    reset_theme_registry()
    registry = get_theme_registry()
    with pytest.raises(ThemeConflictError):
        save_override(
            registry,
            "default",
            "index.html",
            "template",
            "<p>stale</p>",
            "not-the-current-hash",
            actor_id="actor",
            actor_name="admin",
        )
    _, current_hash = load_editable_file(registry, "default", "index.html", "template")
    with pytest.raises(ThemeManagementError, match="syntax error"):
        save_override(
            registry,
            "default",
            "index.html",
            "template",
            "{% if broken %}",
            current_hash,
            actor_id="actor",
            actor_name="admin",
        )


def test_invalid_manifest_edit_does_not_create_or_damage_derived_theme(
    tmp_path: Path,
) -> None:
    from arborpress.runtime.paths import initialize_runtime

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    reset_theme_registry()
    registry = get_theme_registry()
    source, expected = derived_manifest_source(registry, "default")
    with pytest.raises(ThemeManagementError, match="Invalid TOML"):
        write_manifest_override(
            registry,
            "default",
            source + "[broken\n",
            expected,
            actor_id="actor",
            actor_name="admin",
        )
    assert registry.record("default-local") is None


def test_derived_file_write_rejects_symlink_escape(tmp_path: Path) -> None:
    from arborpress.runtime.paths import initialize_runtime

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    reset_theme_registry()
    registry = get_theme_registry()
    child = ensure_derived_theme(registry, "default")
    outside = tmp_path / "outside"
    outside.mkdir()
    (child.theme_dir / "templates").symlink_to(outside, target_is_directory=True)
    _, expected_hash = load_editable_file(registry, "default", "index.html", "template")
    with pytest.raises(ThemeManagementError, match="escapes"):
        save_override(
            registry,
            "default",
            "index.html",
            "template",
            "<p>escape</p>",
            expected_hash,
            actor_id="actor",
            actor_name="admin",
        )
    assert list(outside.iterdir()) == []


def test_theme_option_schema_inherits_defaults_and_validates_values(tmp_path: Path) -> None:
    from arborpress.runtime.paths import initialize_runtime

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    themes = get_runtime_paths().themes
    parent = _write_theme(
        themes,
        "options-parent",
        """name = "Options parent"
version = "1.0.0"
type = "public"

[options.accent]
type = "color"
label = "Accent"
default = "#123456"

[options.items_per_page]
type = "integer"
label = "Items per page"
default = 10
minimum = 1
maximum = 40
""",
    )
    _ = parent
    _write_theme(
        themes,
        "options-child",
        """name = "Options child"
version = "1.0.0"
type = "public"
parent = "options-parent"

[options.accent]
type = "color"
label = "Child accent"
default = "#abcdef"
""",
    )
    registry = ThemeRegistry()
    registry.load()
    definitions = merged_option_definitions(registry, "options-child")
    assert definitions["accent"].default == "#abcdef"
    assert definitions["items_per_page"].default == 10
    assert resolve_option_values(registry, "options-child", {}) == {
        "accent": "#abcdef",
        "items_per_page": 10,
    }
    values = validate_option_values(
        registry,
        "options-child",
        {"accent": "#102030", "items_per_page": "12"},
    )
    assert values == {"accent": "#102030", "items_per_page": 12}
    assert resolve_option_values(registry, "options-child", {"options-child": values}) == values
    with pytest.raises(ThemeManagementError, match="Invalid value"):
        validate_option_values(
            registry,
            "options-child",
            {"accent": "url(javascript:alert(1))", "items_per_page": "99"},
        )


def test_theme_option_parent_type_conflicts_are_rejected(tmp_path: Path) -> None:
    from arborpress.runtime.paths import initialize_runtime

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    themes = get_runtime_paths().themes
    _write_theme(
        themes,
        "conflict-parent",
        """name = "Parent"
version = "1.0.0"
type = "public"
[options.value]
type = "string"
label = "Value"
default = "x"
""",
    )
    _write_theme(
        themes,
        "conflict-child",
        """name = "Child"
version = "1.0.0"
type = "public"
parent = "conflict-parent"
[options.value]
type = "integer"
label = "Value"
default = 2
""",
    )
    registry = ThemeRegistry()
    registry.load()
    with pytest.raises(ThemeManagementError, match="changes type"):
        merged_option_definitions(registry, "conflict-child")


def test_theme_options_reject_unknown_assets_nonfinite_numbers_and_invalid_booleans(
    tmp_path: Path,
) -> None:
    from arborpress.runtime.paths import initialize_runtime

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    root = get_runtime_paths().themes
    _write_theme(
        root,
        "typed-options",
        '''name = "Typed options"
version = "1.0.0"
type = "public"
capabilities = ["public_assets"]
[assets]
images = ["static/logo.svg"]
[options.logo]
type = "asset"
label = "Logo"
default = "static/logo.svg"
[options.ratio]
type = "number"
label = "Ratio"
default = 1.0
[options.enabled]
type = "boolean"
label = "Enabled"
default = false
''',
    )
    theme_dir = root / "typed-options"
    (theme_dir / "static").mkdir()
    (theme_dir / "static/logo.svg").write_text("<svg/>", encoding="utf-8")
    registry = ThemeRegistry()
    registry.load()
    with pytest.raises(ThemeManagementError, match="declared in its parent chain"):
        validate_option_values(
            registry,
            "typed-options",
            {"logo": "static/not-declared.png", "ratio": "2", "enabled": "true"},
        )
    with pytest.raises(ThemeManagementError, match="Invalid value"):
        validate_option_values(
            registry,
            "typed-options",
            {"logo": "static/logo.svg", "ratio": "nan", "enabled": "true"},
        )
    with pytest.raises(ThemeManagementError, match="Invalid value"):
        validate_option_values(
            registry,
            "typed-options",
            {"logo": "static/logo.svg", "ratio": "2", "enabled": "maybe"},
        )


def test_instance_theme_trust_requires_local_administrator_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from arborpress.runtime.paths import initialize_runtime
    from arborpress.themes.jinja import template_overrides_trusted

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    root = get_runtime_paths().themes
    theme_dir = _write_theme(
        root,
        "untrusted-template",
        '''name = "Untrusted template"
version = "1.0.0"
type = "public"
capabilities = ["templates"]
templates = ["index.html"]
''',
    )
    (theme_dir / "templates").mkdir()
    (theme_dir / "templates" / "index.html").write_text(
        "<main>Theme override</main>", encoding="utf-8"
    )
    theme = ThemeRegistry().get("untrusted-template")
    assert theme is not None
    monkeypatch.setattr(
        "arborpress.core.site_settings.get_cached",
        lambda _section: {"trusted_themes": []},
    )
    assert template_overrides_trusted(theme) is False
    monkeypatch.setattr(
        "arborpress.core.site_settings.get_cached",
        lambda _section: {"trusted_themes": [theme.id]},
    )
    assert template_overrides_trusted(theme) is True


def test_untrusted_template_override_uses_sandboxed_rendering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, app
) -> None:
    from jinja2 import FileSystemLoader

    from arborpress.models.content import Comment, Post
    from arborpress.runtime.paths import initialize_runtime
    from arborpress.themes.jinja import install_theme_template_loader
    from arborpress.themes.sandbox import ArborPressSandboxedEnvironment

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    instance = get_runtime_paths().themes
    theme_dir = _write_theme(
        instance,
        "untrusted-render",
        '''name = "Untrusted render"
version = "1.0.0"
type = "public"
capabilities = ["templates"]
templates = ["index.html"]
''',
    )
    (theme_dir / "templates").mkdir()
    (theme_dir / "templates/index.html").write_text(
        "{{ value.title }}|{{ value.comments }}|{{ private.author_email }}", encoding="utf-8"
    )
    core = tmp_path / "core"
    core.mkdir()
    (core / "index.html").write_text("core", encoding="utf-8")
    registry = ThemeRegistry()
    registry.load()
    monkeypatch.setattr("arborpress.themes.jinja.template_theme_type", lambda: "public")
    monkeypatch.setattr(
        registry,
        "active",
        lambda _theme_type="public": registry.get("untrusted-render"),
    )
    monkeypatch.setattr("arborpress.core.site_settings.get_cached", lambda _section: None)
    monkeypatch.setattr(
        "arborpress.core.site_settings.get_defaults", lambda _section: {"trusted_themes": []}
    )
    environment = ArborPressSandboxedEnvironment(
        app, loader=FileSystemLoader(core), autoescape=True
    )
    install_theme_template_loader(environment, registry)

    assert environment.get_template("index.html").render(
        value=Post(title="Theme title", slug="theme-title"),
        private=Comment(author_email="private@example.test"),
    ) == "Theme title||"


def test_jinja_sandbox_blocks_private_attribute_traversal(app) -> None:
    from jinja2.exceptions import SecurityError

    environment = app.jinja_env
    from arborpress.themes.sandbox import ArborPressSandboxedEnvironment

    assert isinstance(environment, ArborPressSandboxedEnvironment)
    assert environment.from_string("{{ value.strftime('%Y') }}").render(
        value=__import__("datetime").datetime.now()
    )
    assert environment.from_string("{{ value.__class__ }}").render(value={}) == ""
    assert environment.from_string("{{ value.__dict__ }}").render(value={}) == ""
    with pytest.raises(SecurityError):
        environment.from_string("{{ value.__class__.__mro__ }}").render(value={})
    from arborpress.models.content import Post

    post = Post(title="Safe title", slug="safe-title")
    assert environment.from_string("{{ value.title }}").render(value=post) == "Safe title"
    assert environment.from_string("{{ value.comments }}").render(value=post) == "[]"
    from arborpress.themes.jinja import theme_context_view
    from arborpress.themes.manifest import get_theme_registry

    default_theme = get_theme_registry().get("default")
    assert default_theme is not None
    safe_theme = theme_context_view(default_theme)
    assert environment.from_string("{{ value.theme_dir }}").render(value=safe_theme) == ""


def test_preview_fingerprint_changes_with_local_theme_override(tmp_path: Path) -> None:
    from arborpress.runtime.paths import initialize_runtime
    from arborpress.themes.management import theme_preview_fingerprint

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    registry = get_theme_registry()
    child = ensure_derived_theme(registry, "default")
    before = theme_preview_fingerprint(registry, child.id)
    style = child.theme_dir / "static/style.css"
    style.parent.mkdir(parents=True, exist_ok=True)
    style.write_text("body { color: red; }", encoding="utf-8")
    manifest = (child.theme_dir / "theme.toml").read_text(encoding="utf-8")
    manifest = manifest.replace('css = []', 'css = ["static/style.css"]')
    manifest = manifest.replace(
        'entry_points = {}', 'entry_points = { public_css = "static/style.css" }'
    )
    (child.theme_dir / "theme.toml").write_text(manifest, encoding="utf-8")
    registry.load()
    after = theme_preview_fingerprint(registry, child.id)
    assert before != after


def test_preview_fingerprint_binds_css_content_not_only_file_metadata(tmp_path: Path) -> None:
    import os

    from arborpress.runtime.paths import initialize_runtime
    from arborpress.themes.management import theme_preview_fingerprint

    ensure_instance_layout(initialize_runtime(tmp_path / "prefix", override=True))
    registry = get_theme_registry()
    child = ensure_derived_theme(registry, "default")
    style = child.theme_dir / "static/style.css"
    style.parent.mkdir(parents=True, exist_ok=True)
    style.write_text("body { color: red; }", encoding="utf-8")
    manifest = (child.theme_dir / "theme.toml").read_text(encoding="utf-8")
    manifest = manifest.replace('css = []', 'css = ["static/style.css"]')
    manifest = manifest.replace(
        'entry_points = {}', 'entry_points = { public_css = "static/style.css" }'
    )
    (child.theme_dir / "theme.toml").write_text(manifest, encoding="utf-8")
    registry.load()

    before = theme_preview_fingerprint(registry, child.id)
    original_stat = style.stat()
    style.write_text("body { color: tan; }", encoding="utf-8")
    os.utime(style, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    assert theme_preview_fingerprint(registry, child.id) != before
