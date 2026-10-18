from __future__ import annotations

import json
from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape
from packaging.version import Version

from arborpress.themes.jinja import install_theme_template_loader
from arborpress.themes.manifest import ThemeManifest, ThemeRegistry, get_theme_registry


def _write_theme(
    root: Path,
    theme_id: str,
    *,
    theme_type: str = "public",
    parent: str | None = None,
    templates: tuple[str, ...] = (),
    css: str | None = None,
    requires: str = ">=0.1.0",
    extra: str = "",
) -> Path:
    theme_dir = root / theme_id
    (theme_dir / "templates").mkdir(parents=True, exist_ok=True)
    capabilities = (["templates"] if templates else []) + (["styles"] if css else [])
    lines = [
        f'name = "{theme_id.title()}"',
        'version = "1.2.3"',
        f'type = "{theme_type}"',
        f'requires_arborpress = "{requires}"',
        f'parent = "{parent}"' if parent else "",
        f"capabilities = {json.dumps(capabilities)}",
        f"templates = {json.dumps(list(templates))}",
        extra,
    ]
    if css:
        asset_dir = theme_dir / "static"
        asset_dir.mkdir(parents=True, exist_ok=True)
        (asset_dir / css).parent.mkdir(parents=True, exist_ok=True)
        (asset_dir / css).write_text("body { color: black; }", encoding="utf-8")
        css_entry = "admin_css" if theme_type == "admin" else "public_css"
        lines.extend(
            [
                "[assets]",
                f'css = ["static/{css}"]',
                "[entry_points]",
                f'{css_entry} = "static/{css}"',
            ]
        )
    for template in templates:
        path = theme_dir / "templates" / template
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{theme_id}:{template}", encoding="utf-8")
    theme_dir.mkdir(parents=True, exist_ok=True)
    (theme_dir / "theme.toml").write_text(
        "\n".join(line for line in lines if line) + "\n", encoding="utf-8"
    )
    return theme_dir


def _registry(tmp_path: Path) -> tuple[ThemeRegistry, Path, Path]:
    builtin = tmp_path / "package-themes"
    instance = tmp_path / "instance-themes"
    _write_theme(builtin, "default", css="css/style.css")
    _write_theme(builtin, "arbor-admin", theme_type="admin")
    return (
        ThemeRegistry(
            builtin_dir=builtin,
            extra_dirs=[instance],
            running_version=Version("0.1.0"),
        ),
        builtin,
        instance,
    )


def test_manifest_requires_valid_public_or_admin_type_and_uses_directory_id(
    tmp_path: Path,
) -> None:
    root = tmp_path / "themes"
    theme_dir = _write_theme(root, "valid-theme", css="style.css")
    manifest = ThemeManifest.from_file(theme_dir / "theme.toml")
    assert manifest.id == "valid-theme"
    assert manifest.type == "public"
    assert manifest.entry_points["public_css"] == "static/style.css"
    assert manifest.css_url == "/static/themes/valid-theme/style.css"


def test_theme_directory_id_rejects_underscore_and_non_ascii(tmp_path: Path) -> None:
    for theme_id in ("invalid_id", "schön"):
        theme_dir = tmp_path / theme_id
        theme_dir.mkdir()
        (theme_dir / "theme.toml").write_text(
            'name = "Invalid ID"\nversion = "1.0.0"\ntype = "public"\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="invalid theme directory ID"):
            ThemeManifest.from_file(theme_dir / "theme.toml")


def test_all_packaged_themes_use_the_valid_manifest_contract() -> None:
    registry = get_theme_registry()
    assert len(registry.all("public")) == 18
    assert [theme.id for theme in registry.all("admin")] == ["arbor-admin"]
    assert all(record.status == "valid" for record in registry.records())


def test_admin_theme_css_uses_its_own_entry_point(tmp_path: Path) -> None:
    registry, builtin, _instance = _registry(tmp_path)
    _write_theme(builtin, "arbor-admin", theme_type="admin", css="admin.css")
    registry.load()
    assert registry.asset_url("arbor-admin") == "/static/themes/arbor-admin/admin.css"


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ('version = "1.0.0"\ntype = "public"\n', "name"),
        ('name = "Bad"\nversion = "1.0.0"\ntype = "private"\n', "type"),
        ('name = "Bad"\nversion = "not-a-version"\ntype = "public"\n', "version"),
        (
            'name = "Bad"\nversion = "1.0.0"\ntype = "public"\nrequires_arborpress = "=>oops"\n',
            "requires_arborpress",
        ),
        (
            'name = "Bad"\nversion = "1.0.0"\ntype = "public"\ncapabilities = ["python"]\n',
            "capabilities",
        ),
        (
            'name = "Bad"\nversion = "1.0.0"\ntype = "public"\nparent = "../outside"\n',
            "parent",
        ),
        (
            'name = "Bad"\nversion = "1.0.0"\ntype = "public"\n'
            'capabilities = ["styles"]\n[assets]\ncss = ["static/../bad.css"]\n',
            "path",
        ),
        (
            'name = "Bad"\nversion = "1.0.0"\ntype = "public"\n'
            'capabilities = ["styles"]\n[assets]\n'
            'css = ["https://example.test/theme.css"]\n',
            "path",
        ),
        (
            'name = "Bad"\nversion = "1.0.0"\ntype = "public"\n'
            'capabilities = ["templates"]\ntemplates = ["../admin.html"]\n',
            "path",
        ),
    ],
)
def test_manifest_validation_rejects_invalid_contracts(
    tmp_path: Path, contents: str, message: str
) -> None:
    theme_dir = tmp_path / "invalid"
    theme_dir.mkdir()
    (theme_dir / "theme.toml").write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        ThemeManifest.from_file(theme_dir / "theme.toml")


def test_malformed_toml_is_retained_as_invalid_registry_record(tmp_path: Path) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    broken = instance / "broken"
    broken.mkdir(parents=True)
    (broken / "theme.toml").write_text('name = "broken"\n[', encoding="utf-8")
    registry.load()
    record = next(item for item in registry.records() if item.id == "broken")
    assert record.status == "invalid"
    assert record.manifest is None
    assert registry.get("broken") is None


def test_public_and_admin_fallbacks_are_independent(tmp_path: Path) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    broken = instance / "broken-public"
    broken.mkdir(parents=True)
    (broken / "theme.toml").write_text('name = "Broken"\ntype = "public"\n', encoding="utf-8")
    registry.load()

    assert registry.get_or_default("broken-public", "public").id == "default"
    assert registry.get_or_default("arbor-admin", "public").id == "default"
    assert registry.get_or_default("missing-admin", "admin").id == "arbor-admin"


def test_discovery_is_prefix_scoped_and_builtin_collision_is_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    _write_theme(instance, "operator")
    _write_theme(instance, "default")
    foreign = tmp_path / "foreign" / "themes"
    _write_theme(foreign, "cwd-only")
    monkeypatch.chdir(tmp_path / "foreign")

    registry.load()
    assert registry.get("operator") is not None
    assert registry.get("default").source == "builtin"
    assert registry.get("cwd-only") is None
    duplicate = next(
        record
        for record in registry.records()
        if record.id == "default" and record.source == "instance"
    )
    assert duplicate.status == "duplicate_id"


def test_compatibility_missing_parent_parent_type_and_depth_statuses(
    tmp_path: Path,
) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    _write_theme(instance, "missing", parent="not-installed")
    _write_theme(instance, "admin-parent", theme_type="admin")
    _write_theme(instance, "wrong-child", parent="admin-parent")
    for index in range(9):
        _write_theme(
            instance,
            f"depth-{index}",
            parent=f"depth-{index - 1}" if index else None,
        )
    _write_theme(instance, "incompatible-version", requires=">=9.0")
    registry.load()

    statuses = {record.id: record.status for record in registry.records()}
    assert statuses["missing"] == "missing_parent"
    assert statuses["wrong-child"] == "incompatible"
    assert statuses["incompatible-version"] == "incompatible"
    assert statuses["depth-7"] == "valid"
    assert statuses["depth-8"] == "incompatible"


def test_theme_companion_cannot_cross_public_admin_boundary(tmp_path: Path) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    _write_theme(instance, "public-with-admin-companion")
    manifest = instance / "public-with-admin-companion" / "theme.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + 'dark_companion = "arbor-admin"\n',
        encoding="utf-8",
    )
    registry.load()

    record = registry.record("public-with-admin-companion")
    assert record is not None
    assert record.status == "incompatible"
    assert "expected 'public'" in record.diagnostics[0]


@pytest.mark.parametrize(
    "parents",
    [
        {"cycle-a": "cycle-a"},
        {"cycle-a": "cycle-b", "cycle-b": "cycle-a"},
        {"cycle-a": "cycle-b", "cycle-b": "cycle-c", "cycle-c": "cycle-a"},
    ],
)
def test_parent_cycles_are_detected(tmp_path: Path, parents: dict[str, str]) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    for theme_id, parent in parents.items():
        _write_theme(instance, theme_id, parent=parent)
    registry.load()
    for theme_id in parents:
        record = next(item for item in registry.records() if item.id == theme_id)
        assert record.status == "cyclic_parent"
        assert registry.get(theme_id) is None
        assert " -> " in record.diagnostics[0]


def test_parent_chain_resolution_uses_child_then_parent_and_assets_fallback(
    tmp_path: Path,
) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    _write_theme(
        instance,
        "base-public",
        templates=("post.html",),
        css="base.css",
    )
    _write_theme(
        instance,
        "child-public",
        parent="base-public",
        templates=("post.html",),
    )
    registry.load()

    chain = registry.chain("child-public")
    assert [theme.id for theme in chain] == ["child-public", "base-public"]
    assert registry.resolve_asset("child-public", "base.css")[0].id == "base-public"
    assert registry.asset_url("child-public") == "/static/themes/base-public/base.css"
    with pytest.raises(ValueError, match="normalized relative"):
        registry.resolve_asset("child-public", "../outside")
    assert registry.resolve_asset("child-public", "unknown.css") is None


def test_multi_level_parent_template_falls_back_to_grandparent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, _builtin, instance = _registry(tmp_path)
    _write_theme(instance, "grandparent", templates=("post.html",))
    _write_theme(instance, "parent", parent="grandparent")
    _write_theme(instance, "child", parent="parent")
    registry.load()
    monkeypatch.setattr("arborpress.themes.jinja.template_theme_type", lambda: "public")
    monkeypatch.setattr(registry, "active", lambda _theme_type="public": registry.get("child"))
    core = tmp_path / "core"
    core.mkdir()
    (core / "post.html").write_text("core", encoding="utf-8")
    environment = Environment(loader=FileSystemLoader(core), autoescape=select_autoescape(["html"]))
    install_theme_template_loader(environment, registry)

    assert [theme.id for theme in registry.chain("child")] == [
        "child",
        "parent",
        "grandparent",
    ]
    assert environment.get_template("post.html").render() == "grandparent:post.html"


def test_template_loader_scopes_public_and_admin_overrides_and_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, builtin, instance = _registry(tmp_path)
    _write_theme(builtin, "default", templates=("post.html",), css="css/style.css")
    _write_theme(builtin, "arbor-admin", theme_type="admin", templates=("admin/posts.html",))
    _write_theme(instance, "public-child", parent="default", templates=("post.html",))
    _write_theme(
        instance,
        "admin-child",
        theme_type="admin",
        parent="arbor-admin",
        templates=("admin/posts.html",),
    )
    registry.load()
    selected = {"public": "public-child", "admin": "admin-child"}
    monkeypatch.setattr("arborpress.themes.jinja.template_theme_type", lambda: selected["current"])
    monkeypatch.setattr(
        registry,
        "active",
        lambda theme_type="public": registry.get(selected[theme_type]),
    )
    core = tmp_path / "core"
    (core / "admin").mkdir(parents=True)
    (core / "post.html").write_text("core post", encoding="utf-8")
    (core / "admin/posts.html").write_text("core admin", encoding="utf-8")
    environment = Environment(
        loader=FileSystemLoader(core),
        autoescape=select_autoescape(["html"]),
    )
    install_theme_template_loader(environment, registry)

    selected["current"] = "public"
    assert environment.get_template("post.html").render() == "public-child:post.html"
    assert environment.get_template("admin/posts.html").render() == "core admin"
    selected["current"] = "admin"
    assert environment.get_template("admin/posts.html").render() == "admin-child:admin/posts.html"
    assert environment.get_template("post.html").render() == "core post"
    with pytest.raises(TemplateNotFound):
        environment.get_template("auth/login.html")


def test_admin_theme_cannot_override_public_template_and_public_cannot_override_admin(
    tmp_path: Path,
) -> None:
    root = tmp_path / "invalid"
    admin = _write_theme(
        root,
        "admin-override",
        theme_type="admin",
        templates=("post.html",),
    )
    with pytest.raises(ValueError, match="not allowed"):
        ThemeManifest.from_file(admin / "theme.toml")

    public = _write_theme(
        root,
        "public-override",
        templates=("admin/posts.html",),
    )
    with pytest.raises(ValueError, match="not allowed"):
        ThemeManifest.from_file(public / "theme.toml")


def test_declared_asset_symlink_cannot_escape_theme_root(tmp_path: Path) -> None:
    theme_dir = _write_theme(tmp_path / "themes", "symlink", css="style.css")
    outside = tmp_path / "outside.css"
    outside.write_text("body{}", encoding="utf-8")
    (theme_dir / "static" / "escape.css").symlink_to(outside)
    manifest = theme_dir / "theme.toml"
    manifest.write_text(
        'name = "Symlink"\nversion = "1.0.0"\ntype = "public"\n'
        'capabilities = ["styles"]\n[assets]\ncss = ["static/escape.css"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="escapes its root"):
        ThemeManifest.from_file(manifest)
