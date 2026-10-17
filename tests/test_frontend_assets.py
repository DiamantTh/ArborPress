"""Tests for the packaged, read-only Vite asset manifest resolver."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arborpress.web.assets import AssetManifestError, AssetResolver


def _write_manifest(dist: Path, manifest: object) -> None:
    manifest_path = dist / ".vite" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def _write_asset(dist: Path, name: str) -> None:
    asset_path = dist / name
    asset_path.parent.mkdir(parents=True, exist_ok=True)
    asset_path.write_text("/* built asset */", encoding="utf-8")


def test_resolves_named_javascript_and_css_assets(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _write_asset(dist, "assets/admin-a1b2.js")
    _write_asset(dist, "assets/admin-c3d4.css")
    _write_manifest(
        dist,
        {
            "src/entries/admin.ts": {
                "file": "assets/admin-a1b2.js",
                "name": "admin",
                "src": "src/entries/admin.ts",
                "isEntry": True,
                "css": ["assets/admin-c3d4.css"],
            }
        },
    )

    bundle = AssetResolver(dist).resolve("admin")

    assert bundle.javascript == "dist/assets/admin-a1b2.js"
    assert bundle.stylesheets == ("dist/assets/admin-c3d4.css",)


def test_entry_without_css_resolves_with_empty_stylesheets(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _write_asset(dist, "assets/public-a1b2.js")
    _write_manifest(
        dist,
        {
            "src/entries/public.ts": {
                "file": "assets/public-a1b2.js",
                "name": "public",
                "isEntry": True,
            }
        },
    )

    assert AssetResolver(dist).resolve("public").stylesheets == ()


def test_missing_entry_is_reported(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _write_manifest(dist, {})

    with pytest.raises(AssetManifestError, match="not present"):
        AssetResolver(dist).resolve("public")


def test_missing_manifest_has_development_build_guidance(tmp_path: Path) -> None:
    with pytest.raises(AssetManifestError, match="npm ci && npm run build"):
        AssetResolver(tmp_path / "dist").resolve("public")


def test_malformed_manifest_is_rejected(tmp_path: Path) -> None:
    manifest_path = tmp_path / "dist" / ".vite" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("{not json", encoding="utf-8")

    with pytest.raises(AssetManifestError, match="could not be read"):
        AssetResolver(tmp_path / "dist").resolve("public")


@pytest.mark.parametrize("filename", ["../secret.js", "/secret.js", "assets\\secret.js"])
def test_manifest_cannot_escape_asset_directory(tmp_path: Path, filename: str) -> None:
    dist = tmp_path / "dist"
    _write_manifest(
        dist,
        {
            "src/entries/public.ts": {
                "file": filename,
                "name": "public",
                "isEntry": True,
            }
        },
    )

    with pytest.raises(AssetManifestError, match="unsafe|malformed"):
        AssetResolver(dist).resolve("public")


def test_missing_built_file_is_rejected(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    _write_manifest(
        dist,
        {
            "src/entries/public.ts": {
                "file": "assets/missing.js",
                "name": "public",
                "isEntry": True,
            }
        },
    )

    with pytest.raises(AssetManifestError, match="is missing"):
        AssetResolver(dist).resolve("public")


def test_app_factory_exposes_the_lazy_manifest_resolver(app) -> None:
    assert callable(app.jinja_env.globals["vite_asset"])
