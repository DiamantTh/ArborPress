"""Read-only lookup for Vite-built browser bundles shipped with ArborPress."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

_ENTRY_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")


class AssetManifestError(RuntimeError):
    """The packaged frontend manifest is absent, invalid, or unsafe."""


@dataclass(frozen=True, slots=True)
class AssetBundle:
    """Static paths relative to Quart's package static directory."""

    javascript: str
    stylesheets: tuple[str, ...]


class AssetResolver:
    """Resolve a stable logical entry using Vite's production manifest."""

    def __init__(self, dist_dir: Path | None = None) -> None:
        package_static = Path(__file__).resolve().parents[1] / "static"
        self.dist_dir = (dist_dir or package_static / "dist").resolve()
        self.manifest_path = self.dist_dir / ".vite" / "manifest.json"

    def resolve(self, entry: str) -> AssetBundle:
        """Return local package-static paths for a named Vite entry."""
        if not _ENTRY_NAME.fullmatch(entry):
            raise AssetManifestError(f"Invalid frontend entry name: {entry!r}")

        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise AssetManifestError(
                "Vite asset manifest is missing; build frontend assets with "
                "`npm ci && npm run build` in frontend/."
            ) from exc
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AssetManifestError("Vite asset manifest could not be read") from exc

        if not isinstance(manifest, dict):
            raise AssetManifestError("Vite asset manifest must be a JSON object")

        records = [
            record
            for key, record in manifest.items()
            if isinstance(record, dict)
            and record.get("isEntry") is True
            and (record.get("name") == entry or key == f"src/entries/{entry}.ts")
        ]
        if not records:
            raise AssetManifestError(
                f"Frontend entry {entry!r} is not present in the Vite manifest"
            )
        if len(records) != 1:
            raise AssetManifestError(f"Frontend entry {entry!r} is ambiguous in the Vite manifest")

        record = records[0]
        javascript = self._static_path(record.get("file"), entry)
        raw_css = record.get("css", [])
        if not isinstance(raw_css, list) or any(not isinstance(path, str) for path in raw_css):
            raise AssetManifestError(f"CSS list for frontend entry {entry!r} is malformed")
        stylesheets = tuple(self._static_path(path, entry) for path in raw_css)
        return AssetBundle(javascript=javascript, stylesheets=stylesheets)

    def _static_path(self, value: Any, entry: str) -> str:
        if not isinstance(value, str) or not value or "\\" in value:
            raise AssetManifestError(f"Asset path for frontend entry {entry!r} is malformed")
        relative = PurePosixPath(value)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise AssetManifestError(f"Asset path for frontend entry {entry!r} is unsafe")

        dist_root = self.dist_dir.resolve()
        asset_path = (dist_root / Path(*relative.parts)).resolve()
        try:
            asset_path.relative_to(dist_root)
        except ValueError as exc:
            raise AssetManifestError(
                f"Asset path for frontend entry {entry!r} escapes dist/"
            ) from exc
        if not asset_path.is_file():
            raise AssetManifestError(f"Built asset for frontend entry {entry!r} is missing")
        return f"dist/{relative.as_posix()}"
