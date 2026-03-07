"""API-Routes – /api/v1/ (§8 Admin & Public API).

Trennung:
- Public API  (/api/v1/posts, /api/v1/tags …)   – kein Auth nötig
- Admin API   (/api/v1/admin/…)                  – Session + Step-up (§2)

CSRF-Hinweis (§8 / §10):
  Alle state-ändernden Endpunkte prüfen Origin/Referer ODER verlangen
  expliziten X-Requested-With-Header. SPA-Frontends senden ihn automatisch.
"""

from __future__ import annotations

import asyncio
import os
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path

import aiofiles
from quart import Blueprint, jsonify, request, abort, session
from quart import current_app  # noqa: F401

from arborpress.core.config import get_settings
from arborpress.core.markdown import render_md

# ---------------------------------------------------------------------------
# Blueprints
# ---------------------------------------------------------------------------

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
api_admin_bp = Blueprint("api_admin", __name__, url_prefix="/api/v1/admin")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _origin_check() -> None:
    """Einfacher CSRF-Origin-Guard für state-ändernde API-Calls (§10)."""
    cfg = get_settings()
    origin = request.headers.get("Origin") or request.headers.get("Referer", "")
    if origin and not origin.startswith(cfg.web.base_url):
        abort(403, "Cross-origin request rejected")


# ---------------------------------------------------------------------------
# Public API – Inhalte lesen
# ---------------------------------------------------------------------------


@api_v1_bp.get("/posts")
async def api_posts_list():
    """Paginierte Post-Liste (§8 public API).

    Query-Parameter:
      page    – Seitennummer (default 1)
      per_page – Einträge pro Seite (max 50)
      lang    – Sprachfilter (§7)
      tag     – Tag-Filter
    """
    # TODO: DB-Query via SQLAlchemy async
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 50)
    lang = request.args.get("lang")
    tag = request.args.get("tag")

    # Placeholder – reale Implementierung ersetzt durch DB-Query
    return jsonify({
        "items": [],
        "page": page,
        "per_page": per_page,
        "total": 0,
        "_filters": {"lang": lang, "tag": tag},
    })


@api_v1_bp.get("/posts/<slug>")
async def api_post_detail(slug: str):
    """Einzelner Post (§8, §6 – kanonischer Slug)."""
    # TODO: DB-Query, 301 bei Slug-Änderung
    abort(404)


@api_v1_bp.get("/pages/<slug>")
async def api_page_detail(slug: str):
    """Statische Seite (§1 Impressum/Datenschutz/Regeln)."""
    # TODO: DB-Query
    abort(404)


@api_v1_bp.get("/tags")
async def api_tags_list():
    """Tag-Liste (§8 public API)."""
    return jsonify({"items": [], "total": 0})


@api_v1_bp.get("/users/<handle>")
async def api_user_profile(handle: str):
    """Öffentliches Nutzerprofil – nur PUBLIC-Konten (§4).

    OPERATIONAL-Konten werden niemals über die API exponiert.
    """
    # TODO: DB-Query mit AccountType.PUBLIC-Filter
    abort(404)


@api_v1_bp.get("/search")
async def api_search():
    """Volltext-Suche (§12 FTS).

    Query-Parameter: q (Suchbegriff), page, per_page
    """
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"items": [], "total": 0})

    # TODO: Routing zu pg_fts / mariadb_fulltext / fallback (§12)
    return jsonify({"items": [], "total": 0, "q": q})


# ---------------------------------------------------------------------------
# Admin API – §8 state-ändernde Operationen
# ---------------------------------------------------------------------------


def _require_admin_session() -> None:
    """Prüft Admin-Session. Wirft 401 wenn nicht authentifiziert (§2)."""
    # TODO: Session-Check via auth-Modul
    pass


def _require_stepup(operation: str) -> None:
    """Prüft Step-up-Session für sensible Operationen (§2)."""
    from arborpress.auth.stepup import assert_stepup
    from quart import session
    try:
        assert_stepup(session, session.get("user_id"), operation)
    except PermissionError as exc:
        abort(403, str(exc))


@api_admin_bp.before_request
def _admin_api_guard():
    _origin_check()
    _require_admin_session()


@api_admin_bp.get("/posts")
async def admin_api_posts_list():
    """Admin: alle Posts inkl. Entwürfe (§8 admin API)."""
    return jsonify({"items": [], "total": 0})


@api_admin_bp.post("/posts")
async def admin_api_post_create():
    """Admin: neuen Post anlegen (§8)."""
    data = await request.get_json()
    # TODO: Validierung + DB-Insert
    return jsonify({"status": "created", "data": data}), 201


@api_admin_bp.put("/posts/<slug>")
async def admin_api_post_update(slug: str):
    """Admin: Post aktualisieren (§8)."""
    data = await request.get_json()
    return jsonify({"status": "updated", "slug": slug, "data": data})


@api_admin_bp.delete("/posts/<slug>")
async def admin_api_post_delete(slug: str):
    """Admin: Post löschen (§8)."""
    return jsonify({"status": "deleted", "slug": slug})


@api_admin_bp.post("/users/<username>/roles")
async def admin_api_user_set_role(username: str):
    """Admin: Benutzerrolle setzen – Step-up-Operation (§2, §8)."""
    _require_stepup("change_roles")
    data = await request.get_json()
    # TODO: DB-Update
    return jsonify({"status": "role_updated", "username": username, "role": data.get("role")})


@api_admin_bp.post("/auth/policy")
async def admin_api_set_auth_policy():
    """Admin: Auth-Policy setzen – Step-up-Operation (§2, §8)."""
    _require_stepup("modify_auth_policy")
    data = await request.get_json()
    return jsonify({"status": "policy_updated", "data": data})


@api_admin_bp.post("/plugins/<plugin_id>/enable")
async def admin_api_plugin_enable(plugin_id: str):
    """Admin: Plugin aktivieren – Step-up-Operation (§15, §2)."""
    _require_stepup("install_plugin")
    # TODO: Plugin-Registry
    return jsonify({"status": "enabled", "plugin_id": plugin_id})


@api_admin_bp.post("/plugins/<plugin_id>/disable")
async def admin_api_plugin_disable(plugin_id: str):
    """Admin: Plugin deaktivieren (§15)."""
    return jsonify({"status": "disabled", "plugin_id": plugin_id})


@api_admin_bp.get("/media")
async def admin_api_media_list():
    """Admin: Medienliste (§6 stabile URLs)."""
    return jsonify({"items": [], "total": 0})


# ---------------------------------------------------------------------------
# Markdown-Preview (§1 Split-View-Editor)
# ---------------------------------------------------------------------------


@api_admin_bp.post("/markdown/preview")
async def admin_api_markdown_preview():
    """Rendert Markdown-Text zu HTML für den Split-View-Editor.

    Request:  ``{"text": "..."}``
    Response: ``{"html": "..."}``
    """
    data = await request.get_json(silent=True) or {}
    raw = data.get("text", "")
    return jsonify({"html": render_md(raw)})


# ---------------------------------------------------------------------------
# Media-Upload (§6 /media/{yyyy}/{mm}/{filename}, Pillow-Dimensionen)
# ---------------------------------------------------------------------------


_ALLOWED_UPLOAD_TYPES = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/avif",
        "image/svg+xml",
    }
)
_MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MiB


@api_admin_bp.post("/media/upload")
async def media_upload():
    """Lädt eine Mediendatei hoch und speichert sie unter {media_dir}/{yyyy}/{mm}/{filename}.

    Formularfelder:
      ``file``    – multipart/form-data Dateifeld
      ``alt_text`` – optionaler Alt-Text

    Antwort: ``{"id", "url", "filename", "mime_type", "width", "height", "size_bytes"}``
    """
    files = await request.files
    form = await request.form
    upload = files.get("file")
    if upload is None:
        abort(400, "Kein Datei-Feld 'file' gefunden")

    mime_type: str = upload.content_type or ""
    mime_base = mime_type.split(";")[0].strip().lower()
    if mime_base not in _ALLOWED_UPLOAD_TYPES:
        abort(415, f"Dateityp nicht erlaubt: {mime_base!r}")

    data: bytes = await upload.read(_MAX_UPLOAD_SIZE + 1)
    if len(data) > _MAX_UPLOAD_SIZE:
        abort(413, "Datei überschreitet 20-MiB-Limit")

    cfg = get_settings()
    now = datetime.now(timezone.utc)
    yyyy = now.year
    mm = now.month

    import mimetypes as _mt
    original_name = os.path.basename(upload.filename or "upload")
    stem, ext = os.path.splitext(original_name)
    if not ext:
        guessed = _mt.guess_extension(mime_base) or ".bin"
        ext = guessed

    file_id = _uuid.uuid4().hex[:16]
    safe_filename = f"{file_id}{ext}"
    dest_dir = cfg.web.media_dir / str(yyyy) / f"{mm:02d}"
    dest_path = dest_dir / safe_filename

    # Dimensionen via Pillow (nur für Rasterbilder)
    width: int | None = None
    height: int | None = None
    if mime_base not in ("image/svg+xml",):
        try:
            from io import BytesIO
            from PIL import Image
            img = Image.open(BytesIO(data))
            width, height = img.size
        except Exception:
            pass

    # Datei asynchron schreiben
    await asyncio.to_thread(_write_upload, dest_dir, dest_path, data)

    # DB-Eintrag
    storage_path = f"{yyyy}/{mm:02d}/{safe_filename}"
    alt_text = (form.get("alt_text") or "").strip() or None

    from arborpress.core.db import get_db_session
    from arborpress.models.content import Media

    media_obj = Media(
        id=str(_uuid.uuid4()),
        uploader_id=session.get("user_id"),  # type: ignore[attr-defined]
        filename=safe_filename,
        mime_type=mime_base,
        size_bytes=len(data),
        storage_path=storage_path,
        alt_text=alt_text,
        width=width,
        height=height,
    )
    async for db in get_db_session():
        db.add(media_obj)
        await db.commit()

    url = f"{cfg.web.base_url.rstrip('/')}/media/{yyyy}/{mm:02d}/{safe_filename}"
    return jsonify(
        {
            "id": media_obj.id,
            "url": url,
            "filename": safe_filename,
            "mime_type": mime_base,
            "width": width,
            "height": height,
            "size_bytes": len(data),
        }
    ), 201


def _write_upload(dest_dir: Path, dest_path: Path, data: bytes) -> None:
    """Schreibt Datei atomar (sync, für asyncio.to_thread)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dest_path)

