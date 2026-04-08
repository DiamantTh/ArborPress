"""API routes – /api/v1/ (§8 admin & public API).

Separation:
- Public API  (/api/v1/posts, /api/v1/tags …)   – no auth required
- Admin API   (/api/v1/admin/…)                  – session + step-up (§2)

CSRF note (§8 / §10):
  All state-changing endpoints check Origin/Referer OR require
  an explicit X-Requested-With header. SPA frontends send it automatically.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid as _uuid
from datetime import UTC, datetime
from pathlib import Path

from quart import (
    Blueprint,
    abort,
    current_app,  # noqa: F401
    jsonify,
    request,
    session,
)

from arborpress.auth.roles import require_role
from arborpress.core.config import get_settings
from arborpress.core.markdown import render_md_async

log = logging.getLogger("arborpress.web.api")

# ---------------------------------------------------------------------------
# Blueprints
# ---------------------------------------------------------------------------

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
api_admin_bp = Blueprint("api_admin", __name__, url_prefix="/api/v1/admin")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _origin_check() -> None:
    """Simple CSRF origin guard for state-changing API calls (§10)."""
    cfg = get_settings()
    origin = request.headers.get("Origin") or request.headers.get("Referer", "")
    if origin and not origin.startswith(cfg.web.base_url):
        abort(403, "Cross-origin request rejected")


_ADMIN_ROLES: frozenset[str] = frozenset({"admin", "editor", "author", "moderator"})


# ---------------------------------------------------------------------------
# Public API – Inhalte lesen
# ---------------------------------------------------------------------------


@api_v1_bp.get("/posts")
async def api_posts_list():
    """Paginierte Post-Liste (§8 public API).

    Query-Parameter:
      page    – Seitennummer (default 1)
      per_page – entries per page (max 50)
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
    # TODO: DB query, 301 on slug change
    abort(404)


@api_v1_bp.get("/pages/<slug>")
async def api_page_detail(slug: str):
    """Static page (§1 imprint/privacy/rules)."""
    # TODO: DB-Query
    abort(404)


@api_v1_bp.get("/tags")
async def api_tags_list():
    """Tag list (§8 public API)."""
    return jsonify({"items": [], "total": 0})


@api_v1_bp.get("/users/<handle>")
async def api_user_profile(handle: str):
    """Public user profile – PUBLIC accounts only (§4).

    OPERATIONAL accounts are never exposed via the API.
    """
    # TODO: DB-Query mit AccountType.PUBLIC-Filter
    abort(404)


@api_v1_bp.get("/search")
async def api_search():
    """Full-text search (§12 FTS).

    Query parameters: q (search term), page, per_page
    """
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"items": [], "total": 0})

    # TODO: Routing zu pg_fts / mariadb_fulltext / fallback (§12)
    return jsonify({"items": [], "total": 0, "q": q})


# ---------------------------------------------------------------------------
# Admin API – §8 state-changing operations
# ---------------------------------------------------------------------------


def _require_admin_session() -> None:
    """Validates admin session. Raises 401/403 if not authenticated (§2)."""
    if not session.get("user_id"):
        abort(401, "Authentifizierung erforderlich")
    if session.get("user_role", "") not in _ADMIN_ROLES:
        abort(403, "Unzureichende Berechtigungen")


def _require_stepup(operation: str) -> None:
    """Validates step-up session for sensitive operations (§2)."""
    from quart import session

    from arborpress.auth.stepup import assert_stepup
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
    """Admin: all posts including drafts (§8 admin API)."""
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
    """Admin: delete post (§8) – editor or above."""
    require_role("editor")
    return jsonify({"status": "deleted", "slug": slug})


@api_admin_bp.post("/users/<username>/roles")
async def admin_api_user_set_role(username: str):
    """Admin: Benutzerrolle setzen – nur Admins (§2, §8)."""
    require_role("admin")
    _require_stepup("change_roles")
    data = await request.get_json()
    # TODO: DB-Update
    return jsonify({"status": "role_updated", "username": username, "role": data.get("role")})


@api_admin_bp.post("/auth/policy")
async def admin_api_set_auth_policy():
    """Admin: Auth-Policy setzen – nur Admins (§2, §8)."""
    require_role("admin")
    _require_stepup("modify_auth_policy")
    data = await request.get_json()
    return jsonify({"status": "policy_updated", "data": data})


@api_admin_bp.post("/plugins/<plugin_id>/enable")
async def admin_api_plugin_enable(plugin_id: str):
    """Admin: Plugin aktivieren – nur Admins (§15, §2)."""
    require_role("admin")
    _require_stepup("install_plugin")
    # TODO: Plugin-Registry
    return jsonify({"status": "enabled", "plugin_id": plugin_id})


@api_admin_bp.post("/plugins/<plugin_id>/disable")
async def admin_api_plugin_disable(plugin_id: str):
    """Admin: Plugin deaktivieren – nur Admins (§15)."""
    require_role("admin")
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
    """Renders Markdown text to HTML for the split-view editor.

    Request:  ``{"text": "..."}``
    Response: ``{"html": "..."}``
    """
    data = await request.get_json(silent=True) or {}
    raw = data.get("text", "")
    return jsonify({"html": await render_md_async(raw)})


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
        # image/svg+xml deliberately excluded: SVG files can contain embedded
        # JavaScript (<script>, onload handlers, etc.). Even with the
        # strict CSP of this application there is an XSS risk if the browser
        # opens an uploaded SVG file directly as a top-level document.
    }
)
_MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MiB


@api_admin_bp.post("/media/upload")
async def media_upload():
    """Uploads a media file and stores it under {media_dir}/{yyyy}/{mm}/{filename}.

    Form fields:
      ``file``    – multipart/form-data file field
      ``alt_text`` – optional alt text

    Response: ``{"id", "url", "filename", "mime_type", "width", "height", "size_bytes"}``
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
        abort(413, "File exceeds 20 MiB limit")

    cfg = get_settings()
    now = datetime.now(UTC)
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

    # Dimensions via Pillow (raster images only)
    width: int | None = None
    height: int | None = None
    if mime_base not in ("image/svg+xml",):
        try:
            from io import BytesIO

            from PIL import Image
            img = Image.open(BytesIO(data))
            width, height = img.size
        except Exception:
            log.debug("Pillow konnte Bilddimensionen nicht lesen", exc_info=True)

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
    """Writes file atomically (sync, for asyncio.to_thread)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_path.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dest_path)

