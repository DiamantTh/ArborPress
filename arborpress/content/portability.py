"""Portable, database-independent content packages.

This is deliberately separate from encrypted instance backups. Packages contain
editorial material only and are untrusted input until every member and relation
has passed validation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
import zipfile
from collections import Counter, deque
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import select
from sqlalchemy import union as sa_union
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from arborpress import BUILD_SHA
from arborpress.core.config import get_settings
from arborpress.models.content import (
    Comment,
    CommentStatus,
    Media,
    Page,
    PageType,
    Post,
    PostAuthorRelation,
    PostStatus,
    PostVisibility,
    Tag,
    post_tags,
)
from arborpress.models.settings import PortableImportReceipt, SiteSetting

FORMAT_ID = "arborpress.portable-content"
FORMAT_LEVEL = 1
MANIFEST = "manifest.json"
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRY_BYTES = 100 * 1024 * 1024
MAX_MEDIA_BYTES = 20 * 1024 * 1024
MAX_RECORD_BYTES = 10 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_RECORDS = 250_000
MAX_PLUGIN_EXTENSION_BYTES = 700 * 1024
MAX_CONTENT_CHARS = 8 * 1024 * 1024
MAX_SLUG = 256
_ENTITY_FILES = {
    "authors": "data/authors.jsonl",
    "tags": "data/tags.jsonl",
    "posts": "data/posts.jsonl",
    "pages": "data/pages.jsonl",
    "comments": "data/comments.jsonl",
    "media": "data/media.jsonl",
}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_LANG_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$")


class PortabilityError(ValueError):
    """The portable package or requested operation is not safe to apply."""


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_loads(value: str | bytes) -> Any:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = item
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON numeric constant: {value}")

    return json.loads(value, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


def _portable_id(namespace: uuid.UUID, kind: str, source_id: object) -> str:
    return str(uuid.uuid5(namespace, f"{kind}:{source_id}"))


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _inside_media_root(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except OSError, RuntimeError, ValueError:
        return False
    return path.is_file() and not path.is_symlink()


async def _chunks(db: AsyncSession, statement: Any, size: int = 200) -> AsyncIterator[list[Any]]:
    result = await db.stream_scalars(statement)
    batch: list[Any] = []
    async for item in result:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


async def export_portable(
    db: AsyncSession,
    destination: Path,
    *,
    include_comments: bool = False,
    include_media: bool = True,
    include_non_public: bool = False,
    plugin_manager: Any | None = None,
) -> dict[str, Any]:
    """Stream editorial data and referenced media into an atomic ZIP package."""
    destination = destination.expanduser().absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    staging_directory = Path(tempfile.mkdtemp(prefix="arborpress-portable-media-"))
    bundle_id = str(uuid.uuid4())
    namespace = uuid.UUID(bundle_id)
    files: dict[str, dict[str, Any]] = {}
    counts: Counter[str] = Counter()
    staged_media_bytes = 0
    extension_metadata: dict[str, dict[str, str]] = {}
    media_root = get_settings().web.media_dir

    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:

            async def add_jsonl(
                name: str, rows: AsyncIterator[dict[str, Any]], entity: str
            ) -> None:
                digest = hashlib.sha256()
                size = 0
                with archive.open(name, "w", force_zip64=True) as member:
                    async for row in rows:
                        if counts[entity] >= MAX_RECORDS:
                            raise PortabilityError(
                                f"The exported {entity} collection exceeds the record limit."
                            )
                        encoded = _json_bytes(row) + b"\n"
                        if len(encoded) > MAX_RECORD_BYTES:
                            raise PortabilityError(
                                f"An exported {entity} record exceeds the size limit."
                            )
                        if size + len(encoded) > MAX_ENTRY_BYTES:
                            raise PortabilityError(
                                f"The exported {entity} data file exceeds the size limit."
                            )
                        member.write(encoded)
                        digest.update(encoded)
                        size += len(encoded)
                        counts[entity] += 1
                files[name] = {"sha256": digest.hexdigest(), "size": size}

            async def authors() -> AsyncIterator[dict[str, Any]]:
                from arborpress.models.user import User

                relation_statement = select(PostAuthorRelation.user_id).join(
                    Post, Post.id == PostAuthorRelation.post_id
                )
                legacy_author_statement = select(Post.author_id).where(
                    Post.author_id.is_not(None)
                )
                if not include_non_public:
                    relation_statement = relation_statement.where(
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                    legacy_author_statement = legacy_author_statement.where(
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                author_sources: list[Any] = [relation_statement, legacy_author_statement]
                if include_comments:
                    comments_query = (
                        select(Comment.author_user_id)
                        .join(Post, Comment.post_id == Post.id)
                        .where(
                            Comment.status == CommentStatus.APPROVED,
                            Comment.author_user_id.is_not(None),
                        )
                    )
                    if not include_non_public:
                        comments_query = comments_query.where(
                            Post.status == PostStatus.PUBLISHED,
                            Post.visibility == PostVisibility.PUBLIC,
                        )
                    author_sources.append(comments_query)
                author_ids = sa_union(*author_sources).subquery()
                statement = (
                    select(User)
                    .join(author_ids, author_ids.c.user_id == User.id)
                    .order_by(User.id)
                )
                async for batch in _chunks(db, statement):
                    for user in batch:
                        yield {
                            "id": _portable_id(namespace, "author", user.id),
                            "display_name": user.display_name or user.username,
                        }

            await add_jsonl(_ENTITY_FILES["authors"], authors(), "authors")

            async def tags() -> AsyncIterator[dict[str, Any]]:
                statement = (
                    select(Tag)
                    .join(post_tags, post_tags.c.tag_id == Tag.id)
                    .join(Post, Post.id == post_tags.c.post_id)
                    .distinct()
                    .order_by(Tag.id)
                )
                if not include_non_public:
                    statement = statement.where(
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                async for batch in _chunks(db, statement):
                    for item in batch:
                        yield {
                            "id": _portable_id(namespace, "tag", item.id),
                            "slug": item.slug,
                            "label": item.label,
                            "lang": item.lang,
                        }

            await add_jsonl(_ENTITY_FILES["tags"], tags(), "tags")

            async def posts() -> AsyncIterator[dict[str, Any]]:
                statement = (
                    select(Post)
                    .options(
                        selectinload(Post.tags),
                        selectinload(Post.author_relations).selectinload(PostAuthorRelation.user),
                    )
                    .order_by(Post.id)
                )
                if not include_non_public:
                    statement = statement.where(
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                async for batch in _chunks(db, statement):
                    for item in batch:
                        counts[f"post_status_{item.status.value}"] += 1
                        relations = sorted(
                            item.author_relations, key=lambda row: (row.position, row.user_id)
                        )
                        portable_authors = [
                            {
                                "author_id": _portable_id(namespace, "author", row.user_id),
                                "role": row.role.value,
                                "position": row.position,
                            }
                            for row in relations
                        ]
                        if not portable_authors and item.author_id:
                            portable_authors = [
                                {
                                    "author_id": _portable_id(namespace, "author", item.author_id),
                                    "role": "primary",
                                    "position": 0,
                                }
                            ]
                        yield {
                            "id": _portable_id(namespace, "post", item.id),
                            "title": item.title,
                            "slug": item.slug,
                            "body_md": item.body_md or "",
                            "excerpt": item.excerpt,
                            "source_status": item.status.value,
                            "visibility": item.visibility.value,
                            "lang": item.lang,
                            "published_at": item.published_at.isoformat()
                            if item.published_at
                            else None,
                            "tag_ids": [
                                _portable_id(namespace, "tag", tag.id) for tag in item.tags
                            ],
                            "authors": portable_authors,
                        }

            await add_jsonl(_ENTITY_FILES["posts"], posts(), "posts")

            async def pages() -> AsyncIterator[dict[str, Any]]:
                page_statement = select(Page).where(Page.page_type == PageType.CUSTOM)
                if not include_non_public:
                    page_statement = page_statement.where(
                        Page.is_published.is_(True), Page.visibility == PostVisibility.PUBLIC
                    )
                async for batch in _chunks(db, page_statement.order_by(Page.id)):
                    for item in batch:
                        yield {
                            "id": _portable_id(namespace, "page", item.id),
                            "title": item.title,
                            "slug": item.slug,
                            "body_md": item.body_md or "",
                            "lang": item.lang,
                            "source_is_published": bool(item.is_published),
                            "visibility": item.visibility.value,
                            "noindex": bool(item.noindex),
                            "show_in_footer": bool(item.show_in_footer),
                        }

            await add_jsonl(_ENTITY_FILES["pages"], pages(), "pages")

            async def comments() -> AsyncIterator[dict[str, Any]]:
                if not include_comments:
                    return
                statement = (
                    select(Comment)
                    .options(selectinload(Comment.parent))
                    .join(Post, Comment.post_id == Post.id)
                    .where(Comment.status == CommentStatus.APPROVED)
                )
                if not include_non_public:
                    statement = statement.where(
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                statement = statement.order_by(Comment.created_at, Comment.id)
                async for batch in _chunks(db, statement):
                    for item in batch:
                        yield {
                            "id": _portable_id(namespace, "comment", item.id),
                            "post_id": _portable_id(namespace, "post", item.post_id),
                            "author_id": _portable_id(namespace, "author", item.author_user_id)
                            if item.author_user_id
                            else None,
                            "author_name": item.author_name[:128],
                            "body": item.body,
                            "parent_id": _portable_id(namespace, "comment", item.parent_id)
                            if item.parent
                            and item.parent.status == CommentStatus.APPROVED
                            and item.parent.post_id == item.post_id
                            else None,
                            "created_at": item.created_at.isoformat() if item.created_at else None,
                        }

            await add_jsonl(_ENTITY_FILES["comments"], comments(), "comments")

            media_manifest_path = staging_directory / "media.jsonl"
            media_manifest_digest = hashlib.sha256()
            media_manifest_size = 0
            base_export_bytes = sum(record["size"] for record in files.values())
            with media_manifest_path.open("wb") as media_manifest_file:
                if include_media:
                    async for batch in _chunks(db, select(Media).order_by(Media.id)):
                        for item in batch:
                            source_path = PurePosixPath(item.storage_path)
                            if (
                                source_path.is_absolute()
                                or ".." in source_path.parts
                                or "\\" in item.storage_path
                            ):
                                continue
                            disk_path = media_root.joinpath(*source_path.parts)
                            if not _inside_media_root(disk_path, media_root):
                                continue
                            portable = _portable_id(namespace, "media", item.id)
                            member_name = f"media/{portable}"
                            staged_path = staging_directory / portable
                            await asyncio.to_thread(shutil.copyfile, disk_path, staged_path)
                            digest, size = await asyncio.to_thread(_hash_file, staged_path)
                            if size > MAX_MEDIA_BYTES:
                                staged_path.unlink(missing_ok=True)
                                continue
                            if counts["media"] >= MAX_RECORDS:
                                staged_path.unlink(missing_ok=True)
                                raise PortabilityError(
                                    "The exported media collection is too large."
                                )
                            media_row = {
                                "id": portable,
                                "source_path": item.storage_path,
                                "member": member_name,
                                "filename": item.filename,
                                "mime_type": item.mime_type,
                                "size": size,
                                "sha256": digest,
                                "alt_text": item.alt_text,
                                "width": item.width,
                                "height": item.height,
                            }
                            encoded = _json_bytes(media_row) + b"\n"
                            projected_archive_size = (
                                base_export_bytes
                                + staged_media_bytes
                                + size
                                + media_manifest_size
                                + len(encoded)
                            )
                            if (
                                len(files) + 3 > MAX_MEMBERS
                                or media_manifest_size + len(encoded) > MAX_ENTRY_BYTES
                                or projected_archive_size > MAX_ARCHIVE_BYTES
                            ):
                                staged_path.unlink(missing_ok=True)
                                raise PortabilityError("Exported media exceeds package limits.")
                            archive.write(staged_path, member_name)
                            files[member_name] = {"sha256": digest, "size": size}
                            staged_path.unlink(missing_ok=True)
                            media_manifest_file.write(encoded)
                            media_manifest_digest.update(encoded)
                            media_manifest_size += len(encoded)
                            staged_media_bytes += size
                            counts["media"] += 1
                            counts["media_files"] += 1
            archive.write(media_manifest_path, _ENTITY_FILES["media"])
            files[_ENTITY_FILES["media"]] = {
                "sha256": media_manifest_digest.hexdigest(),
                "size": media_manifest_size,
            }

            if plugin_manager is not None:
                from arborpress.plugins.capabilities import Capability

                for plugin_id in plugin_manager.portable_plugin_ids(Capability.EXPORTER):
                    try:
                        payload = await plugin_manager.export_portable_extension(
                            plugin_id,
                            context={"bundle_id": bundle_id, "format_level": FORMAT_LEVEL},
                        )
                    except Exception as exc:
                        raise PortabilityError(f"Portable exporter {plugin_id!r} failed.") from exc
                    if not isinstance(payload, dict):
                        raise PortabilityError("A plugin exporter returned invalid extension data.")
                    try:
                        encoded = _json_bytes(payload)
                    except (TypeError, ValueError, RecursionError) as exc:
                        raise PortabilityError(
                            f"Portable exporter {plugin_id!r} returned invalid JSON data."
                        ) from exc
                    if len(encoded) > MAX_PLUGIN_EXTENSION_BYTES:
                        raise PortabilityError("A plugin extension exceeds the size limit.")
                    if (
                        len(files) + 2 > MAX_MEMBERS
                        or sum(record["size"] for record in files.values()) + len(encoded)
                        > MAX_ARCHIVE_BYTES
                    ):
                        raise PortabilityError("Plugin extensions exceed package limits.")
                    member_name = f"extensions/{plugin_id}/data.json"
                    archive.writestr(member_name, encoded)
                    files[member_name] = {
                        "sha256": hashlib.sha256(encoded).hexdigest(),
                        "size": len(encoded),
                    }
                    extension_metadata[plugin_id] = {
                        "capability": "exporter",
                        "member": member_name,
                    }

            settings_row = await db.get(SiteSetting, "general")
            public_settings: dict[str, Any] = {}
            if settings_row:
                try:
                    configured = json.loads(settings_row.value)
                    public_settings = {
                        key: configured[key]
                        for key in ("site_title", "site_description", "site_language")
                        if key in configured and isinstance(configured[key], str)
                    }
                except ValueError, TypeError:
                    public_settings = {}
            theme_row = await db.get(SiteSetting, "theme")
            theme_reference: str | None = None
            if theme_row:
                try:
                    configured_theme = json.loads(theme_row.value).get("active")
                    if isinstance(configured_theme, str) and re.fullmatch(
                        r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", configured_theme
                    ):
                        theme_reference = configured_theme
                except (ValueError, TypeError, AttributeError):
                    pass
            canonical_entries = {name: record["sha256"] for name, record in sorted(files.items())}
            record_counts = {key: counts.get(key, 0) for key in _ENTITY_FILES}
            record_counts.update(
                {key: value for key, value in counts.items() if key not in record_counts}
            )
            manifest = {
                "format": FORMAT_ID,
                "format_level": FORMAT_LEVEL,
                "bundle_id": bundle_id,
                "exported_at": datetime.now(UTC).isoformat(),
                "source_build_sha": BUILD_SHA,
                "source_alembic_head": _source_alembic_head(),
                "contains": [name for name in _ENTITY_FILES if counts.get(name, 0)],
                "counts": dict(sorted(record_counts.items())),
                "files": files,
                "bundle_hash": hashlib.sha256(_json_bytes(canonical_entries)).hexdigest(),
                "public_site_settings_proposal": public_settings,
                "theme_selection_reference": theme_reference,
                "extensions": extension_metadata,
                "non_public_content_included": include_non_public,
                "security_data_included": False,
            }
            manifest_bytes = _json_bytes(manifest)
            if (
                len(manifest_bytes) > 2 * 1024 * 1024
                or sum(record["size"] for record in files.values()) + len(manifest_bytes)
                > MAX_ARCHIVE_BYTES
                or len(files) + 1 > MAX_MEMBERS
            ):
                raise PortabilityError("Portable package manifest or archive exceeds limits.")
            archive.writestr(MANIFEST, manifest_bytes)
        if temporary.stat().st_size > MAX_ARCHIVE_BYTES:
            raise PortabilityError("Compressed portable package exceeds the size limit.")
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(staging_directory, ignore_errors=True)
    return {
        "bundle_id": bundle_id,
        "path": str(destination),
        "counts": dict(counts),
        "bundle_hash": manifest["bundle_hash"],
    }


def _source_alembic_head() -> str:
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        config = Config(str(Path(__file__).parents[1] / "migrations" / "alembic.ini"))
        return str(ScriptDirectory.from_config(config).get_current_head() or "unknown")
    except Exception:
        return "unknown"


def _safe_member(name: str) -> bool:
    if not name or "\\" in name or name.startswith("/"):
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _read_manifest(archive: zipfile.ZipFile) -> dict[str, Any]:
    infos = archive.infolist()
    if len(infos) > MAX_MEMBERS:
        raise PortabilityError("Archive contains too many entries.")
    names: set[str] = set()
    total = 0
    for info in infos:
        if not _safe_member(info.filename) or info.filename in names:
            raise PortabilityError("Archive contains an unsafe or duplicate path.")
        names.add(info.filename)
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode) or info.flag_bits & 0x1:
            raise PortabilityError("Archive contains a symlink or encrypted entry.")
        if info.file_size > MAX_ENTRY_BYTES:
            raise PortabilityError("Archive member exceeds the size limit.")
        total += info.file_size
        if total > MAX_ARCHIVE_BYTES:
            raise PortabilityError("Archive exceeds the total uncompressed size limit.")
        if (
            info.file_size > 1024 * 1024
            and info.compress_size
            and info.file_size / info.compress_size > 1000
        ):
            raise PortabilityError("Archive compression ratio exceeds the safety limit.")
    if MANIFEST not in names:
        raise PortabilityError("Archive manifest is missing.")
    info = archive.getinfo(MANIFEST)
    if info.file_size > 2 * 1024 * 1024:
        raise PortabilityError("Manifest exceeds the size limit.")
    try:
        value = _json_loads(archive.read(MANIFEST))
    except (ValueError, UnicodeDecodeError, RecursionError, zipfile.BadZipFile) as exc:
        raise PortabilityError("Manifest is malformed.") from exc
    if not isinstance(value, dict) or value.get("format") != FORMAT_ID:
        raise PortabilityError("Unsupported portable package format.")
    if value.get("format_level") != FORMAT_LEVEL:
        raise PortabilityError("Unsupported portable format level.")
    if value.get("security_data_included") is not False:
        raise PortabilityError("Portable packages must explicitly exclude security data.")
    if not isinstance(value.get("source_build_sha"), str) or len(value["source_build_sha"]) > 64:
        raise PortabilityError("Manifest source build identity is invalid.")
    if not isinstance(value.get("source_alembic_head"), str) or len(
        value["source_alembic_head"]
    ) > 128:
        raise PortabilityError("Manifest source schema identity is invalid.")
    if not isinstance(value.get("exported_at"), str):
        raise PortabilityError("Manifest export timestamp is invalid.")
    if not isinstance(value.get("bundle_id"), str) or not _UUID_RE.fullmatch(value["bundle_id"]):
        raise PortabilityError("Manifest bundle id is invalid.")
    files = value.get("files")
    if not isinstance(files, dict) or set(files) != names - {MANIFEST}:
        raise PortabilityError("Manifest file list does not match archive members.")
    canonical: dict[str, str] = {}
    for name, record in files.items():
        if not _safe_member(name) or not isinstance(record, dict):
            raise PortabilityError("Manifest contains an invalid file entry.")
        digest, size = record.get("sha256"), record.get("size")
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(size, int)
            or size < 0
        ):
            raise PortabilityError("Manifest file metadata is invalid.")
        if archive.getinfo(name).file_size != size:
            raise PortabilityError("Archive member size does not match the manifest.")
        hasher = hashlib.sha256()
        with archive.open(name) as member:
            while chunk := member.read(1024 * 1024):
                hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise PortabilityError(f"Hash mismatch for package member {name}.")
        canonical[name] = digest
    counts = value.get("counts")
    if not isinstance(counts, dict):
        raise PortabilityError("Manifest record counts are missing.")
    for entity in _ENTITY_FILES:
        count = counts.get(entity)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise PortabilityError("Manifest record counts are invalid.")
    expected_contains = [entity for entity in _ENTITY_FILES if counts[entity] > 0]
    if value.get("contains") != expected_contains:
        raise PortabilityError("Manifest content declaration does not match its record counts.")
    if hashlib.sha256(_json_bytes(dict(sorted(canonical.items())))).hexdigest() != value.get(
        "bundle_hash"
    ):
        raise PortabilityError("Package bundle hash is invalid.")
    allowed = {MANIFEST, *_ENTITY_FILES.values()}
    for name in names - allowed:
        if not name.startswith(("extensions/", "media/")):
            raise PortabilityError("Package contains an unrecognized non-extension member.")
    extensions = value.get("extensions", {})
    if not isinstance(extensions, dict) or len(extensions) > 100:
        raise PortabilityError("Extension namespace metadata is invalid.")
    for namespace, metadata in extensions.items():
        if (
            not isinstance(namespace, str)
            or not isinstance(metadata, dict)
            or not re.fullmatch(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", namespace)
            or set(metadata) != {"capability", "member"}
            or metadata.get("capability") != "exporter"
        ):
            raise PortabilityError("Extension namespace is invalid.")
        member_name = metadata.get("member")
        if (
            member_name != f"extensions/{namespace}/data.json"
            or member_name not in files
            or files[member_name]["size"] > MAX_PLUGIN_EXTENSION_BYTES
        ):
            raise PortabilityError("Extension data member is invalid or oversized.")
        try:
            extension_payload = _json_loads(archive.read(member_name))
        except (ValueError, UnicodeDecodeError, RecursionError, zipfile.BadZipFile) as exc:
            raise PortabilityError("Extension data is malformed.") from exc
        if not isinstance(extension_payload, dict):
            raise PortabilityError("Extension data must be a JSON object.")
    declared_extension_members = {
        metadata["member"] for metadata in extensions.values() if isinstance(metadata, dict)
    }
    archived_extension_members = {name for name in names if name.startswith("extensions/")}
    if declared_extension_members != archived_extension_members:
        raise PortabilityError("Extension members do not match declared namespaces.")
    return value


def _records(
    archive: zipfile.ZipFile, member_name: str, *, max_record: int = MAX_RECORD_BYTES
) -> list[dict[str, Any]]:
    if member_name not in archive.namelist():
        return []
    result: list[dict[str, Any]] = []
    with archive.open(member_name) as source:
        while line := source.readline(max_record + 1):
            if len(line) > max_record or len(result) >= MAX_RECORDS:
                raise PortabilityError("Portable data exceeds a record or count limit.")
            try:
                value = _json_loads(line)
            except (ValueError, UnicodeDecodeError, RecursionError) as exc:
                raise PortabilityError(f"Malformed JSON record in {member_name}.") from exc
            if not isinstance(value, dict):
                raise PortabilityError("Portable records must be JSON objects.")
            result.append(value)
    return result


def _valid_text(value: object, *, name: str, limit: int, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or len(value) > limit or (not allow_empty and not value.strip()):
        raise PortabilityError(f"Invalid {name} field.")
    return value


def _validate_archive_structure(
    archive: zipfile.ZipFile,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    manifest = _read_manifest(archive)
    entities = {key: _records(archive, name) for key, name in _ENTITY_FILES.items()}
    for key, filename in _ENTITY_FILES.items():
        if filename not in manifest["files"]:
            raise PortabilityError(f"Required portable data file is missing: {filename}.")
        expected_count = manifest.get("counts", {}).get(key)
        if expected_count is not None and expected_count != len(entities[key]):
            raise PortabilityError(f"Manifest count does not match {filename}.")
    ids: dict[str, set[str]] = {key: set() for key in entities}
    for kind in ("authors", "tags", "posts", "pages", "comments", "media"):
        for row in entities[kind]:
            ref = row.get("id")
            if not isinstance(ref, str) or not _UUID_RE.fullmatch(ref) or ref in ids[kind]:
                raise PortabilityError(f"Invalid or repeated portable {kind} id.")
            ids[kind].add(ref)
    author_refs = ids["authors"]
    tag_refs = ids["tags"]
    post_refs = ids["posts"]
    comment_refs = ids["comments"]
    for row in entities["authors"]:
        _valid_text(
            row.get("display_name"), name="author display name", limit=160, allow_empty=False
        )
    tag_slugs: set[str] = set()
    for row in entities["tags"]:
        slug = _valid_text(row.get("slug"), name="tag slug", limit=128, allow_empty=False)
        if not _SLUG_RE.fullmatch(slug) or slug in tag_slugs:
            raise PortabilityError("Invalid or duplicate tag slug.")
        tag_slugs.add(slug)
        _valid_text(row.get("label"), name="tag label", limit=128, allow_empty=False)
        if row.get("lang") is not None and (
            not isinstance(row["lang"], str) or not _LANG_RE.fullmatch(row["lang"])
        ):
            raise PortabilityError("Invalid tag language.")
    post_slugs: set[str] = set()
    for row in entities["posts"]:
        _valid_text(row.get("title"), name="post title", limit=512, allow_empty=False)
        _valid_text(row.get("slug"), name="post slug", limit=MAX_SLUG, allow_empty=False)
        _valid_text(row.get("body_md"), name="post body", limit=MAX_CONTENT_CHARS)
        if row.get("excerpt") is not None:
            _valid_text(row["excerpt"], name="post excerpt", limit=MAX_CONTENT_CHARS)
        if not _SLUG_RE.fullmatch(row["slug"]):
            raise PortabilityError("Invalid post slug.")
        if row["slug"] in post_slugs:
            raise PortabilityError("Duplicate post slug in package.")
        post_slugs.add(row["slug"])
        if row.get("visibility") not in {value.value for value in PostVisibility}:
            raise PortabilityError("Unsupported post visibility.")
        if row.get("source_status") not in {value.value for value in PostStatus}:
            raise PortabilityError("Unsupported source post status.")
        if row.get("lang") is not None and (
            not isinstance(row["lang"], str) or not _LANG_RE.fullmatch(row["lang"])
        ):
            raise PortabilityError("Invalid post language.")
        tag_ids = row.get("tag_ids")
        if not isinstance(tag_ids, list) or len(tag_ids) > MAX_RECORDS:
            raise PortabilityError("Post tag references are invalid.")
        if len(tag_ids) != len(set(tag_ids)) or any(value not in tag_refs for value in tag_ids):
            raise PortabilityError("Post references an unknown tag.")
        authors = row.get("authors")
        if not isinstance(authors, list) or len(authors) > 100:
            raise PortabilityError("Post author list is invalid.")
        positions: set[int] = set()
        roles: list[str] = []
        for author in authors:
            if not isinstance(author, dict) or author.get("author_id") not in author_refs:
                raise PortabilityError("Post references an unknown author.")
            if (
                author.get("role") not in {"primary", "coauthor"}
                or not isinstance(author.get("position"), int)
                or isinstance(author.get("position"), bool)
            ):
                raise PortabilityError("Post author relation is invalid.")
            roles.append(author["role"])
            positions.add(author["position"])
        if authors and (
            roles.count("primary") != 1
            or positions != set(range(len(positions)))
            or 0 not in positions
            or any(
                author["position"] == 0
                and author["role"] != "primary"
                or author["position"] > 0
                and author["role"] != "coauthor"
                for author in authors
            )
        ):
            raise PortabilityError("Each authored post must have exactly one primary author.")
    page_slugs: set[str] = set()
    for row in entities["pages"]:
        _valid_text(row.get("title"), name="page title", limit=512, allow_empty=False)
        slug = _valid_text(row.get("slug"), name="page slug", limit=MAX_SLUG, allow_empty=False)
        if not _SLUG_RE.fullmatch(slug) or slug in page_slugs:
            raise PortabilityError("Invalid or duplicate page slug.")
        page_slugs.add(slug)
        _valid_text(row.get("body_md"), name="page body", limit=MAX_CONTENT_CHARS)
        if row.get("visibility") not in {value.value for value in PostVisibility}:
            raise PortabilityError("Unsupported page visibility.")
        if row.get("lang") is not None and (
            not isinstance(row["lang"], str) or not _LANG_RE.fullmatch(row["lang"])
        ):
            raise PortabilityError("Invalid page language.")
        if not isinstance(row.get("noindex", False), bool) or not isinstance(
            row.get("show_in_footer", False), bool
        ):
            raise PortabilityError("Page flags must be boolean.")
    comments_by_id = {row["id"]: row for row in entities["comments"]}
    for row in entities["comments"]:
        if row.get("post_id") not in post_refs:
            raise PortabilityError("Comment references an unknown post.")
        if row.get("author_id") is not None and row["author_id"] not in author_refs:
            raise PortabilityError("Comment references an unknown author.")
        if row.get("parent_id") is not None and row["parent_id"] not in comment_refs:
            raise PortabilityError("Comment references an unknown parent.")
        if row.get("parent_id") == row["id"]:
            raise PortabilityError("Comment cannot be its own parent.")
        parent = comments_by_id.get(row.get("parent_id"))
        if parent is not None and parent.get("post_id") != row.get("post_id"):
            raise PortabilityError("Comment parent belongs to a different post.")
        _valid_text(row.get("author_name"), name="comment author", limit=128, allow_empty=False)
        _valid_text(row.get("body"), name="comment body", limit=20_000, allow_empty=False)
    for row in entities["comments"]:
        visited: set[str] = set()
        current = row
        while isinstance(current.get("parent_id"), str):
            parent_id = current["parent_id"]
            if parent_id in visited:
                raise PortabilityError("Comment thread contains a cycle.")
            visited.add(parent_id)
            parent = comments_by_id.get(parent_id)
            if parent is None:
                break
            current = parent
    source_media_paths: set[str] = set()
    for row in entities["media"]:
        name, path = row.get("member"), row.get("source_path")
        if not isinstance(name, str) or not name.startswith("media/") or not _safe_member(name):
            raise PortabilityError("Media reference path is unsafe.")
        if not isinstance(path, str) or not path:
            raise PortabilityError("Media source path is invalid.")
        source_path = PurePosixPath(path)
        if source_path.is_absolute() or ".." in source_path.parts or "\\" in path:
            raise PortabilityError("Media source path is unsafe.")
        if path in source_media_paths:
            raise PortabilityError("Media source path is duplicated.")
        source_media_paths.add(path)
        if (
            not isinstance(row.get("size"), int)
            or isinstance(row.get("size"), bool)
        ):
            raise PortabilityError("Media metadata is invalid.")
        if name not in manifest["files"] or manifest["files"][name]["size"] > MAX_MEDIA_BYTES:
            raise PortabilityError("Media file is missing or too large.")
        if (
            row.get("sha256") != manifest["files"][name]["sha256"]
            or row.get("size") != manifest["files"][name]["size"]
        ):
            raise PortabilityError("Media metadata does not match the media file.")
        _valid_text(row.get("mime_type"), name="media type", limit=128, allow_empty=False)
        if (
            not isinstance(row.get("filename"), str)
            or Path(row["filename"]).name != row["filename"]
            or "\\" in row["filename"]
            or "\x00" in row["filename"]
            or len(row["filename"]) > 256
        ):
            raise PortabilityError("Media filename is unsafe.")
        if row.get("alt_text") is not None:
            _valid_text(row["alt_text"], name="media alternative text", limit=512)
        for dimension in ("width", "height"):
            value = row.get(dimension)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 1
            ):
                raise PortabilityError("Media dimensions are invalid.")
    media_members = {row["member"] for row in entities["media"]}
    archived_media = {name for name in manifest["files"] if name.startswith("media/")}
    if media_members != archived_media:
        raise PortabilityError("Media archive members do not match the media manifest.")
    return manifest, entities


def _validate_archive(
    archive: zipfile.ZipFile,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    try:
        return _validate_archive_structure(archive)
    except PortabilityError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        zipfile.BadZipFile,
    ) as exc:
        raise PortabilityError("Portable package structure is malformed.") from exc


async def inspect_portable(
    db: AsyncSession,
    source: Path,
    *,
    conflict: str = "fail",
    author_map: Mapping[str, str] | None = None,
    plugin_manager: Any | None = None,
    available_importer_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Fully validate a package and produce a no-write import plan."""
    if conflict not in {"fail", "skip", "remap"}:
        raise PortabilityError("Conflict policy must be fail, skip or remap.")
    try:
        if source.stat().st_size > MAX_ARCHIVE_BYTES:
            raise PortabilityError("Compressed package exceeds the input size limit.")
    except OSError as exc:
        raise PortabilityError("Portable package cannot be read safely.") from exc
    try:
        with zipfile.ZipFile(source, "r") as archive:
            manifest, entities = _validate_archive(archive)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise PortabilityError("Portable package cannot be read safely.") from exc
    receipt = await db.scalar(
        select(PortableImportReceipt).where(
            PortableImportReceipt.bundle_id == manifest["bundle_id"]
        )
    )
    if receipt:
        if receipt.bundle_hash != manifest["bundle_hash"]:
            raise PortabilityError("A previously imported bundle ID has conflicting content.")
        return {
            "bundle_id": manifest["bundle_id"],
            "already_imported": True,
            "creates": {},
            "skips": sum(manifest.get("counts", {}).values()),
            "remaps": [],
            "conflicts": [],
            "warnings": ["This exact package has already been imported."],
            "errors": [],
        }

    mapped = dict(author_map or {})
    author_ids = {row["id"] for row in entities["authors"]}
    errors = []
    if set(mapped) - author_ids:
        errors.append("Author mapping contains an unknown portable author reference.")
    from arborpress.models.user import User

    local_ids = set(mapped.values())
    active_users = (
        set(
            (
                await db.scalars(
                    select(User.id).where(User.id.in_(local_ids), User.is_active.is_(True))
                )
            ).all()
        )
        if local_ids
        else set()
    )
    if active_users != local_ids:
        errors.append("Every mapped local author must exist and be active.")
    if any(
        len({mapped.get(author["author_id"]) for author in post.get("authors", [])})
        != len(post.get("authors", []))
        for post in entities["posts"]
        if all(author.get("author_id") in mapped for author in post.get("authors", []))
    ):
        errors.append("A post cannot map multiple source authors to one local account.")
    missing = author_ids - set(mapped)
    if missing:
        errors.append(
            f"Explicit local author mapping is required for {len(missing)} source author(s)."
        )
    extension_namespaces = set(manifest.get("extensions", {}))
    available_importers: set[str] = set()
    if plugin_manager is not None:
        from arborpress.plugins.capabilities import Capability

        available_importers = set(plugin_manager.portable_plugin_ids(Capability.IMPORTER))
    elif available_importer_ids is not None:
        available_importers = set(available_importer_ids)
    missing_importers = extension_namespaces - available_importers
    if missing_importers:
        errors.append(
            "A declared importer capability is required for extension(s): "
            + ", ".join(sorted(missing_importers))
        )

    slug_conflicts: list[dict[str, str]] = []
    existing_post_slugs = (
        set(
            (
                await db.scalars(
                    select(Post.slug).where(
                        Post.slug.in_([row["slug"] for row in entities["posts"]])
                    )
                )
            ).all()
        )
        if entities["posts"]
        else set()
    )
    existing_page_slugs = (
        set(
            (
                await db.scalars(
                    select(Page.slug).where(
                        Page.slug.in_([row["slug"] for row in entities["pages"]])
                    )
                )
            ).all()
        )
        if entities["pages"]
        else set()
    )
    existing_tag_slugs = (
        set(
            (
                await db.scalars(
                    select(Tag.slug).where(Tag.slug.in_([row["slug"] for row in entities["tags"]]))
                )
            ).all()
        )
        if entities["tags"]
        else set()
    )
    for kind, rows, present in (
        ("post", entities["posts"], existing_post_slugs),
        ("page", entities["pages"], existing_page_slugs),
        ("tag", entities["tags"], existing_tag_slugs),
    ):
        for row in rows:
            if row["slug"] in present:
                slug_conflicts.append({"kind": kind, "slug": row["slug"], "portable_id": row["id"]})
    if conflict == "fail" and slug_conflicts:
        errors.append(
            f"{len(slug_conflicts)} local slug conflict(s) require an explicit "
            "skip or remap policy."
        )
    warnings = [
        "Imported posts are always created as drafts; imported pages are unpublished.",
        "Public site settings are exported as a proposal only and are not applied.",
    ]
    if entities["comments"]:
        warnings.append(
            "Approved source comments re-enter local moderation as pending review; "
            "the destination guest policy can reject them."
        )
    skipped = len(slug_conflicts) if conflict == "skip" else 0
    return {
        "bundle_id": manifest["bundle_id"],
        "already_imported": False,
        "creates": {key: len(rows) for key, rows in entities.items()},
        "skips": skipped,
        "remaps": slug_conflicts if conflict == "remap" else [],
        "conflicts": slug_conflicts,
        "warnings": warnings,
        "errors": errors,
        "valid": not errors,
        "bundle_hash": manifest["bundle_hash"],
        "source_build_sha": manifest.get("source_build_sha", "unknown"),
        "extensions": sorted(extension_namespaces),
        "required_author_mappings": [
            {"portable_id": row["id"], "display_name": row["display_name"]}
            for row in entities["authors"]
        ],
    }


def _unique_slug(slug: str, portable_id: str, occupied: set[str]) -> str:
    base = f"{slug[:230]}-import-{portable_id[:8]}"
    candidate = base
    suffix = 2
    while candidate in occupied:
        candidate = f"{base[:245]}-{suffix}"
        suffix += 1
    occupied.add(candidate)
    return candidate


def _order_comments_by_parent(
    comments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return a stable parent-before-child order for imported threads."""
    by_id = {row["id"]: row for row in comments}
    children: dict[str, list[dict[str, Any]]] = {}
    roots: list[dict[str, Any]] = []
    for row in comments:
        parent_id = row.get("parent_id")
        parent = by_id.get(parent_id) if isinstance(parent_id, str) else None
        if parent is not None and isinstance(parent_id, str):
            children.setdefault(parent_id, []).append(row)
        else:
            roots.append(row)

    def ordering(row: dict[str, Any]) -> tuple[str, str]:
        return str(row.get("created_at") or ""), row["id"]

    for rows in children.values():
        rows.sort(key=ordering)
    ordered: list[dict[str, Any]] = []
    pending = deque(sorted(roots, key=ordering))
    while pending:
        row = pending.popleft()
        ordered.append(row)
        pending.extend(children.get(row["id"], []))
    if len(ordered) != len(comments):
        raise PortabilityError("Comment thread contains an unresolved cycle.")
    return ordered


async def import_portable(
    db: AsyncSession,
    source: Path,
    *,
    actor_user_id: str,
    author_map: Mapping[str, str],
    conflict: str = "fail",
    dry_run: bool = False,
    include_comments: bool = True,
    plugin_manager: Any | None = None,
) -> dict[str, Any]:
    """Validate then import package content under one DB transaction.

    The caller supplies a fresh AsyncSession. DB changes commit atomically; media
    files are staged through the existing upload pipeline and removed if the DB
    transaction fails. A process/power loss between filesystem and DB commit is
    reported as an operational limitation, not a cross-resource transaction.
    """
    plan = await inspect_portable(
        db,
        source,
        conflict=conflict,
        author_map=author_map,
        plugin_manager=plugin_manager,
    )
    if dry_run or plan.get("already_imported"):
        return plan
    if not plan.get("valid"):
        raise PortabilityError("Import preflight failed: " + "; ".join(plan["errors"]))
    if conflict == "fail" and plan["conflicts"]:
        raise PortabilityError("Import has slug conflicts; choose skip or remap explicitly.")
    # End the preflight read transaction before calling an isolated importer.
    await db.rollback()
    extension_results: dict[str, dict[str, Any]] = {}
    if plan.get("extensions"):
        if plugin_manager is None:
            raise PortabilityError(
                "Package extensions require their declared isolated plugin importers."
            )
        with zipfile.ZipFile(source, "r") as extension_archive:
            extension_manifest = _read_manifest(extension_archive)
            for plugin_id in plan["extensions"]:
                member_name = extension_manifest["extensions"][plugin_id]["member"]
                extension_payload = _json_loads(extension_archive.read(member_name))
                try:
                    extension_results[plugin_id] = await plugin_manager.import_portable_extension(
                        plugin_id,
                        data=extension_payload,
                        context={
                            "bundle_id": plan["bundle_id"],
                            "format_level": FORMAT_LEVEL,
                            "source_build_sha": extension_manifest.get(
                                "source_build_sha", "unknown"
                            ),
                        },
                    )
                except Exception as exc:
                    raise PortabilityError(
                        f"Portable importer {plugin_id!r} rejected the package."
                    ) from exc

    disk_files: list[Path] = []
    try:
        with zipfile.ZipFile(source, "r") as archive:
            manifest, entities = _validate_archive(archive)
            async with db.begin():
                receipt = await db.scalar(
                    select(PortableImportReceipt).where(
                        PortableImportReceipt.bundle_id == manifest["bundle_id"]
                    )
                )
                if receipt:
                    if receipt.bundle_hash != manifest["bundle_hash"]:
                        raise PortabilityError(
                            "A previously imported bundle ID has conflicting content."
                        )
                    return {**plan, "already_imported": True}
                occupied_post = set((await db.scalars(select(Post.slug))).all())
                occupied_page = set((await db.scalars(select(Page.slug))).all())
                occupied_tag = set((await db.scalars(select(Tag.slug))).all())
                tag_map: dict[str, int] = {}
                post_map: dict[str, str] = {}
                comment_map: dict[str, str] = {}
                media_path_map: dict[str, str] = {}
                counts: Counter[str] = Counter()
                conflict_rows = {item["portable_id"] for item in plan["conflicts"]}

                from arborpress.content.authors import replace_post_authors
                from arborpress.core.audit import write_audit_event
                from arborpress.core.markdown import render_md
                from arborpress.media.service import MediaUploadError, store_media_upload
                from arborpress.models.content import PostRevision
                from arborpress.models.user import AccountType, User, UserRole

                actor = await db.get(User, actor_user_id)
                if (
                    actor is None
                    or not actor.is_active
                    or actor.account_type != AccountType.OPERATIONAL
                    or actor.role != UserRole.ADMIN
                ):
                    raise PortabilityError("An active operational administrator is required.")

                for tag_data in entities["tags"]:
                    if conflict == "skip" and tag_data["id"] in conflict_rows:
                        existing = await db.scalar(select(Tag).where(Tag.slug == tag_data["slug"]))
                        if existing:
                            tag_map[tag_data["id"]] = int(existing.id)
                        counts["skipped_tags"] += 1
                        continue
                    slug = tag_data["slug"]
                    if slug in occupied_tag:
                        if conflict == "remap":
                            slug = _unique_slug(slug, tag_data["id"], occupied_tag)
                        elif conflict == "skip":
                            existing = await db.scalar(select(Tag).where(Tag.slug == slug))
                            if existing:
                                tag_map[tag_data["id"]] = int(existing.id)
                            counts["skipped_tags"] += 1
                            continue
                    tag_object = Tag(slug=slug, label=tag_data["label"], lang=tag_data.get("lang"))
                    db.add(tag_object)
                    await db.flush()
                    tag_map[tag_data["id"]] = int(tag_object.id)
                    counts["tags"] += 1

                for item in entities["media"]:
                    raw = archive.read(item["member"])
                    if (
                        len(raw) != item["size"]
                        or hashlib.sha256(raw).hexdigest() != item["sha256"]
                    ):
                        raise PortabilityError("Media changed after preflight.")
                    try:
                        media = await store_media_upload(
                            db,
                            uploader_id=actor_user_id,
                            filename=item["filename"],
                            content_type=item["mime_type"],
                            data=raw,
                            alt_text=item.get("alt_text"),
                            file_created_callback=disk_files.append,
                        )
                    except MediaUploadError as exc:
                        raise PortabilityError(
                            "Imported media failed local media validation."
                        ) from exc
                    # Keep the local row ID generated by the upload service.
                    media_path_map[item["source_path"]] = media.storage_path
                    counts["media"] += 1

                post_slugs: set[str] = set()
                for row in entities["posts"]:
                    if conflict == "skip" and row["id"] in conflict_rows:
                        counts["skipped_posts"] += 1
                        continue
                    slug = row["slug"]
                    if slug in occupied_post:
                        if conflict == "remap":
                            slug = _unique_slug(slug, row["id"], occupied_post)
                        elif conflict == "skip":
                            counts["skipped_posts"] += 1
                            continue
                    if slug in post_slugs:
                        slug = _unique_slug(slug, row["id"], occupied_post | post_slugs)
                    post_slugs.add(slug)
                    body_md = row["body_md"]
                    for old_path, new_path in media_path_map.items():
                        body_md = body_md.replace(f"/media/{old_path}", f"/media/{new_path}")
                    post = Post(
                        id=str(uuid.uuid4()),
                        short_id=uuid.uuid4().hex[:12],
                        author_id=None,
                        title=row["title"],
                        slug=slug,
                        body_md=body_md,
                        body_html=render_md(body_md),
                        excerpt=row.get("excerpt"),
                        status=PostStatus.DRAFT,
                        visibility=PostVisibility(row["visibility"]),
                        lang=row.get("lang"),
                        reading_time_min=Post.calc_reading_time(body_md),
                        published_at=None,
                    )
                    db.add(post)
                    await db.flush()
                    post_map[row["id"]] = str(post.id)
                    author_rows = row.get("authors", [])
                    if author_rows:
                        ordered = sorted(author_rows, key=lambda value: value["position"])
                        primary = next(value for value in ordered if value["role"] == "primary")
                        coauthors = [
                            author_map[value["author_id"]]
                            for value in ordered
                            if value["role"] == "coauthor"
                        ]
                        await replace_post_authors(
                            db,
                            post_id=str(post.id),
                            primary_user_id=author_map[primary["author_id"]],
                            coauthor_user_ids=coauthors,
                            actor_user_id=actor_user_id,
                        )
                    for tag_ref in row.get("tag_ids", []):
                        tag_id = tag_map.get(tag_ref)
                        if tag_id is not None:
                            tag = await db.get(Tag, tag_id)
                            if tag:
                                post.tags.append(tag)
                    db.add(
                        PostRevision(
                            post_id=post.id,
                            rev_number=1,
                            title=post.title,
                            body_md=body_md,
                            diff_to_prev=None,
                            changed_by_id=actor_user_id,
                            change_summary="Portable import; source history is not imported",
                        )
                    )
                    counts["posts"] += 1

                for row in entities["pages"]:
                    if conflict == "skip" and row["id"] in conflict_rows:
                        counts["skipped_pages"] += 1
                        continue
                    slug = row["slug"]
                    if slug in occupied_page:
                        if conflict == "remap":
                            slug = _unique_slug(slug, row["id"], occupied_page)
                        elif conflict == "skip":
                            counts["skipped_pages"] += 1
                            continue
                    if slug in occupied_page:
                        slug = _unique_slug(slug, row["id"], occupied_page)
                    body_md = row["body_md"]
                    for old_path, new_path in media_path_map.items():
                        body_md = body_md.replace(f"/media/{old_path}", f"/media/{new_path}")
                    db.add(
                        Page(
                            id=str(uuid.uuid4()),
                            title=row["title"],
                            slug=slug,
                            body_md=body_md,
                            body_html=render_md(body_md),
                            page_type=PageType.CUSTOM,
                            lang=row.get("lang"),
                            is_published=False,
                            visibility=PostVisibility(row["visibility"]),
                            noindex=bool(row.get("noindex", False)),
                            show_in_footer=bool(row.get("show_in_footer", False)),
                        )
                    )
                    counts["pages"] += 1

                if include_comments:
                    from arborpress.comments.policy import resolve_comment_policy
                    from arborpress.comments.service import CommentPolicyError, create_comment
                    from arborpress.core.site_settings import get_section

                    settings = await get_section("comments", db)
                    ordered_comments = _order_comments_by_parent(entities["comments"])
                    for row in ordered_comments:
                        post_id = post_map.get(row["post_id"])
                        if post_id is None:
                            counts["skipped_comments"] += 1
                            continue
                        comment_post = await db.get(Post, post_id)
                        if comment_post is None:
                            continue
                        author_user = (
                            await db.get(User, author_map[row["author_id"]])
                            if row.get("author_id")
                            else None
                        )
                        parent_ref = row.get("parent_id")
                        parent_id = (
                            comment_map.get(parent_ref) if isinstance(parent_ref, str) else None
                        )
                        policy = resolve_comment_policy(comment_post, settings)
                        try:
                            imported_author_name = (
                                author_user.display_name or author_user.username
                                if author_user is not None
                                else row["author_name"]
                            )
                            created = await create_comment(
                                db,
                                post=comment_post,
                                policy=policy,
                                author_name=imported_author_name,
                                author_email=None,
                                body=row["body"],
                                author_user=author_user,
                                parent_id=parent_id,
                                imported=True,
                            )
                        except CommentPolicyError as exc:
                            raise PortabilityError(
                                "A comment failed the destination comment policy."
                            ) from exc
                        comment_map[row["id"]] = str(created.comment.id)
                        counts["comments"] += 1

                receipt = PortableImportReceipt(
                    id=str(uuid.uuid4()),
                    bundle_id=manifest["bundle_id"],
                    bundle_hash=manifest["bundle_hash"],
                    source_build_sha=str(manifest.get("source_build_sha", "unknown"))[:64],
                    imported_by_user_id=actor_user_id,
                    summary=json.dumps(dict(counts), sort_keys=True, separators=(",", ":")),
                )
                db.add(receipt)
                await db.flush()
                await write_audit_event(
                    event_type="portable_content_imported",
                    outcome="success",
                    actor_id=str(actor.id),
                    actor_name=actor.username,
                    target_id=manifest["bundle_id"],
                    detail=json.dumps(dict(counts), sort_keys=True, separators=(",", ":")),
                    db=db,
                )
    except Exception:
        for path in disk_files:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return {
        **plan,
        "imported": dict(counts),
        "extensions_imported": sorted(extension_results),
        "already_imported": False,
    }
