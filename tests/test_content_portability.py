"""Security and semantic roundtrip tests for portable content transfer."""

from __future__ import annotations

import hashlib
import json
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def _png() -> bytes:
    from io import BytesIO

    output = BytesIO()
    Image.new("RGB", (2, 2), (20, 30, 40)).save(output, format="PNG")
    return output.getvalue()


@pytest.mark.asyncio
async def test_export_import_roundtrip_is_safe_and_repeatable(tmp_path: Path, monkeypatch):
    import arborpress.models  # noqa: F401
    from arborpress.content.portability import (
        PortabilityError,
        _json_bytes,
        export_portable,
        import_portable,
        inspect_portable,
    )
    from arborpress.core.db import Base
    from arborpress.models.content import (
        Comment,
        CommentStatus,
        ContentTranslationGroup,
        Media,
        Page,
        PageType,
        Post,
        PostAuthorRelation,
        PostAuthorRole,
        PostStatus,
        PostVisibility,
        Tag,
    )
    from arborpress.models.user import AccountType, User, UserRole

    source_root = tmp_path / "source-media"
    target_root = tmp_path / "target-media"
    source_root.mkdir()
    target_root.mkdir()
    stored_image = source_root / "2025/03/source.png"
    stored_image.parent.mkdir(parents=True)
    stored_image.write_bytes(_png())
    source_settings = SimpleNamespace(
        web=SimpleNamespace(media_dir=source_root, default_lang="de-DE")
    )
    target_settings = SimpleNamespace(
        web=SimpleNamespace(media_dir=target_root, default_lang="de-DE")
    )
    monkeypatch.setattr("arborpress.content.portability.get_settings", lambda: source_settings)
    monkeypatch.setattr("arborpress.media.service.get_settings", lambda: target_settings)

    source_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'source.db'}")
    target_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'target.db'}")
    async with source_engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with target_engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    source_factory = async_sessionmaker(source_engine, expire_on_commit=False)
    target_factory = async_sessionmaker(target_engine, expire_on_commit=False)

    source_user_id = str(uuid.uuid4())
    source_translation_group_id = str(uuid.uuid4())
    async with source_factory() as db:
        source_user = User(
            id=source_user_id,
            username="source-author",
            display_name="Source Author",
            email="must-not-export@example.invalid",
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
        tag = Tag(slug="portable-tag", label="Portable", lang="en")
        private_tag = Tag(slug="private-tag", label="Private", lang="en")
        db.add_all(
            [
                source_user,
                tag,
                private_tag,
                ContentTranslationGroup(id=source_translation_group_id, content_kind="post"),
            ]
        )
        await db.flush()
        post = Post(
            id=str(uuid.uuid4()),
            short_id=uuid.uuid4().hex[:12],
            author_id=source_user_id,
            slug="portable-post",
            title="Portable Post",
            body_md="A body with [image](/media/2025/03/source.png).",
            body_html="<p>A body</p>",
            status=PostStatus.PUBLISHED,
            visibility=PostVisibility.PUBLIC,
            lang="en-GB",
            translation_group_id=source_translation_group_id,
            reading_time_min=1,
        )
        post.tags.append(tag)
        db.add(post)
        await db.flush()
        private_post = Post(
            id=str(uuid.uuid4()),
            short_id=uuid.uuid4().hex[:12],
            author_id=source_user_id,
            slug="private-post",
            title="Private Post",
            body_md="Private body",
            body_html="<p>Private body</p>",
            status=PostStatus.DRAFT,
            visibility=PostVisibility.PRIVATE,
            reading_time_min=1,
        )
        private_post.tags.append(private_tag)
        db.add(private_post)
        await db.flush()
        db.add(
            PostAuthorRelation(
                post_id=post.id,
                user_id=source_user_id,
                role=PostAuthorRole.PRIMARY,
                position=0,
            )
        )
        db.add(
            Page(
                id=str(uuid.uuid4()),
                slug="portable-page",
                title="Portable Page",
                body_md="Page body",
                body_html="<p>Page body</p>",
                page_type=PageType.CUSTOM,
                is_published=True,
                visibility=PostVisibility.PUBLIC,
            )
        )
        db.add(
            Media(
                id=str(uuid.uuid4()),
                uploader_id=source_user_id,
                filename="source.png",
                mime_type="image/png",
                size_bytes=len(_png()),
                storage_path="2025/03/source.png",
            )
        )
        root_comment_id = str(uuid.uuid4())
        db.add(
            Comment(
                id=root_comment_id,
                post_id=post.id,
                author_user_id=source_user_id,
                author_name="Source Author",
                author_email="comment-private@example.invalid",
                body="Approved source comment",
                status=CommentStatus.APPROVED,
                ip_address="192.0.2.3",
                user_agent="private-agent",
                created_at=datetime(2025, 3, 2),
            )
        )
        db.add(
            Comment(
                id=str(uuid.uuid4()),
                post_id=post.id,
                author_user_id=source_user_id,
                author_name="Source Author",
                body="Reply created earlier than its parent",
                status=CommentStatus.APPROVED,
                parent_id=root_comment_id,
                created_at=datetime(2025, 3, 1),
            )
        )
        hidden_parent_id = str(uuid.uuid4())
        db.add(
            Comment(
                id=hidden_parent_id,
                post_id=post.id,
                author_name="Unapproved source commenter",
                body="This pending parent is intentionally not exported",
                status=CommentStatus.PENDING_MODERATION,
            )
        )
        db.add(
            Comment(
                id=str(uuid.uuid4()),
                post_id=post.id,
                author_user_id=source_user_id,
                author_name="Source Author",
                body="Reply to an unexported pending comment",
                status=CommentStatus.APPROVED,
                parent_id=hidden_parent_id,
                created_at=datetime(2025, 3, 3),
            )
        )
        await db.commit()

    package = tmp_path / "portable.zip"
    async with source_factory() as db:
        result = await export_portable(db, package, include_comments=True)
    assert result["counts"]["posts"] == 1
    monkeypatch.setattr("arborpress.content.portability.MAX_RECORDS", 1)
    async with source_factory() as db:
        with pytest.raises(PortabilityError, match="record or count limit"):
            await inspect_portable(db, package)
    monkeypatch.setattr("arborpress.content.portability.MAX_RECORDS", 250_000)
    with zipfile.ZipFile(package) as archive:
        payload = b"".join(archive.read(name) for name in archive.namelist())
    assert b"must-not-export@example.invalid" not in payload
    assert b"comment-private@example.invalid" not in payload
    assert b"192.0.2.3" not in payload
    assert b"private-agent" not in payload
    with zipfile.ZipFile(package) as archive:
        exported_tags = archive.read("data/tags.jsonl").decode()
        assert "portable-tag" in exported_tags
        assert "private-tag" not in exported_tags
        missing_media_package = tmp_path / "missing-media.zip"
        with zipfile.ZipFile(missing_media_package, "w") as broken:
            for name in archive.namelist():
                if not name.startswith("media/"):
                    broken.writestr(name, archive.read(name))

    target_user_id = str(uuid.uuid4())
    operator_id = str(uuid.uuid4())
    async with target_factory() as db:
        target_user = User(
            id=target_user_id,
            username="target-author",
            display_name="Mapped Local Author",
            account_type=AccountType.PUBLIC,
            role=UserRole.AUTHOR,
            is_active=True,
        )
        operator = User(
            id=operator_id,
            username="portable-operator",
            display_name="Portable Operator",
            account_type=AccountType.OPERATIONAL,
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add_all([target_user, operator])
        await db.commit()
        missing_map = await inspect_portable(db, package)
        assert not missing_map["valid"]
        author_ref = missing_map["required_author_mappings"][0]["portable_id"]
        mapping = {author_ref: target_user_id}
        plan = await inspect_portable(db, package, author_map=mapping)
        assert plan["valid"]
        assert await db.scalar(select(Post)) is None
        assert not [path for path in target_root.rglob("*") if path.is_file()]
        with pytest.raises(PortabilityError, match="operational administrator"):
            await import_portable(
                db,
                package,
                actor_user_id=target_user_id,
                author_map=mapping,
                include_comments=True,
            )
        assert await db.scalar(select(Post)) is None
        dry_run = await import_portable(
            db,
            package,
            actor_user_id=operator_id,
            author_map=mapping,
            include_comments=True,
            dry_run=True,
        )
        assert dry_run["valid"]
        assert await db.scalar(select(Post)) is None
        assert not [path for path in target_root.rglob("*") if path.is_file()]
        with pytest.raises(PortabilityError):
            await inspect_portable(db, missing_media_package, author_map=mapping)
        from arborpress.comments.service import CommentPolicyError, create_comment

        async def fail_imported_comment(*args, **kwargs):
            raise CommentPolicyError("synthetic failure after media staging")

        monkeypatch.setattr("arborpress.comments.service.create_comment", fail_imported_comment)
        with pytest.raises(PortabilityError, match="comment failed"):
            await import_portable(
                db,
                package,
                actor_user_id=operator_id,
                author_map=mapping,
                include_comments=True,
            )
        assert await db.scalar(select(Post)) is None
        assert await db.scalar(select(Media)) is None
        assert not [path for path in target_root.rglob("*") if path.is_file()]
        monkeypatch.setattr("arborpress.comments.service.create_comment", create_comment)
        report = await import_portable(
            db,
            package,
            actor_user_id=operator_id,
            author_map=mapping,
            include_comments=True,
        )
        assert report["imported"]["posts"] == 1
        assert report["imported"]["pages"] == 1
        assert report["imported"]["comments"] == 3
        assert (await db.scalar(select(Post))).status == PostStatus.DRAFT
        imported_post = await db.scalar(select(Post))
        assert imported_post is not None
        assert imported_post.author_id == target_user_id
        assert imported_post.translation_group_id
        assert imported_post.translation_group_id != source_translation_group_id
        imported_group = await db.get(ContentTranslationGroup, imported_post.translation_group_id)
        assert imported_group is not None and imported_group.content_kind == "post"
        assert '<a href="/media/' in imported_post.body_html
        assert "source.png" not in imported_post.body_md
        assert "/media/" in imported_post.body_md
        imported_page = await db.scalar(select(Page))
        assert imported_page is not None and imported_page.is_published is False
        imported_comment = await db.scalar(select(Comment).where(Comment.parent_id.is_(None)))
        assert imported_comment is not None
        assert imported_comment.status == CommentStatus.PENDING_MODERATION
        assert imported_comment.author_email is None
        assert imported_comment.ip_address is None
        assert imported_comment.author_name == "Mapped Local Author"
        imported_reply = await db.scalar(
            select(Comment).where(Comment.parent_id == imported_comment.id)
        )
        assert imported_reply is not None
        assert imported_reply.status == CommentStatus.PENDING_MODERATION
        imported_orphan_reply = await db.scalar(
            select(Comment).where(Comment.body == "Reply to an unexported pending comment")
        )
        assert imported_orphan_reply is not None and imported_orphan_reply.parent_id is None
        repeated = await import_portable(
            db,
            package,
            actor_user_id=operator_id,
            author_map=mapping,
        )
        assert repeated["already_imported"] is True

        conflicting_bundle = tmp_path / "conflicting-bundle-id.zip"
        with zipfile.ZipFile(package) as source_archive:
            package_manifest = json.loads(source_archive.read("manifest.json"))
            members = {
                name: source_archive.read(name)
                for name in source_archive.namelist()
                if name != "manifest.json"
            }
        post_lines = members["data/posts.jsonl"].splitlines()
        post_record = json.loads(post_lines[0])
        post_record["title"] = "Changed content with the old bundle id"
        members["data/posts.jsonl"] = _json_bytes(post_record) + b"\n"
        for name, content in members.items():
            package_manifest["files"][name] = {
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        package_manifest["bundle_hash"] = hashlib.sha256(
            _json_bytes(
                {
                    name: record["sha256"]
                    for name, record in sorted(package_manifest["files"].items())
                }
            )
        ).hexdigest()
        with zipfile.ZipFile(conflicting_bundle, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for name, content in members.items():
                target.writestr(name, content)
            target.writestr("manifest.json", _json_bytes(package_manifest))
        with pytest.raises(PortabilityError, match="conflicting content"):
            await inspect_portable(db, conflicting_bundle, author_map=mapping)

        second_package = tmp_path / "portable-second-export.zip"
        async with source_factory() as source_db:
            await export_portable(source_db, second_package, include_comments=True)
        second_unmapped = await inspect_portable(db, second_package)
        second_author_ref = second_unmapped["required_author_mappings"][0]["portable_id"]
        second_mapping = {second_author_ref: target_user_id}
        default_conflict = await inspect_portable(
            db, second_package, author_map=second_mapping, conflict="fail"
        )
        assert not default_conflict["valid"]
        skip_conflict = await inspect_portable(
            db, second_package, author_map=second_mapping, conflict="skip"
        )
        assert skip_conflict["valid"]
        assert skip_conflict["skips"] >= 3
        remap_conflict = await inspect_portable(
            db, second_package, author_map=second_mapping, conflict="remap"
        )
        assert remap_conflict["valid"]
        remapped = await import_portable(
            db,
            second_package,
            actor_user_id=operator_id,
            author_map=second_mapping,
            conflict="remap",
            include_comments=False,
        )
        assert remapped["imported"]["posts"] == 1
        assert await db.scalar(select(Post).where(Post.slug.like("portable-post-import-%")))

    await source_engine.dispose()
    await target_engine.dispose()


@pytest.mark.asyncio
async def test_preflight_rejects_hash_tampering_and_unsafe_archive_names(tmp_path: Path):
    import arborpress.models  # noqa: F401
    from arborpress.content.portability import (
        PortabilityError,
        _json_bytes,
        _records,
        export_portable,
        inspect_portable,
    )
    from arborpress.core.db import Base

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'empty.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    package = tmp_path / "empty.zip"
    async with factory() as db:
        await export_portable(db, package, include_media=False)
        with zipfile.ZipFile(package) as archive:
            manifest = archive.read("manifest.json")
            content = archive.read("data/posts.jsonl")
        tampered = tmp_path / "tampered.zip"
        with zipfile.ZipFile(tampered, "w") as archive:
            archive.writestr("manifest.json", manifest)
            archive.writestr("data/posts.jsonl", content + b"{}\n")
            for name in (
                "data/authors.jsonl",
                "data/tags.jsonl",
                "data/pages.jsonl",
                "data/comments.jsonl",
                "data/media.jsonl",
            ):
                archive.writestr(name, b"")
        with pytest.raises(PortabilityError):
            await inspect_portable(db, tampered)

        traversal = tmp_path / "traversal.zip"
        fake_manifest = {
            "format": "arborpress.portable-content",
            "format_level": 1,
            "bundle_id": str(uuid.uuid4()),
            "files": {"../outside": {"sha256": hashlib.sha256(b"x").hexdigest(), "size": 1}},
            "bundle_hash": "0" * 64,
        }
        with zipfile.ZipFile(traversal, "w") as archive:
            archive.writestr("manifest.json", _json_bytes(fake_manifest))
            archive.writestr("../outside", b"x")
        with pytest.raises(PortabilityError):
            await inspect_portable(db, traversal)

        symlink = tmp_path / "symlink.zip"
        with zipfile.ZipFile(symlink, "w") as archive:
            archive.writestr("manifest.json", b"{}")
            link = zipfile.ZipInfo("data/link")
            link.create_system = 3
            link.external_attr = (0o120777 << 16) | 0xA000
            archive.writestr(link, b"../../outside")
        with pytest.raises(PortabilityError, match="symlink"):
            await inspect_portable(db, symlink)

        records_archive = tmp_path / "record-limit.zip"
        with zipfile.ZipFile(records_archive, "w") as archive:
            archive.writestr("data/records.jsonl", b'{"id":1}\n{"id":2}\n')
        with zipfile.ZipFile(records_archive) as archive, pytest.raises(
            PortabilityError, match="count limit"
        ):
            _records(archive, "data/records.jsonl", max_records=1)

        from arborpress.content.portability import _json_loads

        with pytest.raises(ValueError, match="duplicate JSON"):
            _json_loads('{"key":1,"key":2}')

        unknown_level = tmp_path / "unknown-level.zip"
        with zipfile.ZipFile(package) as source:
            unknown_manifest = json.loads(source.read("manifest.json"))
            unknown_members = {
                name: source.read(name) for name in source.namelist() if name != "manifest.json"
            }
        unknown_manifest["format_level"] = 999
        with zipfile.ZipFile(unknown_level, "w") as target:
            for name, content in unknown_members.items():
                target.writestr(name, content)
            target.writestr("manifest.json", _json_bytes(unknown_manifest))
        with pytest.raises(PortabilityError, match="format level"):
            await inspect_portable(db, unknown_level)

        archive_bomb = tmp_path / "archive-bomb.zip"
        with zipfile.ZipFile(archive_bomb, "w", compression=zipfile.ZIP_DEFLATED) as target:
            target.writestr("large/repeated.json", b"0" * (2 * 1024 * 1024))
            target.writestr("manifest.json", b"{}")
        with pytest.raises(PortabilityError, match="compression ratio"):
            await inspect_portable(db, archive_bomb)

        class TestExporter:
            def portable_plugin_ids(self, capability):
                assert capability.value == "exporter"
                return ("portable-addon",)

            async def export_portable_extension(self, plugin_id, *, context):
                assert plugin_id == "portable-addon"
                return {"records": [{"kind": "example", "value": "bounded"}]}

        class TestImporter:
            def portable_plugin_ids(self, capability):
                assert capability.value == "importer"
                return ("portable-addon",)

        extension_package = tmp_path / "with-extension.zip"
        await export_portable(
            db,
            extension_package,
            include_media=False,
            plugin_manager=TestExporter(),
        )
        without_importer = await inspect_portable(db, extension_package)
        assert not without_importer["valid"]
        with_importer = await inspect_portable(db, extension_package, plugin_manager=TestImporter())
        assert with_importer["valid"]
        assert with_importer["extensions"] == ["portable-addon"]
        dry_run_with_grant = await inspect_portable(
            db,
            extension_package,
            available_importer_ids={"portable-addon"},
        )
        assert dry_run_with_grant["valid"]
    await engine.dispose()
