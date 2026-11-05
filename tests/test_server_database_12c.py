"""Disposable PostgreSQL/MariaDB migration, persistence and recovery drill."""

from __future__ import annotations

import os
import secrets
import uuid
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from arborpress.backups.encryption import BackupKey
from arborpress.backups.restore import plan_restore, validate_restore_staging
from arborpress.backups.service import create_backup, verify_backup
from arborpress.core.db_capabilities import detect_capabilities
from arborpress.core.migrations import downgrade_database, schema_status, upgrade_database
from arborpress.runtime.paths import ArborPressPaths, ensure_instance_layout


@pytest.mark.asyncio
@pytest.mark.parametrize("start_revision", (
    "0012_federation_signature_summaries", "0013_oidc_external_identities",
    "0014_oidc_provider_lifecycle", "0015_oauth_oidc_authorization_server",
    "0016_oauth_resource_idempotency", "0017_search_indexes",
))
async def test_server_database_release_drill(tmp_path: Path, start_revision: str) -> None:
    database_url = os.environ.get("ARBORPRESS_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set ARBORPRESS_TEST_DATABASE_URL to a disposable server database")

    import arborpress.models  # noqa: F401
    from arborpress.models.content import Post, PostStatus, PostVisibility
    from arborpress.models.oidc import OAuthClient, OIDCSubject
    from arborpress.models.user import AccountType, User, UserRole

    engine = create_async_engine(database_url)
    paths = ArborPressPaths.from_prefix(tmp_path / "server-db-drill")
    ensure_instance_layout(paths)
    try:
        fresh = await upgrade_database(engine)
        assert fresh.is_current
        assert (await schema_status(engine)).is_current

        capabilities = await detect_capabilities(engine)
        assert capabilities.engine_name in {"postgresql", "mysql"}
        if capabilities.engine_name == "postgresql":
            assert capabilities.major >= 16
        else:
            assert "MariaDB" in capabilities.version_string
            assert (capabilities.major, capabilities.minor) >= (11, 4)

        await downgrade_database(start_revision, engine)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        user_id = str(uuid.uuid4())
        suffix = secrets.token_hex(6)
        async with session_factory() as db:
            user = User(
                id=user_id,
                username=f"drill-{suffix}",
                display_name="Database release drill",
                account_type=AccountType.OPERATIONAL,
                role=UserRole.ADMIN,
                is_active=True,
            )
            post = Post(
                id=str(uuid.uuid4()),
                short_id=secrets.token_hex(6),
                author_id=user_id,
                slug=f"release-drill-{suffix}",
                title="Persisted content",
                body_md="Recovery fixture",
                body_html="<p>Recovery fixture</p>",
                status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
            )
            db.add_all((user, post))
            await db.commit()

        upgraded = await upgrade_database(engine)
        assert upgraded.is_current
        async with session_factory() as db:
            assert await db.get(User, user_id) is not None
            assert await db.scalar(
                select(func.count()).select_from(Post).where(Post.author_id == user_id)
            ) == 1
            db.add_all(
                (
                    OAuthClient(
                        client_id=f"drill-{suffix}",
                        name="Release drill client",
                        client_type="public",
                        secret_hash=None,
                        redirect_uris='["https://client.example/callback"]',
                        allowed_scopes='["openid","profile"]',
                        enabled=True,
                    ),
                    OIDCSubject(
                        id=str(uuid.uuid4()),
                        user_id=user_id,
                        subject=secrets.token_hex(24),
                    ),
                )
            )
            await db.commit()

        key = BackupKey("keyfile", secrets.token_bytes(32))
        backup = await create_backup(
            paths=paths,
            engine=engine,
            components=("database",),
            key=key,
        )
        verification = verify_backup(backup.backup_id, paths, key=key)
        assert verification.verification_level == "full-cryptographic"
        plan = await plan_restore(
            backup.backup_id,
            paths=paths,
            engine=engine,
            components=("database",),
            key=key,
        )
        assert plan.compatible
        await validate_restore_staging(plan, paths=paths, engine=engine, key=key)
        async with session_factory() as db:
            assert await db.get(User, user_id) is not None
    finally:
        await engine.dispose()
