"""Exercise supported update entry points with existing user and content data."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from arborpress.core.migrations import downgrade_database, upgrade_database
from arborpress.models.content import Post, PostStatus, PostVisibility
from arborpress.models.user import User

START_REVISIONS = (
    '0012_federation_signature_summaries',
    '0013_oidc_external_identities',
    '0014_oidc_provider_lifecycle',
    '0015_oauth_oidc_authorization_server',
    '0016_oauth_resource_idempotency',
    '0017_search_indexes',
)


@pytest.mark.parametrize('start_revision', START_REVISIONS)
async def test_sqlite_upgrade_preserves_existing_identity_and_content(
    tmp_path: Path, start_revision: str,
) -> None:
    engine = create_async_engine(f'sqlite+aiosqlite:///{tmp_path / "upgrade.db"}')
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        await upgrade_database(engine)
        await downgrade_database(start_revision, engine)
        user_id = str(uuid.uuid4())
        post_id = str(uuid.uuid4())
        async with factory() as db:
            db.add(User(id=user_id, username='upgrade-author', display_name='Original identity'))
            await db.flush()
            db.add(Post(
                id=post_id, short_id='upgrade-post', slug='preserved-post',
                author_id=user_id, title='Preserved title', body_md='Preserved body',
                body_html='<p>Preserved body</p>', status=PostStatus.PUBLISHED,
                visibility=PostVisibility.PUBLIC,
            ))
            await db.commit()
        assert (await upgrade_database(engine)).is_current
        async with factory() as db:
            user = await db.get(User, user_id)
            post = await db.scalar(select(Post).where(Post.id == post_id))
            assert user is not None and user.display_name == 'Original identity'
            assert post is not None and post.author_id == user_id
            assert post.body_md == 'Preserved body'
    finally:
        await engine.dispose()
