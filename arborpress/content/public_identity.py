"""Shared language and stable-URL data helpers for public content."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.core.i18n import normalize_language
from arborpress.models.content import ContentSlugHistory


async def remember_old_slugs(
    db: AsyncSession,
    *,
    kind: str,
    content_id: str,
    language: str | None,
    slugs: tuple[str | None, ...],
) -> None:
    """Persist old routes before a slug mutation; reject cross-object collisions."""
    language_key = normalize_language(language) or ""
    for slug in dict.fromkeys(item for item in slugs if item):
        existing = (
            await db.execute(
                select(ContentSlugHistory).where(
                    ContentSlugHistory.content_kind == kind,
                    ContentSlugHistory.language == language_key,
                    ContentSlugHistory.slug == slug,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing.content_id != content_id:
                raise ValueError("This historic slug is already assigned to other content")
            continue
        db.add(
            ContentSlugHistory(
                content_kind=kind,
                content_id=content_id,
                language=language_key,
                slug=slug,
            )
        )


async def historic_slug_owner(
    db: AsyncSession, *, kind: str, slug: str, except_content_id: str | None = None
) -> str | None:
    """Return a different object's reservation for a former public slug."""
    owner = await db.scalar(
        select(ContentSlugHistory.content_id).where(
            ContentSlugHistory.content_kind == kind,
            ContentSlugHistory.slug == slug,
        )
    )
    if owner is not None and owner != except_content_id:
        return str(owner)
    return None


async def set_translation_group(
    db: AsyncSession,
    *,
    content_kind: str,
    lang: str | None,
    group_id: str | None,
    content_id: str | None = None,
) -> str | None:
    """Validate explicit translation membership and return canonical group id."""
    from arborpress.models.content import ContentTranslationGroup, Page, Post

    if group_id in (None, ""):
        return None
    try:
        group_id = str(uuid.UUID(group_id))
    except (ValueError, AttributeError) as exc:
        raise ValueError("Translation group ID must be a UUID") from exc
    normalized = normalize_language(lang)
    if normalized is None:
        raise ValueError("Translation members require a supported BCP-47 content language")
    group = await db.get(ContentTranslationGroup, group_id)
    if group is None:
        group = ContentTranslationGroup(id=group_id, content_kind=content_kind)
        db.add(group)
        await db.flush()
    if group.content_kind != content_kind:
        raise ValueError("Translation groups cannot mix posts and pages")
    model = Post if content_kind == "post" else Page
    membership_filters = [
        model.translation_group_id == group.id,
        model.lang == normalized,
    ]
    if content_id is not None:
        membership_filters.append(model.id != content_id)
    member_id = await db.scalar(select(model.id).where(*membership_filters))
    if member_id is not None:
        raise ValueError("A translation group can contain only one item per language")
    return group.id
