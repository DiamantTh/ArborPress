"""Public content search shared by SSR and the public API.

Search is query-time against the authoritative content tables. PostgreSQL and
MariaDB use their native full-text indexes where available; SQLite and any
provider/index failure use a bounded, parameterized LIKE fallback. There is
no separately maintained document index to become stale.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, func, literal, select, text, union_all
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from arborpress.core.db_capabilities import DBCapabilities, get_capabilities
from arborpress.models.content import Page, Post, PostStatus, PostVisibility

log = logging.getLogger("arborpress.search")

MAX_QUERY_LENGTH = 200
MAX_PAGE = 10_000
MAX_PER_PAGE = 50
DEFAULT_PER_PAGE = 20


@dataclass(frozen=True)
class SearchHit:
    kind: str
    object_id: str
    slug: str
    title: str
    excerpt: str | None
    lang: str | None
    updated_at: datetime | None


@dataclass(frozen=True)
class SearchResult:
    query: str
    items: list[SearchHit]
    page: int
    per_page: int
    total: int
    provider: str
    degraded: bool = False
    diagnostic: str = "ok"


def normalize_query(query: str) -> str:
    value = query.strip()
    if len(value) > MAX_QUERY_LENGTH:
        raise ValueError(f"query must be at most {MAX_QUERY_LENGTH} characters")
    return value


def normalize_pagination(page: int, per_page: int) -> tuple[int, int]:
    if page < 1 or page > MAX_PAGE:
        raise ValueError(f"page must be between 1 and {MAX_PAGE}")
    if per_page < 1:
        raise ValueError("per_page must be a positive integer")
    return page, min(per_page, MAX_PER_PAGE)


def _provider(caps: DBCapabilities | None, configured: str) -> tuple[str, bool, str]:
    """Choose a provider implemented by this service, never a health-only adapter."""
    engine = caps.engine_name if caps else ""
    if engine == "postgresql":
        native = "pg_fts"
    elif engine == "mysql":
        native = "mariadb_fulltext"
    else:
        native = "like"
    if configured in {"meilisearch", "typesense", "elasticsearch", "manticore"}:
        # Capability detection currently checks reachability only; the service
        # has no document sync/query adapter for these providers.
        return native, True, "external_adapter_unavailable_using_database_search"
    if configured == "sqlite_fts5":
        return "like", True, "sqlite_fts5_index_not_maintained_using_like"
    if configured in {"pg_fts", "mariadb_fulltext"} and configured != native:
        return "like", True, "configured_provider_incompatible_with_database_using_like"
    if configured == "fallback":
        return "like", False, "ok"
    return native, False, "ok"


def search_diagnostics(configured: str = "auto") -> dict[str, Any]:
    try:
        caps = get_capabilities()
    except RuntimeError:
        caps = None
    provider, degraded, diagnostic = _provider(caps, configured)
    return {
        "configured_provider": configured,
        "provider": provider,
        "healthy": not degraded,
        "degraded": degraded,
        "diagnostic": diagnostic,
        "database": caps.engine_name if caps else "unknown",
        "index_mode": (
            "database_index"
            if provider in {"pg_fts", "mariadb_fulltext"}
            else "parameterized_like"
        ),
    }


async def search_health(engine: AsyncEngine, configured: str = "auto") -> dict[str, Any]:
    """Check database connectivity and whether the selected native indexes exist."""
    dialect = engine.dialect.name
    provider, degraded, diagnostic = _provider(DBCapabilities(engine_name=dialect), configured)
    status: dict[str, Any] = {
        "configured_provider": configured,
        "provider": provider,
        "healthy": not degraded,
        "degraded": degraded,
        "diagnostic": diagnostic,
        "database": dialect,
        "index_mode": (
            "database_index"
            if provider in {"pg_fts", "mariadb_fulltext"}
            else "parameterized_like"
        ),
    }
    index_healthy: bool | None = None
    if status["provider"] == "pg_fts":
        async with engine.connect() as connection:
            count = await connection.scalar(
                text(
                    "SELECT count(*) FROM pg_indexes "
                    "WHERE schemaname = current_schema() "
                    "AND indexname IN ('ix_posts_search_vector', 'ix_pages_search_vector')"
                )
            )
        index_healthy = int(count or 0) == 2
    elif status["provider"] == "mariadb_fulltext":
        async with engine.connect() as connection:
            count = await connection.scalar(
                text(
                    "SELECT count(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS "
                    "WHERE TABLE_SCHEMA = DATABASE() AND INDEX_NAME IN "
                    "('ix_posts_search_fulltext', 'ix_pages_search_fulltext')"
                )
            )
        index_healthy = int(count or 0) == 2
    if index_healthy is False:
        status["healthy"] = False
        status["degraded"] = True
        status["index_healthy"] = False
        if dialect == "mysql":
            status["provider"] = "like"
            status["index_mode"] = "parameterized_like"
            status["diagnostic"] = "native_index_missing_using_like_fallback"
        else:
            status["index_mode"] = "query_without_index"
            status["diagnostic"] = "native_index_missing_query_time_scan"
    else:
        status["index_healthy"] = index_healthy
    status["database"] = dialect
    return status


def _condition(model: type[Post] | type[Page], provider: str, query: str) -> Any:
    if provider == "pg_fts":
        document = func.to_tsvector(
            "simple",
            func.coalesce(model.title, "") + " " + func.coalesce(model.body_md, ""),
        )
        return document.op("@@")(func.plainto_tsquery("simple", query))
    if provider == "mariadb_fulltext":
        table = "posts" if model is Post else "pages"
        return text(
            f"MATCH({table}.title, {table}.body_md) "
            "AGAINST(:search_query IN NATURAL LANGUAGE MODE)"
        ).bindparams(search_query=query)
    return model.title.contains(query, autoescape=True) | model.body_md.contains(
        query, autoescape=True
    )


def _base(model: type[Post] | type[Page]) -> tuple[Any, ...]:
    if model is Post:
        return (
            Post.status == PostStatus.PUBLISHED,
            Post.visibility == PostVisibility.PUBLIC,
            Post.noindex.is_(False),
        )
    return (
        Page.is_published.is_(True),
        Page.visibility == PostVisibility.PUBLIC,
        Page.noindex.is_(False),
    )


def _union(query: str, provider: str, language: str | None) -> Any:
    post_filters = [*_base(Post), _condition(Post, provider, query)]
    page_filters = [*_base(Page), _condition(Page, provider, query)]
    if language:
        post_filters.append(Post.lang == language)
        page_filters.append(Page.lang == language)
    post_select = select(
        literal("post").label("kind"),
        cast(Post.id, String).label("object_id"),
        Post.slug.label("slug"),
        Post.title.label("title"),
        Post.excerpt.label("excerpt"),
        Post.lang.label("lang"),
        Post.updated_at.label("updated_at"),
    ).where(*post_filters)
    page_select = select(
        literal("page").label("kind"),
        cast(Page.id, String).label("object_id"),
        Page.slug.label("slug"),
        Page.title.label("title"),
        cast(literal(None), String).label("excerpt"),
        Page.lang.label("lang"),
        Page.updated_at.label("updated_at"),
    ).where(*page_filters)
    return union_all(post_select, page_select).subquery("public_search")


async def search_public_content(
    db: AsyncSession,
    query: str,
    *,
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
    language: str | None = None,
    configured_provider: str = "auto",
    capabilities: DBCapabilities | None = None,
) -> SearchResult:
    """Search only public, published, indexable posts and pages."""
    normalized = normalize_query(query)
    page, per_page = normalize_pagination(page, per_page)
    if language is not None:
        language = language.strip()
        if not language or len(language) > 8:
            raise ValueError("lang must contain between 1 and 8 characters")
    if not normalized:
        provider, degraded, diagnostic = _provider(capabilities, configured_provider)
        return SearchResult(normalized, [], page, per_page, 0, provider, degraded, diagnostic)

    if capabilities is None:
        try:
            capabilities = get_capabilities()
        except RuntimeError:
            capabilities = None
    provider, degraded, diagnostic = _provider(capabilities, configured_provider)

    async def run(selected: str) -> tuple[list[SearchHit], int]:
        documents = _union(normalized, selected, language)
        total = int((await db.execute(select(func.count()).select_from(documents))).scalar_one())
        rows = (
            await db.execute(
                select(documents)
                .order_by(documents.c.updated_at.desc(), documents.c.kind, documents.c.slug)
                .offset((page - 1) * per_page)
                .limit(per_page)
            )
        ).all()
        items = [SearchHit(**dict(row._mapping)) for row in rows]
        return items, total

    if provider != "like":
        try:
            # Isolate a failed optional/native query so its transaction state
            # cannot poison the deterministic database fallback.
            async with db.begin_nested():
                items, total = await run(provider)
            return SearchResult(
                normalized, items, page, per_page, total, provider, degraded, diagnostic
            )
        except Exception as exc:
            log.warning(
                "Search provider %s failed (%s); using LIKE fallback",
                provider,
                type(exc).__name__,
            )
            provider = "like"
            degraded = True
            diagnostic = "provider_query_failed_using_like"

    items, total = await run("like")
    return SearchResult(normalized, items, page, per_page, total, provider, degraded, diagnostic)
