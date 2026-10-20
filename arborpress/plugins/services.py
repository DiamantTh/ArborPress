"""Capability-scoped Core services exposed through the plugin RPC dispatcher."""

from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from arborpress.models.content import (
    Comment,
    CommentStatus,
    Post,
    PostStatus,
    PostVisibility,
)
from arborpress.models.plugin import PluginJob, PluginStorageEntry

MAX_STORAGE_KEY = 128
MAX_STORAGE_VALUE_BYTES = 64 * 1024
MAX_PLUGIN_ENTRIES = 1000
MAX_TOTAL_PLUGIN_STORAGE_BYTES = 8 * 1024 * 1024
MAX_JOB_PAYLOAD_BYTES = 64 * 1024
MAX_PENDING_JOBS = 500
MAX_JOB_ATTEMPTS = 8
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_TASK_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class PluginServiceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


async def _audit_plugin_event(
    db: AsyncSession, event_type: str, plugin_id: str, target_id: str, detail: str
) -> None:
    from arborpress.core.audit import write_audit_event

    await write_audit_event(
        event_type=event_type,
        outcome="success",
        actor_id=None,
        actor_name=f"plugin:{plugin_id}"[:32],
        target_id=target_id,
        detail=detail,
        db=db,
    )


def _json_size(value: Any) -> int:
    try:
        _validate_json(value)
        return len(
            json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise PluginServiceError("invalid_params", "value must be JSON-compatible") from exc


def _validate_json(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("JSON nesting is too deep")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON number must be finite")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _validate_json(item, depth + 1)
        return
    raise TypeError("unsupported JSON value")


def _key(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_STORAGE_KEY
        or not _KEY_RE.fullmatch(value)
    ):
        raise PluginServiceError("invalid_params", "invalid storage key")
    return value


class PluginCoreServices:
    """Every operation is scoped to the trusted process-channel plugin id."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def storage_get(self, plugin_id: str, params: dict[str, Any]) -> dict[str, Any]:
        key = _key(params.get("key"))
        async with self.sessions() as db:
            row = await db.scalar(
                select(PluginStorageEntry).where(
                    PluginStorageEntry.plugin_id == plugin_id, PluginStorageEntry.key == key
                )
            )
            return {
                "found": row is not None,
                "value": row.value if row else None,
                "revision": row.revision if row else None,
            }

    async def storage_set(self, plugin_id: str, params: dict[str, Any]) -> dict[str, Any]:
        key = _key(params.get("key"))
        value = params.get("value")
        size = _json_size(value)
        if size > MAX_STORAGE_VALUE_BYTES:
            raise PluginServiceError("resource_limit", "storage value exceeds the per-value limit")
        expected = params.get("expected_revision")
        if expected is not None and (
            not isinstance(expected, int) or isinstance(expected, bool) or expected < 1
        ):
            raise PluginServiceError(
                "invalid_params", "expected_revision must be a positive integer"
            )
        async with self.sessions() as db:
            async with db.begin():
                row = await db.scalar(
                    select(PluginStorageEntry)
                    .where(PluginStorageEntry.plugin_id == plugin_id, PluginStorageEntry.key == key)
                    .with_for_update()
                )
                if row is None:
                    if expected is not None:
                        raise PluginServiceError(
                            "revision_conflict", "storage entry does not exist"
                        )
                    count = await db.scalar(
                        select(func.count())
                        .select_from(PluginStorageEntry)
                        .where(PluginStorageEntry.plugin_id == plugin_id)
                    )
                    existing_values = (
                        await db.scalars(
                            select(PluginStorageEntry.value).where(
                                PluginStorageEntry.plugin_id == plugin_id
                            )
                        )
                    ).all()
                    total = sum(_json_size(item) for item in existing_values)
                    if (
                        int(count or 0) >= MAX_PLUGIN_ENTRIES
                        or total + size > MAX_TOTAL_PLUGIN_STORAGE_BYTES
                    ):
                        raise PluginServiceError("resource_limit", "plugin storage quota exceeded")
                    row = PluginStorageEntry(plugin_id=plugin_id, key=key, value=value, revision=1)
                    db.add(row)
                else:
                    if expected != row.revision:
                        raise PluginServiceError(
                            "revision_conflict", "storage entry revision changed"
                        )
                    other_values = (
                        await db.scalars(
                            select(PluginStorageEntry.value).where(
                                PluginStorageEntry.plugin_id == plugin_id,
                                PluginStorageEntry.key != key,
                            )
                        )
                    ).all()
                    if (
                        sum(_json_size(item) for item in other_values) + size
                        > MAX_TOTAL_PLUGIN_STORAGE_BYTES
                    ):
                        raise PluginServiceError("resource_limit", "plugin storage quota exceeded")
                    updated: Any = await db.execute(
                        update(PluginStorageEntry)
                        .where(
                            PluginStorageEntry.id == row.id,
                            PluginStorageEntry.revision == expected,
                        )
                        .values(value=value, revision=PluginStorageEntry.revision + 1)
                    )
                    if updated.rowcount != 1:
                        raise PluginServiceError(
                            "revision_conflict", "storage entry revision changed"
                        )
                    row.revision = expected + 1
                await db.flush()
                return {"revision": row.revision}

    async def storage_delete(self, plugin_id: str, params: dict[str, Any]) -> dict[str, Any]:
        key = _key(params.get("key"))
        expected = params.get("expected_revision")
        if expected is not None and (
            not isinstance(expected, int) or isinstance(expected, bool) or expected < 1
        ):
            raise PluginServiceError("invalid_params", "expected_revision must be positive")
        async with self.sessions() as db:
            async with db.begin():
                row = await db.scalar(
                    select(PluginStorageEntry)
                    .where(PluginStorageEntry.plugin_id == plugin_id, PluginStorageEntry.key == key)
                    .with_for_update()
                )
                if row is None:
                    return {"deleted": False}
                if expected is not None and expected != row.revision:
                    raise PluginServiceError("revision_conflict", "storage entry revision changed")
                await db.delete(row)
                return {"deleted": True}

    async def storage_list(self, plugin_id: str, params: dict[str, Any]) -> dict[str, Any]:
        prefix = params.get("prefix", "")
        limit = params.get("limit", 100)
        if (
            not isinstance(prefix, str)
            or len(prefix) > MAX_STORAGE_KEY
            or not isinstance(limit, int)
            or not 1 <= limit <= 500
        ):
            raise PluginServiceError("invalid_params", "invalid list prefix or limit")
        after = params.get("after")
        if after is not None and not isinstance(after, str):
            raise PluginServiceError("invalid_params", "after must be a string")
        async with self.sessions() as db:
            query = select(PluginStorageEntry).where(
                PluginStorageEntry.plugin_id == plugin_id,
                PluginStorageEntry.key.startswith(prefix),
            )
            if after:
                query = query.where(PluginStorageEntry.key > after)
            rows = (await db.scalars(query.order_by(PluginStorageEntry.key).limit(limit + 1))).all()
            page = rows[:limit]
            return {
                "items": [{"key": row.key, "revision": row.revision} for row in page],
                "next": page[-1].key if len(rows) > limit and page else None,
            }

    async def content_get(self, _plugin_id: str, params: dict[str, Any]) -> dict[str, Any]:
        content_id = params.get("id")
        if not isinstance(content_id, str) or len(content_id) > 36:
            raise PluginServiceError("invalid_params", "invalid content id")
        async with self.sessions() as db:
            post = await db.scalar(
                select(Post).where(
                    Post.id == content_id,
                    Post.status == PostStatus.PUBLISHED,
                    Post.visibility == PostVisibility.PUBLIC,
                )
            )
            if post is None:
                return {"found": False}
            return {
                "found": True,
                "content": {
                    "id": post.id,
                    "type": "post",
                    "slug": post.slug,
                    "title": post.title,
                    "excerpt": post.excerpt,
                    "published_at": post.published_at.isoformat() if post.published_at else None,
                },
            }

    async def content_list(self, _plugin_id: str, params: dict[str, Any]) -> dict[str, Any]:
        limit = params.get("limit", 50)
        offset = params.get("offset", 0)
        if (
            not isinstance(limit, int)
            or not 1 <= limit <= 100
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise PluginServiceError("invalid_params", "invalid pagination")
        async with self.sessions() as db:
            rows = (
                await db.scalars(
                    select(Post)
                    .where(
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                    .order_by(Post.created_at.desc(), Post.id)
                    .offset(offset)
                    .limit(limit)
                )
            ).all()
            return {
                "items": [
                    {
                        "id": row.id,
                        "type": "post",
                        "slug": row.slug,
                        "title": row.title,
                        "excerpt": row.excerpt,
                        "published_at": row.published_at.isoformat() if row.published_at else None,
                    }
                    for row in rows
                ]
            }

    async def comments_list(self, _plugin_id: str, params: dict[str, Any]) -> dict[str, Any]:
        content_id = params.get("content_id")
        limit = params.get("limit", 100)
        if not isinstance(content_id, str) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise PluginServiceError("invalid_params", "invalid content id or limit")
        async with self.sessions() as db:
            rows = (
                await db.scalars(
                    select(Comment)
                    .join(Post, Post.id == Comment.post_id)
                    .where(
                        Comment.post_id == content_id,
                        Comment.status == CommentStatus.APPROVED,
                        Post.status == PostStatus.PUBLISHED,
                        Post.visibility == PostVisibility.PUBLIC,
                    )
                    .order_by(Comment.created_at, Comment.id)
                    .limit(limit)
                )
            ).all()
            return {
                "items": [
                    {
                        "id": row.id,
                        "post_id": row.post_id,
                        "parent_id": row.parent_id,
                        "body": row.body,
                        "display_name": row.author_name,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in rows
                ]
            }

    async def schedule_job(
        self, plugin_id: str, params: dict[str, Any], declared_tasks: tuple[str, ...]
    ) -> dict[str, Any]:
        task = params.get("task")
        payload = params.get("payload", {})
        delay = params.get("delay_seconds", 0)
        idem = params.get("idempotency_key")
        if not isinstance(task, str) or task not in declared_tasks or not _TASK_RE.fullmatch(task):
            raise PluginServiceError("invalid_params", "task is not declared by this plugin")
        if not isinstance(payload, dict) or _json_size(payload) > MAX_JOB_PAYLOAD_BYTES:
            raise PluginServiceError("resource_limit", "invalid or oversized task payload")
        if (
            not isinstance(delay, (int, float))
            or isinstance(delay, bool)
            or not 0 <= delay <= 366 * 86400
        ):
            raise PluginServiceError("invalid_params", "invalid job delay")
        if idem is not None and (not isinstance(idem, str) or not idem or len(idem) > 128):
            raise PluginServiceError("invalid_params", "invalid idempotency key")
        async with self.sessions() as db:
            async with db.begin():
                count = await db.scalar(
                    select(func.count())
                    .select_from(PluginJob)
                    .where(
                        PluginJob.plugin_id == plugin_id,
                        PluginJob.status.in_(["pending", "retry", "running"]),
                    )
                )
                if int(count or 0) >= MAX_PENDING_JOBS:
                    raise PluginServiceError("resource_limit", "plugin pending-job quota exceeded")
                if idem:
                    existing = await db.scalar(
                        select(PluginJob).where(
                            PluginJob.plugin_id == plugin_id,
                            PluginJob.task == task,
                            PluginJob.idempotency_key == idem,
                        )
                    )
                    if existing:
                        return {"job_id": existing.id, "status": existing.status, "duplicate": True}
                row = PluginJob(
                    plugin_id=plugin_id,
                    task=task,
                    payload=payload,
                    run_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=delay),
                    idempotency_key=idem,
                )
                db.add(row)
                await db.flush()
                await _audit_plugin_event(
                    db,
                    "plugin_job_scheduled",
                    plugin_id,
                    row.id,
                    f"task={task}",
                )
                return {"job_id": row.id, "status": row.status, "duplicate": False}

    async def claim_due_job(self, now: datetime | None = None) -> PluginJob | None:
        """Atomically lease one due job; concurrent workers skip locked rows."""
        moment = now or datetime.now(UTC).replace(tzinfo=None)
        async with self.sessions() as db:
            async with db.begin():
                candidate = await db.scalar(
                    select(PluginJob)
                    .where(
                        or_(
                            and_(
                                PluginJob.status.in_(["pending", "retry"]),
                                PluginJob.run_at <= moment,
                            ),
                            and_(PluginJob.status == "running", PluginJob.lease_until <= moment),
                        )
                    )
                    .order_by(PluginJob.run_at, PluginJob.id)
                    .with_for_update(skip_locked=True)
                    .limit(1)
                )
                if candidate is None:
                    return None
                previous_status = candidate.status
                previous_lease = candidate.lease_until
                if candidate.attempts >= min(candidate.max_attempts, MAX_JOB_ATTEMPTS):
                    await db.execute(
                        update(PluginJob)
                        .where(
                            PluginJob.id == candidate.id,
                            PluginJob.status == previous_status,
                            PluginJob.lease_until == previous_lease,
                        )
                        .values(status="dead", lease_until=None, last_error="lease_expired")
                    )
                    return None
                claimed: Any = await db.execute(
                    update(PluginJob)
                    .where(
                        PluginJob.id == candidate.id,
                        PluginJob.status == previous_status,
                        PluginJob.lease_until == previous_lease,
                    )
                    .values(
                        status="running",
                        attempts=PluginJob.attempts + 1,
                        lease_until=moment + timedelta(minutes=5),
                    )
                )
                if claimed.rowcount != 1:
                    return None
                await db.flush()
                return await db.get(PluginJob, candidate.id)

    async def finish_job(self, job_id: str, *, error: str | None = None) -> None:
        async with self.sessions() as db:
            async with db.begin():
                row = await db.scalar(
                    select(PluginJob).where(PluginJob.id == job_id).with_for_update()
                )
                if row is None or row.status != "running":
                    raise PluginServiceError("conflict", "job is not leased")
                row.lease_until = None
                if error is None:
                    row.status = "succeeded"
                    row.last_error = None
                elif row.attempts >= min(row.max_attempts, MAX_JOB_ATTEMPTS):
                    row.status = "dead"
                    row.last_error = error[:128]
                    await _audit_plugin_event(
                        db,
                        "plugin_job_dead",
                        row.plugin_id,
                        row.id,
                        f"task={row.task};error={error[:64]}",
                    )
                else:
                    row.status = "retry"
                    row.last_error = error[:128]
                    row.run_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(
                        seconds=min(3600, 2**row.attempts * 5)
                    )

    async def defer_job(self, job_id: str, delay_seconds: int = 60) -> None:
        """Release work without consuming an attempt when a plugin is stopped."""
        async with self.sessions() as db:
            async with db.begin():
                row = await db.scalar(
                    select(PluginJob).where(PluginJob.id == job_id).with_for_update()
                )
                if row is None or row.status != "running":
                    return
                row.status = "pending"
                row.attempts = max(0, row.attempts - 1)
                row.lease_until = None
                row.run_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(
                    seconds=delay_seconds
                )

    async def cancel_job(self, job_id: str, reason: str = "capability_revoked") -> None:
        async with self.sessions() as db:
            async with db.begin():
                row = await db.scalar(
                    select(PluginJob).where(PluginJob.id == job_id).with_for_update()
                )
                if row is not None and row.status == "running":
                    row.status = "cancelled"
                    row.lease_until = None
                    row.last_error = reason[:128]
                    await _audit_plugin_event(
                        db,
                        "plugin_job_cancelled",
                        row.plugin_id,
                        row.id,
                        f"task={row.task};reason={reason[:64]}",
                    )
