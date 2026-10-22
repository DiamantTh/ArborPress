"""Operator actions and bounded retention for federation transport metadata."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from arborpress.federation.policy import domain_allowed
from arborpress.federation.security import (
    normalize_domain,
    validate_remote_url,
    validate_remote_url_syntax,
)
from arborpress.models.federation import (
    FederationActorKeyHistory,
    FederationDelivery,
    FederationInboxActivity,
    FederationSignatureFailureDaily,
    RemoteActor,
    RemoteActorKey,
)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


_SIGNATURE_FAILURE_CATEGORIES = frozenset(
    {
        "rfc9421_not_supported",
        "missing_or_malformed_signature",
        "invalid_key_id",
        "remote_key_unavailable",
        "missing_signature",
        "malformed_signature",
        "unsupported_signature_algorithm",
        "invalid_signed_header_name",
        "required_component_not_covered",
        "required_header_missing",
        "invalid_date",
        "stale_date",
        "invalid_digest",
        "digest_mismatch",
        "signed_header_missing",
        "unsafe_public_key",
        "signature_invalid",
        "actor_mismatch",
    }
)


async def record_signature_failure(
    db: AsyncSession, reason: str, *, now: datetime | None = None
) -> None:
    """Increment a bounded daily class counter without retaining peer identity."""
    from sqlalchemy.exc import IntegrityError

    bucket = (now or _now()).date()
    category = reason if reason in _SIGNATURE_FAILURE_CATEGORIES else "other"
    row = (
        await db.execute(
            select(FederationSignatureFailureDaily)
            .where(
                FederationSignatureFailureDaily.date_bucket == bucket,
                FederationSignatureFailureDaily.category == category,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is not None:
        row.failure_count += 1
        await db.flush()
        return
    try:
        async with db.begin_nested():
            db.add(
                FederationSignatureFailureDaily(
                    date_bucket=bucket, category=category, failure_count=1
                )
            )
            await db.flush()
    except IntegrityError:
        row = (
            await db.execute(
                select(FederationSignatureFailureDaily)
                .where(
                    FederationSignatureFailureDaily.date_bucket == bucket,
                    FederationSignatureFailureDaily.category == category,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise
        row.failure_count += 1
        await db.flush()


async def retry_delivery(db: AsyncSession, delivery_id: str) -> FederationDelivery:
    """Requeue the same immutable activity after a fresh policy and SSRF check."""
    from arborpress.core.site_settings import get_section

    delivery = await db.get(FederationDelivery, delivery_id)
    if delivery is None or delivery.status not in {"dead", "retry"}:
        raise ValueError("delivery_not_retryable")
    settings = await get_section("federation", db)
    host, _ = validate_remote_url_syntax(delivery.target_inbox)
    domain = normalize_domain(delivery.domain)
    if host != domain or not await domain_allowed(db, domain, settings):
        raise ValueError("delivery_domain_blocked")
    await validate_remote_url(delivery.target_inbox)
    delivery.status = "pending"
    delivery.attempts = 0
    delivery.next_attempt_at = _now()
    delivery.lease_owner = None
    delivery.lease_until = None
    delivery.response_status = None
    delivery.last_error = None
    await db.flush()
    return delivery


async def cancel_delivery(db: AsyncSession, delivery_id: str) -> FederationDelivery:
    delivery = await db.get(FederationDelivery, delivery_id)
    if delivery is None or delivery.status in {"delivered", "cancelled"}:
        raise ValueError("delivery_not_cancellable")
    delivery.status = "cancelled"
    delivery.lease_owner = None
    delivery.lease_until = None
    await db.flush()
    return delivery


async def reprocess_inbox(db: AsyncSession, intake_id: str) -> FederationInboxActivity:
    """Reprocess only previously authenticated activities with transient failures."""
    item = await db.get(FederationInboxActivity, intake_id)
    if (
        item is None
        or item.processing_state != "failed"
        or item.last_error != "internal_processing_error"
    ):
        raise ValueError("inbox_item_not_reprocessable")
    item.processing_state = "received"
    item.attempt_count = 0
    item.received_at = _now()
    item.last_error = None
    item.processed_at = None
    item.lease_owner = None
    item.lease_until = None
    await db.flush()
    return item


async def refresh_remote_actor(
    db: AsyncSession, remote_actor_id: str, *, signing_actor_id: str | None = None
) -> RemoteActor:
    """Refresh a cached actor through the existing guarded fetcher and owner checks."""
    from arborpress.core.site_settings import get_section
    from arborpress.federation.remote import fetch_remote_actor

    actor = await db.get(RemoteActor, remote_actor_id)
    if actor is None:
        raise ValueError("remote_actor_not_found")
    if signing_actor_id is not None:
        from arborpress.models.federation import LocalFederationActor

        signer = await db.get(LocalFederationActor, signing_actor_id)
        if signer is None or not signer.enabled or signer.current_keypair_id is None:
            raise ValueError("signed_fetch_actor_unavailable")
    return await fetch_remote_actor(
        db, actor.actor_uri, await get_section("federation", db), force=True,
        signing_actor_id=signing_actor_id
    )


async def cleanup_transport_metadata(
    db: AsyncSession,
    *,
    delivered_days: int = 90,
    dead_days: int = 365,
    inbox_payload_days: int = 30,
    now: datetime | None = None,
) -> dict[str, int]:
    """Bound transport metadata without removing activity/idempotency history."""
    current = now or _now()
    delivered_before = current - timedelta(days=max(30, min(delivered_days, 3650)))
    dead_before = current - timedelta(days=max(180, min(dead_days, 3650)))
    payload_before = current - timedelta(days=max(7, min(inbox_payload_days, 3650)))

    old_delivered = list(
        (
            await db.scalars(
                select(FederationDelivery).where(
                    FederationDelivery.status == "delivered",
                    FederationDelivery.delivered_at.is_not(None),
                    FederationDelivery.delivered_at < delivered_before,
                )
            )
        ).all()
    )
    old_dead = list(
        (
            await db.scalars(
                select(FederationDelivery).where(
                    FederationDelivery.status.in_(("dead", "cancelled")),
                    FederationDelivery.updated_at < dead_before,
                )
            )
        ).all()
    )
    payload_rows = list(
        (
            await db.scalars(
                select(FederationInboxActivity).where(
                    FederationInboxActivity.processing_state.in_(("processed", "ignored")),
                    FederationInboxActivity.received_at < payload_before,
                    FederationInboxActivity.payload_json != "{}",
                )
            )
        ).all()
    )
    old_local_keys = list(
        (
            await db.scalars(
                select(FederationActorKeyHistory).where(
                    FederationActorKeyHistory.retired_at < current - timedelta(days=365)
                )
            )
        ).all()
    )
    expired_remote_keys = list(
        (
            await db.scalars(
                select(RemoteActorKey).where(
                    RemoteActorKey.expires_at < current - timedelta(days=30)
                )
            )
        ).all()
    )
    old_signature_summaries = list(
        (
            await db.scalars(
                select(FederationSignatureFailureDaily).where(
                    FederationSignatureFailureDaily.date_bucket
                    < current.date() - timedelta(days=90)
                )
            )
        ).all()
    )
    for inbox_row in payload_rows:
        inbox_row.payload_json = "{}"
    for delivery_row in (*old_delivered, *old_dead):
        await db.delete(delivery_row)
    for key_row in (*old_local_keys, *expired_remote_keys):
        await db.delete(key_row)
    for summary_row in old_signature_summaries:
        await db.delete(summary_row)
    await db.flush()
    return {
        "delivered_rows_removed": len(old_delivered),
        "dead_rows_removed": len(old_dead),
        "inbox_payloads_redacted": len(payload_rows),
        "retired_local_keys_removed": len(old_local_keys),
        "expired_remote_keys_removed": len(expired_remote_keys),
        "signature_summaries_removed": len(old_signature_summaries),
    }
