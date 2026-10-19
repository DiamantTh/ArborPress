"""The single effective comment policy resolver."""

from __future__ import annotations

from dataclasses import dataclass

from arborpress.models.content import Post


@dataclass(frozen=True, slots=True)
class CommentPolicy:
    enabled: bool
    allow_guests: bool
    allow_replies: bool
    allow_quotes: bool
    guest_confirmation_required: bool
    moderation_mode: str
    first_n_count: int
    visible_max_depth: int
    edit_window_minutes: int
    max_user_edits: int
    trusted_edit_bypass: bool
    max_comment_length: int
    confirmation_ttl_hours: int


def resolve_comment_policy(
    post: Post | None = None,
    settings: dict[str, object] | None = None,
) -> CommentPolicy:
    """Resolve per-post nullable overrides against the `comments` settings."""
    values = settings or {}
    moderation_mode = str(values.get("moderation_mode") or "")
    if moderation_mode not in {"always", "first_n", "trusted_bypass", "none"}:
        moderation_mode = "always" if values.get("require_admin_approval", True) else "none"

    post_mode = post.comment_moderation_mode if post is not None else None
    if post_mode is not None:
        if post_mode not in {"always", "first_n", "trusted_bypass", "none"}:
            moderation_mode = "always"
        else:
            moderation_mode = post_mode

    return CommentPolicy(
        enabled=post.comments_enabled
        if post is not None and post.comments_enabled is not None
        else bool(values.get("enabled", True)),
        allow_guests=bool(values.get("allow_anonymous", True)),
        allow_replies=bool(values.get("allow_replies", True)),
        allow_quotes=bool(values.get("allow_quotes", True)),
        guest_confirmation_required=(
            post.guest_confirmation_required
            if post is not None and post.guest_confirmation_required is not None
            else bool(values.get("require_email_confirmation", True))
        ),
        moderation_mode=moderation_mode,
        first_n_count=max(0, _integer(values.get("first_n_count"), 1)),
        visible_max_depth=max(
            1, _integer(values.get("visible_max_depth", values.get("max_depth")), 4)
        ),
        edit_window_minutes=max(0, _integer(values.get("edit_window_minutes"), 30)),
        max_user_edits=max(0, _integer(values.get("max_user_edits"), 2)),
        trusted_edit_bypass=bool(values.get("trusted_edit_bypass", False)),
        max_comment_length=max(1, _integer(values.get("max_comment_length"), 10_000)),
        confirmation_ttl_hours=min(168, max(1, _integer(values.get("confirmation_ttl_hours"), 24))),
    )


def _integer(value: object, default: int) -> int:
    if not isinstance(value, (int, str)):
        return default
    try:
        return int(value)
    except TypeError, ValueError:
        return default
