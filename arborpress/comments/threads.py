"""Deterministic in-memory thread construction; quote references stay separate."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class CommentThreadNode:
    comment: Any
    replies: list[CommentThreadNode] = field(default_factory=list)


def build_comment_thread(comments: Iterable[Any]) -> list[CommentThreadNode]:
    """Build chronological roots; malformed/cyclic parents safely become roots."""
    items = list(comments)
    by_id = {str(item.id): CommentThreadNode(item) for item in items}

    def sort_key(item: Any) -> tuple[datetime, str]:
        return (item.created_at, str(item.id))

    ordered = sorted(items, key=sort_key)
    roots: list[CommentThreadNode] = []
    for item in ordered:
        node = by_id[str(item.id)]
        parent_id = getattr(item, "parent_id", None)
        parent = by_id.get(str(parent_id)) if parent_id else None
        if parent is None or parent is node or _would_cycle(node, parent, by_id):
            roots.append(node)
        else:
            parent.replies.append(node)
    for node in by_id.values():
        node.replies.sort(key=lambda child: sort_key(child.comment))
    return sorted(roots, key=lambda node: sort_key(node.comment))


def _would_cycle(
    node: CommentThreadNode, parent: CommentThreadNode, nodes: dict[str, CommentThreadNode]
) -> bool:
    target = str(node.comment.id)
    cursor: CommentThreadNode | None = parent
    seen: set[str] = set()
    while cursor is not None:
        current_id = str(cursor.comment.id)
        if current_id == target or current_id in seen:
            return True
        seen.add(current_id)
        parent_id = getattr(cursor.comment, "parent_id", None)
        cursor = nodes.get(str(parent_id)) if parent_id else None
    return False
