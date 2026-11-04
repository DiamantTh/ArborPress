"""HTTP validators for public resources and private SSR documents."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from quart import Response, request
from werkzeug.http import parse_date, parse_etags


async def conditional_response(
    response: Response,
    *,
    etag: str | None = None,
    last_modified: datetime | float | None = None,
    private: bool = False,
    max_age: int = 60,
    weak_etag: bool = False,
    cache_control: str | None = None,
) -> Response:
    """Attach validators and evaluate conditional request headers.

    Private HTML uses ``private, no-cache`` and varies on Cookie. Public JSON,
    feeds, and immutable media may use shared caching. Callers must only use
    this on routes that have already applied their normal visibility policy.
    """
    if etag is None:
        body = await response.get_data()
        if isinstance(body, str):
            body = body.encode()
        etag = hashlib.sha256(body).hexdigest()
    response.set_etag(etag, weak=weak_etag)
    if last_modified is not None:
        response.last_modified = (
            last_modified
            if isinstance(last_modified, datetime)
            else datetime.fromtimestamp(last_modified, UTC)
        )
    if private:
        response.headers["Cache-Control"] = "private, no-cache"
        response.vary.add("Cookie")
    else:
        response.headers["Cache-Control"] = cache_control or (
            f"public, max-age={max_age}, must-revalidate"
        )

    not_modified = False
    if_none_match = request.headers.get("If-None-Match")
    current_etag, _is_weak = response.get_etag()
    if if_none_match and current_etag is not None:
        not_modified = parse_etags(if_none_match).contains_weak(current_etag)
    elif last_modified is not None:
        if isinstance(last_modified, datetime):
            modified_at = last_modified
            if modified_at.tzinfo is None:
                modified_at = modified_at.replace(tzinfo=UTC)
            modified_timestamp = int(modified_at.timestamp())
        else:
            modified_timestamp = int(last_modified)
        since = parse_date(request.headers.get("If-Modified-Since", ""))
        if since is not None:
            not_modified = modified_timestamp <= int(since.timestamp())

    if request.method in {"GET", "HEAD"} and not_modified:
        response.status_code = 304
        response.set_data(b"")
        response.headers.pop("Content-Type", None)
        response.headers.pop("Content-Length", None)
    return response
