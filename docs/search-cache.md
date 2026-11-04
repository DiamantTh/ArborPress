# Search and Cache Operations

## Search

Public SSR search (`/search`) and `GET /api/v1/search` share
`arborpress.core.search.search_public_content`. Both use the same bounded query,
pagination, language, visibility, publication, and `noindex` filters. Search
includes public indexable posts and pages. Hidden, private, draft, unpublished,
deleted/archived, and `noindex` content is not returned.

PostgreSQL uses a GIN expression index over `to_tsvector('simple', title ||
' ' || body_md)`. MariaDB uses a FULLTEXT index over title and body. Migration
`0017_search_indexes` installs those indexes; the database maintains them when
content changes, so create/update/publish/unpublish/visibility/delete and author
changes require no separate search-index job. SQLite and incompatible/missing
native indexes use a parameterized `LIKE` fallback. Queries are limited to 200
characters and at most 50 results per page.

External search settings are currently health-probed only; ArborPress does not
yet synchronize documents to or query Meilisearch, Typesense, Elasticsearch, or
Manticore. Selecting one is reported as degraded and public search safely uses
the database implementation. There is no false-success external reindex path.
`arborpress search status [--json]` reports the configured/effective provider
and health. `arborpress search reindex` verifies the active path: database
indexes are maintained transactionally and LIKE has no separate index to
rebuild. A provider failure falls back to LIKE for that request and logs only
the provider and exception class.

## Cache

Supported cache backends remain memory, Redis, Valkey, Memcached, file, and none.
All keys are isolated by the internal `arborpress:cache:v1` format namespace,
the resolved instance prefix, and configured key prefix. This is an internal
cache namespace, not a product version. Cache values are disposable; database
state remains authoritative.

Redis and Valkey purge uses incremental `SCAN` batches. Memcached purge rotates
an ArborPress-owned generation key instead of calling global `flush_all()`.
File purge is limited to the instance's owned filename prefix. Cache status
never prints connection URLs, passwords, hosts, or filesystem paths. Backend
read/write failures fail open to the authoritative read path; purge errors are
reported instead of claiming success.

Optional L1/L2 mode limits L1 entries to five seconds even if a larger value is
configured. This is the maximum stale-read window across workers when one
worker invalidates an L2 key; site-setting process caches likewise expire after
five seconds. Explicit saves invalidate the current worker immediately. No
shared cache currently stores posts, pages, comments, authorization/session
state, or search results, so those resources read from Core/DB and need no
object-cache invalidation. Public media uses HTTP validators and the immutable
URL policy. Theme/template caches use their dedicated Core invalidation paths.

`arborpress cache status` reports backend reachability, namespace and L1/L2
mode. `arborpress cache purge` only removes this instance's cache entries.
`arborpress cache warm` is intentionally a no-op while no shared public response
cache is configured; it does not load mail, authentication, federation, or
other private settings into a short-lived CLI process.

## HTTP caching

Public API JSON and RSS/Atom feeds include strong body ETags and honor
`If-None-Match`; feed output is deterministic. Public media includes a weak
filesystem-metadata ETag and Last-Modified and honors both conditional headers.
Post/page SSR has body ETags but remains `private, no-cache` and varies on
Cookie because rendered controls and thread state can change independently of
the Post/Page row timestamp. OAuth,
admin, cookie-bearing, and Authorization-bearing responses are never assigned
shared public cache policy by the security middleware. Optional cache systems
do not gate readiness.
