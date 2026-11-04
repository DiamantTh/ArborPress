# API v1

ArborPress exposes two deliberately separate `/api/v1` surfaces:

- **Public API** such as `GET /api/v1/posts`, `/pages`, `/tags`, `/search`, and
  public profile reads. These routes return only public, published resources.
- **OAuth Resource API** under `/api/v1/oauth`. Every request requires an
  active `Authorization: Bearer` access token. A browser session cookie never
  substitutes for a bearer token.
- **Admin API** under `/api/v1/admin` remains session-authenticated and keeps
  its CSRF, RBAC, and step-up requirements.

## OAuth resources and scopes

| Routes | Required scope | Additional ArborPress policy |
| --- | --- | --- |
| `GET /api/v1/oauth/me` | `profile` | Returns only the token owner's public profile fields. |
| `GET /api/v1/oauth/posts` and `/posts/{slug}` | `posts:read` | Public, published posts only. |
| `POST /api/v1/oauth/posts` | `posts:write` | Requires local content-create permission; creates drafts. |
| `PUT/PATCH /api/v1/oauth/posts/{slug}` | `posts:write` | Requires the central content-edit resolver, including author and object relations. |
| `GET /api/v1/oauth/comments` | `comments:read` | Approved comments on public, published posts only. |
| `POST /api/v1/oauth/posts/{slug}/comments` | `comments:write` | Uses the normal CommentPolicy and moderation pipeline. |
| `PATCH /api/v1/oauth/comments/{id}` | `comments:write` | Own registered comment and existing edit-window/revision rules only. |
| `GET /api/v1/oauth/media` and `/media/{id}` | `media:read` | Only media uploaded by the token owner. |
| `POST /api/v1/oauth/media` | `media:write` | Also requires local media-upload permission and the Core raster-image validation/storage pipeline. |

An OAuth scope grants no ArborPress role. The effective decision is the
intersection of the token scope, the central local permission resolver, and
resource visibility/ownership policy. `comments:write` never grants comment
moderation. OAuth-created posts are drafts; publication remains a local
editorial action.

## Pagination, errors, limits, retries

Collection routes accept `page` (default `1`) and `per_page` (default `20`,
maximum `50`). Values must be single positive integers; result ordering is
stable and each response includes `items`, `page`, `per_page`, and `total`.
Public API read responses use ETags and return `304 Not Modified` when the
client's validator still matches. Cookie or Bearer-authenticated responses are
private/no-store. `GET /api/v1/search` shares its public visibility rules with
SSR search and returns only public, published, indexable posts and pages.

API errors use a stable envelope:

```json
{"error":{"code":"insufficient_scope","message":"insufficient scope"}}
```

The API does not return exception text, SQL, stack traces, tokens, or filesystem
paths. Existing rate-limit infrastructure applies to OAuth authorization,
token, search, post-write, comment-write, and media-upload routes. A request
rejected by a limit returns HTTP 429.

Post creation/update, comment creation, and media upload accept an optional
`Idempotency-Key` header (1–128 ASCII letters, digits, `.`, `_`, `:`, or `-`).
Receipts are scoped to OAuth client and user, store only key/request hashes and
resource references, and expire after 24 hours. Reusing a key with different
request bytes returns HTTP 409. The first create returns 201; a matching retry
returns the existing resource without repeating the write.

## Compatibility and security

The `/api/v1` path is retained. These routes are additive; existing public and
admin endpoints keep their paths. No general API v2 or browser-cookie bearer
fallback is introduced. Hidden, private, unpublished, moderated, and
unowned resources are omitted or rejected according to their existing Core
policy. No endpoint exposes moderation notes, author email, authentication or
MFA state, audit details, or federation transport metadata.
