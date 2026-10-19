# Comment core and moderation (Phases 7A–7B)

ArborPress stores guest and account comments in the same `comments` table.
The state is explicit and independent of guest e-mail confirmation:

| State | Meaning |
| --- | --- |
| `pending_confirmation` | A guest must confirm the address; the comment is private. |
| `pending_moderation` | Confirmation, when required, is complete; moderation remains. |
| `approved` | Publicly visible. |
| `rejected` | Rejected by moderation. |
| `spam` | Classified as spam. |
| `deleted` | Soft removal; the row and thread position remain. |

The Alembic revision `0002_comment_core` maps legacy `PENDING` to
`pending_confirmation`, `CONFIRMED` to `pending_moderation`, and retains the
meaning of the terminal legacy states. Existing pending confirmation UUIDs
are SHA-256 hashed, assigned a 24-hour expiry from their original creation
time, then removed from storage. Older pending links therefore expire rather
than becoming permanent bearer credentials. The prior `approved_at` is used to
backfill `published_at` where available.

## Policy and threading

`arborpress.comments.resolve_comment_policy(post, settings)` is the central
resolver. Nullable `Post.comments_enabled`, `Post.guest_confirmation_required`
and `Post.comment_moderation_mode` values inherit the `comments` SiteSetting
section. Existing `require_admin_approval` remains a compatibility fallback;
new installations default to review-all (`always`). Supported modes are
`always`, `first_n`, and `trusted_bypass`, with `none` retained for the
existing explicit “no approval” setting. Global policy keys include
`first_n_count`, `visible_max_depth` (default 4), `edit_window_minutes`
(default 30), `max_user_edits` (default 2), `trusted_edit_bypass` (default
false), `max_comment_length` (default 10,000), `confirmation_ttl_hours`
(default 24), `allow_replies`, and `allow_quotes`.

`Comment.parent_id` models reply/thread structure. `quote_of_id` is an
independent same-post reference and has no effect on sorting. The
`build_comment_thread` helper sorts by `(created_at, id)` and represents the
entire logical tree; presentation code may flatten visible depth without
changing stored parentage. Core services accept only same-post approved reply
and quote targets, and refuse an already cyclic parent chain.

## Confirmation and editing

`create_comment` returns `CommentCreation(comment, confirmation_token)`. The
URL-safe 256-bit token is returned only for mail delivery; only its SHA-256
digest, expiry, and sent time are stored. `confirm_guest_comment` checks the
pending state, expiry and digest, then conditionally consumes it once and
applies the current policy. `issue_guest_confirmation` rotates the token and
has a 60-second default cooldown. Routes and future resend UX must not reveal
whether an address or comment exists.

`create_comment_revision` enforces author ownership, publication-time edit
window and the server-side edit count. Normal author edits become pending
`CommentRevision` snapshots; the published body stays visible until
`review_comment_revision(..., approve=True)` applies the new version.
Moderator edits and explicitly enabled trusted-author bypasses apply
immediately but remain revisioned. `Comment.is_edited` is derived from
`edited_at`; public revision history is not provided.

## Voting and privacy

`cast_comment_vote` supports `-1`, `0` (remove), and `+1` for authenticated
registered accounts only. The unique `(user_id, comment_id)` constraint is the
source of truth; counts come from vote rows, not a denormalized counter. Only
approved comments are votable, and account authors cannot vote on their own
comments. Votes do not affect thread order. No browser fingerprint or guest
vote identity is stored.

Guest e-mail remains private data and is nullable for account-authored
comments. The public route still uses the existing anti-spam filters, CAPTCHA,
CSRF check, consent and IP rate limit. Confirmation and moderation emails
escape untrusted HTML. The account trust flag `User.comment_trusted` is local
state for `trusted_bypass`; it does not grant any account or object
authorization.

## Decisions and appeals (Phase 7B)

Alembic revision `0003_comment_moderation_appeals` adds immutable
`ModerationDecision` rows for a `comment` or `revision` target and
`CommentModerationAppeal` rows bound to one decision. Outcomes record a stable
reason code, restriction category, source (`human`, `automated`, or
`assisted`), optional escaped human explanation and optional rule reference.
The reason catalog is `arborpress.comments.REASON_CATALOG`; the `other` code
requires a human explanation. Existing decisions are superseded by new rows,
never rewritten. Automatic policy outcomes are recorded as `automated`, not
attributed to a person or described as AI.

Core operations are `moderate_comment`, `moderate_revision`,
`submit_comment_appeal`, `review_comment_appeal`, and
`moderation_transparency`. A rejected revision leaves the current public body
untouched. Approving one replaces the body without changing its original
publication time. Appeals are currently limited to registered authors, have
one submission per decision, and use the `comments.appeal_window_days`
SiteSetting (default 14, capped at 90 days). Guest confirmation proves an
address for publication flow but is not a general guest account credential,
so it does not authorize appeals.

Moderation and appeal pages are Quart/Jinja SSR at `/admin/comments`,
`/admin/comments/<comment_id>`, and `/admin/comments/transparency`. Mutations
remain POST-only and require the existing session, moderator role, and CSRF
checks. The transparency page is a grouped, non-identifying report for
moderators; ArborPress does not publish it automatically.

Public article pages render approved threads, chronological replies,
independent quote previews, edited markers, vote counts/forms and neutral
deleted placeholders in the initial HTML. Reply, quote, edit, vote and appeal
forms use ordinary server requests; no JavaScript is required. Only the
registered author sees their pending/hidden status and decision explanation.
Guest email, internal user IDs and moderator identity are not rendered
publicly. Public revision history remains hidden.

Phase 7B supplies the decision and presentation foundation, not Primary
Author/Coauthor relations, object-level ReBAC permissions or the final
author-profile experience; those belong to Phase 7C.
