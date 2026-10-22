# ActivityPub foundation (Phase 10A)

ArborPress already had legacy ActivityPub-facing routes and account keypair/follower tables. Phase 10A hardens and narrows that implementation: federation is now off unless the administrator enables the explicit master switch, and a public account is not advertised merely because it exists. An operator must explicitly enable a local actor. Follow processing, federation delivery, and remote-comment creation remain deferred to Phase 10B.

## Operator controls

In Admin → Settings → Federation, enable the master switch and choose the legacy operating mode. Federation IDs require the configured `web.base_url` to be HTTPS; IDs are never formed from `Host` or forwarded request headers. The first explicitly enabled local actor pins the configured origin in `federation_instance_identity`. If `web.base_url` later differs from that pin, local actor discovery is withheld and actor enablement fails with an explicit-migration error. Phase 10C will provide the operator-facing identity migration workflow.

Create or remove local actors through the CLI:

```text
arborpress federation actors enable <username>
arborpress federation actors disable <username>
arborpress federation actors list
arborpress federation actors inspect <username>
```

Actor IDs are persisted and do not change if a local username later changes. A local actor uses the existing encrypted `ActorKeypair` storage and requires `auth.actor_key_enc_key`; the first key is RSA-SHA256, 3072 bits. The private key is never exposed in Actor JSON, CLI diagnostics, or audit data.

Remote domain rules are exact normalized IDNA hostnames. `open` permits domains except blocks; `limited` requires an explicit allow rule. Rules are managed locally:

```text
arborpress federation domains allow <domain>
arborpress federation domains block <domain>
arborpress federation domains remove <domain>
arborpress federation domains list
```

Useful read-only diagnostics include `arborpress federation status`, `arborpress federation fetch-actor <https-url>`, and `arborpress federation inbox inspect <intake-id>`. The fetch command uses the same URL and domain checks as runtime.

## Protocol and safety boundary

WebFinger, actor, NodeInfo, public object/outbox, and inbox endpoints are all behind the federation master switch. WebFinger only resolves explicitly enabled actors. The Inbox accepts bounded ActivityStreams JSON only over HTTPS with a required legacy RSA-SHA256 HTTP Signature. The signature must cover `(request-target)`, `host`, `date`, and `digest`; request dates are limited to five minutes, the body digest is verified, and the verified key owner must match the Activity `actor`. Inbox traffic is persisted as sanitized, deduplicated intake only. No Follow, post, comment, or other domain side effect is performed in 10A.

Remote actor and key fetches go exclusively through `arborpress.federation.security.fetch_remote`. URLs must use HTTPS, contain no credentials, and resolve only to public addresses. Redirect destinations are revalidated, response types and sizes are bounded, and a peer IP is checked when HTTPX exposes it. HTTPX does not provide portable DNS pinning here, so a residual DNS-rebinding time-of-check/time-of-use gap remains; the peer check is defense-in-depth, not a claim of perfect pinning. No remote JSON-LD context is dereferenced. RFC 9421 Message Signatures are explicitly rejected in 10A because this release has no established structured-fields signature verifier dependency; legacy Fediverse signatures remain supported.

The existing SSRF guard in `arborpress.core.validators` remains shared with other Core features. ActivityPub uses the stricter Federation-specific HTTPS-only wrapper because its remote identity and delivery URLs must not fall back to plain HTTP.

## 10B extension points

`FederationInboxActivity` is the durable, idempotent intake boundary. Activity IDs are unique; the SHA-256 of the exact signed body detects conflicting reuse. Its allowlisted intake types are `Follow`, `Accept`, `Reject`, `Undo`, `Create`, `Update`, and `Delete`; types outside that list are recorded as ignored. The next phase can claim `received` items and apply domain behavior transactionally, using `activity_uri` as the idempotency anchor.

`LocalFederationActor`, `RemoteActor`, `RemoteActorKey`, `FederationDomainRule`, `federation_is_enabled`, `domain_allowed`, `fetch_remote_actor`, `resolve_remote_key`, `verify_request_signature`, and `sign_legacy_request` are the Core contracts intended for 10B. Keep remote fetching centralized and do not interpret intake JSON as trusted HTML or ORM data.

## Phase 10B: follows, delivery, posts, and comments

Phase 10B extends those 10A contracts in place. The legacy `Follower` model in
`arborpress.models.user` is the sole follow/follower store. Incoming Follow,
Accept, Reject and Undo are processed by `arborpress.federation.inbox`; outgoing
Follow requests and Undo use `follow_remote_actor` and `unfollow_remote_actor`.
Incoming Follow is automatically accepted by default for an explicitly enabled
local actor. Set `require_approval_to_follow` in the instance Federation settings
to retain new requests as pending; the service `respond_inbound_follow` queues
the corresponding Accept or Reject.

Outbound activities are immutable `FederationOutboxActivity` rows, with one
`FederationDelivery` row per destination inbox. Delivery uses expiring leases,
bounded retry/backoff and the existing legacy RSA HTTP-signature signer. Shared
inboxes are deduplicated when recipients are enqueued. The `federation worker`
CLI command processes both durable inbox intake and delivery; the same services
are also run as lifecycle-owned embedded tasks. GET actor outboxes and
followers/following collections are cursor-paged. ActivityPub client-to-server
POSTs remain unsupported.

Public Articles are emitted only when their primary author has an enabled local
Federation actor. A coauthor is never substituted for a non-federating primary
author. Post publication, public edits and removal enqueue Create/Update/Delete
inside the Core database transaction; no remote HTTP request runs in the user
request. A Delete is sent only to inboxes previously recorded for that post's
public Create/Update deliveries. Existing public object IDs remain stable.

Remote Note replies are represented as ordinary ArborPress `Comment` rows with
`remote_actor_id` and a unique `remote_object_uri`; no remote identity is
created in the local User table. Remote comments have no guest email or
confirmation token, bypass no trust/reputation rule, and enter the configured
CommentPolicy (pending moderation by default). HTML is reduced to plain text
before storage. Remote Update creates a normal pending `CommentRevision`; the
approved body remains visible until the existing moderator approves it. Remote
Delete is ownership-checked and leaves a neutral deleted-comment placeholder.
These decisions and appeals remain local; internal reasons are not federated.

Locally authored registered-user comments are federated only after approval,
only under an already federated public post, and only when their author has an
enabled LocalFederationActor. Guest and remote comments are never re-signed as
local authors. Moderative removal of a local federated comment can emit a
Tombstone as that local author; local moderators never emit a Delete pretending
to be the remote author of a remote comment.

Delivery targets are checked against the shared domain policy and the central
SSRF-safe fetch validation before each POST. Redirects are not followed. A 404
or 410 permits exactly one forced refresh of a known remote actor/inbox; failed
or unchanged refresh becomes dead-lettered. There is intentionally no delivery
fallback between signature formats in this release: Phase 10A provides legacy
Fediverse RSA signatures only and explicitly rejects RFC 9421 verification.
The existing DNS rebinding TOCTOU limitation documented above also applies to
outbound delivery.
