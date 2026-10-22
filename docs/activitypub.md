# ActivityPub federation

ArborPress federation is an optional server-to-server feature. It is disabled by
default. It does not provide an ActivityPub client-to-server API, OAuth for
Fediverse clients, a relay, remote likes/votes, or a general media proxy.
ActivityPub identities and objects are generated only from the configured
canonical HTTPS origin; request `Host` and forwarded headers never define them.

## Operator setup and identity

An administrator enables federation under Admin → Settings → Federation.
Enabling is guarded by the configured HTTPS origin, schema, route and signing
key checks. Once the first local actor pins the canonical origin in
`federation_instance_identity`, changing `web.base_url` is rejected while it
would rewrite published identity. There is not yet an automatic identity-domain
migration tool; do not change the public origin of an active federation site.

Authors opt in separately at `/auth/federation`. An account is never advertised
merely because it exists or is a content author. The page previews its stable
Actor URL and Fediverse handle, explains that public posts and approved comments
may be copied by remote servers, and provides an explicit disable action.
Disabling prevents new activity but cannot retract remote copies. The stable
Actor URI is independent of a mutable username; renaming `preferredUsername`
is not exposed as a UI operation.

Local signing keys are encrypted using the existing ArborPress actor-key secret
configuration. The private part is never displayed or downloaded. An
authenticated actor owner can rotate a key after step-up authentication. The
Actor URI and key ID stay stable; the new RSA-3072 key becomes current
atomically, only the current key signs new requests, and retired public-key
metadata is retained for a bounded period. Rotation does not promise that every
remote server immediately refreshes its cached public key.

The encrypted private key is part of the normal database backup. Restoring it
requires the matching `auth.actor_key_enc_key` configuration secret; use the
existing encrypted full-backup flow when that secret is to be backed up. An
unencrypted backup must not be treated as a recoverable federation identity
backup if the key-encryption secret was omitted.

## Discovery, identities, and protocol

WebFinger resolves only enabled local actors. Actor documents expose a Person,
public key, inbox, outbox, followers, and following endpoints. Public HTML
profiles remain ordinary ArborPress pages. ActivityPub routes return the
ActivityStreams media types and set `Vary: Accept`; optional authorized-fetch
responses are private/no-store and vary on signature. WebFinger and HTML pages
remain public when authorized fetch is enabled.

Remote actor and key discovery uses the single
`arborpress.federation.security.fetch_remote` boundary. An operator can request
an actor-signed GET for a guarded remote-actor refresh from the Remote Actor
admin detail; the local actor is selected explicitly and each redirect hop is
validated and freshly signed rather than forwarding credentials. This is not
a blanket policy that signs every remote GET. Remote URLs require
HTTPS, no credentials, allowed domains, public-address resolution, redirect
revalidation, response type/size bounds, and timeouts. A peer-IP check is used
when HTTPX exposes it. HTTPX does not offer portable DNS pinning in this
configuration, so DNS rebinding retains a documented time-of-check/time-of-use
limitation. No arbitrary JSON-LD context is fetched or executed. Remote HTML is
untrusted and sanitized; remote media is not automatically fetched.

Domain rules are normalized IDNA hostnames with explicit exact-domain or
`include_subdomains` semantics. A block wins over an allow. `open` admits
otherwise-unblocked domains; `limited` admits only allowlisted domains. The
policy applies to inbound processing, remote fetch and outbound delivery. A
block takes effect on future work but does not delete already stored comments
or history.

Inbound POSTs require a fresh legacy Fediverse HTTP Signature using RSA-SHA256;
the signed request binds the request target, host, date and SHA-256 body digest,
and the signer key owner must match the asserted actor. Staleness is limited to
five minutes. On a key verification failure ArborPress makes at most one guarded
refresh/reverification. Outbound requests are signed with the current local
actor key and bind their body digest. RFC 9421 HTTP Message Signatures are not
implemented in this release and are not advertised as supported.

## Follow, content, and comments

The legacy `Follower` model is the follow relationship store. Incoming Follow,
Accept, Reject and Undo are ownership-checked and idempotently processed.
Incoming follows are accepted by default for enabled actors; the instance
setting `require_approval_to_follow` changes new follows to pending. Follow
responses are queued rather than synchronously sent from inbox requests.
Followers and following collections are cursor-paged and expose only actor
URIs.

Immutable `FederationOutboxActivity` rows represent Create, Update and Delete;
each destination has a `FederationDelivery` with a lease, bounded retries and
status. The `arborpress federation worker` handles inbox processing and
deliveries, and lifecycle-owned embedded tasks use the same services. Shared
inboxes are deduplicated for public deliveries. Redirects are not followed for
delivery. Retry reuses the existing activity and rechecks current domain and
SSRF policy. The admin interface can inspect, retry or cancel eligible
deliveries and reprocess only authenticated transient inbox failures.

Public Articles are attributed only to the enabled federation actor of the
content's Primary Author. Coauthors do not replace a non-federating primary
author. Create/Update/Delete rows are created with the content transaction;
remote HTTP delivery is asynchronous. Existing public object IDs remain
stable, and deletion sends a minimal tombstone to previously recorded targets.

Remote Note replies are ordinary ArborPress Comments with a `remote_actor_id`,
stable `remote_object_uri`, and an optional authenticated inbox-intake
reference. They never create fake local users or guest emails. Remote comments
use the ordinary CommentPolicy and moderation/revision/appeal records; the
default is pending moderation. Remote Update uses the normal pending
`CommentRevision` flow, keeping the approved version visible. An ownership-
checked remote Delete leaves a neutral placeholder and keeps replies. Local
registered users' approved comments may federate under their own enabled actor;
guest and remote comments are never signed as local authors. Moderators do not
issue a Delete pretending to be a remote author.

## Operations and privacy

The federation admin pages show sanitized status, local and remote actors,
inbox intake metadata, delivery attempts and domain rules. They do not show
private keys, request signature headers, full transport payloads or secrets.
Sensitive global/domain/key operations use the existing RBAC, CSRF and step-up
controls. Signature failures are summarized by UTC day and a bounded reason
class, without recording remote IP, actor URI or raw headers; the admin overview
shows the last 30 days. Account federation enablement is an explicit author
action.

`authorized_fetch` is an optional inbound secure mode for ActivityPub actor,
object and collection GETs: it requires the same fresh, actor-bound legacy
signature policy as the inbox. It does not gate WebFinger or normal HTML
profiles. Federation admin diagnostics call this “Authorized Fetch” to
distinguish it from an explicitly signed outbound fetch.

`arborpress federation retention-cleanup` removes old delivered rows (default
90 days) and old dead/cancelled delivery rows (default 365 days), redacts
processed/ignored inbox payloads after 30 days, and expires retired local and
remote key metadata. It intentionally retains immutable outbox activities and
inbox IDs/body hashes needed for idempotency and removes daily signature
aggregates older than 90 days. This cleanup is explicit; no new
scheduler or legal-hold system is introduced.

The transport is bounded by request/response size limits, timeouts, collection
and recipient limits, signature freshness, and queue retry limits. Logs and
audit records omit private keys, signature headers and complete activities.
Federation is not a hostile-code sandbox and has no external federation service
dependency.

The implementation intentionally does not claim full ActivityPub conformance.
There is no C2S/OAuth API, arbitrary context resolution, Linked Data
Signatures, Like/Announce/Boost product, remote vote mapping, relay, full-text
remote crawler, or untrusted remote-media proxy.
