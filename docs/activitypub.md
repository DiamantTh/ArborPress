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
