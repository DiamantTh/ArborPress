# SMTP profiles and the mail outbox

ArborPress keeps accepted deliveries in the database table `mail_queue`. This
table is the only authoritative queue; a process restart does not discard queued
mail. A delivery has one SMTP envelope recipient. Header `To`/`Cc` values are
stored separately, and `Bcc` is never emitted as a message header. The current
Core producer API creates one-recipient messages; it does not implement a bulk
campaign or newsletter product.

## Profiles and transport security

SMTP profiles are stored per instance in `smtp_profiles`. The compatibility
settings form manages the `transactional` profile; CLI operators can configure
additional named profiles:

```text
arborpress mail profiles configure alerts
arborpress mail profiles list --json
arborpress mail profiles inspect transactional --json
arborpress mail profiles test transactional --json
```

`configure` prompts for the SMTP secret without echoing it. The secret is
encrypted at rest using a domain-separated key derived from the instance web
secret key. Rotating that root key requires re-entering profile credentials.
Secrets are not returned by profile inspection, audit events, or mail logs.

Only `implicit_tls` and strict `starttls` are supported. Certificate chain and
hostname validation use the Python/system trust store. STARTTLS must be
advertised and successfully negotiated before AUTH; there is no plaintext or
opportunistic downgrade mode. Profile testing connects, negotiates TLS, EHLOs,
and authenticates if configured, but sends no message.

## Queue and workers

Delivery states are `pending`, `leased`, `retry`, `sent`, `dead`, and
`cancelled`. Claims use a database conditional update and a 90-second lease;
expired leases can be recovered after a worker crash. Transient failures use
bounded exponential backoff with jitter (five attempts by default); operators
can explicitly retry a dead delivery. `sent` means the configured SMTP server
accepted the recipient, not that the recipient's mailbox or device received it.
Because SMTP acceptance and the database commit cannot be one transaction, an
ambiguous crash may lead to a duplicate delivery. Retries retain a stable
Message-ID; exactly-once delivery is not claimed.

The web lifecycle starts an embedded worker and uses
`instance/var/run/mail-worker.lock` so only one process per instance owns its
poll loop. Graceful shutdown stops new claims and lets an in-flight bounded SMTP
operation finish. An optional standalone process uses the same queue and lock:

```text
arborpress mail worker --interval 5
arborpress mail process --once
arborpress mail queue list --json
arborpress mail queue inspect <job-id> --json
arborpress mail queue retry <job-id>
arborpress mail queue cancel <job-id>
```

Administrative diagnostics are server-rendered at `/admin/mail`; they omit
message bodies and recipient local-parts. Retry/cancel forms require the normal
admin role and CSRF validation.

Core producers render registered templates before enqueueing. The subject and
both bodies are snapshotted in `mail_queue`; `template_id`, selected locale, and
the effective package/override revision are retained as diagnostic metadata.
Retries therefore cannot change content after an administrator edits a
template. Guest confirmation and comment review mail use package defaults by
stable ID, and notification email uses the same outbox only when the user opts
into email delivery for that notification type.

Template defaults are package resources under `arborpress/mail/templates/` and
are not themes. Administrators manage instance-local overrides, preview, reset,
and immutable revisions at `/admin/mail/templates`. Edits use a strict Jinja
sandbox, a registered context allowlist, HTML sanitization, CSRF, admin access,
and step-up authentication. Already queued mail remains unchanged.

## Envelope, VERP, and DSN

`From`, visible recipients, `Reply-To`, and custom headers are distinct from the
SMTP envelope. `Return-Path` is not accepted as a producer-supplied header. Each
delivery gets a stable Message-ID based on its generated job ID and the
configured canonical site domain, never an inbound Host header.

When a profile has an envelope/bounce domain, the worker creates a random,
persisted VERP token and uses `bounce+<opaque-token>@<domain>` as MAIL FROM.
`arborpress.mail.delivery.apply_dsn` is the normalized status-update boundary
for a future inbound DSN receiver. No inbound SMTP server/mailbox poller exists
in 9A. DSN ESMTP parameters (`RET`, `ENVID`, and recipient `NOTIFY`) are sent
only when the relay advertises DSN. A remote acceptance is still only `sent`;
`delivered`, `delayed`, and `bounced` are recorded only from an explicit DSN
update.

## DNS, DNSSEC, DANE, and CAA

`SMTPDNSResolver` queries A, AAAA, MX, TLSA, and CAA records through dnspython;
it sends DNSSEC DO requests and does not send ECS. SMTP connects to the
configured relay, so recipient MX records do not select the transport host.
The default `own_validation` policy currently reports `indeterminate`: ArborPress
does not yet implement a local DNSSEC chain validator. The explicitly selected
`trusted_ad` policy may trust the AD bit supplied by the configured recursive
resolver. DANE is report-only in this phase: diagnostics identify DNSSEC-secure
TLSA records, but do not match them against the SMTP peer certificate. CAA is
informational. No strict DANE fail-closed mode is enabled.

## Legacy settings and downgrade

The old single-SMTP settings form remains compatible and now writes encrypted
credentials to the `transactional` profile. On first use of a legacy database
configuration, the runtime copies the old SMTP password to the encrypted
profile and removes that password from the settings JSON. SMTP host and sender
fields remain as compatibility display values in SiteSetting, while the profile
row is authoritative for delivery.

Alembic revision `0006_smtp_profiles_mail_outbox` preserves existing
`mail_queue` payloads, maps `FAILED` to `dead`, and assigns stable Message-IDs.
Downgrade necessarily collapses `retry`/`leased` to the prior `PENDING` state
and `dead` to `FAILED`; lease and DSN details are discarded by that downgrade.
