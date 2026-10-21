# Notifications (Phase 9B)

ArborPress keeps user notifications in the instance database. `NotificationEvent`
is the inbox source of truth; the in-process Core event dispatcher is not the
notification store, and WebSocket connections are not durable delivery queues.
The initial catalog contains only comment moderation decisions and appeal
reviews. Their DTO payloads contain an outcome code, not comment text, email,
tokens, or moderation notes. More event-to-user mappings and channel preferences
per type are reserved for Phase 9C.

## Inbox and live delivery

`GET /notifications` renders the signed-in user's own paginated inbox without
JavaScript. Read operations are idempotent and scoped to that user. Live WSS is
opt-in (`live_wss_enabled`, default false). The socket is same-origin and checks
the configured `web.base_url` Origin, not the request Host. A browser obtains a
45-second (configurable from 30 to 60 seconds) database-backed, one-shot ticket
with a CSRF-protected POST and sends it as the first WebSocket JSON frame. The
ticket is bound to the authenticated user, database session, purpose, and
expected Origin; it is never accepted from a URL.

The socket uses protocol `arborpress.notifications.v1`, bounded JSON frames,
three-second database polling, a 10-second bounded send, and a 250-item delivery
cap per connection. Reconnects use new tickets. A cursor only selects rows owned
by the authenticated user; missing/old cursors trigger a bounded recent catch-up
or resync notice. Each worker polls its own local sockets against the shared DB,
so no Redis/Valkey or PostgreSQL-only notification feature is required. The
database persists events through process restarts and socket loss.

## Web Push

Web Push is separately opt-in (`web_push_enabled`, default false). The browser
asks for permission only after an explicit button click. ArborPress serves a
minimal same-origin `/service-worker.js` for `push` and `notificationclick`; it
does not cache pages or create an offline app. Each user may have multiple
subscriptions. Endpoint/key material is private, only subscription IDs and
creation dates appear in the account's own settings page, and VAPID private
material is never returned to the browser.

Inject the private key through the deployment's secret mechanism, using
`ARBORPRESS_NOTIFICATIONS__VAPID_PRIVATE_KEY`; do not put it in source control
or an ordinary instance backup. Configure the matching public key as
`notifications.vapid_public_key` and the contact as `notifications.vapid_subject`
(the public value is safe to publish). Both keys must be present before the UI
allows Web Push opt-in. Use a keypair produced for the `pywebpush`/VAPID format.
Changing the pair invalidates browser subscriptions and normally requires users
to subscribe again.

The core delegates payload encryption and VAPID to the established `pywebpush`
library. Delivery jobs are unique per notification and subscription, leased in
the DB, retried with bounded backoff, and disabled for expired 404/410 endpoints.
Push payloads carry only the catalog's neutral title/message and a validated
same-origin relative path. Server-side DNS preflight rejects endpoints resolving
to private/reserved addresses, redirects are disabled, TLS verification is
left at the library/system default, and ambient requests proxy settings are not
used. As with any hostname check followed by a separate HTTP connection, DNS
rebinding cannot be ruled out completely by this application-level check; this
is not an OS network sandbox.

`arborpress notifications worker` runs the same worker as the embedded app
lifecycle. A per-instance runtime lock prevents two local worker processes from
delivering the same work concurrently; the DB lease remains authoritative for
multi-worker claims. Turning off the channel or removing a subscription cancels
pending/retry deliveries without deleting inbox events.

## Boundaries

The inbox event is independent of optional delivery channels. Per-type choices
are stored in `notification_type_preferences`; they can only narrow delivery,
because WSS and Web Push still require their global user opt-in, and Push also
requires a live browser subscription. New per-type Push and email choices default
off. Email notification delivery is rendered immediately into the Phase 9A DB
outbox and does not mark an inbox item read. SMTP acceptance and Push delivery
failures do not remove the inbox item.

The account inbox page contains global and per-type channel controls plus an
optional preferred mail locale. Transactional mail such as guest confirmation
is not controlled by notification preferences. Core notification mail uses the
same SMTP outbox as transactional mail.

Core mail templates have stable registry IDs and package-owned defaults under
`arborpress/mail/templates/`. Supported defaults currently ship in `de-DE` and
`en-GB`; locale selection checks explicit/user/site locale and falls back to the
package English default. Administrators can edit a database override in the SSR
admin mail-template screens. Each validated save, restore, or reset appends an
immutable source revision. Existing outbox messages keep the subject and bodies
rendered when enqueued, even after a later template edit.

Mail templates have a separate strict Jinja sandbox and context allowlists; they
are not ArborPress themes. Includes, imports, calls, attribute access, active
HTML, and arbitrary template globals are blocked. HTML is escaped and passed
through a mail-oriented allowlist sanitizer. Preview uses synthetic data and
renders HTML in a sandboxed frame. Admin changes require CSRF, the existing
admin role, and the registered `edit_mail_template` step-up operation.

WebSocket remains a best-effort live view backed by DB catch-up, not a delivery
receipt or exactly-once transport. Web Push provider acceptance does not prove
delivery to a device.
