# Portable content transfer

`arborpress content export` and `arborpress content import` move editorial data
between ArborPress instances and supported database backends. This package is
not a database backup, a disaster-recovery backup, a filesystem copy, or a SQL
dump. Use the encrypted backup and restore commands for recovery of an entire
instance, credentials, keys, plugin state, or deployment configuration.

## Package contract

The ZIP format identifier is `arborpress.portable-content`; `format_level: 1`
is a technical transfer-schema level, not an ArborPress product version. The
manifest is written last and records a random bundle ID, UTC export time,
source build SHA, source Alembic Head, included data kinds, record counts,
member sizes and SHA-256 hashes, a hash over the member-hash map, and a
`security_data_included: false` marker. This detects accidental damage; it is
not a digital signature or proof of who created a package. The manifest may
also carry public site settings as a proposal and the selected theme ID as a
reference; neither is applied or causes theme code to be copied or executed.

Structured records use bounded JSON Lines files. Media blobs are separate ZIP
members named by package-local opaque IDs. Export streams database records in
batches and stages media in a private temporary directory before atomically
replacing the output file. Import verifies the whole archive before mutation,
including member paths, file types, sizes, compression ratios, record limits,
references and hashes. Import does not extract arbitrary archive paths.
The package is limited to 512 MiB total compressed and uncompressed data and
250,000 structured records across all entity types; individual structured
members, records, content fields, media files and extension payloads have
smaller limits enforced by the importer. Export streams DB records, while the
current full relational preflight retains bounded record data in memory. For
transfers approaching these limits, split the editorial transfer into smaller
packages and review each dry-run before import; do not raise limits without
revalidating worker memory headroom and archive protections.

Explicit post/page translation groups are represented by stable, bundle-local
group references. Import maps those references to new target-local group IDs;
source database IDs are never reused. Group membership is restored only when
the package contains the corresponding content records, and no translation is
inferred from matching slugs or text.

## Data scope and privacy

By default, export includes public published posts, public published custom
pages, tags, their local author relations, and validated media rows located
inside the configured media root. `--include-non-public` also includes drafts,
hidden/private posts and unpublished custom pages. `--include-comments` opts in
only approved comments. Imported comments re-enter local moderation as pending
review and are subject to the destination guest/comment policy.
Replies whose source parent is not part of the approved-comment export are
portable as standalone comments, so the package does not expose an unapproved
parent.

An actual import requires an active operational administrator as its local
operator. Successful imports create a local audit event containing the bundle
ID and aggregate object counts, never source credentials or comment contact
metadata.

Author references are opaque and scoped to one bundle. The package contains a
display name for mapping, but not login names, e-mail, internal user IDs, roles,
or external identity subjects. Comment export omits e-mail, IP, user agent,
country, moderation notes, federation actor IDs, and transport metadata.
Public general settings are included as a proposal only; the importer does not
apply settings or theme/plugin code.

The exporter never reads authentication or operational tables. It excludes
passwords, WebAuthn, TOTP, backup codes, sessions, OAuth/OIDC credentials and
tokens, signing keys, federation keys, `web.secret_key`, mail/CAPTCHA secrets,
backup keys, and security audit data. Text and media authored by operators can
still contain information they intentionally placed in content; review the
package scope before transferring it.

## Author mapping and safe publication

Every source author reference used by a post or registered-user comment must be
explicitly mapped to an active local user with repeated
`--author-map SOURCE_REF=LOCAL_USER_ID` options. E-mail and username are never
used to select or link accounts. No users or roles are created from the package.
The operator's local account is recorded as the importer; source authorship is
restored only through the explicit mapping.

Imported posts are always drafts and imported pages are always unpublished.
Imported publication state, ownership, visibility, revisions and roles from a
source do not cause publication or privilege grants on the target. Each
imported post receives one local initial revision; source revision history,
votes, moderation decisions, appeals, and audit events are not portable.
Review and publish imported content through the destination's normal editorial
workflow.

## Conflicts and repeat imports

The default `fail` policy rejects slug conflicts before writes. `skip` leaves
conflicting local objects untouched and can map a colliding tag to the existing
tag. `remap` creates deterministic `-import-<portable-id>` slugs. No policy
silently overwrites existing posts, pages, tags, or media. Each successful
package import records its bundle ID and hash in the database; importing that
exact package again is an idempotent no-op. Re-exporting the same source creates
a new bundle and is subject to the selected conflict policy.

`--dry-run` fully checks the package, account mappings, database slug conflicts
and declared/granted plugin importer capabilities without starting plugin code
or changing the database or filesystem. It prints planned counts, conflicts,
remaps, warnings and required author mappings.

## Media and failure boundaries

Media is exported only when its stored path resolves to a regular file under the
instance media root. Import verifies the content hash and then calls ArborPress'
existing raster-image upload validation, which checks actual image type,
dimensions, size and content. Local filenames and paths are newly generated;
references in Markdown are rewritten to the new local media paths.

Database changes are committed in one transaction. Imported files are removed
if the database operation fails, including a failed flush or commit. A host
crash between filesystem writes and database commit cannot be made globally
atomic across these resources; inspect the restore/maintenance markers and
remove only orphaned generated files after a crash. The CLI reports failures
with a nonzero exit status.

## Plugin extensions

Plugin data is excluded unless `--include-plugin-data` is used. Only enabled
plugins that declared and were explicitly granted the `exporter` capability
are called. Their isolated worker must implement
`export_portable(context) -> JSON object`. Data is namespaced under
`extensions/<plugin-id>/data.json`, bounded to 700 KiB per extension, hashed,
and treated as untrusted on import. The matching enabled plugin must separately
declare and receive the `importer` capability and implement
`import_portable(data, context) -> JSON object`. The Core never imports plugin
entrypoint code into its own process and never executes extension data.

An extension importer runs only after archive, hash, and schema preflight and
before Core content writes. Plugin-owned side effects cannot participate in
the SQL transaction; plugin implementations must stage work, use the bundle ID
for idempotency, and return an error before committing if they cannot accept
the data. Plugins must not use extension data to bypass Core content,
authorization, or media services. The CLI reports missing or ungranted
importer capabilities as a preflight error.

## CLI

```text
arborpress content export --output ./site-transfer.zip
arborpress content export --output ./full-editorial.zip --include-non-public --include-comments
arborpress content export --output ./with-plugin-data.zip --include-plugin-data --json
arborpress content import ./site-transfer.zip --dry-run --json
arborpress content import ./site-transfer.zip --dry-run --author-map SOURCE_REF=LOCAL_USER_ID
arborpress content import ./site-transfer.zip --actor-user-id LOCAL_ADMIN_ID \
  --author-map SOURCE_REF=LOCAL_AUTHOR_ID --conflict remap --json
```

Run the import dry-run first, review all required author mappings and conflicts,
then run the actual import with the same mapping and policy. Keep the original
package until the target content has been reviewed.
