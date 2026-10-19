# Authors and object-scoped permissions

ArborPress keeps editorial attribution separate from authorization. A post's
canonical author list is stored in `post_author_relations`; the `primary`
relation is first and coauthors follow in their persisted `position` order.
Every newly created post receives its creator as primary author. Existing
`posts.author_id` values are copied by Alembic revision
`0004_authors_and_object_relations` and synchronized by the author service as
a transitional compatibility projection for older integrations. A legacy
post with no author is not assigned a fabricated identity. Static/system Pages
are not authored objects in this first ReBAC release.

The database enforces unique post/user links and unique author positions; the
author service replaces assignments under a transaction and always creates
one primary row. New posts get a primary author before commit, and routes reject
new publication or scheduling without one. The old nullable schema can still
contain already-published rows with no legacy author; those exceptional rows
remain unassigned rather than being attributed to an invented user. Existing
inactive author links are retained until a manager explicitly removes them;
inactive users cannot be newly assigned.

Public `/@<handle>` profiles show only active public accounts and their public,
published primary- or coauthored posts. Post pages render an SSR author box.
Comment author markers use the authenticated `author_user_id` plus the
canonical author relations; a guest with the same display name is not marked.
Bio is rendered as escaped text with line breaks. Email, role, security and
authorization details remain private.

Global site roles and permissions remain in the existing `User.role` RBAC.
`ObjectRelation` is a small positive-grant relation table currently restricted
to `object_type=content` (a Post ID) and the relations `editor` or
`comment_moderator`. It is not an ACL wildcard system and does not replace
global roles. The resolver in `arborpress.auth.permissions` exposes
`can(db, actor, action, object)` and `require_permission(...)` for:

| Action | Global grant | Object/domain grant |
| --- | --- | --- |
| `content.edit` | editor or admin | primary author, coauthor, or `editor` relation |
| `content.manage_authors` | editor or admin | none |
| `comments.moderate` | moderator, editor, or admin | `comment_moderator` relation |
| `object_relations.manage` | editor or admin | none |

Editing content does not implicitly allow publishing-state changes, author
management, or moderation. Comment trust policy remains separate from ReBAC.
Only global content managers can grant/revoke object relations or change the
author list; a subject/editor cannot self-grant a relation.
No new settings keys or database role tables are introduced. Author assignment
and relation grant/revoke operations emit the existing audit events using actor,
subject, object and relation identifiers only.

The initial management forms are Quart/Jinja SSR and work without JavaScript.
There is no OpenFGA service, external authorization process, deny relation,
group relation, or second role store. Object moderators see server-scoped
comment moderation queues and aggregate reports only for their assigned
posts. Global moderators retain their site-wide scope.

This release deliberately starts with Posts because they are ArborPress's
existing user-authored publishable model. Static Pages, groups/teams, public
moderator directories, profile editing, deny grants, relationship expiry and
third-party policy engines are not added. Primary/coauthor membership grants
only `content.edit`; changing publication state, managing author lists,
moderating comments, or managing relations still requires the corresponding
global policy or explicit relation described above.
