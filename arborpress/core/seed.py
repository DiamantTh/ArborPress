"""Seed data: example posts, pages, imprint, and privacy policy (§14).

Called by `arborpress init --seed` or `arborpress db seed`.
Idempotent: checks whether data already exists before inserting.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("arborpress.seed")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid.uuid4())


def _short_id() -> str:
    return secrets.token_urlsafe(8)[:10]


def _now() -> datetime:
    return datetime.now(UTC)


def _md_to_html(md: str) -> str:
    """Simple Markdown→HTML without an external library (fallback)."""
    try:
        import markdown  # type: ignore
        return markdown.markdown(md, extensions=["fenced_code", "tables", "toc"])
    except ImportError:
        # Minimal fallback: paragraphs
        paras = md.strip().split("\n\n")
        return "\n".join(f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paras)


# ---------------------------------------------------------------------------
# Seed content
# ---------------------------------------------------------------------------

_POST_1_SLUG = "welcome-to-arborpress"
_POST_1_TITLE = "Welcome to ArborPress"
_POST_1_MD = """\
# Welcome to ArborPress

Glad to have you here! **ArborPress** is a self-hosted blogging platform
that you control completely – no tracking, no third-party servers, no compromises.

## What can ArborPress do?

- **WebAuthn login** – passwordless sign-in with a hardware token or device sensor
- **ActivityPub federation** – your posts appear in the Fediverse (Mastodon, Misskey …)
- **Multilingual** – publish posts in multiple languages
- **Full-text search** – powered by PostgreSQL `pg_fts` or MariaDB FULLTEXT
- **Plugins** – the system is easy to extend

## Getting started

1. Sign up at `/auth/register` and set up your WebAuthn key
2. Create your first real post in the [admin area](/admin/)
3. Customize the theme in `config.toml` under `[web] theme = "dark"`

> "The Web is for everyone." – Tim Berners-Lee

Happy writing!
"""

_POST_2_SLUG = "markdown-reference"
_POST_2_TITLE = "Markdown Formatting Reference"
_POST_2_MD = """\
# Markdown Formatting Reference

This post demonstrates all supported formatting options at a glance.

## Headings

# H1 – Page heading
## H2 – Section heading
### H3 – Subsection

## Text formatting

**Bold**, *italic*, ~~strikethrough~~, `inline code`, [Link](https://arborpress.dev)

## Lists

- First item
- Second item
  - Indented
- Third item

1. Numbered item
2. Another one

## Block quote

> This is a block quote spanning multiple lines.
> It can contain multiple paragraphs.

## Code block

```python
def hello(name: str) -> str:
    return f"Hello, {name}!"

print(hello("World"))
```

## Table

| Column A | Column B | Column C |
|----------|----------|----------|
| Value 1  | Value 2  | Value 3  |
| Alpha    | Beta     | Gamma    |

## Image

![Placeholder](https://picsum.photos/seed/arborpress/720/360)

---

*Last update: inserted automatically on init.*
"""

_IMPRESSUM_SLUG = "imprint"
_IMPRESSUM_TITLE = "Imprint"
_IMPRESSUM_MD = """\
# Imprint

**Information according to § 5 TMG**

Max Sample  
Sample Street 1  
12345 Sample City  
Germany

**Contact:**  
E-Mail: contact@example.com  
Phone: +49 (0)123 456789

**Responsible for content according to § 55 Para. 2 RStV:**  
Max Sample  
Sample Street 1  
12345 Sample City

---

## Disclaimer

### Liability for content

The contents of this page have been created with the utmost care. We assume no
liability for the correctness, completeness, and up-to-dateness of the content.
As a service provider, we are responsible for our own content on these pages
in accordance with § 7 Para. 1 TMG under the general laws.

### Liability for links

Our website contains links to external third-party websites whose content we
have no influence over. We therefore cannot assume any liability for this
third-party content.

### Copyright

The content and works created by the site operators on these pages are subject
to German copyright law.

> **Note:** Please adapt this information to your actual details.
> The imprint serves only as a template.
"""

_PRIVACY_SLUG = "privacy"
_PRIVACY_TITLE = "Privacy Policy"
_PRIVACY_MD = """\
# Privacy Policy

## 1. Controller

The controller responsible for data processing on this website:

Max Sample  
Sample Street 1  
12345 Sample City  
E-Mail: privacy@example.com

## 2. Collection and processing of personal data

### Server log files

When you visit our website, information is automatically stored in server log
files that your browser transmits:

- Browser type and version
- Operating system
- Referrer URL
- Hostname of the accessing computer
- Time of the server request
- IP address (anonymised)

This data is not merged with other data sources.
Legal basis: Art. 6 Para. 1 lit. f GDPR.

### Cookies

This website uses only technically necessary cookies (session cookie
for logged-in users). No tracking or advertising cookies are used.

## 3. Contact form / e-mail

If you contact us by e-mail, your details will be stored to process your
request and for possible follow-up questions. Legal basis: Art. 6 Para. 1
lit. b GDPR (contract fulfilment) or Art. 6 Para. 1 lit. f GDPR (legitimate interest).

## 4. User accounts (WebAuthn)

During registration, a cryptographic public key (WebAuthn credential) is stored.
No passwords are stored. Biometric data is processed exclusively locally on your
device and never leaves it.

Stored data: username, public key, time of registration and last login.

Legal basis: Art. 6 Para. 1 lit. b GDPR.

## 5. Your rights

Under GDPR you have the following rights:

- **Right of access** (Art. 15 GDPR)
- **Right to rectification** (Art. 16 GDPR)
- **Right to erasure** (Art. 17 GDPR)
- **Right to restriction of processing** (Art. 18 GDPR)
- **Right to data portability** (Art. 20 GDPR)
- **Right to object** (Art. 21 GDPR)

To exercise your rights, please contact: privacy@example.com

You also have the right to lodge a complaint with a data protection supervisory authority.

## 6. No disclosure to third parties

Personal data will not be passed on to third parties unless there is a legal obligation.

## 7. Federation (ActivityPub)

If federation is enabled, published posts are transmitted to followers in other
Fediverse instances. This includes post title, content, publication time, and
author name. The transmission is based on Art. 6 Para. 1 lit. b GDPR (user agreement).

---

> **Note:** Please adapt this privacy policy to your actual processing activities.
> This text is a template and does not replace legal advice.

*As of: {{ date }}*
"""


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------


async def seed_database(db: AsyncSession, *, force: bool = False) -> dict[str, int]:
    """Insert example content.

    Args:
        db:    Active AsyncSession
        force: If True, re-inserts even when data already exists

    Returns:
        Dict with inserted records per table.
    """
    from arborpress.models.content import Page, PageType, Post, PostStatus, Tag

    inserted: dict[str, int] = {"posts": 0, "pages": 0, "tags": 0}

    # ---- Tags ----
    existing_tags = (await db.execute(select(Tag))).scalars().all()
    tag_slugs = {t.slug for t in existing_tags}
    seed_tags = [
        Tag(slug="news",     label="News",     lang="en"),
        Tag(slug="tutorial", label="Tutorial", lang="en"),
        Tag(slug="meta",     label="Meta",     lang="en"),
    ]
    created_tags: dict[str, Tag] = {}
    for tag in seed_tags:
        if not force and tag.slug in tag_slugs:
            # Tag existiert schon – referenzieren
            for et in existing_tags:
                if et.slug == tag.slug:
                    created_tags[tag.slug] = et
            continue
        db.add(tag)
        created_tags[tag.slug] = tag
        inserted["tags"] += 1

    await db.flush()

    # ---- Posts ----
    _q1 = await db.execute(select(Post).where(Post.slug == _POST_1_SLUG))
    if force or not _q1.scalar_one_or_none():
        post1 = Post(
            id=_uid(),
            short_id=_short_id(),
            slug=_POST_1_SLUG,
            title=_POST_1_TITLE,
            body_md=_POST_1_MD,
            body_html=_md_to_html(_POST_1_MD),
            excerpt="Discover ArborPress – a self-hosted blogging platform "
                    "with WebAuthn login, ActivityPub, and full control over your data.",
            status=PostStatus.PUBLISHED,
            lang="en",
            published_at=_now(),
        )
        tags_for_post1 = [created_tags[s] for s in ("news", "meta") if s in created_tags]
        post1.tags = tags_for_post1
        db.add(post1)
        inserted["posts"] += 1

    _q2 = await db.execute(select(Post).where(Post.slug == _POST_2_SLUG))
    if force or not _q2.scalar_one_or_none():
        post2 = Post(
            id=_uid(),
            short_id=_short_id(),
            slug=_POST_2_SLUG,
            title=_POST_2_TITLE,
            body_md=_POST_2_MD,
            body_html=_md_to_html(_POST_2_MD),
            excerpt="All supported formatting options at a glance: "
                    "headings, lists, code blocks, tables, and more.",
            status=PostStatus.PUBLISHED,
            lang="en",
            published_at=_now(),
        )
        tags_for_post2 = [created_tags[s] for s in ("tutorial", "meta") if s in created_tags]
        post2.tags = tags_for_post2
        db.add(post2)
        inserted["posts"] += 1

    # ---- System-Seiten ----
    date_str = _now().strftime("%B %Y")

    async def _upsert_page(slug: str, title: str, md: str, ptype: PageType) -> None:
        existing = (await db.execute(select(Page).where(Page.slug == slug))).scalar_one_or_none()
        if existing and not force:
            return
        md_rendered = md.replace("{{ date }}", date_str)
        if existing:
            existing.title = title
            existing.body_md = md_rendered
            existing.body_html = _md_to_html(md_rendered)
        else:
            page = Page(
                id=_uid(),
                slug=slug,
                title=title,
                body_md=md_rendered,
                body_html=_md_to_html(md_rendered),
                page_type=ptype,
                lang="en",
                is_published=True,
                show_in_footer=True,
                noindex=(ptype == PageType.IMPRESSUM),
            )
            db.add(page)
            inserted["pages"] += 1

    await _upsert_page(
        _IMPRESSUM_SLUG, _IMPRESSUM_TITLE, _IMPRESSUM_MD, PageType.IMPRESSUM  # /page/imprint
    )
    await _upsert_page(
        _PRIVACY_SLUG, _PRIVACY_TITLE, _PRIVACY_MD, PageType.PRIVACY  # /page/privacy
    )

    await db.commit()
    log.info("Seed completed: %s", inserted)
    return inserted
