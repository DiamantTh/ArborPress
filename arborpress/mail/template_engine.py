"""Registry-backed, sandboxed mail templates with immutable local revisions.

Templates are rendered before an outbox row is created.  The outbox therefore
remains a snapshot of the message even if an administrator later edits a template.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

import bleach  # type: ignore[import-untyped]
from jinja2 import StrictUndefined, meta, nodes
from jinja2.sandbox import ImmutableSandboxedEnvironment
from sqlalchemy import select

from arborpress.models.mail import MailTemplateOverride, MailTemplateRevision

MAX_SOURCE = 64 * 1024
MAX_RENDERED = 128 * 1024
HTML_TAGS = {
    "p",
    "br",
    "h1",
    "h2",
    "h3",
    "em",
    "strong",
    "b",
    "i",
    "a",
    "ul",
    "ol",
    "li",
    "blockquote",
    "hr",
}
HTML_ATTRIBUTES = {"a": ["href", "title"]}
_DANGEROUS_TAG = re.compile(
    r"^\s*<(?:script|iframe|object|embed|form|input|button|style|svg|math)\b", re.I
)
_EVENT_ATTRIBUTE = re.compile(r"\son[a-z]+\s*=", re.I)
_JAVASCRIPT_SCHEME = re.compile(r"javascript\s*:", re.I)


@dataclass(frozen=True, slots=True)
class MailTemplateDefinition:
    id: str
    category: str
    description: str
    required: frozenset[str]
    optional: frozenset[str]
    schema_version: int = 1
    locales: tuple[str, ...] = ("de-DE", "en-GB")
    has_html: bool = True


TEMPLATE_REGISTRY: dict[str, MailTemplateDefinition] = {
    "comment.guest_confirmation": MailTemplateDefinition(
        "comment.guest_confirmation",
        "transactional",
        "Confirm a guest comment",
        frozenset({"display_name", "post_title", "confirmation_url", "site_name"}),
        frozenset(),
    ),
    "comment.admin_notice": MailTemplateDefinition(
        "comment.admin_notice",
        "administrative",
        "Notify moderators about a comment",
        frozenset(
            {"display_name", "author_email", "post_title", "comment_body", "admin_url", "site_name"}
        ),
        frozenset(),
    ),
    "notification.generic": MailTemplateDefinition(
        "notification.generic",
        "notification",
        "Generic user notification email",
        frozenset({"display_name", "notification_title", "notification_message", "site_name"}),
        frozenset({"action_url"}),
    ),
}

_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,95}$")
_LOCALE = re.compile(r"^[a-z]{2,3}-[A-Z]{2}$")
_EMAIL_SUBJECT = re.compile(r"[\r\n\x00]")


class TemplateError(ValueError):
    """A mail template or override is invalid or unsafe."""


def _environment(*, html: bool) -> ImmutableSandboxedEnvironment:
    env = ImmutableSandboxedEnvironment(
        autoescape=html,
        undefined=StrictUndefined,
        auto_reload=False,
    )
    env.globals.clear()
    env.filters = {
        name: env.filters[name] for name in ("escape", "e", "lower", "upper", "trim", "default")
    }
    env.is_safe_attribute = lambda obj, attr, value: False  # type: ignore[method-assign]
    env.is_safe_callable = lambda obj: False  # type: ignore[method-assign]
    return env


def _validate_source(source: str, allowed_fields: frozenset[str], *, html: bool = False) -> None:
    if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE:
        raise TemplateError("Template source is invalid or too large.")
    env = _environment(html=html)
    try:
        tree = env.parse(source)
    except Exception as exc:
        raise TemplateError("Template syntax is invalid.") from exc
    forbidden = (
        nodes.Include,
        nodes.Import,
        nodes.FromImport,
        nodes.Extends,
        nodes.Call,
        nodes.Getattr,
    )
    if any(isinstance(node, forbidden) for node in tree.find_all(nodes.Node)):
        raise TemplateError("Template uses a forbidden operation.")
    unknown = meta.find_undeclared_variables(tree) - allowed_fields
    if unknown:
        raise TemplateError("Template references fields outside its context schema.")


def _safe_html(value: str) -> str:
    tags = re.findall(r"<[^>]*>", value)
    if any(
        _DANGEROUS_TAG.search(tag) or _EVENT_ATTRIBUTE.search(tag) or _JAVASCRIPT_SCHEME.search(tag)
        for tag in tags
    ):
        raise TemplateError("HTML contains active or unsafe content.")
    cleaned = bleach.clean(
        value,
        tags=HTML_TAGS,
        attributes=HTML_ATTRIBUTES,
        protocols={"http", "https", "mailto"},
        strip=True,
        strip_comments=True,
    )
    return str(cleaned)


def _validate_locale(value: str) -> str:
    if not _LOCALE.fullmatch(value):
        raise TemplateError("Unsupported locale identifier.")
    return value


def resolve_locale(
    requested: str | None,
    *,
    user_locale: str | None = None,
    site_locale: str | None = None,
    supported: tuple[str, ...] = ("de-DE", "en-GB"),
) -> str:
    """Resolve exact, base-language, site, then package English fallback."""
    candidates = [requested, user_locale, site_locale, "en-GB"]
    for candidate in candidates:
        if not candidate:
            continue
        if candidate in supported:
            return candidate
        base = candidate.split("-", 1)[0].lower()
        match = next((item for item in supported if item.split("-", 1)[0].lower() == base), None)
        if match:
            return match
    return supported[0]


def _packaged_source(template_id: str, locale: str, kind: str) -> str:
    definition = TEMPLATE_REGISTRY.get(template_id)
    if (
        definition is None
        or not _SAFE_NAME.fullmatch(template_id)
        or kind not in {"subject", "plain", "html"}
    ):
        raise TemplateError("Unknown mail template.")
    package = files("arborpress.mail.templates")
    choices = [locale, locale.split("-", 1)[0] + "-GB", "en-GB"]
    for candidate in dict.fromkeys(choices):
        if candidate not in definition.locales:
            continue
        resource = package.joinpath(template_id, candidate, f"{kind}.j2")
        if resource.is_file():
            return resource.read_text(encoding="utf-8")
    raise TemplateError("Packaged mail template resource is missing.")


async def _effective_sources(
    db: Any, template_id: str, locale: str
) -> tuple[dict[str, str | None], str]:
    definition = TEMPLATE_REGISTRY.get(template_id)
    if definition is None:
        raise TemplateError("Unknown mail template.")
    locale = resolve_locale(locale, supported=definition.locales)
    row = await db.scalar(
        select(MailTemplateOverride).where(
            MailTemplateOverride.template_id == template_id,
            MailTemplateOverride.locale == locale,
            MailTemplateOverride.active.is_(True),
        )
    )
    if row is not None:
        return (
            {"subject": row.subject_source, "plain": row.plain_source, "html": row.html_source},
            f"db:{row.current_revision}",
        )
    return (
        {
            kind: _packaged_source(template_id, locale, kind)
            if kind != "html" or definition.has_html
            else None
            for kind in ("subject", "plain", "html")
        },
        "package:1",
    )


def _context(definition: MailTemplateDefinition, supplied: dict[str, Any]) -> dict[str, str]:
    allowed = definition.required | definition.optional
    if set(supplied) - allowed:
        raise TemplateError("Context contains fields not allowed by the template registry.")
    missing = definition.required - supplied.keys()
    if missing:
        raise TemplateError("Required template context is missing.")
    if any(not isinstance(value, str) or len(value) > 16_384 for value in supplied.values()):
        raise TemplateError("Template context values must be bounded strings.")
    return dict(supplied)


def render_sources(
    definition: MailTemplateDefinition,
    sources: dict[str, str | None],
    supplied_context: dict[str, Any],
) -> tuple[str, str, str | None]:
    context = _context(definition, supplied_context)
    subject_src = sources["subject"] or ""
    plain_src = sources["plain"] or ""
    html_src = sources["html"]
    _validate_source(subject_src, definition.required | definition.optional)
    _validate_source(plain_src, definition.required | definition.optional)
    if html_src is not None:
        _validate_source(html_src, definition.required | definition.optional, html=True)
        source_tags = re.findall(r"<[^>]*>", html_src)
        if any(
            _DANGEROUS_TAG.search(tag)
            or _EVENT_ATTRIBUTE.search(tag)
            or _JAVASCRIPT_SCHEME.search(tag)
            for tag in source_tags
        ):
            raise TemplateError("HTML template contains active or unsafe content.")
    try:
        subject = _environment(html=False).from_string(subject_src).render(context).strip()
        plain = _environment(html=False).from_string(plain_src).render(context)
        html = (
            _environment(html=True).from_string(html_src).render(context)
            if html_src is not None
            else None
        )
    except Exception as exc:
        raise TemplateError("Mail template rendering failed.") from exc
    if _EMAIL_SUBJECT.search(subject) or not subject or len(subject) > 512:
        raise TemplateError("Rendered subject is invalid.")
    if (
        not plain.strip()
        or len(plain) > MAX_RENDERED
        or (html is not None and len(html) > MAX_RENDERED)
    ):
        raise TemplateError("Rendered mail content is empty or too large.")
    if html is not None:
        html = _safe_html(html)
    return subject, plain, html


async def render_mail_template(
    db: Any,
    template_id: str,
    context: dict[str, Any],
    *,
    locale: str | None = None,
    user_locale: str | None = None,
    site_locale: str | None = None,
) -> tuple[str, str, str | None, str, str]:
    definition = TEMPLATE_REGISTRY.get(template_id)
    if definition is None:
        raise TemplateError("Unknown mail template.")
    effective_locale = resolve_locale(
        locale, user_locale=user_locale, site_locale=site_locale, supported=definition.locales
    )
    sources, revision = await _effective_sources(db, template_id, effective_locale)
    subject, plain, html = render_sources(definition, sources, context)
    return subject, plain, html, effective_locale, revision


async def enqueue_template_mail(
    db: Any = None,
    *,
    template_id: str,
    to: str,
    context: dict[str, Any],
    locale: str | None = None,
    user_locale: str | None = None,
    site_locale: str | None = None,
    idempotency_key: str | None = None,
    purpose: str = "transactional",
) -> str:
    """Render now and store immutable rendered content in the DB outbox."""
    owns_session = db is None
    if owns_session:
        from arborpress.core.db import get_session_factory

        db = get_session_factory()()
    try:
        return await _enqueue_template_mail(
            db,
            template_id=template_id,
            to=to,
            context=context,
            locale=locale,
            user_locale=user_locale,
            site_locale=site_locale,
            idempotency_key=idempotency_key,
            purpose=purpose,
            commit=owns_session,
        )
    except Exception:
        if owns_session:
            await db.rollback()
        raise
    finally:
        if owns_session:
            await db.close()


async def _enqueue_template_mail(
    db: Any,
    *,
    template_id: str,
    to: str,
    context: dict[str, Any],
    locale: str | None,
    user_locale: str | None,
    site_locale: str | None,
    idempotency_key: str | None,
    purpose: str,
    commit: bool,
) -> str:
    subject, plain, html, effective_locale, revision = await render_mail_template(
        db, template_id, context, locale=locale, user_locale=user_locale, site_locale=site_locale
    )
    from arborpress.mail.queue import enqueue_mail

    result = await enqueue_mail(
        to,
        subject,
        plain,
        html,
        idempotency_key,
        purpose=purpose,
        session=db,
        template_id=template_id,
        template_locale=effective_locale,
        template_revision=revision,
    )
    if commit:
        await db.commit()
    return result


async def validate_override(
    db: Any,
    template_id: str,
    locale: str,
    subject: str,
    plain: str,
    html: str | None,
) -> None:
    definition = TEMPLATE_REGISTRY.get(template_id)
    if definition is None or locale not in definition.locales:
        raise TemplateError("Unknown template or locale.")
    fields = definition.required | definition.optional
    sources = {"subject": subject, "plain": plain, "html": html}
    sample = {field: f"Sample {field}" for field in fields}
    if "confirmation_url" in sample or "action_url" in sample or "admin_url" in sample:
        for field in ("confirmation_url", "action_url", "admin_url"):
            if field in sample:
                sample[field] = "https://example.invalid/action"
    render_sources(definition, sources, sample)


async def save_template_override(
    db: Any,
    *,
    template_id: str,
    locale: str,
    subject: str,
    plain: str,
    html: str | None,
    actor_user_id: str,
    expected_revision: int,
) -> int:
    await validate_override(db, template_id, locale, subject, plain, html)
    row = await db.scalar(
        select(MailTemplateOverride)
        .where(
            MailTemplateOverride.template_id == template_id, MailTemplateOverride.locale == locale
        )
        .with_for_update()
    )
    current = row.current_revision if row else 0
    if current != expected_revision:
        raise TemplateError("Template changed concurrently; reload before saving.")
    number = current + 1
    previous = (
        await db.scalar(
            select(MailTemplateRevision).where(
                MailTemplateRevision.template_id == template_id,
                MailTemplateRevision.locale == locale,
                MailTemplateRevision.revision_number == current,
            )
        )
        if current
        else None
    )
    revision = MailTemplateRevision(
        template_id=template_id,
        locale=locale,
        revision_number=number,
        actor_user_id=actor_user_id,
        subject_source=subject,
        plain_source=plain,
        html_source=html,
        action="save",
        previous_revision_id=previous.id if previous else None,
    )
    db.add(revision)
    if row is None:
        row = MailTemplateOverride(template_id=template_id, locale=locale)
        db.add(row)
    row.subject_source, row.plain_source, row.html_source = subject, plain, html
    row.active, row.current_revision, row.updated_by = True, number, actor_user_id
    await db.flush()
    return number


async def restore_template_revision(
    db: Any,
    *,
    template_id: str,
    locale: str,
    revision_number: int,
    actor_user_id: str,
    expected_revision: int,
) -> int:
    source = await db.scalar(
        select(MailTemplateRevision).where(
            MailTemplateRevision.template_id == template_id,
            MailTemplateRevision.locale == locale,
            MailTemplateRevision.revision_number == revision_number,
        )
    )
    if source is None or source.action == "reset":
        raise TemplateError("Template revision does not exist.")
    await validate_override(
        db, template_id, locale, source.subject_source, source.plain_source, source.html_source
    )
    return await _commit_revision(
        db,
        template_id=template_id,
        locale=locale,
        subject=source.subject_source,
        plain=source.plain_source,
        html=source.html_source,
        actor_user_id=actor_user_id,
        expected_revision=expected_revision,
        action="restore",
    )


async def reset_template_override(
    db: Any,
    *,
    template_id: str,
    locale: str,
    actor_user_id: str,
    expected_revision: int,
) -> int:
    definition = TEMPLATE_REGISTRY.get(template_id)
    if definition is None or locale not in definition.locales:
        raise TemplateError("Unknown template or locale.")
    sources = {
        kind: _packaged_source(template_id, locale, kind)
        if kind != "html" or definition.has_html
        else None
        for kind in ("subject", "plain", "html")
    }
    return await _commit_revision(
        db,
        template_id=template_id,
        locale=locale,
        subject=sources["subject"] or "",
        plain=sources["plain"] or "",
        html=sources["html"],
        actor_user_id=actor_user_id,
        expected_revision=expected_revision,
        action="reset",
        active=False,
    )


async def _commit_revision(
    db: Any,
    *,
    template_id: str,
    locale: str,
    subject: str,
    plain: str,
    html: str | None,
    actor_user_id: str,
    expected_revision: int,
    action: str,
    active: bool = True,
) -> int:
    row = await db.scalar(
        select(MailTemplateOverride)
        .where(
            MailTemplateOverride.template_id == template_id, MailTemplateOverride.locale == locale
        )
        .with_for_update()
    )
    current = row.current_revision if row else 0
    if current != expected_revision:
        raise TemplateError("Template changed concurrently; reload before saving.")
    number = current + 1
    previous = (
        await db.scalar(
            select(MailTemplateRevision).where(
                MailTemplateRevision.template_id == template_id,
                MailTemplateRevision.locale == locale,
                MailTemplateRevision.revision_number == current,
            )
        )
        if current
        else None
    )
    db.add(
        MailTemplateRevision(
            template_id=template_id,
            locale=locale,
            revision_number=number,
            actor_user_id=actor_user_id,
            subject_source=subject,
            plain_source=plain,
            html_source=html,
            action=action,
            previous_revision_id=previous.id if previous else None,
        )
    )
    if row is None:
        row = MailTemplateOverride(template_id=template_id, locale=locale)
        db.add(row)
    row.subject_source, row.plain_source, row.html_source = subject, plain, html
    row.active, row.current_revision, row.updated_by = active, number, actor_user_id
    await db.flush()
    return number
