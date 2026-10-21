from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from arborpress.mail.template_engine import (
    TEMPLATE_REGISTRY,
    TemplateError,
    _packaged_source,
    render_mail_template,
    render_sources,
    reset_template_override,
    resolve_locale,
    restore_template_revision,
    save_template_override,
    validate_override,
)


def _sample_context(template_id: str) -> dict[str, str]:
    definition = TEMPLATE_REGISTRY[template_id]
    return {
        name: ("https://example.invalid/action" if name.endswith("_url") else f"Sample {name}")
        for name in definition.required | definition.optional
    }


@pytest.mark.parametrize("template_id", sorted(TEMPLATE_REGISTRY))
@pytest.mark.parametrize("locale", ["de-DE", "en-GB"])
def test_packaged_defaults_render(template_id: str, locale: str) -> None:
    definition = TEMPLATE_REGISTRY[template_id]
    sources = {
        kind: (
            _packaged_source(template_id, locale, kind)
            if kind != "html" or definition.has_html
            else None
        )
        for kind in ("subject", "plain", "html")
    }
    subject, plain, html = render_sources(definition, sources, _sample_context(template_id))
    assert subject
    assert plain
    assert html is None or "<script" not in html.lower()


def test_locale_resolution_prefers_exact_then_base_then_site_then_package() -> None:
    assert resolve_locale("de-DE", user_locale="en-GB", site_locale="en-GB") == "de-DE"
    assert resolve_locale(None, user_locale="de-AT", site_locale="en-GB") == "de-DE"
    assert resolve_locale(None, user_locale="fr-FR", site_locale="en-GB") == "en-GB"
    assert resolve_locale(None, user_locale="fr-FR", site_locale=None) == "en-GB"


def test_context_schema_rejects_missing_and_unknown_fields() -> None:
    definition = TEMPLATE_REGISTRY["comment.guest_confirmation"]
    sources = {
        kind: _packaged_source(definition.id, "en-GB", kind)
        for kind in ("subject", "plain", "html")
    }
    with pytest.raises(TemplateError, match="Context"):
        render_sources(definition, sources, {"display_name": "Ada", "unexpected": "secret"})
    with pytest.raises(TemplateError, match="Required"):
        render_sources(definition, sources, {"display_name": "Ada"})


def test_sandbox_rejects_private_attributes_and_jinja_imports() -> None:
    definition = TEMPLATE_REGISTRY["notification.generic"]
    context = _sample_context(definition.id)
    sources = {
        "subject": "{{ display_name.__class__ }}",
        "plain": "{{ display_name }}",
        "html": None,
    }
    with pytest.raises(TemplateError):
        render_sources(definition, sources, context)
    sources["subject"] = "Normal"
    sources["plain"] = "{% include 'other' %}"
    with pytest.raises(TemplateError, match="forbidden"):
        render_sources(definition, sources, context)


@pytest.mark.asyncio
async def test_override_validation_rejects_header_injection_and_active_html() -> None:
    definition = TEMPLATE_REGISTRY["notification.generic"]
    context = _sample_context(definition.id)
    subject = "{{ notification_title }}\nBcc: attacker@example.invalid"
    with pytest.raises(TemplateError):
        render_sources(
            definition,
            {"subject": subject, "plain": "{{ notification_message }}", "html": None},
            context,
        )
    with pytest.raises(TemplateError, match="active or unsafe"):
        await validate_override(
            None,
            definition.id,
            "en-GB",
            "Subject",
            "Body",
            '<p onclick="alert(1)">{{ notification_message }}</p>',
        )


def test_override_html_escapes_untrusted_values() -> None:
    definition = TEMPLATE_REGISTRY["notification.generic"]
    context = _sample_context(definition.id)
    context["notification_message"] = "<script>alert(1)</script>"
    subject, plain, html = render_sources(
        definition,
        {
            "subject": "{{ notification_title }}",
            "plain": "{{ notification_message }}",
            "html": "<p>{{ notification_message }}</p>",
        },
        context,
    )
    assert subject
    assert "<script>" in plain
    assert html == "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"


@pytest.mark.asyncio
async def test_override_revision_restore_reset_and_optimistic_conflict(db_session) -> None:
    from arborpress.models.mail import MailTemplateRevision
    from arborpress.models.user import AccountType, User, UserRole

    suffix = uuid.uuid4().hex[:10]
    actor = User(
        username=f"template-{suffix}",
        display_name="Template Admin",
        account_type=AccountType.PUBLIC,
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(actor)
    await db_session.flush()
    template_id = "notification.generic"
    context = _sample_context(template_id)
    original = await render_mail_template(db_session, template_id, context, locale="en-GB")

    revision = await save_template_override(
        db_session,
        template_id=template_id,
        locale="en-GB",
        subject="Custom {{ notification_title }}",
        plain="Custom {{ notification_message }}",
        html="<p>Custom {{ notification_message }}</p>",
        actor_user_id=str(actor.id),
        expected_revision=0,
    )
    assert revision == 1
    customized = await render_mail_template(db_session, template_id, context, locale="en-GB")
    assert customized[0].startswith("Custom ")
    assert customized[4] == "db:1"
    with pytest.raises(TemplateError, match="concurrently"):
        await save_template_override(
            db_session,
            template_id=template_id,
            locale="en-GB",
            subject="Stale",
            plain="Stale",
            html=None,
            actor_user_id=str(actor.id),
            expected_revision=0,
        )

    restored_revision = await restore_template_revision(
        db_session,
        template_id=template_id,
        locale="en-GB",
        revision_number=1,
        actor_user_id=str(actor.id),
        expected_revision=1,
    )
    assert restored_revision == 2
    reset_revision = await reset_template_override(
        db_session,
        template_id=template_id,
        locale="en-GB",
        actor_user_id=str(actor.id),
        expected_revision=2,
    )
    assert reset_revision == 3
    reset = await render_mail_template(db_session, template_id, context, locale="en-GB")
    assert reset[0] == original[0]
    assert reset[4] == "package:1"
    revisions = list(
        (
            await db_session.scalars(
                select(MailTemplateRevision).where(
                    MailTemplateRevision.template_id == template_id,
                    MailTemplateRevision.locale == "en-GB",
                )
            )
        ).all()
    )
    assert [row.action for row in revisions] == ["save", "restore", "reset"]
