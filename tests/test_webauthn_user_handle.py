from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from arborpress.auth.webauthn import (
    WebAuthnService,
    decode_webauthn_user_handle,
    encode_webauthn_user_handle,
    new_webauthn_user_handle,
)


def test_user_handle_is_64_random_bytes_and_pending_encoding_roundtrips() -> None:
    first = new_webauthn_user_handle()
    second = new_webauthn_user_handle()
    assert len(first) == 64
    assert len(second) == 64
    assert first != second
    assert decode_webauthn_user_handle(encode_webauthn_user_handle(first)) == first

    with pytest.raises(ValueError):
        encode_webauthn_user_handle(b"too short")
    with pytest.raises(ValueError):
        decode_webauthn_user_handle("not-a-valid-user-handle")


@pytest.mark.parametrize("resident_key", ["preferred", "discouraged"])
def test_registration_options_use_the_persisted_handle_without_transforming_it(
    resident_key: str,
) -> None:
    handle = new_webauthn_user_handle()
    service = WebAuthnService(
        "example.test",
        "ArborPress",
        "https://example.test",
        resident_key=resident_key,
    )

    options = [
        service.generate_registration_options(
            user_id=handle,
            user_name="mutable-login-name",
            user_display_name="Mutable Display Name",
        )
        for _ in range(2)
    ]

    assert [option.user.id for option in options] == [handle, handle]
    for option in options:
        assert option.user.name == "mutable-login-name"
        assert option.user.display_name == "Mutable Display Name"
        assert option.authenticator_selection is not None
        assert option.authenticator_selection.resident_key.value == resident_key


@pytest.mark.asyncio
async def test_accounts_get_distinct_handles_independent_of_database_ids(db_session) -> None:
    from arborpress.models.user import User

    first = User(
        id=str(uuid.uuid4()),
        username=f"handle-a-{uuid.uuid4().hex[:10]}",
        display_name="First",
    )
    second = User(
        id=str(uuid.uuid4()),
        username=f"handle-b-{uuid.uuid4().hex[:10]}",
        display_name="Second",
    )
    db_session.add_all([first, second])
    await db_session.flush()

    assert first.webauthn_user_handle != second.webauthn_user_handle
    for user in (first, second):
        assert len(user.webauthn_user_handle) == 64
        assert user.webauthn_user_handle != str(user.id).encode("utf-8")


@pytest.mark.asyncio
async def test_user_handle_constraints_reject_reuse_and_wrong_length(db_session) -> None:
    from arborpress.models.user import User

    handle = new_webauthn_user_handle()
    db_session.add(User(
        username=f"handle-unique-a-{uuid.uuid4().hex[:8]}",
        display_name="First",
        webauthn_user_handle=handle,
    ))
    await db_session.flush()
    db_session.add(User(
        username=f"handle-unique-b-{uuid.uuid4().hex[:8]}",
        display_name="Second",
        webauthn_user_handle=handle,
    ))
    with pytest.raises(IntegrityError):
        await db_session.flush()


@pytest.mark.asyncio
async def test_user_handle_length_is_database_enforced(db_session) -> None:
    from arborpress.models.user import User

    db_session.add(User(
        username=f"handle-length-{uuid.uuid4().hex[:8]}",
        display_name="Invalid Handle",
        webauthn_user_handle=b"x" * 63,
    ))
    with pytest.raises(IntegrityError):
        await db_session.flush()

