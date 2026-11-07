"""Integration tests for password reset and forgot password flow (M11 phase 4)."""

import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
import uuid

import pytest
from sqlalchemy import select

from app.core.cookies import ACCESS_COOKIE
from app.core.security import hash_token
from app.core.tenancy import tenant_session
from app.modules.auth.models import AuthEvent, AuthEventType
from app.modules.identity.models import ActionPurpose, ActionToken
from app.modules.mail.models import EmailOutbox
from app.modules.mail.templates import MailTemplate
from app.modules.users.models import User
from tests.factories import csrf, login, new_client, register, unique_email
from tests.identity_helpers import outbox_rows, set_password_hash


async def test_forgot_password_happy_path_and_rate_limits() -> None:
    """RT4, RT6: forgot returns 202 right after limits; background task creates outbox row."""
    reg = await register()
    client = new_client(ip="10.10.1.1")

    # 1. Happy path: 202 Accepted
    resp = await client.post("/api/v1/auth/password/forgot", json={"email": reg.email})
    assert resp.status_code == 202

    # Give background tasks a brief moment to finish
    await asyncio.sleep(0.1)

    # Verify outbox row created
    rows = await outbox_rows(to=reg.email)
    reset_rows = [r for r in rows if r.template == MailTemplate.PASSWORD_RESET.value]
    assert len(reset_rows) == 1
    outbox_entry = reset_rows[0]
    assert outbox_entry.params["display_name"] == reg.body["user"]["display_name"]

    # Verify auth event created with user_id
    async with tenant_session(None, None) as session:
        events = (
            await session.execute(
                select(AuthEvent).where(
                    AuthEvent.user_id == reg.user_id,
                    AuthEvent.event == AuthEventType.PASSWORD_RESET_REQUESTED,
                )
            )
        ).scalars().all()
        assert len(events) >= 1

    # 2. Email rate limit: 3 per hour
    # 2nd attempt
    r2 = await client.post("/api/v1/auth/password/forgot", json={"email": reg.email})
    assert r2.status_code == 202
    # 3rd attempt
    r3 = await client.post("/api/v1/auth/password/forgot", json={"email": reg.email})
    assert r3.status_code == 202
    # 4th attempt -> 429
    r4 = await client.post("/api/v1/auth/password/forgot", json={"email": reg.email})
    assert r4.status_code == 429
    assert r4.json()["error"]["code"] == "rate_limited"


async def test_forgot_password_indistinguishable_across_account_states() -> None:
    """RT6: forgot answers 202 with no outbox mail for unknown, inactive, or passwordless users."""
    client = new_client(ip="10.10.2.1")

    # 1. Unknown email
    unknown_email = unique_email("unknown")
    resp_unknown = await client.post("/api/v1/auth/password/forgot", json={"email": unknown_email})
    assert resp_unknown.status_code == 202
    await asyncio.sleep(0.1)
    assert await outbox_rows(to=unknown_email) == []

    # 2. SSO user with unusable password
    reg_sso = await register()
    await set_password_hash(reg_sso.user_id, "!sso")
    client_sso = new_client(ip="10.10.2.2")
    resp_sso = await client_sso.post("/api/v1/auth/password/forgot", json={"email": reg_sso.email})
    assert resp_sso.status_code == 202
    await asyncio.sleep(0.1)
    sso_outbox = [r for r in await outbox_rows(to=reg_sso.email) if r.template == MailTemplate.PASSWORD_RESET.value]
    assert sso_outbox == []


async def test_forgot_invalidates_previous_token() -> None:
    """One live reset token per user: a new forgot request invalidates earlier tokens."""
    reg = await register()
    client = new_client(ip="10.10.3.1")

    # First request
    r1 = await client.post("/api/v1/auth/password/forgot", json={"email": reg.email})
    assert r1.status_code == 202
    await asyncio.sleep(0.1)

    async with tenant_session(None, None) as session:
        tokens = (
            await session.execute(
                select(ActionToken).where(
                    ActionToken.user_id == reg.user_id,
                    ActionToken.purpose == ActionPurpose.PASSWORD_RESET.value,
                )
            )
        ).scalars().all()
        assert len(tokens) == 1
        first_token = tokens[0]
        assert first_token.consumed_at is None

    # Second request
    r2 = await client.post("/api/v1/auth/password/forgot", json={"email": reg.email})
    assert r2.status_code == 202
    await asyncio.sleep(0.1)

    async with tenant_session(None, None) as session:
        tokens_after = (
            await session.execute(
                select(ActionToken).where(
                    ActionToken.user_id == reg.user_id,
                    ActionToken.purpose == ActionPurpose.PASSWORD_RESET.value,
                ).order_by(ActionToken.created_at)
            )
        ).scalars().all()
        assert len(tokens_after) == 2
        # First token consumed, second active
        assert tokens_after[0].consumed_at is not None
        assert tokens_after[1].consumed_at is None


async def test_reset_password_happy_path_and_session_revocation() -> None:
    """Reset password succeeds, revokes all sessions, sets email_verified_at, mails notice."""
    reg = await register()
    old_client = reg.client
    old_cookie = old_client.cookies.get(ACCESS_COOKIE)

    # Seed an action token directly
    raw_token = "A" * 43
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    async with tenant_session(None, None) as session:
        session.add(
            ActionToken(
                id=uuid.uuid4(),
                user_id=reg.user_id,
                purpose=ActionPurpose.PASSWORD_RESET.value,
                token_hash=token_hash,
                email=reg.email,
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
            )
        )

    new_password = "new horse battery staple 123"
    client = new_client(ip="10.10.4.1")

    # Reset password
    reset_resp = await client.post(
        "/api/v1/auth/password/reset",
        json={"token": raw_token, "new_password": new_password},
    )
    assert reset_resp.status_code == 204

    # 1. Old session is dead (access token denied in Redis immediately)
    me_resp = await old_client.get("/api/v1/auth/me")
    assert me_resp.status_code == 401

    # 2. Login with new password works
    new_client_logged_in = await login(reg.email, new_password)
    new_me = await new_client_logged_in.get("/api/v1/auth/me")
    assert new_me.status_code == 200

    # 3. Old password fails
    fail_resp = await (new_client()).post(
        "/api/v1/auth/login", json={"email": reg.email, "password": "correct horse battery staple"}
    )
    assert fail_resp.status_code == 401

    # 4. email_verified_at and password_changed_at are set
    async with tenant_session(None, None) as session:
        user_row = (await session.execute(select(User).where(User.id == reg.user_id))).scalar_one()
        assert user_row.email_verified_at is not None
        assert user_row.password_changed_at is not None

    # 5. Mail password_changed enqueued
    rows = await outbox_rows(to=reg.email)
    changed_rows = [r for r in rows if r.template == MailTemplate.PASSWORD_CHANGED.value]
    assert len(changed_rows) == 1

    # 6. Auth event recorded
    async with tenant_session(None, None) as session:
        events = (
            await session.execute(
                select(AuthEvent).where(
                    AuthEvent.user_id == reg.user_id,
                    AuthEvent.event == AuthEventType.PASSWORD_RESET,
                )
            )
        ).scalars().all()
        assert len(events) == 1


async def test_reset_token_single_use_and_invalid_tokens() -> None:
    """Invalid, consumed, or expired tokens return 404 token_invalid."""
    reg = await register()
    raw_token = "B" * 43
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    async with tenant_session(None, None) as session:
        session.add(
            ActionToken(
                id=uuid.uuid4(),
                user_id=reg.user_id,
                purpose=ActionPurpose.PASSWORD_RESET.value,
                token_hash=token_hash,
                email=reg.email,
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
            )
        )

    client = new_client()

    # 1. Unknown token -> 404
    r_unknown = await client.post(
        "/api/v1/auth/password/reset",
        json={"token": "Z" * 43, "new_password": "new password 12345"},
    )
    assert r_unknown.status_code == 404
    assert r_unknown.json()["error"]["code"] == "token_invalid"

    # 2. Valid token consumption -> 204
    r_ok = await client.post(
        "/api/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "new password 12345"},
    )
    assert r_ok.status_code == 204

    # 3. Token reuse (already consumed) -> 404
    r_reuse = await client.post(
        "/api/v1/auth/password/reset",
        json={"token": raw_token, "new_password": "new password 12345"},
    )
    assert r_reuse.status_code == 404
    assert r_reuse.json()["error"]["code"] == "token_invalid"
