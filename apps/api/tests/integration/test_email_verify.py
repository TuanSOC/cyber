"""Integration tests for email verification token flow and link scanner defense (M11 phase 3)."""

from datetime import UTC, datetime, timedelta
import secrets
import pytest
from sqlalchemy import select

from app.core.security import hash_token
from app.core.tenancy import tenant_session
from app.modules.auth.models import AuthEvent, AuthEventType
from app.modules.identity.models import ActionToken
from app.modules.mail.models import EmailOutbox
from app.modules.users.models import User
from tests.factories import csrf, new_client, register


@pytest.mark.asyncio
async def test_email_verify_request_creates_token_and_outbox() -> None:
    async with new_client() as client:
        user = await register(client, email="verify_target@example.com")
        headers = csrf(user)

        resp = await client.post("/api/v1/auth/email/verify-request", headers=headers)
        assert resp.status_code == 204

        # Check DB for ActionToken and EmailOutbox
        async with tenant_session(None, user.user_id) as session:
            tok = (
                await session.execute(
                    select(ActionToken).where(
                        ActionToken.user_id == user.user_id,
                        ActionToken.purpose == "email_verify",
                    )
                )
            ).scalar_one_or_none()
            assert tok is not None
            assert tok.consumed_at is None
            assert tok.email == "verify_target@example.com"

            outbox_row = (
                await session.execute(
                    select(EmailOutbox).where(EmailOutbox.to_email == "verify_target@example.com")
                )
            ).scalar_one_or_none()
            assert outbox_row is not None
            assert outbox_row.template == "email_verify"


@pytest.mark.asyncio
async def test_email_verify_link_scanner_defense_rt8() -> None:
    """A link scanner or another authenticated user cannot consume or verify another user's token."""
    # 1. Target user has pending verification token
    raw_token = secrets.token_urlsafe(32)
    token_h = hash_token(raw_token)

    async with new_client() as target_client:
        target = await register(target_client, email="victim@example.com")
        async with tenant_session(None, target.user_id) as session:
            session.add(
                ActionToken(
                    user_id=target.user_id,
                    purpose="email_verify",
                    token_hash=token_h,
                    email="victim@example.com",
                    expires_at=datetime.now(UTC) + timedelta(hours=24),
                )
            )

    # 2. Scanner or third party signed in as another user attempts to verify with victim's token
    async with new_client() as attacker_client:
        attacker = await register(attacker_client, email="attacker@example.com")
        headers = csrf(attacker)

        resp = await attacker_client.post(
            "/api/v1/auth/email/verify",
            headers=headers,
            json={"token": raw_token},
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "token_invalid"

        # Verify token remains UNCONSUMED
        async with tenant_session(None, target.user_id) as session:
            tok = (
                await session.execute(
                    select(ActionToken).where(ActionToken.token_hash == token_h)
                )
            ).scalar_one()
            assert tok.consumed_at is None

            # Victim email is not verified yet
            victim_user = (
                await session.execute(
                    select(User).where(User.id == target.user_id)
                )
            ).scalar_one()
            assert victim_user.email_verified_at is None


@pytest.mark.asyncio
async def test_email_verify_success_and_single_use() -> None:
    raw_token = secrets.token_urlsafe(32)
    token_h = hash_token(raw_token)

    async with new_client() as client:
        user = await register(client, email="legit_user@example.com")
        async with tenant_session(None, user.user_id) as session:
            session.add(
                ActionToken(
                    user_id=user.user_id,
                    purpose="email_verify",
                    token_hash=token_h,
                    email="legit_user@example.com",
                    expires_at=datetime.now(UTC) + timedelta(hours=24),
                )
            )

        headers = csrf(user)
        # 1. First verification succeeds
        resp = await client.post(
            "/api/v1/auth/email/verify",
            headers=headers,
            json={"token": raw_token},
        )
        assert resp.status_code == 204

        # Verify user is marked verified
        async with tenant_session(None, user.user_id) as session:
            u = (
                await session.execute(
                    select(User).where(User.id == user.user_id)
                )
            ).scalar_one()
            assert u.email_verified_at is not None

            tok = (
                await session.execute(
                    select(ActionToken).where(ActionToken.token_hash == token_h)
                )
            ).scalar_one()
            assert tok.consumed_at is not None

            # Check AuthEvent
            event = (
                await session.execute(
                    select(AuthEvent).where(
                        AuthEvent.user_id == user.user_id,
                        AuthEvent.event == AuthEventType.EMAIL_VERIFIED,
                    )
                )
            ).scalar_one_or_none()
            assert event is not None

        # 2. Second verification with same token fails 404 (single use)
        resp2 = await client.post(
            "/api/v1/auth/email/verify",
            headers=headers,
            json={"token": raw_token},
        )
        assert resp2.status_code == 404
        assert resp2.json()["error"]["code"] == "token_invalid"

