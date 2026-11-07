"""Integration tests for registration modes (open vs invite_only) and register-with-invitation (M11 phase 3)."""

from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.invitations.models import OrgInvitation
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.users.models import User
from tests.factories import csrf, new_client, register
from tests.identity_helpers import seed_invitation


@pytest.mark.asyncio
async def test_invite_only_refuses_open_registration(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "registration_mode", "invite_only")

    async with new_client() as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "uninvited@example.com",
                "password": "Password123!Secure",
                "display_name": "Uninvited User",
                "organization_name": "Uninvited Org",
            },
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "registration_closed"


@pytest.mark.asyncio
async def test_invite_only_allows_valid_invitation(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "registration_mode", "invite_only")

    # 1. Seed invitation in target org
    async with new_client() as client:
        # Temporarily enable open to register owner or seed directly
        monkeypatch.setattr(settings, "registration_mode", "open")
        owner = await register(client, org_name="Target Org")
        monkeypatch.setattr(settings, "registration_mode", "invite_only")

        seeded = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="invitee_user@example.com",
            role=MemberRole.ANALYST,
        )

    # 2. Register with invitation in invite_only mode
    async with new_client() as register_client:
        resp = await register_client.post(
            "/api/v1/auth/register",
            json={
                "email": "invitee_user@example.com",
                "password": "Password123!Secure",
                "display_name": "Invited Analyst",
                "invitation_token": seeded.token,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        user_data = data["user"]
        assert user_data["email"] == "invitee_user@example.com"

        # Exactly 1 membership in the target org, no new org created
        memberships = data["memberships"]
        assert len(memberships) == 1
        assert memberships[0]["organization_id"] == str(owner.org_id)
        assert memberships[0]["role"] == "analyst"

        # Check in DB that user owns no orgs and email is verified
        user_id = user_data["id"]
        async with tenant_session(owner.org_id, user_id) as session:
            user_row = (
                await session.execute(
                    select(User).where(User.id == user_id)
                )
            ).scalar_one()
            assert user_row.email_verified_at is not None

            owned_orgs = (
                await session.execute(
                    select(Organization).where(Organization.created_by == user_id)
                )
            ).scalars().all()
            assert len(owned_orgs) == 0

            # Invitation is consumed
            inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == seeded.id)
                )
            ).scalar_one()
            assert inv.accepted_at is not None
            assert str(inv.accepted_by) == user_id


@pytest.mark.asyncio
async def test_register_with_invitation_email_mismatch_fails_409() -> None:
    async with new_client() as client:
        owner = await register(client)
        seeded = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="proper@example.com",
            role=MemberRole.VIEWER,
        )

    async with new_client() as reg_client:
        resp = await reg_client.post(
            "/api/v1/auth/register",
            json={
                "email": "different@example.com",
                "password": "Password123!Secure",
                "display_name": "Mismatch User",
                "invitation_token": seeded.token,
            },
        )
        assert resp.status_code == 409
        assert resp.json()["error"]["code"] == "invitation_email_mismatch"


@pytest.mark.asyncio
async def test_register_with_invalid_or_expired_token_fails_404() -> None:
    async with new_client() as reg_client:
        resp = await reg_client.post(
            "/api/v1/auth/register",
            json={
                "email": "someone@example.com",
                "password": "Password123!Secure",
                "display_name": "Test User",
                "invitation_token": "x" * 43,
            },
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "invitation_invalid"

