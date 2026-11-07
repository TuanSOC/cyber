"""Integration tests for invitation inspect and accept (M11 phase 3)."""

import asyncio
from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy import select, update

from app.core.security import hash_token
from app.core.tenancy import tenant_session
from app.modules.invitations.models import InvitationIndex, OrgInvitation
from app.modules.organizations.models import MemberRole, OrganizationMember
from app.modules.users.models import User
from tests.factories import csrf, new_client, register, make_user
from tests.identity_helpers import seed_invitation


@pytest.mark.asyncio
async def test_inspect_valid_invitation() -> None:
    async with new_client() as client:
        owner = await register(client, org_name="Acme Corp")
        seeded = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="developer@example.com",
            role=MemberRole.ANALYST,
        )

        resp = await client.post(
            "/api/v1/invitations/inspect",
            json={"token": seeded.token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_masked"] == "d***@example.com"
        assert data["organization_name"] == "Acme Corp"
        assert data["role"] == "analyst"
        assert data["inviter_name"] is not None
        assert "expires_at" in data


@pytest.mark.asyncio
async def test_inspect_invalid_token_answers_404() -> None:
    async with new_client() as client:
        resp = await client.post(
            "/api/v1/invitations/inspect",
            json={"token": "x" * 43},
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "invitation_invalid"


@pytest.mark.asyncio
async def test_accept_invitation_success() -> None:
    # 1. Owner creates invitation for invitee@example.com
    async with new_client() as owner_client:
        owner = await register(owner_client, org_name="Target Org")
        seeded = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="invitee@example.com",
            role=MemberRole.ANALYST,
        )

    # 2. Invitee signs in with matching email
    async with new_client() as invitee_client:
        invitee = await register(invitee_client, email="invitee@example.com")
        headers = csrf(invitee)

        resp = await invitee_client.post(
            "/api/v1/invitations/accept",
            headers=headers,
            json={"token": seeded.token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == str(owner.org_id)
        assert data["role"] == "analyst"
        assert data["already_member"] is False

        # 3. Verify membership in database
        async with tenant_session(owner.org_id, invitee.user_id) as session:
            member = (
                await session.execute(
                    select(OrganizationMember).where(
                        OrganizationMember.organization_id == owner.org_id,
                        OrganizationMember.user_id == invitee.user_id,
                    )
                )
            ).scalar_one_or_none()
            assert member is not None
            assert member.role == MemberRole.ANALYST

            # Email verified
            user = (
                await session.execute(
                    select(User).where(User.id == invitee.user_id)
                )
            ).scalar_one()
            assert user.email_verified_at is not None

            # Invitation is consumed
            inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == seeded.id)
                )
            ).scalar_one()
            assert inv.accepted_at is not None
            assert inv.accepted_by == invitee.user_id

        # 4. Single-use: accepting again answers 404
        second_resp = await invitee_client.post(
            "/api/v1/invitations/accept",
            headers=headers,
            json={"token": seeded.token},
        )
        assert second_resp.status_code == 404
        assert second_resp.json()["error"]["code"] == "invitation_invalid"


@pytest.mark.asyncio
async def test_accept_invitation_email_mismatch_fails_409_without_consuming() -> None:
    async with new_client() as owner_client:
        owner = await register(owner_client, org_name="Target Org")
        seeded = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="intended@example.com",
            role=MemberRole.ANALYST,
        )

    # Actor has different email
    async with new_client() as wrong_client:
        wrong_user = await register(wrong_client, email="different@example.com")
        headers = csrf(wrong_user)

        resp = await wrong_client.post(
            "/api/v1/invitations/accept",
            headers=headers,
            json={"token": seeded.token},
        )
        assert resp.status_code == 409
        assert resp.json()["error"]["code"] == "invitation_email_mismatch"

        # Verify invitation is NOT consumed
        async with tenant_session(owner.org_id, owner.user_id) as session:
            inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == seeded.id)
                )
            ).scalar_one()
            assert inv.accepted_at is None


@pytest.mark.asyncio
async def test_accept_invitation_already_member_consumes_and_returns_200() -> None:
    async with new_client() as owner_client:
        owner = await register(owner_client, org_name="Target Org")

    # Invitee signs in and is already a member (e.g. as viewer)
    async with new_client() as member_client:
        member = await register(member_client, email="existing@example.com")
        async with tenant_session(owner.org_id, owner.user_id) as session:
            session.add(
                OrganizationMember(
                    organization_id=owner.org_id,
                    user_id=member.user_id,
                    role=MemberRole.VIEWER,
                )
            )

        seeded = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="existing@example.com",
            role=MemberRole.ANALYST,
        )

        headers = csrf(member)
        resp = await member_client.post(
            "/api/v1/invitations/accept",
            headers=headers,
            json={"token": seeded.token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["already_member"] is True

        # Existing role (VIEWER) remains unchanged
        async with tenant_session(owner.org_id, member.user_id) as session:
            m = (
                await session.execute(
                    select(OrganizationMember).where(
                        OrganizationMember.organization_id == owner.org_id,
                        OrganizationMember.user_id == member.user_id,
                    )
                )
            ).scalar_one()
            assert m.role == MemberRole.VIEWER

            # Invitation is consumed
            inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == seeded.id)
                )
            ).scalar_one()
            assert inv.accepted_at is not None


@pytest.mark.asyncio
async def test_accept_expired_invitation_answers_404() -> None:
    async with new_client() as owner_client:
        owner = await register(owner_client, org_name="Target Org")
        # Expired invitation (created 8 days ago, 7 day ttl)
        seeded = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="expired@example.com",
            ttl=timedelta(days=7),
            created_at=datetime.now(UTC) - timedelta(days=8),
        )

    async with new_client() as user_client:
        user = await register(user_client, email="expired@example.com")
        headers = csrf(user)

        resp = await user_client.post(
            "/api/v1/invitations/accept",
            headers=headers,
            json={"token": seeded.token},
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "invitation_invalid"

