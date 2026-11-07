"""Integration tests for invitation creation, domain allowlist, and outbox integration (M11 phase 3)."""

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import get_engine
from app.core.tenancy import tenant_session
from app.modules.identity.models import OrgSecurityPolicy
from app.modules.invitations.models import InvitationIndex, OrgInvitation
from app.modules.mail.models import EmailOutbox
from app.modules.organizations.models import MemberRole
from tests.factories import csrf, new_client, register
from tests.integration.seed import seed_tenant


@pytest.mark.asyncio
async def test_owner_can_create_invitation_and_enqueues_outbox() -> None:
    async with new_client() as client:
        owner = await register(client)
        headers = csrf(owner)

        resp = await client.post(
            f"/api/v1/orgs/{owner.org_id}/invitations",
            headers=headers,
            json={"email": "new_analyst@example.com", "role": "analyst"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "new_analyst@example.com"
        assert data["role"] == "analyst"
        assert data["status"] == "pending"
        assert "token" not in data  # Token is NEVER in the API response

        inv_id = data["id"]

        # Verify DB entries
        async with tenant_session(owner.org_id, owner.user_id) as session:
            inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == inv_id)
                )
            ).scalar_one()
            assert inv.email == "new_analyst@example.com"
            assert inv.token_hash is not None
            assert inv.accepted_at is None

            idx = (
                await session.execute(
                    select(InvitationIndex).where(InvitationIndex.invitation_id == inv_id)
                )
            ).scalar_one()
            assert idx.token_hash == inv.token_hash

            # Check email outbox
            outbox_row = (
                await session.execute(
                    select(EmailOutbox).where(EmailOutbox.to_email == "new_analyst@example.com")
                )
            ).scalar_one()
            assert outbox_row.template == "invite"
            assert outbox_row.secret_epk is not None


@pytest.mark.asyncio
async def test_reinviting_same_email_revokes_previous_invitation() -> None:
    async with new_client() as client:
        owner = await register(client)
        headers = csrf(owner)

        # 1. First invitation
        r1 = await client.post(
            f"/api/v1/orgs/{owner.org_id}/invitations",
            headers=headers,
            json={"email": "contractor@example.com", "role": "viewer"},
        )
        assert r1.status_code == 201
        first_id = r1.json()["id"]

        # 2. Second invitation for same email with different role
        r2 = await client.post(
            f"/api/v1/orgs/{owner.org_id}/invitations",
            headers=headers,
            json={"email": "contractor@example.com", "role": "analyst"},
        )
        assert r2.status_code == 201
        second_id = r2.json()["id"]

        assert first_id != second_id

        # Verify first is revoked and second is pending
        async with tenant_session(owner.org_id, owner.user_id) as session:
            first_inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == first_id)
                )
            ).scalar_one()
            assert first_inv.revoked_at is not None

            second_inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == second_id)
                )
            ).scalar_one()
            assert second_inv.revoked_at is None


@pytest.mark.asyncio
async def test_domain_allowlist_enforced() -> None:
    async with new_client() as client:
        owner = await register(client)
        headers = csrf(owner)

        # Set invite_domain_allowlist to corp.example.com
        async with tenant_session(owner.org_id, owner.user_id) as session:
            session.add(
                OrgSecurityPolicy(
                    organization_id=owner.org_id,
                    invite_domain_allowlist=["corp.example.com"],
                )
            )

        # Invitation to non-allowlisted domain fails 422
        bad_resp = await client.post(
            f"/api/v1/orgs/{owner.org_id}/invitations",
            headers=headers,
            json={"email": "user@gmail.com", "role": "analyst"},
        )
        assert bad_resp.status_code == 422
        assert "invite_domain_not_allowed" in bad_resp.text

        # Invitation to allowlisted domain succeeds
        good_resp = await client.post(
            f"/api/v1/orgs/{owner.org_id}/invitations",
            headers=headers,
            json={"email": "user@corp.example.com", "role": "analyst"},
        )
        assert good_resp.status_code == 201

