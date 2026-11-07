"""Integration tests for the operator bootstrap-owner CLI command (M11 phase 3)."""

import uuid
import pytest
from sqlalchemy import select

from app.core.config import RETENTION_SYSTEM_USER_ID
from app.core.tenancy import tenant_session
from app.modules.invitations.admin_bootstrap import bootstrap_owner
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.users.models import User
from tests.factories import new_client, register


@pytest.mark.asyncio
async def test_bootstrap_owner_success_and_register() -> None:
    # 1. Bootstrap owner link
    code, link = await bootstrap_owner(
        email="operator_bootstrap@corp.example",
        org_name="Bootstrap Corporation",
    )
    assert code == 0
    assert "/register#t=" in link
    token = link.split("#t=")[-1]
    assert token

    # 2. Register using the link token
    async with new_client() as client:
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "operator_bootstrap@corp.example",
                "password": "Password123!Secure",
                "display_name": "Bootstrap Owner",
                "invitation_token": token,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        user_id = data["user"]["id"]
        memberships = data["memberships"]
        assert len(memberships) == 1
        assert memberships[0]["role"] == "owner"
        org_id = memberships[0]["organization_id"]

        # Verify org created_by was the system user
        async with tenant_session(uuid.UUID(org_id), RETENTION_SYSTEM_USER_ID) as session:
            org = (
                await session.execute(
                    select(Organization).where(Organization.id == org_id)
                )
            ).scalar_one()
            assert org.created_by == RETENTION_SYSTEM_USER_ID

    # 3. Second run for same org refuses while an owner exists
    code2, msg2 = await bootstrap_owner(
        email="second_bootstrap@corp.example",
        org_name="Bootstrap Corporation",
    )
    assert code2 == 1
    assert "already exists and has an owner" in msg2


@pytest.mark.asyncio
async def test_bootstrap_owner_refuses_existing_user() -> None:
    async with new_client() as client:
        existing = await register(client, email="existing_lead@corp.example")

    code, msg = await bootstrap_owner(
        email="existing_lead@corp.example",
        org_name="Another Org",
    )
    assert code == 1
    assert "already exists" in msg

