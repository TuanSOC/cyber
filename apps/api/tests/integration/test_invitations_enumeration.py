"""Tests verifying timing-safe, zero-leakage anti-enumeration across invitations and registration (M11 phase 3)."""

from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy import event, select

from app.core.config import get_settings
from app.core.db import get_engine
from app.core.tenancy import tenant_session
from app.modules.invitations.models import InvitationIndex, OrgInvitation
from app.modules.organizations.models import MemberRole
from tests.factories import csrf, new_client, register
from tests.identity_helpers import seed_invitation


@pytest.mark.asyncio
async def test_invitation_creation_reveals_nothing_about_email_registration() -> None:
    """Zero query on `users` table when creating an invitation; identical response structure."""
    async with new_client() as client:
        owner = await register(client)
        headers = csrf(owner)

        # 1. Target A is registered
        registered_email = "already_registered@example.com"
        async with new_client() as other_client:
            await register(other_client, email=registered_email)

        # 2. Target B is not registered
        unknown_email = "completely_unknown_user@example.com"

        # Record SQL queries for both calls
        engine = get_engine().sync_engine
        queries_registered: list[str] = []
        queries_unknown: list[str] = []

        def record_reg(conn, cursor, statement, parameters, context, executemany):
            queries_registered.append(statement)

        def record_unk(conn, cursor, statement, parameters, context, executemany):
            queries_unknown.append(statement)

        # Invitation for registered email
        event.listen(engine, "before_cursor_execute", record_reg)
        try:
            resp_reg = await client.post(
                f"/api/v1/orgs/{owner.org_id}/invitations",
                headers=headers,
                json={"email": registered_email, "role": "analyst"},
            )
        finally:
            event.remove(engine, "before_cursor_execute", record_reg)

        assert resp_reg.status_code == 201
        data_reg = resp_reg.json()

        # Invitation for unknown email
        event.listen(engine, "before_cursor_execute", record_unk)
        try:
            resp_unk = await client.post(
                f"/api/v1/orgs/{owner.org_id}/invitations",
                headers=headers,
                json={"email": unknown_email, "role": "analyst"},
            )
        finally:
            event.remove(engine, "before_cursor_execute", record_unk)

        assert resp_unk.status_code == 201
        data_unk = resp_unk.json()

        # Both have identical keys
        assert set(data_reg.keys()) == set(data_unk.keys())
        assert "token" not in data_reg
        assert "token" not in data_unk

        # Assert no queries queried the users table by email
        for q in queries_registered + queries_unknown:
            lower_q = q.lower()
            assert "users.email =" not in lower_q
            assert "where email =" not in lower_q

        # Assert exact query count match
        assert len(queries_registered) == len(queries_unknown)


@pytest.mark.asyncio
async def test_inspect_gives_identical_404_for_all_failure_modes() -> None:
    async with new_client() as client:
        owner = await register(client)

        # 1. Non-existent token
        resp_unknown = await client.post(
            "/api/v1/invitations/inspect",
            json={"token": "x" * 43},
        )
        assert resp_unknown.status_code == 404
        assert resp_unknown.json()["error"]["code"] == "invitation_invalid"

        # 2. Consumed token
        seeded_used = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="used@example.com",
        )
        async with tenant_session(owner.org_id, owner.user_id) as session:
            inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == seeded_used.id)
                )
            ).scalar_one()
            inv.accepted_at = datetime.now(UTC)
            inv.accepted_by = owner.user_id

        resp_used = await client.post(
            "/api/v1/invitations/inspect",
            json={"token": seeded_used.token},
        )
        assert resp_used.status_code == 404
        assert resp_used.json() == resp_unknown.json()

        # 3. Revoked token
        seeded_revoked = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="revoked@example.com",
        )
        async with tenant_session(owner.org_id, owner.user_id) as session:
            inv = (
                await session.execute(
                    select(OrgInvitation).where(OrgInvitation.id == seeded_revoked.id)
                )
            ).scalar_one()
            inv.revoked_at = datetime.now(UTC)
            inv.revoked_by = owner.user_id

        resp_revoked = await client.post(
            "/api/v1/invitations/inspect",
            json={"token": seeded_revoked.token},
        )
        assert resp_revoked.status_code == 404
        assert resp_revoked.json() == resp_unknown.json()

        # 4. Expired token (created 8 days ago, 7 day ttl)
        seeded_expired = await seed_invitation(
            org_id=owner.org_id,
            invited_by=owner.user_id,
            email="expired@example.com",
            ttl=timedelta(days=7),
            created_at=datetime.now(UTC) - timedelta(days=8),
        )

        resp_expired = await client.post(
            "/api/v1/invitations/inspect",
            json={"token": seeded_expired.token},
        )
        assert resp_expired.status_code == 404
        assert resp_expired.json() == resp_unknown.json()


@pytest.mark.asyncio
async def test_invite_only_gives_identical_403_for_existing_and_new_emails(monkeypatch) -> None:
    async with new_client() as client:
        # 1. Existing registered email (registered during open mode)
        existing = await register(client, email="already_exists@example.com")

    settings = get_settings()
    monkeypatch.setattr(settings, "registration_mode", "invite_only")

    async with new_client() as probe_client:
        # Try registering existing email in invite_only mode
        resp_existing = await probe_client.post(
            "/api/v1/auth/register",
            json={
                "email": "already_exists@example.com",
                "password": "Password123!Secure",
                "display_name": "Attacker Probe",
                "organization_name": "Test Org",
            },
        )
        assert resp_existing.status_code == 403
        assert resp_existing.json()["error"]["code"] == "registration_closed"

        # Try registering unknown email in invite_only mode
        resp_unknown = await probe_client.post(
            "/api/v1/auth/register",
            json={
                "email": "completely_new_user@example.com",
                "password": "Password123!Secure",
                "display_name": "New User",
                "organization_name": "Test Org",
            },
        )
        assert resp_unknown.status_code == 403
        assert resp_unknown.json()["error"]["code"] == "registration_closed"
        assert resp_existing.json() == resp_unknown.json()

