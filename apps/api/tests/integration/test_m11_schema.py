"""M11 phase 1 schema (0019): user kinds, session rows and their backfill (RT7), the global
uniqueness of verified domains, the member-readable security policy (RT13), the system
lookups, the outbox checks and the mail worker's DB role (RT9). Test values only."""

import importlib.util
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import RETENTION_SYSTEM_USER_ID
from app.core.tenancy import tenant_session
from app.modules.identity.models import OrgSecurityPolicy
from app.modules.invitations.models import InvitationIndex
from tests.conftest import API_ROOT
from tests.factories import register
from tests.identity_helpers import seed_domain, seed_invitation, session_id_of

MIGRATION = API_ROOT / "alembic" / "versions" / "0019_m11_identity.py"


def _migration() -> object:
    spec = importlib.util.spec_from_file_location("m0019", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_user_kinds(owner_engine: AsyncEngine) -> None:
    async with owner_engine.connect() as conn:
        kind = (
            await conn.execute(
                text("SELECT kind FROM users WHERE id = :id"), {"id": RETENTION_SYSTEM_USER_ID}
            )
        ).scalar_one()
    assert kind == "system"
    reg = await register()
    with pytest.raises(IntegrityError, match="ck_users_kind"):
        async with tenant_session(None, reg.user_id) as session:
            await session.execute(
                text("UPDATE users SET kind = 'robot' WHERE id = :id"), {"id": reg.user_id}
            )


async def test_session_rows_are_checked(owner_engine: AsyncEngine) -> None:
    reg = await register()
    sid = session_id_of(reg.client)
    for assignment, constraint in (
        ("amr = ARRAY['pwd', 'magic']", "ck_user_sessions_amr"),
        ("amr = ARRAY[]::text[]", "ck_user_sessions_amr"),
        ("revoked_at = now()", "ck_user_sessions_revoked_pair"),
    ):
        with pytest.raises(IntegrityError, match=constraint):
            async with tenant_session(None, reg.user_id) as session:
                await session.execute(
                    text(f"UPDATE user_sessions SET {assignment} WHERE id = :id"), {"id": sid}
                )
    # An SSO session names its org, a password session none.
    with pytest.raises(IntegrityError, match="ck_user_sessions_sso_iff_method"):
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("UPDATE user_sessions SET sso_org_id = :org WHERE id = :id"),
                {"org": reg.org_id, "id": sid},
            )


async def test_the_backfill_gives_live_families_a_row(owner_engine: AsyncEngine) -> None:
    """RT7: one row per live refresh family (password, {pwd}, start + 30 d); dead families
    get none; existing rows are left alone."""
    reg = await register()
    live, dead = uuid.uuid4(), uuid.uuid4()
    now = datetime.now(UTC)
    insert = text(
        "INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, "
        "revoked_at, revoked_reason, created_at) VALUES (gen_random_uuid(), :user, :family, "
        ":hash, :expires, :revoked, CAST(:reason AS refresh_revoked_reason), :created)"
    )
    async with owner_engine.begin() as conn:
        for family, hash_char, revoked in ((live, "a", None), (dead, "b", now)):
            await conn.execute(
                insert,
                {
                    "user": reg.user_id,
                    "family": family,
                    "hash": hash_char * 64,
                    "expires": now + timedelta(days=3),
                    "revoked": revoked,
                    "reason": "logout" if revoked else None,
                    "created": now - timedelta(days=2),
                },
            )
        await conn.execute(text(_migration().SESSION_BACKFILL))  # type: ignore[attr-defined]
        rows = (
            await conn.execute(
                text(
                    "SELECT id, method, amr, expires_at - created_at AS span FROM user_sessions "
                    "WHERE id IN (:live, :dead)"
                ),
                {"live": live, "dead": dead},
            )
        ).all()
    assert [(r.id, r.method, r.amr, r.span) for r in rows] == [
        (live, "password", ["pwd"], timedelta(days=30))
    ]


async def test_a_verified_domain_belongs_to_one_org() -> None:
    a = await register(org_name="Domain A")
    b = await register(org_name="Domain B")
    await seed_domain(a.org_id, a.user_id, "corp.example", verified=True)
    await seed_domain(b.org_id, b.user_id, "corp.example")  # pending: allowed
    with pytest.raises(IntegrityError, match="ux_org_domains_domain_verified"):
        async with tenant_session(b.org_id, b.user_id) as session:
            await session.execute(
                text(
                    "UPDATE org_domains SET status = 'verified', method = 'dns', "
                    "verified_at = now() WHERE domain = 'corp.example'"
                )
            )
    with pytest.raises(IntegrityError, match="ck_org_domains_domain"):
        await seed_domain(a.org_id, a.user_id, "Not_A_Domain")


async def test_members_read_their_orgs_security_policy_only() -> None:
    """RT13: the MFA-disable rule reads the policy of every org of the user without opening
    each org's tenant session; non-members see nothing."""
    a = await register(org_name="Policy A")
    outsider = await register(org_name="Policy B")
    async with tenant_session(a.org_id, a.user_id) as session:
        session.add(OrgSecurityPolicy(organization_id=a.org_id, require_mfa=True))
    async with tenant_session(None, a.user_id) as session:
        rows = (await session.execute(select(OrgSecurityPolicy))).scalars().all()
    assert [(r.organization_id, r.require_mfa) for r in rows] == [(a.org_id, True)]
    async with tenant_session(outsider.org_id, outsider.user_id) as session:
        assert (await session.execute(select(OrgSecurityPolicy))).scalars().all() == []
    async with tenant_session(None, a.user_id) as session:  # writes stay org-scoped
        result = await session.execute(
            text("UPDATE org_security_policies SET require_mfa = false")
        )
    assert result.rowcount == 0  # type: ignore[attr-defined]


async def test_the_invitation_index_is_a_system_lookup() -> None:
    a = await register(org_name="Invite A")
    b = await register(org_name="Invite B")
    seeded = await seed_invitation(a.org_id, a.user_id, "x@example.com")
    async with tenant_session(None, None) as session:
        found = (await session.execute(select(InvitationIndex))).scalars().all()
    assert [i.invitation_id for i in found] == [seeded.id]
    async with tenant_session(b.org_id, b.user_id) as session:
        assert (await session.execute(select(InvitationIndex))).scalars().all() == []


async def test_the_outbox_checks(owner_engine: AsyncEngine) -> None:
    insert = (
        "INSERT INTO email_outbox (template, to_email, params, status{extra_cols}) "
        "VALUES (:template, 'a@example.com', CAST(:params AS jsonb), :status{extra_vals})"
    )
    for values, constraint in (
        ({"template": "spam", "params": "{}", "status": "pending"}, "template"),
        ({"template": "invite", "params": "[]", "status": "pending"}, "params"),
        ({"template": "invite", "params": "{}", "status": "sent"}, "sent"),
        ({"template": "invite", "params": "{}", "status": "sending"}, "claimed"),
    ):
        with pytest.raises(IntegrityError, match=f"ck_email_outbox_{constraint}"):
            async with tenant_session(None, None) as session:
                await session.execute(
                    text(insert.format(extra_cols="", extra_vals="")), values
                )


def _mail_url() -> str:
    url = os.environ.get("MAIL_TEST_DATABASE_URL")
    if not url:
        pytest.fail("MAIL_TEST_DATABASE_URL (the cyberlab_mail role) is not set in api-test")
    return url


async def test_the_mail_role_reads_and_updates_the_outbox_only() -> None:
    """RT9: SELECT / UPDATE (status columns) on `email_outbox`; nothing else at all."""
    engine = create_async_engine(_mail_url(), poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT count(*) FROM email_outbox"))
            await conn.execute(
                text("UPDATE email_outbox SET status = status, claimed_at = claimed_at")
            )
        for statement in (
            "SELECT count(*) FROM users",
            "SELECT count(*) FROM user_sessions",
            "SELECT count(*) FROM refresh_tokens",
            "SELECT count(*) FROM organizations",
            "UPDATE email_outbox SET to_email = to_email",
            "UPDATE email_outbox SET params = params",
            "DELETE FROM email_outbox",
            "INSERT INTO email_outbox (template, to_email) VALUES ('invite', 'x@example.com')",
        ):
            with pytest.raises(DBAPIError, match="permission denied"):
                async with engine.begin() as conn:
                    await conn.execute(text(statement))
    finally:
        await engine.dispose()


def test_the_migration_file_is_0019_after_0018() -> None:
    module = _migration()
    assert (module.revision, module.down_revision) == ("0019", "0018")  # type: ignore[attr-defined]
    assert Path(MIGRATION).name.startswith("0019_")
