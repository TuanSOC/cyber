import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.investigations.models import Investigation, Severity
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.users.models import User
from tests.integration.seed import Tenant, seed_tenant, seed_user


async def _count_investigations(org_id: uuid.UUID | None, user_id: uuid.UUID | None) -> int:
    async with tenant_session(org_id, user_id) as s:
        return (await s.execute(select(func.count()).select_from(Investigation))).scalar_one()


async def test_no_context_sees_no_tenant_rows() -> None:
    a = await seed_tenant("alpha")
    assert await _count_investigations(a.org_id, a.owner_id) == 1  # the row exists
    assert await _count_investigations(None, None) == 0


async def test_org_context_sees_only_own_rows() -> None:
    a = await seed_tenant("alpha")
    await seed_tenant("bravo")
    async with tenant_session(a.org_id, a.owner_id) as s:
        rows = (await s.execute(select(Investigation.organization_id))).scalars().all()
    assert rows == [a.org_id]


async def test_insert_into_other_org_is_rejected() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    with pytest.raises(DBAPIError, match="row-level security"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            s.add(
                Investigation(
                    organization_id=b.org_id,
                    case_number=99,
                    title="smuggled",
                    severity=Severity.LOW,
                    created_by=a.owner_id,
                )
            )


async def test_user_context_lists_own_memberships_across_orgs() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    # Make alpha's owner also a member of bravo.
    async with tenant_session(b.org_id, b.owner_id) as s:
        s.add(OrganizationMember(organization_id=b.org_id, user_id=a.owner_id, role="viewer"))

    async with tenant_session(None, a.owner_id) as s:
        orgs = set((await s.execute(select(OrganizationMember.organization_id))).scalars())
        visible_orgs = set((await s.execute(select(Organization.id))).scalars())
    assert orgs == {a.org_id, b.org_id}
    assert visible_orgs == {a.org_id, b.org_id}


async def test_user_context_does_not_see_foreign_orgs() -> None:
    a = await seed_tenant("alpha")
    await seed_tenant("bravo")
    async with tenant_session(None, a.owner_id) as s:
        visible_orgs = set((await s.execute(select(Organization.id))).scalars())
    assert visible_orgs == {a.org_id}


async def test_context_does_not_leak_across_pooled_transactions() -> None:
    a = await seed_tenant("alpha")
    engine = create_async_engine(get_settings().database_url, pool_size=1, max_overflow=0)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with tenant_session(a.org_id, a.owner_id, sessionmaker=maker) as s:
            assert (await s.execute(select(func.count()).select_from(Investigation))).scalar() == 1
        # Same single pooled connection, new transaction without context.
        async with maker() as s, s.begin():
            count = (await s.execute(select(func.count()).select_from(Investigation))).scalar()
            org_guc = (await s.execute(text("SELECT current_setting('app.org_id', true)"))).scalar()
        assert count == 0
        assert org_guc in ("", None)
    finally:
        await engine.dispose()


async def test_app_role_cannot_switch_off_row_security() -> None:
    await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="row-level security"):
        async with tenant_session(None, None) as s:
            await s.execute(text("SET LOCAL row_security = off"))
            await s.execute(select(func.count()).select_from(Investigation))


async def test_app_role_cannot_disable_rls() -> None:
    with pytest.raises(DBAPIError, match="must be owner"):
        async with tenant_session(None, None) as s:
            await s.execute(text("ALTER TABLE investigations DISABLE ROW LEVEL SECURITY"))


async def test_org_insert_requires_matching_context() -> None:
    a = await seed_tenant("alpha")
    with pytest.raises(DBAPIError, match="row-level security"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            s.add(Organization(name="rogue", slug="rogue", created_by=a.owner_id))


async def test_tenant_row_cannot_be_moved_to_another_org() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    with pytest.raises(DBAPIError, match="row-level security"):
        async with tenant_session(a.org_id, a.owner_id) as s:
            await s.execute(
                text("UPDATE investigations SET organization_id = :b WHERE id = :id"),
                {"b": b.org_id, "id": a.investigation_id},
            )


async def _dual_member() -> tuple[Tenant, Tenant]:
    """alpha's owner also holds an owner membership in bravo."""
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    async with tenant_session(b.org_id, b.owner_id) as s:
        s.add(
            OrganizationMember(organization_id=b.org_id, user_id=a.owner_id, role=MemberRole.OWNER)
        )
    return a, b


async def _membership_exists(org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    async with tenant_session(org_id, None) as s:
        stmt = select(OrganizationMember.id).where(OrganizationMember.user_id == user_id)
        return (await s.execute(stmt)).first() is not None


async def test_own_membership_in_other_org_cannot_be_deleted_cross_tenant() -> None:
    a, b = await _dual_member()
    async with tenant_session(a.org_id, a.owner_id) as s:
        result = await s.execute(
            text("DELETE FROM organization_members WHERE organization_id = :b AND user_id = :u"),
            {"b": b.org_id, "u": a.owner_id},
        )
    assert result.rowcount == 0
    assert await _membership_exists(b.org_id, a.owner_id)


async def test_own_membership_in_other_org_cannot_be_updated_cross_tenant() -> None:
    a, b = await _dual_member()
    async with tenant_session(a.org_id, a.owner_id) as s:
        result = await s.execute(
            text(
                "UPDATE organization_members SET role = 'viewer' "
                "WHERE organization_id = :b AND user_id = :u"
            ),
            {"b": b.org_id, "u": a.owner_id},
        )
    assert result.rowcount == 0


async def test_foreign_org_cannot_be_locked_or_updated() -> None:
    a, b = await _dual_member()
    async with tenant_session(a.org_id, a.owner_id) as s:
        stmt = select(Organization.id).where(Organization.id == b.org_id).with_for_update()
        locked = (await s.execute(stmt)).all()
        updated = await s.execute(
            text("UPDATE organizations SET name = 'pwned' WHERE id = :b"), {"b": b.org_id}
        )
    assert locked == []
    assert updated.rowcount == 0


async def test_membership_lookup_inside_org_context() -> None:
    """The require() pattern: tenant_session(org, user) then look up (org, user)."""
    a = await seed_tenant("alpha")
    outsider = await seed_user("outsider@example.com")

    async def lookup(user_id: uuid.UUID) -> MemberRole | None:
        async with tenant_session(a.org_id, user_id) as s:
            stmt = select(OrganizationMember.role).where(
                OrganizationMember.organization_id == a.org_id,
                OrganizationMember.user_id == user_id,
            )
            return (await s.execute(stmt)).scalar_one_or_none()

    assert await lookup(a.owner_id) == MemberRole.OWNER
    assert await lookup(outsider) is None


async def test_register_sequence_in_one_session() -> None:
    """Phase 3 register: user, org (pre-generated id), owner membership, audit in one txn."""
    org_id, user_id = uuid.uuid4(), uuid.uuid4()
    async with tenant_session(org_id, user_id) as s:
        s.add(User(id=user_id, email="new@example.com", password_hash="x", display_name="new"))
        await s.flush()
        s.add(Organization(id=org_id, name="New", slug="new", created_by=user_id))
        await s.flush()
        s.add(OrganizationMember(organization_id=org_id, user_id=user_id, role=MemberRole.OWNER))
        s.add(AuditLog(organization_id=org_id, actor_id=user_id, action="org.created"))

    async with tenant_session(None, user_id) as s:
        assert (await s.execute(select(Organization.id))).scalars().all() == [org_id]


async def test_updated_at_is_loaded_after_commit() -> None:
    a = await seed_tenant("alpha")
    async with tenant_session(a.org_id, a.owner_id) as s:
        investigation = await s.get_one(Investigation, a.investigation_id)
        before = investigation.updated_at
        investigation.title = "renamed"
    # Block committed; attribute must already be loaded (no lazy load on a closed txn).
    assert investigation.updated_at >= before
