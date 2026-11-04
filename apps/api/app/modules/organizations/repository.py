import uuid

from sqlalchemy import Select, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.users.models import User


async def list_memberships(
    session: AsyncSession, user_id: uuid.UUID
) -> list[tuple[uuid.UUID, str, MemberRole]]:
    """The user's memberships across orgs (needs app.user_id; members SELECT policy)."""
    stmt = (
        select(Organization.id, Organization.name, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user_id)
        .order_by(OrganizationMember.created_at, Organization.name)
    )
    return [(org_id, name, role) for org_id, name, role in (await session.execute(stmt)).all()]


async def my_orgs(
    session: AsyncSession, user_id: uuid.UUID, page: PageParams
) -> tuple[list[tuple[Organization, MemberRole]], int]:
    base = (
        select(Organization, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user_id)
    )
    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    stmt = (
        base.order_by(OrganizationMember.created_at, Organization.name)
        .limit(page.limit)
        .offset(page.offset)
    )
    return [(org, role) for org, role in (await session.execute(stmt)).all()], total


async def get_org(session: AsyncSession, org_id: uuid.UUID) -> Organization | None:
    return await session.get(Organization, org_id)


async def lock_org(session: AsyncSession, org_id: uuid.UUID) -> None:
    """Serialize membership changes in one org (needs the orgs UPDATE policy: current org)."""
    await session.execute(
        select(Organization.id).where(Organization.id == org_id).with_for_update()
    )


def _members_with_users(org_id: uuid.UUID) -> Select[OrganizationMember, User]:
    return (
        select(OrganizationMember, User)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.organization_id == org_id)
    )


async def list_members(
    session: AsyncSession, org_id: uuid.UUID, page: PageParams
) -> tuple[list[tuple[OrganizationMember, User]], int]:
    count_stmt = select(func.count()).where(OrganizationMember.organization_id == org_id)
    total = (await session.execute(count_stmt)).scalar_one()
    stmt = (
        _members_with_users(org_id)
        .order_by(OrganizationMember.created_at, OrganizationMember.id)
        .limit(page.limit)
        .offset(page.offset)
    )
    return [(m, u) for m, u in (await session.execute(stmt)).all()], total


async def get_member_with_user(
    session: AsyncSession, org_id: uuid.UUID, member_id: uuid.UUID, *, for_update: bool = False
) -> tuple[OrganizationMember, User] | None:
    stmt = _members_with_users(org_id).where(OrganizationMember.id == member_id)
    if for_update:
        stmt = stmt.with_for_update(of=OrganizationMember)
    row = (await session.execute(stmt)).one_or_none()
    return (row[0], row[1]) if row else None


async def find_member_by_user(
    session: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID
) -> OrganizationMember | None:
    stmt = select(OrganizationMember).where(
        OrganizationMember.organization_id == org_id, OrganizationMember.user_id == user_id
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def lock_owner(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Serialize org creation per user (transaction-scoped advisory lock, no table grant)."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"org-owner:{user_id}"},
    )


async def count_owned(session: AsyncSession, user_id: uuid.UUID) -> int:
    """Orgs the user owns (members SELECT policy: the caller's own memberships)."""
    stmt = select(func.count()).where(
        OrganizationMember.user_id == user_id, OrganizationMember.role == MemberRole.OWNER
    )
    return (await session.execute(stmt)).scalar_one()


async def count_owners(session: AsyncSession, org_id: uuid.UUID) -> int:
    stmt = select(func.count()).where(
        OrganizationMember.organization_id == org_id,
        OrganizationMember.role == MemberRole.OWNER,
    )
    return (await session.execute(stmt)).scalar_one()
