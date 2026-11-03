import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.organizations.models import MemberRole, Organization, OrganizationMember


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
    return [(row.id, row.name, row.role) for row in await session.execute(stmt)]
