"""Org-scoped authorization.

RLS trusts `app.org_id`, so a tenant session for an org taken from the request may only be
opened here, after the caller's membership is verified inside that same session.
"""

import enum
import functools
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentUser, CurrentUserDep
from app.core.errors import Forbidden, NotFound
from app.core.tenancy import tenant_session
from app.modules.organizations.models import MemberRole, OrganizationMember


class Permission(enum.StrEnum):
    ORG_READ = "org.read"
    ORG_UPDATE = "org.update"
    MEMBERS_READ = "members.read"
    MEMBERS_MANAGE = "members.manage"
    INVESTIGATION_READ = "investigation.read"
    INVESTIGATION_WRITE = "investigation.write"
    EVIDENCE_READ = "evidence.read"
    EVIDENCE_WRITE = "evidence.write"
    AUDIT_READ = "audit.read"


_READ = {
    Permission.ORG_READ,
    Permission.MEMBERS_READ,
    Permission.INVESTIGATION_READ,
    Permission.EVIDENCE_READ,
}
_ANALYST = _READ | {Permission.INVESTIGATION_WRITE, Permission.EVIDENCE_WRITE}
_ADMIN = _ANALYST | {Permission.ORG_UPDATE, Permission.MEMBERS_MANAGE, Permission.AUDIT_READ}

ROLE_PERMISSIONS: dict[MemberRole, frozenset[Permission]] = {
    MemberRole.OWNER: frozenset(_ADMIN),
    MemberRole.ADMIN: frozenset(_ADMIN),
    MemberRole.ANALYST: frozenset(_ANALYST),
    MemberRole.VIEWER: frozenset(_READ),
}


@dataclass(frozen=True)
class OrgContext:
    org_id: uuid.UUID
    user: CurrentUser
    role: MemberRole
    session: AsyncSession


async def membership_role(
    session: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID, *, for_update: bool = False
) -> MemberRole | None:
    stmt = select(OrganizationMember.role).where(
        OrganizationMember.organization_id == org_id, OrganizationMember.user_id == user_id
    )
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.execute(stmt)).scalar_one_or_none()


def check(role: MemberRole | None, permission: Permission) -> MemberRole:
    if role is None:
        raise NotFound()  # non-member: do not reveal that the org exists
    if permission not in ROLE_PERMISSIONS[role]:
        raise Forbidden()
    return role


@functools.cache
def require(
    permission: Permission,
) -> Callable[[uuid.UUID, CurrentUser], AsyncIterator[OrgContext]]:
    """Dependency: one tenant session for the request, membership checked inside it.

    Cached per permission so FastAPI dedupes it; use at most one per route. Mutating
    handlers must `await ctx.session.commit()` as their last database step.
    """

    async def dependency(org_id: uuid.UUID, user: CurrentUserDep) -> AsyncIterator[OrgContext]:
        async with tenant_session(org_id, user.id) as session:
            role = check(await membership_role(session, org_id, user.id), permission)
            yield OrgContext(org_id=org_id, user=user, role=role, session=session)

    return dependency


async def authorize(org_id: uuid.UUID, user: CurrentUser, permission: Permission) -> MemberRole:
    """Same check in a short session that closes immediately (long-running routes)."""
    async with tenant_session(org_id, user.id) as session:
        return check(await membership_role(session, org_id, user.id), permission)
