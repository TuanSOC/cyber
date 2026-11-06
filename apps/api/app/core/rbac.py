"""Org-scoped authorization.

RLS trusts `app.org_id`, so a tenant session for an org taken from the request may only be
opened here, after the caller's membership is verified inside that same session.

M11 (phase 1, FROZEN):
- `Permission.SECURITY_MANAGE` (owners only): SSO, domains, the org security policy, API keys.
- `OrgContext.permissions` is the caller's effective set: the role's permissions for a
  session, role ∩ scopes for an API key (RT1). `require()` and every in-service check read it;
  no module outside this file reads `ROLE_PERMISSIONS[...]` (`tests/unit/test_permission_reads`).
- `org_session` accepts a principal: an API key is resolved inside the org's tenant session
  (`api_keys.auth.resolve`, phase 9), `app.user_id` is then set to its service account, and
  the membership check runs as for a session. After the membership check,
  `identity.policy.check_org_access` applies the org security policy (phase 6) unless the
  route is `policy_exempt` (RT13).
"""

import enum
import functools
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import ApiKeyPrincipal, CurrentUser, Principal, PrincipalDep
from app.core.errors import Forbidden, NotFound
from app.core.tenancy import set_app_user, tenant_session
from app.modules.api_keys import auth as api_key_auth
from app.modules.identity import policy as identity_policy
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
    # Threat intel provider keys, terms acknowledgement and TI settings (M4).
    INTEGRATIONS_MANAGE = "integrations.manage"
    # M11: SSO, domains, the security policy and platform API keys (owners only).
    SECURITY_MANAGE = "security.manage"


_READ = {
    Permission.ORG_READ,
    Permission.MEMBERS_READ,
    Permission.INVESTIGATION_READ,
    Permission.EVIDENCE_READ,
}
_ANALYST = _READ | {Permission.INVESTIGATION_WRITE, Permission.EVIDENCE_WRITE}
_ADMIN = _ANALYST | {
    Permission.ORG_UPDATE,
    Permission.MEMBERS_MANAGE,
    Permission.AUDIT_READ,
    Permission.INTEGRATIONS_MANAGE,
}
_OWNER = _ADMIN | {Permission.SECURITY_MANAGE}

ROLE_PERMISSIONS: dict[MemberRole, frozenset[Permission]] = {
    MemberRole.OWNER: frozenset(_OWNER),
    MemberRole.ADMIN: frozenset(_ADMIN),
    MemberRole.ANALYST: frozenset(_ANALYST),
    MemberRole.VIEWER: frozenset(_READ),
}


class _FromRole(frozenset[Permission]):
    """Sentinel type: `OrgContext(permissions=...)` omitted means the role's permissions."""


_FROM_ROLE = _FromRole()


def role_permissions(role: MemberRole) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


def effective_permissions(role: MemberRole, scopes: frozenset[str] | None) -> frozenset[Permission]:
    """A session: the role's permissions. An API key: role ∩ scopes (RT1)."""
    granted = ROLE_PERMISSIONS[role]
    if scopes is None:
        return granted
    return frozenset(p for p in granted if p.value in scopes)


@dataclass(frozen=True)
class OrgContext:
    org_id: uuid.UUID
    user: CurrentUser
    role: MemberRole
    session: AsyncSession
    permissions: frozenset[Permission] = _FROM_ROLE

    def __post_init__(self) -> None:
        if self.permissions is _FROM_ROLE:
            object.__setattr__(self, "permissions", ROLE_PERMISSIONS[self.role])

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions


async def membership_role(
    session: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID, *, for_update: bool = False
) -> MemberRole | None:
    stmt = select(OrganizationMember.role).where(
        OrganizationMember.organization_id == org_id, OrganizationMember.user_id == user_id
    )
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.execute(stmt)).scalar_one_or_none()


def check(
    role: MemberRole | None,
    permission: Permission,
    *,
    permissions: frozenset[Permission] | None = None,
) -> MemberRole:
    if role is None:
        raise NotFound()  # non-member: do not reveal that the org exists
    granted = ROLE_PERMISSIONS[role] if permissions is None else permissions
    if permission not in granted:
        raise Forbidden()
    return role


@functools.cache
def require(
    permission: Permission, *, policy_exempt: bool = False
) -> Callable[[uuid.UUID, Principal], AsyncIterator[OrgContext]]:
    """Dependency: one org_session() for the request.

    Cached per (permission, policy_exempt) so FastAPI dedupes it; use at most one per route.
    Mutating handlers must `await ctx.session.commit()` as their last database step.
    `policy_exempt=True` skips the org security policy (RT13): `GET /orgs/{org}` and
    `GET /orgs/{org}/security-policy` only (a test lists the exempt routes).
    """

    async def dependency(org_id: uuid.UUID, principal: PrincipalDep) -> AsyncIterator[OrgContext]:
        async with org_session(org_id, principal, permission, policy_exempt=policy_exempt) as ctx:
            yield ctx

    dependency.policy_exempt = policy_exempt  # type: ignore[attr-defined]
    return dependency


@asynccontextmanager
async def org_session(
    org_id: uuid.UUID,
    user: Principal,
    permission: Permission,
    *,
    snapshot_read: bool = False,
    policy_exempt: bool = False,
) -> AsyncIterator[OrgContext]:
    """A short, explicitly scoped tenant session with the membership check inside it.

    Long-running routes (evidence transfer) use several of these instead of one
    request-wide session, so no connection is held while bytes move and the caller is
    re-authorized before every write. `snapshot_read=True` (M6, RT14) opens it as one
    REPEATABLE READ READ ONLY transaction (the report snapshot builder).
    """
    if isinstance(user, ApiKeyPrincipal):
        async with tenant_session(org_id, None, snapshot_read=snapshot_read) as session:
            resolved = await api_key_auth.resolve(session, org_id, user.parsed)
            await set_app_user(session, resolved.service_user_id)
            role = await membership_role(session, org_id, resolved.service_user_id)
            if role is None:
                raise NotFound()
            permissions = effective_permissions(role, resolved.scopes)
            check(role, permission, permissions=permissions)
            principal = CurrentUser(
                id=resolved.service_user_id,
                email=f"svc-{resolved.service_user_id}@service.invalid",
                display_name=resolved.name,
                jti="",
                family_id=resolved.key_id,
                token_expires_at=resolved.expires_at,
                amr=frozenset(),
                kind="api_key",
                has_password=False,
                api_key_id=resolved.key_id,
            )
            if not policy_exempt:
                await identity_policy.check_org_access(session, org_id, principal)
            yield OrgContext(
                org_id=org_id,
                user=principal,
                role=role,
                session=session,
                permissions=permissions,
            )
        return
    async with tenant_session(org_id, user.id, snapshot_read=snapshot_read) as session:
        role = check(await membership_role(session, org_id, user.id), permission)
        if not policy_exempt:
            await identity_policy.check_org_access(session, org_id, user)
        yield OrgContext(org_id=org_id, user=user, role=role, session=session)
