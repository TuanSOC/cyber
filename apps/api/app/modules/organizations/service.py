"""Organization lifecycle (members live in members.py)."""

import re
import secrets
import uuid

from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.errors import Conflict, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext
from app.core.tenancy import tenant_session
from app.modules.audit import service as audit
from app.modules.organizations import repository as repo
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.organizations.schemas import MyOrgOut, MyOrgPage

ORG_CREATE_LIMIT_PER_HOUR = 10


def slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"
    return f"{base}-{secrets.token_hex(6)}"


def _to_out(org: Organization, role: MemberRole) -> MyOrgOut:
    return MyOrgOut(id=org.id, name=org.name, slug=org.slug, created_at=org.created_at, role=role)


async def list_my_orgs(user: CurrentUser, page: PageParams) -> MyOrgPage:
    async with tenant_session(None, user.id) as session:
        rows, total = await repo.my_orgs(session, user.id, page)
    return MyOrgPage(items=[_to_out(org, role) for org, role in rows], total=total)


async def create_org(user: CurrentUser, name: str, request: HTTPConnection) -> MyOrgOut:
    await rate_limit.hit(f"org:create:{user.id}", ORG_CREATE_LIMIT_PER_HOUR, 3600)
    # A brand-new org id (never request input): the creator becomes its first owner.
    org_id = uuid.uuid4()
    limit = get_settings().max_owned_orgs_per_user
    async with tenant_session(org_id, user.id) as session:
        # RT8: bounds how much storage quota one account can claim by creating orgs.
        await repo.lock_owner(session, user.id)
        if await repo.count_owned(session, user.id) >= limit:
            raise Conflict(
                f"You already own the maximum of {limit} organizations", code="org_limit_reached"
            )
        org = Organization(id=org_id, name=name, slug=slugify(name), created_by=user.id)
        session.add(org)
        await session.flush()
        session.add(
            OrganizationMember(organization_id=org_id, user_id=user.id, role=MemberRole.OWNER)
        )
        audit.record(
            session,
            action="org.created",
            org_id=org_id,
            actor_id=user.id,
            target_type="organization",
            target_id=org_id,
            details={"name": name},
            request=request,
        )
    return _to_out(org, MemberRole.OWNER)


async def get_org(ctx: OrgContext) -> MyOrgOut:
    org = await repo.get_org(ctx.session, ctx.org_id)
    if org is None:
        raise NotFound()
    return _to_out(org, ctx.role)


async def rename_org(ctx: OrgContext, name: str, request: HTTPConnection) -> MyOrgOut:
    org = await repo.get_org(ctx.session, ctx.org_id)
    if org is None:
        raise NotFound()
    old_name = org.name
    org.name = name
    audit.record(
        ctx.session,
        action="org.updated",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="organization",
        target_id=ctx.org_id,
        details={"name": {"from": old_name, "to": name}},
        request=request,
    )
    await ctx.session.flush()
    out = _to_out(org, ctx.role)
    await ctx.session.commit()
    return out
