"""Membership management.

Every mutation first locks the org row, then re-reads the actor's role and the target row,
so decisions never rest on roles read before a concurrent change committed.
"""

import uuid

from sqlalchemy.exc import IntegrityError
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.errors import Conflict, Forbidden, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext, Permission, check, membership_role
from app.modules.audit import service as audit
from app.modules.organizations import repository as repo
from app.modules.organizations.models import MemberRole, OrganizationMember
from app.modules.organizations.schemas import MemberOut, MemberPage
from app.modules.users import repository as users
from app.modules.users.models import User

MEMBER_ADD_LIMIT_PER_10MIN = 30


def _to_out(member: OrganizationMember, user: User) -> MemberOut:
    return MemberOut(
        id=member.id,
        user_id=member.user_id,
        email=user.email,
        display_name=user.display_name,
        role=member.role,
        created_at=member.created_at,
    )


async def list_members(ctx: OrgContext, page: PageParams) -> MemberPage:
    rows, total = await repo.list_members(ctx.session, ctx.org_id, page)
    return MemberPage(items=[_to_out(m, u) for m, u in rows], total=total)


async def _lock_and_reauthorize(ctx: OrgContext) -> MemberRole:
    """Lock the org, then re-read the actor's role (it may have changed since require())."""
    await repo.lock_org(ctx.session, ctx.org_id)
    role = await membership_role(ctx.session, ctx.org_id, ctx.user.id, for_update=True)
    return check(role, Permission.MEMBERS_MANAGE)


def _ensure_may_manage(
    actor_role: MemberRole, current: MemberRole | None, new: MemberRole | None
) -> None:
    """Admins manage analysts/viewers/admins; only owners touch the owner role."""
    if MemberRole.OWNER in (current, new) and actor_role != MemberRole.OWNER:
        raise Forbidden("Only owners can grant, change or remove the owner role")


async def ensure_other_owner_remains(ctx: OrgContext, member: OrganizationMember) -> None:
    """Caller must hold the org lock."""
    if member.role == MemberRole.OWNER and await repo.count_owners(ctx.session, ctx.org_id) <= 1:
        raise Conflict("An organization must keep at least one owner", code="last_owner")


async def _get_other_member(
    ctx: OrgContext, member_id: uuid.UUID
) -> tuple[OrganizationMember, User]:
    row = await repo.get_member_with_user(ctx.session, ctx.org_id, member_id, for_update=True)
    if row is None:
        raise NotFound()
    if row[0].user_id == ctx.user.id:
        raise Forbidden("You cannot change your own membership", code="cannot_modify_self")
    return row


async def add_member(
    ctx: OrgContext, email: str, role: MemberRole, request: HTTPConnection
) -> MemberOut:
    # Bounds probing which emails are registered (user_not_found vs created).
    await rate_limit.hit(f"member:add:{ctx.user.id}", MEMBER_ADD_LIMIT_PER_10MIN, 600)
    actor_role = await _lock_and_reauthorize(ctx)
    _ensure_may_manage(actor_role, None, role)
    user = await users.get_by_email(ctx.session, email)
    if user is None or not user.is_active:
        raise NotFound("No active user with this email", code="user_not_found")
    if await repo.find_member_by_user(ctx.session, ctx.org_id, user.id) is not None:
        raise Conflict("User is already a member", code="already_member")
    member = OrganizationMember(organization_id=ctx.org_id, user_id=user.id, role=role)
    ctx.session.add(member)
    try:
        await ctx.session.flush()
    except IntegrityError as exc:  # concurrent add of the same user
        raise Conflict("User is already a member", code="already_member") from exc
    audit.record(
        ctx.session,
        action="member.added",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="member",
        target_id=member.id,
        details={"user_id": str(user.id), "role": role.value},
        request=request,
    )
    out = _to_out(member, user)
    await ctx.session.commit()
    return out


async def change_role(
    ctx: OrgContext, member_id: uuid.UUID, role: MemberRole, request: HTTPConnection
) -> MemberOut:
    actor_role = await _lock_and_reauthorize(ctx)
    member, user = await _get_other_member(ctx, member_id)
    _ensure_may_manage(actor_role, member.role, role)
    if member.role == role:
        return _to_out(member, user)
    if role != MemberRole.OWNER:
        await ensure_other_owner_remains(ctx, member)
    old_role = member.role
    member.role = role
    audit.record(
        ctx.session,
        action="member.role_changed",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="member",
        target_id=member.id,
        details={"user_id": str(member.user_id), "from": old_role.value, "to": role.value},
        request=request,
    )
    await ctx.session.flush()
    out = _to_out(member, user)
    await ctx.session.commit()
    return out


async def remove_member(ctx: OrgContext, member_id: uuid.UUID, request: HTTPConnection) -> None:
    actor_role = await _lock_and_reauthorize(ctx)
    member, _ = await _get_other_member(ctx, member_id)
    _ensure_may_manage(actor_role, member.role, None)
    await ensure_other_owner_remains(ctx, member)
    audit.record(
        ctx.session,
        action="member.removed",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="member",
        target_id=member.id,
        details={"user_id": str(member.user_id), "role": member.role.value},
        request=request,
    )
    await ctx.session.delete(member)
    await ctx.session.commit()
