"""Invitation service implementing member lifecycle, inspect, accept, and registration (M11 phase 3)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import logging
import secrets
from typing import Any
import uuid

from sqlalchemy import func, select, update
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.client_ip import ip_key
from app.core.config import get_settings
from app.core.cookies import IssuedTokens
from app.core.deps import CurrentUser
from app.core.errors import Conflict, Forbidden, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext, membership_role
from app.core.security import hash_password_async
from app.core.stepup import StepUpAction, require_recent_auth
from app.core.tenancy import tenant_session
from app.modules.audit import service as audit
from app.modules.auth import sessions
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType
from app.modules.auth.schemas import RegisterIn
from app.modules.identity.errors import (
    InvitationEmailMismatch,
    InvitationInvalid,
    InviteDomainNotAllowed,
)
from app.modules.identity.models import OrgSecurityPolicy
from app.modules.identity.schemas import (
    InvitationAcceptOut,
    InvitationCreate,
    InvitationInspectOut,
    InvitationOut,
    InvitationPage,
)
from app.modules.invitations import repository as repo
from app.modules.invitations.models import InvitationIndex, InvitationStatus, OrgInvitation
from app.modules.mail import outbox
from app.modules.mail.models import EmailOutbox
from app.modules.mail.templates import MailTemplate
from app.modules.organizations import repository as repo_orgs
from app.modules.organizations.members import _ensure_may_manage
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.users import repository as users_repo
from app.modules.users.models import User

log = logging.getLogger(__name__)

INVITE_EXPIRY_DAYS = 7


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _mask_email(email_str: str) -> str:
    parts = email_str.split("@", 1)
    if len(parts) != 2:
        return email_str
    local, domain = parts
    masked_local = f"{local[0]}***" if local else "***"
    return f"{masked_local}@{domain}"


async def _get_mail_status(session: Any, inv_id: uuid.UUID) -> str | None:
    stmt = (
        select(EmailOutbox.status)
        .where(
            EmailOutbox.template == MailTemplate.INVITE.value,
            EmailOutbox.context_org_id.isnot(None),
        )
        .order_by(EmailOutbox.created_at.desc())
        .limit(1)
    )
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def list_invitations(ctx: OrgContext, page: PageParams) -> InvitationPage:
    now = datetime.now(timezone.utc)
    rows, total = await repo.list_invitations(ctx.session, ctx.org_id, page)
    items: list[InvitationOut] = []
    for inv, inviter_name in rows:
        status_val = repo.compute_status(inv, now).value
        items.append(
            InvitationOut(
                id=inv.id,
                email=str(inv.email),
                role=inv.role,
                status=status_val,
                invited_by=inv.invited_by,
                invited_by_name=inviter_name,
                created_at=inv.created_at,
                expires_at=inv.expires_at,
                last_sent_at=inv.last_sent_at,
                resend_count=inv.resend_count,
                mail_status="sent" if inv.accepted_at else "pending",
            )
        )
    return InvitationPage(items=items, total=total)


async def create_invitation(
    ctx: OrgContext, data: InvitationCreate, request: HTTPConnection
) -> InvitationOut:
    # 1. Rate limits
    await rate_limit.hit(f"invite:actor:{ctx.user.id}:10m", 30, 600)
    await rate_limit.hit(f"invite:actor:{ctx.user.id}:1d", 100, 86400)
    await rate_limit.hit(f"invite:org:{ctx.org_id}:1d", 200, 86400)

    # 2. Re-read actor role under org lock
    await repo_orgs.lock_org(ctx.session, ctx.org_id)
    actor_role = await membership_role(ctx.session, ctx.org_id, ctx.user.id, for_update=True)
    _ensure_may_manage(actor_role, None, data.role)

    # 3. Step-up if inviting admin or owner
    if data.role in (MemberRole.ADMIN, MemberRole.OWNER):
        await require_recent_auth(ctx.session, ctx.user, action=StepUpAction.MEMBER_ELEVATE)

    email_clean = str(data.email).strip().lower()

    # 4. Check domain allowlist from OrgSecurityPolicy
    stmt_policy = select(OrgSecurityPolicy).where(OrgSecurityPolicy.organization_id == ctx.org_id)
    policy = (await ctx.session.execute(stmt_policy)).scalar_one_or_none()
    if policy and policy.invite_domain_allowlist:
        email_domain = email_clean.rsplit("@", 1)[-1]
        allowed = [d.lower().strip() for d in policy.invite_domain_allowlist]
        if email_domain not in allowed:
            raise InviteDomainNotAllowed()

    # 5. Revoke any pending invitation for same (org, email) in this transaction
    await repo.revoke_pending_by_email(ctx.session, ctx.org_id, email_clean, ctx.user.id)

    # 6. Generate token and hash
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=INVITE_EXPIRY_DAYS)
    inv_id = uuid.uuid4()

    # 7. Insert org_invitations and invitation_index
    inv = OrgInvitation(
        id=inv_id,
        organization_id=ctx.org_id,
        email=email_clean,
        role=data.role,
        token_hash=token_hash,
        invited_by=ctx.user.id,
        expires_at=expires_at,
        resend_count=0,
    )
    ctx.session.add(inv)
    await ctx.session.flush()

    idx = InvitationIndex(
        invitation_id=inv_id,
        organization_id=ctx.org_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    ctx.session.add(idx)

    # 8. Query org name
    org = await repo_orgs.get_org(ctx.session, ctx.org_id)
    org_name = org.name if org else "an organization on CyberLab"

    # 9. Enqueue outbox mail
    outbox_id = await outbox.enqueue(
        ctx.session,
        template=MailTemplate.INVITE,
        to=email_clean,
        params={
            "org_name": org_name,
            "inviter_name": ctx.user.display_name,
            "role": data.role.value,
            "expires_at": expires_at,
        },
        secret=token,
        org_id=ctx.org_id,
        user_id=ctx.user.id,
    )

    # 10. Audit
    audit.record(
        ctx.session,
        action="invitation.created",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="invitation",
        target_id=inv_id,
        details={"email": email_clean, "role": data.role.value},
        request=request,
    )

    await ctx.session.commit()
    await outbox.publish_after_commit(outbox_id)

    return InvitationOut(
        id=inv.id,
        email=inv.email,
        role=inv.role,
        status="pending",
        invited_by=ctx.user.id,
        invited_by_name=ctx.user.display_name,
        created_at=inv.created_at,
        expires_at=inv.expires_at,
        last_sent_at=inv.last_sent_at,
        resend_count=0,
        mail_status="pending",
    )


async def resend_invitation(
    ctx: OrgContext, invitation_id: uuid.UUID, request: HTTPConnection
) -> InvitationOut:
    await repo_orgs.lock_org(ctx.session, ctx.org_id)
    inv = await repo.get_invitation(ctx.session, ctx.org_id, invitation_id, for_update=True)
    if inv is None:
        raise NotFound("Invitation not found", code="invitation_not_found")

    now = datetime.now(timezone.utc)
    if repo.compute_status(inv, now) != InvitationStatus.PENDING:
        raise Conflict("Only pending invitations can be resent", code="invitation_not_pending")

    if inv.resend_count >= 3:
        raise Conflict("Maximum resend attempts reached for this invitation today", code="max_resends_exceeded")

    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    expires_at = now + timedelta(days=INVITE_EXPIRY_DAYS)

    inv.token_hash = token_hash
    inv.expires_at = expires_at
    inv.resend_count += 1
    inv.last_sent_at = func.now()

    await ctx.session.execute(
        update(InvitationIndex)
        .where(InvitationIndex.invitation_id == inv.id)
        .values(token_hash=token_hash, expires_at=expires_at)
    )

    org = await repo_orgs.get_org(ctx.session, ctx.org_id)
    org_name = org.name if org else "an organization on CyberLab"

    outbox_id = await outbox.enqueue(
        ctx.session,
        template=MailTemplate.INVITE,
        to=inv.email,
        params={
            "org_name": org_name,
            "inviter_name": ctx.user.display_name,
            "role": inv.role.value,
            "expires_at": expires_at,
        },
        secret=token,
        org_id=ctx.org_id,
        user_id=ctx.user.id,
    )

    audit.record(
        ctx.session,
        action="invitation.resent",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="invitation",
        target_id=inv.id,
        details={"email": inv.email, "resend_count": inv.resend_count},
        request=request,
    )

    await ctx.session.commit()
    await outbox.publish_after_commit(outbox_id)

    return InvitationOut(
        id=inv.id,
        email=inv.email,
        role=inv.role,
        status="pending",
        invited_by=inv.invited_by,
        invited_by_name=ctx.user.display_name,
        created_at=inv.created_at,
        expires_at=inv.expires_at,
        last_sent_at=datetime.now(timezone.utc),
        resend_count=inv.resend_count,
        mail_status="pending",
    )


async def revoke_invitation(
    ctx: OrgContext, invitation_id: uuid.UUID, request: HTTPConnection
) -> InvitationOut:
    await repo_orgs.lock_org(ctx.session, ctx.org_id)
    inv = await repo.get_invitation(ctx.session, ctx.org_id, invitation_id, for_update=True)
    if inv is None:
        raise NotFound("Invitation not found", code="invitation_not_found")

    now = datetime.now(timezone.utc)
    if inv.accepted_at is not None:
        raise Conflict("Accepted invitations cannot be revoked", code="invitation_already_accepted")

    inv.revoked_at = func.now()
    inv.revoked_by = ctx.user.id

    audit.record(
        ctx.session,
        action="invitation.revoked",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="invitation",
        target_id=inv.id,
        details={"email": inv.email},
        request=request,
    )

    await ctx.session.commit()

    return InvitationOut(
        id=inv.id,
        email=inv.email,
        role=inv.role,
        status="revoked",
        invited_by=inv.invited_by,
        invited_by_name=ctx.user.display_name,
        created_at=inv.created_at,
        expires_at=inv.expires_at,
        last_sent_at=inv.last_sent_at,
        resend_count=inv.resend_count,
        mail_status=None,
    )


async def inspect_invitation(token: str, request: HTTPConnection) -> InvitationInspectOut:
    await rate_limit.hit(f"invite:inspect:{ip_key(request)}", 20, 600)
    token_hash = _hash_token(token)

    # 1. Lookup org via index
    async with tenant_session(None, None) as sys_session:
        idx = await repo.lookup_index(sys_session, token_hash)
        if idx is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")
        org_id = idx.organization_id

    # 2. Vetted tenant session read
    async with tenant_session(org_id, None) as session:
        stmt = (
            select(OrgInvitation, Organization.name, User.display_name)
            .join(Organization, OrgInvitation.organization_id == Organization.id)
            .join(User, OrgInvitation.invited_by == User.id)
            .where(
                OrgInvitation.organization_id == org_id,
                OrgInvitation.token_hash == token_hash,
                OrgInvitation.accepted_at.is_(None),
                OrgInvitation.revoked_at.is_(None),
                OrgInvitation.expires_at > func.now(),
            )
        )
        res = (await session.execute(stmt)).first()
        if res is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")
        inv, org_name, inviter_name = res

    return InvitationInspectOut(
        organization_name=org_name,
        role=inv.role,
        inviter_name=inviter_name,
        email_masked=_mask_email(inv.email),
        expires_at=inv.expires_at,
    )


async def accept_invitation(
    user: CurrentUser, token: str, request: HTTPConnection
) -> InvitationAcceptOut:
    if getattr(user, "kind", "session") == "api_key":
        raise Conflict("Service accounts cannot accept invitations", code="service_account_invitation")

    token_hash = _hash_token(token)

    # 1. Lookup org in system session
    async with tenant_session(None, None) as sys_session:
        idx = await repo.lookup_index(sys_session, token_hash)
        if idx is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")
        org_id = idx.organization_id

    # 2. Tenant session mutate
    async with tenant_session(org_id, user.id) as session:
        db_user = await users_repo.get_active(session, user.id)
        if db_user is not None and db_user.kind != "human":
            raise Conflict("Service accounts cannot accept invitations", code="service_account_invitation")

        stmt_inv = select(OrgInvitation).where(
            OrgInvitation.organization_id == org_id,
            OrgInvitation.token_hash == token_hash,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
            OrgInvitation.expires_at > func.now(),
        )
        inv = (await session.execute(stmt_inv)).scalar_one_or_none()
        if inv is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")

        if user.email.lower() != inv.email.lower():
            raise Conflict("Signed in email does not match invitation", code="invitation_email_mismatch")

        # Atomic consume
        consumed = await repo.consume_invitation_atomically(session, org_id, token_hash, user.id)
        if consumed is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")

        existing_member = await repo_orgs.find_member_by_user(session, org_id, user.id)
        if existing_member is not None:
            already_member = True
            role = existing_member.role
        else:
            already_member = False
            role = inv.role
            new_member = OrganizationMember(organization_id=org_id, user_id=user.id, role=role)
            session.add(new_member)
            await session.flush()
            audit.record(
                session,
                action="member.added",
                org_id=org_id,
                actor_id=user.id,
                target_type="member",
                target_id=new_member.id,
                details={"user_id": str(user.id), "role": role.value, "via": "invitation"},
                request=request,
            )

        audit.record(
            session,
            action="invitation.accepted",
            org_id=org_id,
            actor_id=user.id,
            target_type="invitation",
            target_id=consumed.id,
            details={"email": inv.email, "role": role.value},
            request=request,
        )

        record_auth_event(
            session,
            AuthEventType.INVITATION_ACCEPTED,
            request=request,
            user_id=user.id,
        )

        # Mark user email verified
        await session.execute(
            update(User)
            .where(User.id == user.id)
            .values(email_verified_at=func.coalesce(User.email_verified_at, func.now()))
        )

    return InvitationAcceptOut(
        organization_id=org_id,
        role=role,
        already_member=already_member,
    )


async def register_with_invitation(
    data: RegisterIn, password_hash: str, request: HTTPConnection
) -> tuple[uuid.UUID, IssuedTokens]:
    """Register and join an organization through an invitation token."""
    token = data.invitation_token or ""
    token_hash = _hash_token(token)

    async with tenant_session(None, None) as sys_session:
        idx = await repo.lookup_index(sys_session, token_hash)
        if idx is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")
        org_id = idx.organization_id

    new_user_id = uuid.uuid4()
    email_clean = str(data.email).strip().lower()

    async with tenant_session(org_id, new_user_id) as session:
        stmt_inv = select(OrgInvitation).where(
            OrgInvitation.organization_id == org_id,
            OrgInvitation.token_hash == token_hash,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
            OrgInvitation.expires_at > func.now(),
        )
        inv = (await session.execute(stmt_inv)).scalar_one_or_none()
        if inv is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")

        if email_clean != inv.email.lower():
            raise Conflict("Registration email does not match invitation", code="invitation_email_mismatch")

        new_user = User(
            id=new_user_id,
            email=email_clean,
            password_hash=password_hash,
            display_name=data.display_name,
            email_verified_at=func.now(),
            kind="human",
        )
        session.add(new_user)
        await session.flush()

        consumed = await repo.consume_invitation_atomically(session, org_id, token_hash, new_user_id)
        if consumed is None:
            raise NotFound("Invalid or expired invitation token", code="invitation_invalid")

        member = OrganizationMember(organization_id=org_id, user_id=new_user_id, role=inv.role)
        session.add(member)
        await session.flush()

        audit.record(
            session,
            action="invitation.accepted",
            org_id=org_id,
            actor_id=new_user_id,
            target_type="invitation",
            target_id=consumed.id,
            details={"email": email_clean, "role": inv.role.value},
            request=request,
        )
        audit.record(
            session,
            action="member.added",
            org_id=org_id,
            actor_id=new_user_id,
            target_type="member",
            target_id=member.id,
            details={"user_id": str(new_user_id), "role": inv.role.value, "via": "invitation"},
            request=request,
        )

        record_auth_event(
            session,
            AuthEventType.REGISTER,
            request=request,
            user_id=new_user_id,
            email=email_clean,
        )
        record_auth_event(
            session,
            AuthEventType.INVITATION_ACCEPTED,
            request=request,
            user_id=new_user_id,
        )

        tokens = await sessions.start_session(session, new_user_id, request)

    return new_user_id, tokens
