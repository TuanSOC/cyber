"""Org security policy (M11 phase 6).

`GET` is `org.read` and policy-exempt (RT13: a member blocked by `require_mfa` still sees why);
`PUT` is `security.manage` + step-up `security_policy_update`; `sso_enforced` is refused
(`409 sso_not_ready`) until the acting owner signed in once through SSO (or break-glass + OTP).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from app.core.rbac import OrgContext, Permission, require
from app.core.stepup import StepUpAction, require_recent_auth
from app.modules.audit import service as audit
from app.modules.identity.errors import MfaRequiredForActor, SsoNotReady
from app.modules.identity.models import (
    DomainStatus,
    OrgDomain,
    OrgIdpConfig,
    OrgSecurityPolicy,
)
from app.modules.identity.schemas import SecurityPolicyOut, SecurityPolicyUpdate
from app.modules.mail import outbox
from app.modules.mail.templates import MailTemplate
from app.modules.organizations import repository as repo_orgs
from app.modules.organizations.models import MemberRole, OrganizationMember
from app.modules.users.models import User

router = APIRouter(prefix="/orgs/{org_id}/security-policy", tags=["identity"])

PolicyRead = Annotated[
    OrgContext,
    Depends(require(Permission.ORG_READ, policy_exempt=True), scope="function"),
]
SecurityManage = Annotated[
    OrgContext, Depends(require(Permission.SECURITY_MANAGE), scope="function")
]


@router.get("", response_model=SecurityPolicyOut)
async def get_security_policy(ctx: PolicyRead) -> SecurityPolicyOut:
    stmt = select(OrgSecurityPolicy).where(OrgSecurityPolicy.organization_id == ctx.org_id)
    policy = (await ctx.session.execute(stmt)).scalar_one_or_none()
    if policy is None:
        return SecurityPolicyOut(
            require_mfa=False,
            sso_enforced=False,
            owners_break_glass=True,
            api_keys_enabled=False,
            invite_domain_allowlist=[],
            updated_by=None,
            updated_at=None,
        )
    return SecurityPolicyOut(
        require_mfa=policy.require_mfa,
        sso_enforced=policy.sso_enforced,
        owners_break_glass=policy.owners_break_glass,
        api_keys_enabled=policy.api_keys_enabled,
        invite_domain_allowlist=policy.invite_domain_allowlist or [],
        updated_by=policy.updated_by,
        updated_at=policy.updated_at,
    )


@router.put("", response_model=SecurityPolicyOut)
async def update_security_policy(
    body: SecurityPolicyUpdate, ctx: SecurityManage, request: Request
) -> SecurityPolicyOut:
    await require_recent_auth(ctx.session, ctx.user, action=StepUpAction.SECURITY_POLICY_UPDATE)

    # Precondition 1: require_mfa requires acting owner to have 'otp' in AMR
    if body.require_mfa and "otp" not in ctx.user.amr:
        raise MfaRequiredForActor()

    # Precondition 2: sso_enforced requires enabled IdP, verified domain, and owner SSO
    # or (break-glass + OTP)
    if body.sso_enforced:
        idp_stmt = select(OrgIdpConfig.id).where(
            OrgIdpConfig.organization_id == ctx.org_id,
            OrgIdpConfig.enabled.is_(True),
        )
        has_enabled_idp = (await ctx.session.execute(idp_stmt)).first() is not None

        dom_stmt = select(OrgDomain.id).where(
            OrgDomain.organization_id == ctx.org_id,
            OrgDomain.status == DomainStatus.VERIFIED.value,
        )
        has_verified_dom = (await ctx.session.execute(dom_stmt)).first() is not None

        if not has_enabled_idp or not has_verified_dom:
            raise SsoNotReady()

        actor_is_sso = ctx.user.sso_org_id == ctx.org_id
        actor_break_glass = body.owners_break_glass and "otp" in ctx.user.amr
        if not actor_is_sso and not actor_break_glass:
            raise SsoNotReady()

    stmt = (
        select(OrgSecurityPolicy)
        .where(OrgSecurityPolicy.organization_id == ctx.org_id)
        .with_for_update()
    )
    policy = (await ctx.session.execute(stmt)).scalar_one_or_none()

    old_state = {
        "require_mfa": policy.require_mfa if policy else False,
        "sso_enforced": policy.sso_enforced if policy else False,
        "owners_break_glass": policy.owners_break_glass if policy else True,
        "api_keys_enabled": policy.api_keys_enabled if policy else False,
        "invite_domain_allowlist": policy.invite_domain_allowlist if policy else [],
    }

    if policy is None:
        policy = OrgSecurityPolicy(organization_id=ctx.org_id)
        ctx.session.add(policy)

    policy.require_mfa = body.require_mfa
    policy.sso_enforced = body.sso_enforced
    policy.owners_break_glass = body.owners_break_glass
    policy.api_keys_enabled = body.api_keys_enabled
    policy.invite_domain_allowlist = list(body.invite_domain_allowlist)
    policy.updated_by = ctx.user.id
    policy.updated_at = func.now()

    audit.record(
        ctx.session,
        action="org.security_policy_updated",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="org_security_policy",
        target_id=ctx.org_id,
        details={"from": old_state, "to": body.model_dump()},
        request=request,
    )

    # Notify all active human owners
    owners_stmt = (
        select(User)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .where(
            OrganizationMember.organization_id == ctx.org_id,
            OrganizationMember.role == MemberRole.OWNER,
            User.kind == "human",
            User.is_active.is_(True),
        )
    )
    owners = (await ctx.session.execute(owners_stmt)).scalars().all()
    org = await repo_orgs.get_org(ctx.session, ctx.org_id)
    org_name = org.name if org else "Organization"
    for owner in owners:
        await outbox.enqueue(
            ctx.session,
            template=MailTemplate.NEW_OWNER_SECURITY_CHANGE,
            to=owner.email,
            params={
                "org_name": org_name,
                "actor_name": ctx.user.display_name,
                "change": "security_policy",
            },
            user_id=owner.id,
        )

    await ctx.session.flush()
    await ctx.session.refresh(policy)
    return SecurityPolicyOut(
        require_mfa=policy.require_mfa,
        sso_enforced=policy.sso_enforced,
        owners_break_glass=policy.owners_break_glass,
        api_keys_enabled=policy.api_keys_enabled,
        invite_domain_allowlist=policy.invite_domain_allowlist or [],
        updated_by=policy.updated_by,
        updated_at=policy.updated_at,
    )
