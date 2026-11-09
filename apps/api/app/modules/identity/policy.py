"""Org security policy enforcement (M11 phase 6).

`check_org_access(session, org_id, principal, role=None)` runs inside `core.rbac.org_session`,
after the membership check, in the org's tenant session (skipped for `require(...,
policy_exempt=True)` routes, RT13).

Rules, in order:
0. API key principals: `api_keys_enabled` false -> `403 api_keys_disabled`. MFA / SSO rules do
   not apply to API keys.
1. An SSO session of org S on org X != S, of a user with a usable password ->
   `403 sso_session_scope` (RT2; SSO-provisioned users without a local password pass this rule).
2. `require_mfa` and `otp` not in the session's `amr` (an SSO session of this org satisfies it)
   -> `403 mfa_required {enroll: bool}` (enroll=True when user has no active factor).
3. `sso_enforced` and the session's `sso_org_id` is not this org ->
   `403 sso_required {sso_start: true}`, except owners with `otp` when `owners_break_glass`
   is True (audited `org.sso_break_glass` once per session via `core.audit_dedupe.once_per`).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit_dedupe
from app.core.deps import CurrentUser
from app.modules.audit import service as audit
from app.modules.identity.errors import (
    ApiKeysDisabled,
    MfaRequired,
    SsoRequired,
    SsoSessionScope,
)
from app.modules.identity.models import MfaFactor, MfaStatus, OrgSecurityPolicy
from app.modules.organizations.models import MemberRole, OrganizationMember


async def check_org_access(
    session: AsyncSession,
    org_id: uuid.UUID,
    principal: CurrentUser,
    role: MemberRole | None = None,
) -> None:
    stmt = select(OrgSecurityPolicy).where(OrgSecurityPolicy.organization_id == org_id)
    policy = (await session.execute(stmt)).scalar_one_or_none()

    # Rule 0: API key principals
    if principal.kind == "api_key":
        if policy is None or not policy.api_keys_enabled:
            raise ApiKeysDisabled()
        return

    # Rule 1: SSO session scope (RT2)
    if (
        principal.sso_org_id is not None
        and principal.sso_org_id != org_id
        and principal.has_password
    ):
        raise SsoSessionScope()

    # Rule 2: MFA enforcement
    if policy is not None and policy.require_mfa:
        is_sso_of_this_org = principal.sso_org_id == org_id
        if "otp" not in principal.amr and not is_sso_of_this_org:
            stmt_mfa = select(MfaFactor.id).where(
                MfaFactor.user_id == principal.id,
                MfaFactor.status == MfaStatus.ACTIVE.value,
            )
            has_active = (await session.execute(stmt_mfa)).first() is not None
            raise MfaRequired(extra={"enroll": not has_active})

    # Rule 3: SSO enforcement and break-glass
    if policy is not None and policy.sso_enforced and principal.sso_org_id != org_id:
        user_role = role
        if user_role is None:
            stmt_role = select(OrganizationMember.role).where(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.user_id == principal.id,
            )
            user_role = (await session.execute(stmt_role)).scalar_one_or_none()

        if policy.owners_break_glass and user_role == MemberRole.OWNER and "otp" in principal.amr:
            dedupe_key = f"sso_break_glass:{org_id}:{principal.session_id}"
            if await audit_dedupe.once_per(dedupe_key, 86400):
                audit.record(
                    session,
                    action="org.sso_break_glass",
                    org_id=org_id,
                    actor_id=principal.id,
                    target_type="organization",
                    target_id=org_id,
                    details={"session_id": str(principal.session_id)},
                )
        else:
            raise SsoRequired(extra={"sso_start": True})
