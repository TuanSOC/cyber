"""Org security policy (M11 phase 6; phase 1 stubs answering 501).

`GET` is `org.read` and policy-exempt (RT13: a member blocked by `require_mfa` still sees why);
`PUT` is `security.manage` + step-up `security_policy_update`; `sso_enforced` is refused
(`409 sso_not_ready`) until the acting owner signed in once through SSO.
"""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.identity.schemas import SecurityPolicyOut, SecurityPolicyUpdate

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
    raise not_implemented()


@router.put("", response_model=SecurityPolicyOut)
async def update_security_policy(
    body: SecurityPolicyUpdate, ctx: SecurityManage
) -> SecurityPolicyOut:
    raise not_implemented()
