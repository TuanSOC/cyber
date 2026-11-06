"""Org security policy enforcement (M11; phase 1 stub, phase 6 implements it).

`check_org_access(session, org_id, principal)` runs inside `core.rbac.org_session`, after
the membership check, in the org's tenant session (skipped for `require(...,
policy_exempt=True)` routes, RT13). Phase 6 rules, in order:
1. an SSO session of org S on org X != S, of a user with a usable password
   -> `403 sso_session_scope` (RT2);
2. `require_mfa` and `otp` not in the session's `amr` (an SSO session counts only when its
   `sso_org_id` is this org) -> `403 mfa_required`;
3. `sso_enforced` and the session's `sso_org_id` is not this org -> `403 sso_required`, except
   owners with `otp` when `owners_break_glass` (audited `org.sso_break_glass` once per session).
API-key principals skip rules 1-3 (keys need `api_keys_enabled`, checked by phase 9 at
resolve). It must stay one indexed read (the policy row by primary key).
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentUser


async def check_org_access(
    session: AsyncSession, org_id: uuid.UUID, principal: CurrentUser
) -> None:
    """No-op until phase 6."""
    return None
