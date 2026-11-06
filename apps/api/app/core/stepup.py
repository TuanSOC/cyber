"""Server-side step-up for sensitive actions (M11 phase 1, FROZEN, implemented).

`require_recent_auth(session, principal, action=...)` passes when the caller's session
(`user_sessions` row = the access token's `sid`) re-authenticated within `STEP_UP_MAX_AGE_S`;
the age is compared in SQL against the DB `now()` (`step_up_at` is written as `now()` by
`identity.sessions_store.mark_step_up`), so API and DB clocks never mix (RT21). Otherwise
`403 step_up_required {action, methods}`: `methods` is `["sso"]` for an SSO session,
`["totp", "recovery_code"]` with an active TOTP factor (`["recovery_code"]` when it is locked),
else `["password"]` with a usable password. API keys never pass
(`403 api_key_step_up_forbidden`). A pass writes nothing; `POST /auth/step-up` (phase 5)
records the auth events. Works in any open session (`user_sessions` has no RLS).

Call sites (one guarded line each, after the route's own checks): phases 3-7 and 9, see the
plan's Step-up section.
"""

import enum

from sqlalchemy import Float, bindparam, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.modules.identity.errors import ApiKeyStepUpForbidden, StepUpRequired
from app.modules.identity.models import MfaFactor, MfaStatus, MfaType, UserSession


class StepUpAction(enum.StrEnum):
    PASSWORD_CHANGE = "password_change"
    MFA_SETUP = "mfa_setup"
    MFA_DISABLE = "mfa_disable"
    RECOVERY_CODES_REGENERATE = "recovery_codes_regenerate"
    MEMBER_ELEVATE = "member_elevate"
    MEMBER_REMOVE = "member_remove"
    SECURITY_POLICY_UPDATE = "security_policy_update"
    SSO_CONFIG_UPDATE = "sso_config_update"
    DOMAIN_CHANGE = "domain_change"
    API_KEY_CREATE = "api_key_create"
    PROVIDER_KEY_CHANGE = "provider_key_change"
    TLP_DOWNGRADE = "tlp_downgrade"
    SHARE_POLICY_RELEASE = "share_policy_release"
    RETENTION_DESTRUCTIVE = "retention_destructive"
    LEGAL_HOLD_RELEASE = "legal_hold_release"


_RECENT = text("step_up_at > now() - make_interval(secs => :max_age)").bindparams(
    bindparam("max_age", type_=Float)
)


async def has_recent_step_up(session: AsyncSession, principal: CurrentUser) -> bool:
    """The live session row of this principal re-authenticated within the max age."""
    stmt = select(UserSession.id).where(
        UserSession.id == principal.session_id,
        UserSession.user_id == principal.id,
        UserSession.revoked_at.is_(None),
        _RECENT,
    )
    params = {"max_age": float(get_settings().step_up_max_age_s)}
    return (await session.execute(stmt, params)).first() is not None


async def step_up_methods(session: AsyncSession, principal: CurrentUser) -> list[str]:
    if principal.sso_org_id is not None:
        return ["sso"]
    status = (
        await session.execute(
            select(MfaFactor.status).where(
                MfaFactor.user_id == principal.id,
                MfaFactor.type == MfaType.TOTP.value,
                MfaFactor.status.in_((MfaStatus.ACTIVE.value, MfaStatus.LOCKED.value)),
            )
        )
    ).scalar_one_or_none()
    if status == MfaStatus.ACTIVE.value:
        return ["totp", "recovery_code"]
    if status == MfaStatus.LOCKED.value:
        return ["recovery_code"]
    return ["password"] if principal.has_password else ["sso"]


async def require_recent_auth(
    session: AsyncSession, principal: CurrentUser, *, action: StepUpAction
) -> None:
    if principal.kind == "api_key":
        raise ApiKeyStepUpForbidden()
    if await has_recent_step_up(session, principal):
        return
    methods = await step_up_methods(session, principal)
    raise StepUpRequired(extra={"action": action.value, "methods": methods})
