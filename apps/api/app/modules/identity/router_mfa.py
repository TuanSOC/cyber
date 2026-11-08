"""TOTP MFA, recovery codes, the login challenge and step-up (M11 phase 5).

- `POST /auth/mfa/verify` completes a `202` login challenge (the `cl_mfa` cookie; CSRF token
  set at the 202) -> `MeOut` + session (`amr` `pwd` + `otp` / `recovery`).
- Enrollment needs `email_verified_at` (RT8) and a non-SSO session (RT2); `setup` and
  `recovery-codes` answer `Cache-Control: no-store`.
- `POST /auth/step-up` writes `user_sessions.step_up_at = now()`
  (`sessions_store.mark_step_up`) and the auth event.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from app.core.deps import CurrentUserDep
from app.core.tenancy import tenant_session
from app.modules.auth.schemas import MeOut
from app.modules.identity import mfa, stepup_api
from app.modules.identity.schemas import (
    MfaStatusOut,
    MfaVerifyIn,
    RecoveryCodesOut,
    StepUpIn,
    TotpConfirmIn,
    TotpDisableIn,
    TotpSetupOut,
)

router = APIRouter(prefix="/auth", tags=["identity"])


@router.post("/mfa/verify", response_model=MeOut)
async def verify_mfa(body: MfaVerifyIn, request: Request, response: Response) -> MeOut:
    return await mfa.verify_login_mfa(body, request, response)


@router.get("/mfa", response_model=MfaStatusOut)
async def get_mfa(user: CurrentUserDep) -> MfaStatusOut:
    async with tenant_session(None, user.id) as session:
        return await mfa.get_mfa_status(user, session)


@router.post("/mfa/totp/setup", response_model=TotpSetupOut)
async def setup_totp(user: CurrentUserDep, response: Response) -> TotpSetupOut:
    response.headers["Cache-Control"] = "no-store"
    async with tenant_session(None, user.id) as session:
        return await mfa.setup_totp(user, session)


@router.post("/mfa/totp/confirm", response_model=RecoveryCodesOut)
async def confirm_totp(
    body: TotpConfirmIn,
    user: CurrentUserDep,
    request: Request,
    response: Response,
) -> RecoveryCodesOut:
    async with tenant_session(None, user.id) as session:
        return await mfa.confirm_totp(body, user, session, request, response)


@router.delete("/mfa/totp", status_code=status.HTTP_204_NO_CONTENT)
async def disable_totp(
    body: TotpDisableIn,
    user: CurrentUserDep,
    request: Request,
) -> None:
    async with tenant_session(None, user.id) as session:
        await mfa.disable_totp(body, user, session, request)


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesOut)
async def regenerate_recovery_codes(
    user: CurrentUserDep,
    request: Request,
    response: Response,
) -> RecoveryCodesOut:
    response.headers["Cache-Control"] = "no-store"
    async with tenant_session(None, user.id) as session:
        return await mfa.regenerate_recovery_codes(user, session, request)


@router.post("/step-up", status_code=status.HTTP_204_NO_CONTENT)
async def step_up(
    body: StepUpIn,
    user: CurrentUserDep,
    request: Request,
    response: Response,
) -> None:
    await stepup_api.perform_step_up(body, user, request, response)
