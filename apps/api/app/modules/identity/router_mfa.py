"""TOTP MFA, recovery codes, the login challenge and step-up (M11 phase 5; phase 1 stubs).

- `POST /auth/mfa/verify` completes a `202` login challenge (the `cl_mfa` cookie; CSRF token
  set at the 202) -> `MeOut` + session (`amr` `pwd` + `otp` / `recovery`).
- Enrollment needs `email_verified_at` (RT8) and a non-SSO session (RT2); `setup` and
  `recovery-codes` answer `Cache-Control: no-store`.
- `POST /auth/step-up` writes `user_sessions.step_up_at = now()`
  (`sessions_store.mark_step_up`) and the auth event.
"""

from fastapi import APIRouter, Request, status

from app.core.deps import CurrentUserDep
from app.core.stubs import not_implemented
from app.modules.auth.schemas import MeOut
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
async def verify_mfa(body: MfaVerifyIn, request: Request) -> MeOut:
    raise not_implemented()


@router.get("/mfa", response_model=MfaStatusOut)
async def get_mfa(user: CurrentUserDep) -> MfaStatusOut:
    raise not_implemented()


@router.post("/mfa/totp/setup", response_model=TotpSetupOut)
async def setup_totp(user: CurrentUserDep) -> TotpSetupOut:
    raise not_implemented()


@router.post("/mfa/totp/confirm", response_model=RecoveryCodesOut)
async def confirm_totp(body: TotpConfirmIn, user: CurrentUserDep) -> RecoveryCodesOut:
    raise not_implemented()


@router.delete("/mfa/totp", status_code=status.HTTP_204_NO_CONTENT)
async def disable_totp(body: TotpDisableIn, user: CurrentUserDep) -> None:
    raise not_implemented()


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesOut)
async def regenerate_recovery_codes(user: CurrentUserDep) -> RecoveryCodesOut:
    raise not_implemented()


@router.post("/step-up", status_code=status.HTTP_204_NO_CONTENT)
async def step_up(body: StepUpIn, user: CurrentUserDep) -> None:
    raise not_implemented()
