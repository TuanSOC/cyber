"""Password recovery and change (M11 phase 4; phase 1 stubs answering 501).

`forgot` answers `202` right after its limits (5 / 10 min per IP, 3 / hour per email); the
lookup, token and outbox row run after the response (RT6). `forgot` and `reset` are
CSRF-exempt (RT4). `change` needs the current password and step-up `password_change`, and is
refused from an SSO session of a password user (`local_reauth_required`, RT2).
"""

from fastapi import APIRouter, status

from app.core.deps import CurrentUserDep
from app.core.stubs import not_implemented
from app.modules.identity.schemas import PasswordChangeIn, PasswordForgotIn, PasswordResetIn

router = APIRouter(prefix="/auth/password", tags=["identity"])


@router.post("/forgot", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(body: PasswordForgotIn) -> None:
    raise not_implemented()


@router.post("/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(body: PasswordResetIn) -> None:
    raise not_implemented()


@router.post("/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(body: PasswordChangeIn, user: CurrentUserDep) -> None:
    raise not_implemented()
