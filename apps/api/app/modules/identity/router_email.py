"""Email verification (M11 phase 3; phase 1 stubs answering 501).

`verify-request` mails a 24 h token (3 / hour per user); `verify` needs a session of the token's
own user (RT8): a link scanner or anyone holding a forwarded link cannot verify an account it
is not signed into.
"""

from fastapi import APIRouter, status

from app.core.deps import CurrentUserDep
from app.core.stubs import not_implemented
from app.modules.identity.schemas import EmailVerifyIn

router = APIRouter(prefix="/auth/email", tags=["identity"])


@router.post("/verify-request", status_code=status.HTTP_204_NO_CONTENT)
async def request_email_verification(user: CurrentUserDep) -> None:
    raise not_implemented()


@router.post("/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_email(body: EmailVerifyIn, user: CurrentUserDep) -> None:
    raise not_implemented()
