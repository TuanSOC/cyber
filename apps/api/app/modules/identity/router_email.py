"""Email verification routes (M11 phase 3)."""

from fastapi import APIRouter, Request, status

from app.core.deps import CurrentUserDep
from app.modules.identity import email_verify
from app.modules.identity.schemas import EmailVerifyIn

router = APIRouter(prefix="/auth/email", tags=["identity"])


@router.post("/verify-request", status_code=status.HTTP_204_NO_CONTENT)
async def request_email_verification(user: CurrentUserDep, request: Request) -> None:
    await email_verify.request_verification(user, request)


@router.post("/verify", status_code=status.HTTP_204_NO_CONTENT)
async def verify_email(body: EmailVerifyIn, user: CurrentUserDep, request: Request) -> None:
    await email_verify.verify_email(user, body.token, request)
