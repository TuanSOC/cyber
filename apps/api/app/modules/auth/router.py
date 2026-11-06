from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.cookies import (
    ACCESS_COOKIE,
    REFRESH_COOKIE,
    clear_auth_cookies,
    set_auth_cookies,
    set_csrf_cookie,
    set_mfa_cookie,
)
from app.core.deps import CurrentUserDep
from app.modules.auth import service, sessions
from app.modules.auth.schemas import LoginIn, MeOut, MfaChallengeOut, RegisterIn

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=MeOut, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterIn, request: Request, response: Response) -> MeOut:
    """M11: `invitation_token` joins the invitation's org (phase 3); `REGISTRATION_MODE=
    invite_only` answers `403 registration_closed` without one."""
    me, tokens = await service.register(body, request)
    set_auth_cookies(response, tokens)
    return me


@router.post(
    "/login",
    response_model=MeOut,
    responses={status.HTTP_202_ACCEPTED: {"model": MfaChallengeOut}},
)
async def login(body: LoginIn, request: Request, response: Response) -> MeOut | JSONResponse:
    """200 `MeOut` + session, or (M11 phase 5) 202 `MfaChallengeOut` + `cl_mfa` + `cl_csrf`
    and no session when the account has an active second factor."""
    result = await service.login(body, request)
    if isinstance(result, service.MfaChallenge):
        challenge = JSONResponse(
            MfaChallengeOut(methods=list(result.methods)).model_dump(),  # type: ignore[arg-type]
            status_code=status.HTTP_202_ACCEPTED,
        )
        set_mfa_cookie(challenge, result.challenge_id)
        set_csrf_cookie(challenge, result.csrf_token)
        return challenge
    me, tokens = result
    set_auth_cookies(response, tokens)
    return me


@router.post("/refresh", status_code=status.HTTP_204_NO_CONTENT)
async def refresh(request: Request, response: Response) -> None:
    tokens = await sessions.refresh(request.cookies.get(REFRESH_COOKIE), request)
    set_auth_cookies(response, tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response) -> None:
    await sessions.logout(
        request, request.cookies.get(REFRESH_COOKIE), request.cookies.get(ACCESS_COOKIE)
    )
    clear_auth_cookies(response)


@router.get("/me", response_model=MeOut)
async def me(user: CurrentUserDep) -> MeOut:
    return await service.me(user.id)
