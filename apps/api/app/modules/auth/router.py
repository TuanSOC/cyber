from fastapi import APIRouter, Request, Response, status

from app.core.cookies import (
    ACCESS_COOKIE,
    REFRESH_COOKIE,
    clear_auth_cookies,
    set_auth_cookies,
)
from app.core.deps import CurrentUserDep
from app.modules.auth import service, sessions
from app.modules.auth.schemas import LoginIn, MeOut, RegisterIn

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=MeOut, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterIn, request: Request, response: Response) -> MeOut:
    me, tokens = await service.register(body, request)
    set_auth_cookies(response, tokens)
    return me


@router.post("/login", response_model=MeOut)
async def login(body: LoginIn, request: Request, response: Response) -> MeOut:
    me, tokens = await service.login(body, request)
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
