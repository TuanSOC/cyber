from dataclasses import dataclass

from starlette.responses import Response

from app.core.config import get_settings
from app.core.security import ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL

ACCESS_COOKIE = "cl_access"
REFRESH_COOKIE = "cl_refresh"
CSRF_COOKIE = "cl_csrf"

# The access JWT only needs to reach the API; the refresh token only the auth routes;
# the CSRF token must be readable by JS on every page (double-submit).
ACCESS_PATH = "/api"
REFRESH_PATH = "/api/v1/auth"
CSRF_PATH = "/"


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    csrf_token: str


def set_auth_cookies(response: Response, tokens: IssuedTokens) -> None:
    secure = get_settings().cookie_secure
    common = {"secure": secure, "samesite": "strict"}
    response.set_cookie(
        ACCESS_COOKIE,
        tokens.access_token,
        max_age=int(ACCESS_TOKEN_TTL.total_seconds()),
        path=ACCESS_PATH,
        httponly=True,
        **common,  # type: ignore[arg-type]
    )
    response.set_cookie(
        REFRESH_COOKIE,
        tokens.refresh_token,
        max_age=int(REFRESH_TOKEN_TTL.total_seconds()),
        path=REFRESH_PATH,
        httponly=True,
        **common,  # type: ignore[arg-type]
    )
    response.set_cookie(
        CSRF_COOKIE,
        tokens.csrf_token,
        max_age=int(REFRESH_TOKEN_TTL.total_seconds()),
        path=CSRF_PATH,
        httponly=False,
        **common,  # type: ignore[arg-type]
    )


def clear_auth_cookies(response: Response) -> None:
    secure = get_settings().cookie_secure
    for name, path, httponly in (
        (ACCESS_COOKIE, ACCESS_PATH, True),
        (REFRESH_COOKIE, REFRESH_PATH, True),
        (CSRF_COOKIE, CSRF_PATH, False),
    ):
        response.delete_cookie(name, path=path, secure=secure, httponly=httponly, samesite="strict")
