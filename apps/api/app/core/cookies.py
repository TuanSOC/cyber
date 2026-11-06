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


# --- M11 (phase 1, FROZEN) -------------------------------------------------------------------
# The MFA login challenge (phase 5): the 202 of `POST /auth/login` sets it with a CSRF token;
# only the MFA routes see it. Strict: the challenge never crosses sites.
MFA_COOKIE = "cl_mfa"
MFA_PATH = "/api/v1/auth/mfa"
MFA_MAX_AGE_S = 300
# The SSO state binding (phase 8): Lax, because the IdP callback is a cross-site top-level GET
# (decision; research open question 2). Only the SSO routes see it.
SSO_COOKIE = "cl_sso"
SSO_PATH = "/api/v1/auth/sso"
SSO_MAX_AGE_S = 600


def set_access_cookie(response: Response, access_token: str) -> None:
    """Replace the access token only (M11: `sessions_store.add_amr` re-issues it after an MFA
    step; the refresh token and the CSRF cookie stay)."""
    response.set_cookie(
        ACCESS_COOKIE,
        access_token,
        max_age=int(ACCESS_TOKEN_TTL.total_seconds()),
        path=ACCESS_PATH,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="strict",
    )


def set_csrf_cookie(response: Response, csrf_token: str) -> None:
    """The double-submit token without a session (the login 202 of an MFA challenge)."""
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=MFA_MAX_AGE_S,
        path=CSRF_PATH,
        httponly=False,
        secure=get_settings().cookie_secure,
        samesite="strict",
    )


def set_mfa_cookie(response: Response, challenge_id: str) -> None:
    response.set_cookie(
        MFA_COOKIE,
        challenge_id,
        max_age=MFA_MAX_AGE_S,
        path=MFA_PATH,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="strict",
    )


def clear_mfa_cookie(response: Response) -> None:
    response.delete_cookie(
        MFA_COOKIE,
        path=MFA_PATH,
        secure=get_settings().cookie_secure,
        httponly=True,
        samesite="strict",
    )


def set_sso_cookie(response: Response, binding: str) -> None:
    response.set_cookie(
        SSO_COOKIE,
        binding,
        max_age=SSO_MAX_AGE_S,
        path=SSO_PATH,
        httponly=True,
        secure=get_settings().cookie_secure,
        samesite="lax",
    )


def clear_sso_cookie(response: Response) -> None:
    response.delete_cookie(
        SSO_COOKIE,
        path=SSO_PATH,
        secure=get_settings().cookie_secure,
        httponly=True,
        samesite="lax",
    )
