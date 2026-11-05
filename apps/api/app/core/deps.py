import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request

from app.core import rate_limit
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.cookies import ACCESS_COOKIE
from app.core.errors import Unauthorized
from app.core.security import decode_access_token
from app.core.tenancy import tenant_session
from app.modules.users import repository as users

DENYLIST_PREFIX = "denylist:"
FAMILY_DENYLIST_PREFIX = "denylist:fam:"

# M7 (phase 6): the global per-user API limit. Exempt: `GET /auth/me` (the shell polls it to
# keep the session). The health routes and `GET /report-signing-keys` never call
# `current_user` (the keys route has its own per-IP limit), so they are exempt by
# construction. The unauthenticated surface (login, register, refresh) keeps its own limits;
# there is no anonymous per-IP limiter (RT14, cut).
USER_LIMIT_PREFIX = "u:"
USER_LIMIT_WINDOW_S = 60
USER_LIMIT_EXEMPT: frozenset[tuple[str, str]] = frozenset({("GET", "/api/v1/auth/me")})
_COUNTED = "cyberlab_user_limit_counted"


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    email: str
    display_name: str
    jti: str
    family_id: uuid.UUID
    token_expires_at: datetime


async def _count_request(request: Request, user_id: uuid.UUID) -> None:
    """One hit per request (an upload or download body counts once), whatever the number of
    dependencies resolving the user. 429 with `Retry-After`; a Redis failure fails closed."""
    if (request.method, request.url.path) in USER_LIMIT_EXEMPT:
        return
    if getattr(request.state, _COUNTED, False):
        return
    setattr(request.state, _COUNTED, True)
    await rate_limit.hit(
        f"{USER_LIMIT_PREFIX}{user_id}",
        get_settings().rate_limit_user_per_min,
        USER_LIMIT_WINDOW_S,
    )


async def current_user(request: Request) -> CurrentUser:
    token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise Unauthorized()
    claims = decode_access_token(token)
    # Denied individually (logout) or with its whole refresh family (logout/reuse/deactivation).
    if await get_redis().exists(
        DENYLIST_PREFIX + claims.jti, FAMILY_DENYLIST_PREFIX + str(claims.family_id)
    ):
        raise Unauthorized(code="invalid_token")
    # After the token is validated, before the database lookup (a flood costs Redis only).
    await _count_request(request, claims.user_id)
    async with tenant_session(None, None) as session:
        user = await users.get_active(session, claims.user_id)
    if user is None:
        raise Unauthorized(code="invalid_token")
    return CurrentUser(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        jti=claims.jti,
        family_id=claims.family_id,
        token_expires_at=claims.expires_at,
    )


CurrentUserDep = Annotated[CurrentUser, Depends(current_user)]
