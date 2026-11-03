import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request

from app.core.clients import get_redis
from app.core.cookies import ACCESS_COOKIE
from app.core.errors import Unauthorized
from app.core.security import decode_access_token
from app.core.tenancy import tenant_session
from app.modules.users import repository as users

DENYLIST_PREFIX = "denylist:"
FAMILY_DENYLIST_PREFIX = "denylist:fam:"


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    email: str
    display_name: str
    jti: str
    family_id: uuid.UUID
    token_expires_at: datetime


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
