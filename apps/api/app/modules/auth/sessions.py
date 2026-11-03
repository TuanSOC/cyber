"""Session lifecycle: token issuing, refresh rotation, logout, family revocation.

Commit rule: revocations and their auth events are committed (tenant_session block left)
before any error is raised.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.client_ip import client_ip, user_agent
from app.core.clients import get_redis
from app.core.cookies import IssuedTokens
from app.core.deps import DENYLIST_PREFIX, FAMILY_DENYLIST_PREFIX
from app.core.errors import Unauthorized
from app.core.security import (
    ACCESS_TOKEN_TTL,
    create_access_token,
    decode_access_token,
    hash_token,
    new_csrf_token,
    new_opaque_token,
)
from app.core.tenancy import tenant_session
from app.modules.auth import repository as tokens
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType, RevokedReason
from app.modules.users import repository as users

log = logging.getLogger(__name__)

# A token rotated this recently by another tab is "stale", not stolen.
REFRESH_GRACE = timedelta(seconds=10)


def issue_tokens(user_id: uuid.UUID, family_id: uuid.UUID, refresh_token: str) -> IssuedTokens:
    access, _ = create_access_token(user_id, family_id)
    return IssuedTokens(
        access_token=access, refresh_token=refresh_token, csrf_token=new_csrf_token()
    )


async def start_session(
    session: AsyncSession, user_id: uuid.UUID, request: HTTPConnection
) -> IssuedTokens:
    """Create a new refresh family inside the caller's transaction."""
    refresh_token, refresh_hash = new_opaque_token()
    family_id = uuid.uuid4()
    await tokens.create(
        session,
        user_id=user_id,
        family_id=family_id,
        token_hash=refresh_hash,
        ip=client_ip(request),
        user_agent=user_agent(request),
    )
    return issue_tokens(user_id, family_id, refresh_token)


async def deny_family_access(family_id: uuid.UUID) -> None:
    """Kill access tokens of a revoked family for the rest of their lifetime."""
    try:
        await get_redis().set(
            FAMILY_DENYLIST_PREFIX + str(family_id), "1", ex=int(ACCESS_TOKEN_TTL.total_seconds())
        )
    except RedisError:
        # Refresh tokens are already revoked in the DB; access tokens expire within 15 min.
        log.error("could not denylist access tokens of family %s", family_id)


async def refresh(refresh_token: str | None, request: HTTPConnection) -> IssuedTokens:
    if not refresh_token:
        raise Unauthorized("Session expired", code="invalid_refresh", clear_auth_cookies=True)
    token_hash = hash_token(refresh_token)
    successor_id = uuid.uuid4()
    new_refresh, new_hash = new_opaque_token()
    outcome = "invalid"
    revoked_family: uuid.UUID | None = None
    rotated: tokens.Rotated | None = None

    async with tenant_session(None, None) as session:
        rotated = await tokens.rotate(session, token_hash, successor_id)
        if rotated is not None:
            if await users.get_active(session, rotated.user_id) is None:
                # Deactivated user: no successor will exist, so drop the pointer to it.
                await tokens.abandon_rotation(session, token_hash, RevokedReason.LOGOUT)
                await tokens.revoke_family(session, rotated.family_id, RevokedReason.LOGOUT)
                revoked_family = rotated.family_id
            else:
                await tokens.create(
                    session,
                    token_id=successor_id,
                    user_id=rotated.user_id,
                    family_id=rotated.family_id,
                    token_hash=new_hash,
                    ip=client_ip(request),
                    user_agent=user_agent(request),
                    family_started_at=await tokens.family_started_at(session, rotated.family_id),
                )
                outcome = "ok"
        else:
            existing = await tokens.get_by_hash(session, token_hash)
            if existing is not None and existing.revoked_at is not None:
                recently_rotated = (
                    existing.revoked_reason == RevokedReason.ROTATED
                    and datetime.now(UTC) - existing.revoked_at < REFRESH_GRACE
                )
                if recently_rotated:
                    outcome = "stale"
                else:
                    outcome = "reused"
                    await tokens.revoke_family(session, existing.family_id, RevokedReason.REUSE)
                    revoked_family = existing.family_id
                    record_auth_event(
                        session,
                        AuthEventType.REFRESH_REUSE_DETECTED,
                        request=request,
                        user_id=existing.user_id,
                        details={"family_id": str(existing.family_id)},
                    )
    # Revocation + event are committed at this point.

    if revoked_family is not None:
        await deny_family_access(revoked_family)
    if outcome == "stale":
        # Another tab rotated a moment ago; its cookies are already in the jar. Keep them.
        raise Unauthorized("Session was refreshed elsewhere, retry", code="stale_refresh")
    if outcome == "reused":
        raise Unauthorized("Session revoked", code="refresh_reused", clear_auth_cookies=True)
    if outcome != "ok" or rotated is None:
        raise Unauthorized("Session expired", code="invalid_refresh", clear_auth_cookies=True)
    return issue_tokens(rotated.user_id, rotated.family_id, new_refresh)


async def logout(
    request: HTTPConnection, refresh_token: str | None, access_token: str | None
) -> None:
    user_id: uuid.UUID | None = None
    family_ids: set[uuid.UUID] = set()
    if access_token:
        try:
            claims = decode_access_token(access_token)
            user_id = claims.user_id
            family_ids.add(claims.family_id)
            remaining = int((claims.expires_at - datetime.now(UTC)).total_seconds())
            if remaining > 0:
                await get_redis().set(DENYLIST_PREFIX + claims.jti, "1", ex=remaining)
        except Unauthorized:
            pass  # expired/invalid access token: nothing to deny
    if refresh_token:
        async with tenant_session(None, None) as session:
            existing = await tokens.get_by_hash(session, hash_token(refresh_token))
            if existing is not None:
                family_ids.add(existing.family_id)
                user_id = user_id or existing.user_id
            for family_id in family_ids:
                await tokens.revoke_family(session, family_id, RevokedReason.LOGOUT)
            if user_id is not None:
                record_auth_event(session, AuthEventType.LOGOUT, request=request, user_id=user_id)
    for family_id in family_ids:
        await deny_family_access(family_id)
