"""User sessions: one `user_sessions` row per refresh family (M11 phase 1, FROZEN, implemented).

The row's id IS the refresh family id and the access token's `sid`. It carries what the
access token re-states at every refresh: `amr` (`pwd`, `otp`, `recovery`, `sso`), the SSO org
(`sso_org_id`) and the absolute expiry (30 days, or `SSO_SESSION_MAX_AGE_H` for SSO). Every
time column is written as the DB `now()` (RT21).

Two calling styles:
- in the caller's transaction (`session` first): `create`, `get_live`, `touch`, `revoke_in`,
  `mark_step_up`, `add_amr`. A caller of `revoke_in` denylists the family's access tokens
  with `deny_family_access` after its commit;
- self-contained (own transaction, then the denylist): `revoke`, `revoke_all` (RT17), used
  by password reset (phase 4), MFA changes (phase 5), operator scripts and the session API.
"""

import logging
import uuid
from collections.abc import Sequence
from datetime import timedelta

from redis.exceptions import RedisError
from sqlalchemy import Text, cast, func, select, update
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.client_ip import client_ip, user_agent
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.deps import FAMILY_DENYLIST_PREFIX
from app.core.security import ACCESS_TOKEN_TTL, AMR_VALUES, SESSION_MAX_AGE
from app.core.tenancy import tenant_session
from app.modules.auth import repository as tokens
from app.modules.auth.models import RefreshToken, RevokedReason
from app.modules.identity.models import Amr, SessionMethod, UserSession

log = logging.getLogger(__name__)

TOUCH_INTERVAL = timedelta(minutes=5)
MFA_AMR = frozenset({Amr.OTP.value, Amr.RECOVERY.value})


def session_cap(method: SessionMethod | str) -> timedelta:
    """The absolute lifetime of a session of this method."""
    if SessionMethod(method) is SessionMethod.SSO:
        return timedelta(hours=get_settings().sso_session_max_age_h)
    return SESSION_MAX_AGE


async def create(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    method: SessionMethod | str,
    amr: Sequence[str],
    sso_org_id: uuid.UUID | None,
    request: HTTPConnection,
    family_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Insert the row of a new refresh family; returns its id (the family id)."""
    method = SessionMethod(method)
    values = list(dict.fromkeys(amr))
    if not values or not set(values) <= AMR_VALUES:
        raise ValueError("invalid amr")
    if (method is SessionMethod.SSO) != (sso_org_id is not None):
        raise ValueError("an SSO session needs its org, a password session none")
    row_id = family_id or uuid.uuid4()
    mfa = bool(set(values) & MFA_AMR)
    session.add(
        UserSession(
            id=row_id,
            user_id=user_id,
            method=method.value,
            amr=values,
            mfa_at=func.now() if mfa else None,
            sso_org_id=sso_org_id,
            ip=client_ip(request),
            user_agent=user_agent(request),
            expires_at=func.now() + session_cap(method),
        )
    )
    return row_id


async def get_live(session: AsyncSession, family_id: uuid.UUID) -> UserSession | None:
    """The row if it is neither revoked nor expired (DB time)."""
    stmt = select(UserSession).where(
        UserSession.id == family_id,
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > func.now(),
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def touch(session: AsyncSession, family_id: uuid.UUID) -> None:
    """`last_seen_at = now()`, at most once per `TOUCH_INTERVAL`."""
    await session.execute(
        update(UserSession)
        .where(
            UserSession.id == family_id,
            UserSession.last_seen_at < func.now() - TOUCH_INTERVAL,
        )
        .values(last_seen_at=func.now())
    )


async def revoke_in(session: AsyncSession, family_id: uuid.UUID, reason: RevokedReason) -> None:
    """Revoke the row and every refresh token of the family in the caller's transaction."""
    await tokens.revoke_family(session, family_id, reason)
    await session.execute(
        update(UserSession)
        .where(UserSession.id == family_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=func.now(), revoked_reason=reason)
    )


async def deny_family_access(family_id: uuid.UUID) -> None:
    """Kill access tokens of a revoked family for the rest of their lifetime."""
    try:
        await get_redis().set(
            FAMILY_DENYLIST_PREFIX + str(family_id), "1", ex=int(ACCESS_TOKEN_TTL.total_seconds())
        )
    except RedisError:
        # Refresh tokens are already revoked in the DB; access tokens expire within 15 min.
        log.error("could not denylist access tokens of family %s", family_id)


async def revoke(
    family_id: uuid.UUID, reason: RevokedReason, *, user_id: uuid.UUID | None = None
) -> bool:
    """Revoke one live session (of `user_id`, when given) and denylist it after the commit.
    False when no such live session exists."""
    async with tenant_session(None, user_id) as session:
        stmt = select(UserSession.id).where(
            UserSession.id == family_id, UserSession.revoked_at.is_(None)
        )
        if user_id is not None:
            stmt = stmt.where(UserSession.user_id == user_id)
        found = (await session.execute(stmt)).scalar_one_or_none()
        if found is None:
            return False
        await revoke_in(session, family_id, reason)
    await deny_family_access(family_id)
    return True


async def revoke_all(
    user_id: uuid.UUID, *, reason: RevokedReason, keep: uuid.UUID | None = None
) -> list[uuid.UUID]:
    """Revoke every live session of a user except `keep` (RT17); returns the revoked ids.
    Refresh families without a row (pre-0019 leftovers) are revoked too."""
    async with tenant_session(None, user_id) as session:
        rows = select(UserSession.id).where(
            UserSession.user_id == user_id, UserSession.revoked_at.is_(None)
        )
        families = set((await session.execute(rows)).scalars())
        live_tokens = select(RefreshToken.family_id).where(
            RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
        )
        families |= set((await session.execute(live_tokens)).scalars())
        if keep is not None:
            families.discard(keep)
        for family_id in sorted(families):
            await revoke_in(session, family_id, reason)
    for family_id in families:
        await deny_family_access(family_id)
    return sorted(families)


async def mark_step_up(session: AsyncSession, family_id: uuid.UUID) -> None:
    """`step_up_at = now()` (DB time, RT21); `core.stepup` compares it in SQL."""
    await session.execute(
        update(UserSession)
        .where(UserSession.id == family_id, UserSession.revoked_at.is_(None))
        .values(step_up_at=func.now())
    )


async def add_amr(session: AsyncSession, family_id: uuid.UUID, value: str) -> list[str]:
    """Add a method to the live session (`otp` / `recovery` also set `mfa_at = now()`) and
    return the new `amr`. The caller re-issues the access token with it
    (`auth.sessions.reissue_access` + `core.cookies.set_access_cookie`)."""
    if value not in AMR_VALUES:
        raise ValueError("invalid amr")
    values: dict[str, object] = {
        "amr": func.array_append(
            func.array_remove(UserSession.amr, cast(value, Text)), cast(value, Text)
        )
    }
    if value in MFA_AMR:
        values["mfa_at"] = func.now()
    stmt = (
        update(UserSession)
        .where(UserSession.id == family_id, UserSession.revoked_at.is_(None))
        .values(**values)
        .returning(cast(UserSession.amr, ARRAY(Text)))
    )
    amr = (await session.execute(stmt)).scalar_one_or_none()
    if amr is None:
        raise LookupError("no live session")
    return list(amr)
