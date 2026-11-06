import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import REFRESH_TOKEN_TTL, SESSION_MAX_AGE
from app.modules.auth.models import RefreshToken, RevokedReason


@dataclass(frozen=True)
class Rotated:
    user_id: uuid.UUID
    family_id: uuid.UUID


async def lock_family(session: AsyncSession, family_id: uuid.UUID) -> None:
    """Serialize rotation and revocation of one family (transaction-scoped advisory lock).

    Without it, a revocation running concurrently with a rotation could miss the successor
    row the rotation is about to insert, and the session would survive logout.
    """
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:family, 0))"),
        {"family": str(family_id)},
    )


async def create(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    family_id: uuid.UUID,
    token_hash: str,
    ip: str | None,
    user_agent: str | None,
    token_id: uuid.UUID | None = None,
    family_started_at: datetime | None = None,
    not_after: datetime | None = None,
) -> RefreshToken:
    now = datetime.now(UTC)
    expires_at = now + REFRESH_TOKEN_TTL
    if family_started_at is not None:
        # Rotation extends the sliding window, never beyond the absolute session lifetime.
        expires_at = min(expires_at, family_started_at + SESSION_MAX_AGE)
    if not_after is not None:
        # M11: never beyond the session row's own expiry (an SSO session's 12 h cap).
        expires_at = min(expires_at, not_after)
    token = RefreshToken(
        id=token_id or uuid.uuid4(),
        user_id=user_id,
        family_id=family_id,
        token_hash=token_hash,
        expires_at=expires_at,
        ip=ip,
        user_agent=user_agent,
    )
    session.add(token)
    return token


async def get_by_hash(session: AsyncSession, token_hash: str) -> RefreshToken | None:
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    return (await session.execute(stmt)).scalar_one_or_none()


async def family_started_at(session: AsyncSession, family_id: uuid.UUID) -> datetime:
    stmt = select(func.min(RefreshToken.created_at)).where(RefreshToken.family_id == family_id)
    return (await session.execute(stmt)).scalar_one()


async def rotate(session: AsyncSession, token_hash: str, successor_id: uuid.UUID) -> Rotated | None:
    """Atomically retire a live token. Exactly one concurrent caller can win; others get None.

    replaced_by points at a row inserted later in the same transaction (deferred FK).
    """
    existing = await get_by_hash(session, token_hash)
    if existing is None:
        return None
    await lock_family(session, existing.family_id)
    stmt = (
        update(RefreshToken)
        .where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > func.now(),
        )
        .values(
            revoked_at=func.now(), revoked_reason=RevokedReason.ROTATED, replaced_by=successor_id
        )
        .returning(RefreshToken.user_id, RefreshToken.family_id)
    )
    row = (await session.execute(stmt)).one_or_none()
    return Rotated(user_id=row.user_id, family_id=row.family_id) if row else None


async def abandon_rotation(session: AsyncSession, token_hash: str, reason: RevokedReason) -> None:
    """Undo the successor pointer of a token whose successor will not be created."""
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .values(replaced_by=None, revoked_reason=reason)
    )


async def revoke_family(session: AsyncSession, family_id: uuid.UUID, reason: RevokedReason) -> None:
    await lock_family(session, family_id)
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=func.now(), revoked_reason=reason)
    )
