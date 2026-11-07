"""Database access for invitations (M11 phase 3)."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.invitations.models import (
    InvitationIndex,
    InvitationStatus,
    OrgInvitation,
)
from app.modules.users.models import User


def compute_status(inv: OrgInvitation, now: datetime) -> InvitationStatus:
    if inv.accepted_at is not None:
        return InvitationStatus.ACCEPTED
    if inv.revoked_at is not None:
        return InvitationStatus.REVOKED
    if inv.expires_at <= now:
        return InvitationStatus.EXPIRED
    return InvitationStatus.PENDING


async def get_invitation(
    session: AsyncSession,
    org_id: uuid.UUID,
    invitation_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> OrgInvitation | None:
    stmt = select(OrgInvitation).where(
        OrgInvitation.organization_id == org_id,
        OrgInvitation.id == invitation_id,
    )
    if for_update:
        stmt = stmt.with_for_update()
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_invitations(
    session: AsyncSession,
    org_id: uuid.UUID,
    page: PageParams,
) -> tuple[list[tuple[OrgInvitation, str]], int]:
    """Returns list of (OrgInvitation, inviter_display_name) and total count."""
    count_stmt = select(func.count(OrgInvitation.id)).where(
        OrgInvitation.organization_id == org_id
    )
    total = (await session.execute(count_stmt)).scalar() or 0

    stmt = (
        select(OrgInvitation, User.display_name)
        .join(User, OrgInvitation.invited_by == User.id)
        .where(OrgInvitation.organization_id == org_id)
        .order_by(OrgInvitation.created_at.desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = (await session.execute(stmt)).all()
    return [(row[0], row[1]) for row in rows], total


async def revoke_pending_by_email(
    session: AsyncSession,
    org_id: uuid.UUID,
    email: str,
    revoked_by: uuid.UUID,
) -> int:
    """Revoke any existing pending invitation for (org_id, email) in the same transaction."""
    stmt = (
        update(OrgInvitation)
        .where(
            OrgInvitation.organization_id == org_id,
            OrgInvitation.email == email,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
            OrgInvitation.expires_at > func.now(),
        )
        .values(
            revoked_at=func.now(),
            revoked_by=revoked_by,
        )
    )
    res = await session.execute(stmt)
    return res.rowcount or 0


async def lookup_index(
    session: AsyncSession,
    token_hash: str,
) -> InvitationIndex | None:
    stmt = select(InvitationIndex).where(
        InvitationIndex.token_hash == token_hash,
        InvitationIndex.expires_at > func.now(),
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def consume_invitation_atomically(
    session: AsyncSession,
    org_id: uuid.UUID,
    token_hash: str,
    accepted_by: uuid.UUID,
) -> OrgInvitation | None:
    stmt = (
        update(OrgInvitation)
        .where(
            OrgInvitation.organization_id == org_id,
            OrgInvitation.token_hash == token_hash,
            OrgInvitation.accepted_at.is_(None),
            OrgInvitation.revoked_at.is_(None),
            OrgInvitation.expires_at > func.now(),
        )
        .values(
            accepted_at=func.now(),
            accepted_by=accepted_by,
        )
        .returning(OrgInvitation)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()

