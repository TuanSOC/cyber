"""Per-organization evidence storage quota (M3 RT8).

Usage is the sum of every evidence row's size, active and archived alike: archived evidence
still occupies retention-locked object storage. The authoritative check runs in the
evidence-insert transaction under the org row lock, so concurrent uploads of one org are
serialized and each one sees the sizes the others committed.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError, NotFound
from app.core.rbac import OrgContext
from app.modules.evidence.models import Evidence
from app.modules.organizations import repository as repo
from app.modules.organizations.models import Organization
from app.modules.organizations.schemas import StorageOut


class StorageQuotaExceeded(AppError):
    status_code = 413
    code = "storage_quota_exceeded"
    message = (
        "This upload would exceed your organization's storage quota. "
        "Archived evidence still counts towards it; ask an administrator for more space."
    )


async def _usage(session: AsyncSession, org_id: uuid.UUID) -> tuple[int, int]:
    """(bytes used, evidence count) of the org (RLS: the session's org)."""
    stmt = select(func.coalesce(func.sum(Evidence.size_bytes), 0), func.count()).where(
        Evidence.organization_id == org_id
    )
    used, count = (await session.execute(stmt)).one()
    return int(used), int(count)


async def _quota(session: AsyncSession, org_id: uuid.UUID) -> int:
    stmt = select(Organization.storage_quota_bytes).where(Organization.id == org_id)
    override = (await session.execute(stmt)).scalar_one_or_none()
    return get_settings().default_storage_quota_bytes if override is None else override


async def get_storage(ctx: OrgContext) -> StorageOut:
    if await repo.get_org(ctx.session, ctx.org_id) is None:
        raise NotFound()
    used, count = await _usage(ctx.session, ctx.org_id)
    return StorageOut(
        used_bytes=used, quota_bytes=await _quota(ctx.session, ctx.org_id), evidence_count=count
    )


async def check_fits(ctx: OrgContext, incoming_bytes: int) -> None:
    """Early, unlocked check (declared Content-Length): fail before reading the body."""
    used, _ = await _usage(ctx.session, ctx.org_id)
    if used + incoming_bytes > await _quota(ctx.session, ctx.org_id):
        raise StorageQuotaExceeded()


async def reserve(ctx: OrgContext, incoming_bytes: int) -> None:
    """Authoritative check: locks the org row until the caller's transaction ends.

    The lock is taken before the usage is summed, so under READ COMMITTED the sum sees
    every upload that committed while this one waited for it. FOR NO KEY UPDATE: uploads
    (and membership changes, case numbering) still serialize on it, but inserts elsewhere in
    the org, whose foreign keys take KEY SHARE on this row, neither wait for it nor can
    deadlock against it.
    """
    stmt = (
        select(Organization.id).where(Organization.id == ctx.org_id).with_for_update(key_share=True)
    )
    await ctx.session.execute(stmt)
    await check_fits(ctx, incoming_bytes)
