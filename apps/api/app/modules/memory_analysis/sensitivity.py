"""Memory sensitivity: TLP:RED by default, released once by an admin (M8 phase 8).

A memory image holds whatever the machine held (passwords, hashes, tokens, keys, mail), so:

- `apply_memory_default(session, org_id, evidence_id, actor_id) -> bool` (frozen signature,
  called by the `kind=memory` upload and by every memory job request, in the caller's
  transaction) inserts `memory_sensitivity` (`restricted`) when the evidence has no row and
  upserts its M6 share policy to `ai_excluded = ti_excluded = true` (it only ever sets flags,
  never loosens). It audits `memory.sensitivity_defaulted` itself (callers do not) and returns
  True when it changed something. Idempotent: a later call, or a `released` row, changes
  nothing.
- `release` (`POST …/memory-sensitivity/release`, `org.update`): `restricted -> released`
  once, acknowledged, with a reason, audited `memory.sensitivity_released`. It does not clear
  the share-policy flags: the analyst does that through the M6 `PUT …/share-policy` route,
  which refuses to clear them while the evidence is restricted (`evidence/share_policy.py`).
  The `memory_sensitivity_guard` trigger (0016) refuses any other transition.

Both write paths first take the evidence's share-policy lock (`lock_evidence_for_policy`, FOR
NO KEY UPDATE), so a concurrent share-policy PUT reads the sensitivity row only after this
transaction ends and can never clear the flags the default has just set.
"""

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.errors import NotFound
from app.core.rbac import OrgContext
from app.modules.analysis.models import AnalysisJob
from app.modules.audit import service as audit
from app.modules.evidence import repository as evidence_repo
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis.errors import AcknowledgementRequired, MemorySensitivityReleased
from app.modules.memory_analysis.models import MemorySensitivity, SensitivityState
from app.modules.memory_analysis.schemas import MemorySensitivityOut, ReleaseIn
from app.modules.users.models import User

RESTRICTED = SensitivityState.RESTRICTED.value
RELEASED = SensitivityState.RELEASED.value
_EXCLUDED = {"ai_excluded": True, "ti_excluded": True}


async def apply_memory_default(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID, actor_id: uuid.UUID
) -> bool:
    await evidence_repo.lock_evidence_for_policy(session, org_id, evidence_id)
    m = MemorySensitivity
    inserted = await session.scalar(
        insert(m)
        .values(
            evidence_id=evidence_id,
            organization_id=org_id,
            state=RESTRICTED,
            defaulted_by=actor_id,
        )
        .on_conflict_do_nothing(index_elements=[m.evidence_id])
        .returning(m.evidence_id)
    )
    if inserted is None:  # already restricted or released: nothing changes
        return False

    p = EvidenceSharePolicy
    before = (
        await session.execute(
            select(p.ai_excluded, p.ti_excluded).where(
                p.organization_id == org_id, p.evidence_id == evidence_id
            )
        )
    ).one_or_none()
    was = {
        "ai_excluded": bool(before.ai_excluded) if before is not None else False,
        "ti_excluded": bool(before.ti_excluded) if before is not None else False,
    }
    if was != _EXCLUDED:
        await session.execute(
            insert(p)
            .values(
                evidence_id=evidence_id, organization_id=org_id, updated_by=actor_id, **_EXCLUDED
            )
            .on_conflict_do_update(
                index_elements=[p.evidence_id],
                set_={**_EXCLUDED, "updated_by": actor_id, "updated_at": func.now()},
            )
        )
    audit.record(
        session,
        action="memory.sensitivity_defaulted",
        org_id=org_id,
        actor_id=actor_id,
        target_type="evidence",
        target_id=evidence_id,
        details={"state": RESTRICTED, "share_policy": {"from": was, "to": dict(_EXCLUDED)}},
    )
    await session.flush()
    return True


async def state_of(
    session: AsyncSession, org_id: uuid.UUID, evidence_ids: list[uuid.UUID]
) -> dict[uuid.UUID, str]:
    """`{evidence_id: "restricted" | "released"}` for the given evidence that have a row."""
    return await evidence_repo.memory_sensitivity_states(session, org_id, evidence_ids)


async def restricted_job_ids(
    session: AsyncSession, org_id: uuid.UUID, job_ids: Iterable[uuid.UUID]
) -> frozenset[uuid.UUID]:
    """The given jobs whose evidence is restricted memory (any analyzer: every result of a
    memory image is memory-derived), as `reports.snapshot_sections.memory_guard` decides."""
    ids = sorted(set(job_ids))
    if not ids:
        return frozenset()
    m = MemorySensitivity
    found = await session.scalars(
        select(AnalysisJob.id)
        .join(m, m.evidence_id == AnalysisJob.evidence_id)
        .where(
            AnalysisJob.organization_id == org_id,
            m.organization_id == org_id,
            m.state == RESTRICTED,
            AnalysisJob.id.in_(ids),
        )
    )
    return frozenset(found)


async def is_restricted(session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID) -> bool:
    return (await state_of(session, org_id, [evidence_id])).get(evidence_id) == RESTRICTED


async def _row(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID, *, for_update: bool = False
) -> MemorySensitivity | None:
    stmt = select(MemorySensitivity).where(
        MemorySensitivity.organization_id == org_id,
        MemorySensitivity.evidence_id == evidence_id,
    )
    if for_update:
        stmt = stmt.with_for_update()
    found: MemorySensitivity | None = await session.scalar(
        stmt.execution_options(populate_existing=True)
    )
    return found


async def _out(
    session: AsyncSession, evidence_id: uuid.UUID, row: MemorySensitivity | None
) -> MemorySensitivityOut:
    if row is None:
        return MemorySensitivityOut(evidence_id=evidence_id, state="none")
    name = None
    if row.released_by is not None:
        name = await session.scalar(select(User.display_name).where(User.id == row.released_by))
    return MemorySensitivityOut(
        evidence_id=evidence_id,
        state="released" if row.state == RELEASED else "restricted",
        defaulted_at=row.defaulted_at,
        released_at=row.released_at,
        released_by_name=name,
        release_reason=row.release_reason,
    )


async def get(ctx: OrgContext, evidence_id: uuid.UUID) -> MemorySensitivityOut:
    if await evidence_repo.get_row(ctx.session, ctx.org_id, evidence_id) is None:
        raise NotFound()
    return await _out(ctx.session, evidence_id, await _row(ctx.session, ctx.org_id, evidence_id))


async def release(
    ctx: OrgContext, evidence_id: uuid.UUID, body: ReleaseIn, request: HTTPConnection
) -> MemorySensitivityOut:
    """Once per evidence. 404 when the evidence is unknown or was never marked (nothing to
    release); `422 acknowledgement_required`; `409 memory_sensitivity_released`."""
    evidence = await evidence_repo.lock_evidence_for_policy(ctx.session, ctx.org_id, evidence_id)
    if evidence is None:
        raise NotFound()
    if not body.acknowledge:
        raise AcknowledgementRequired()
    row = await _row(ctx.session, ctx.org_id, evidence_id, for_update=True)
    if row is None:
        raise NotFound()
    if row.state != RESTRICTED:
        raise MemorySensitivityReleased()
    reason = body.reason.strip() or body.reason
    row.state = RELEASED
    row.released_by = ctx.user.id
    row.released_at = datetime.now(UTC)
    row.release_reason = reason
    audit.record(
        ctx.session,
        action="memory.sensitivity_released",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="evidence",
        target_id=evidence_id,
        details={"from": RESTRICTED, "to": RELEASED, "reason": reason, "acknowledged": True},
        request=request,
    )
    await ctx.session.flush()
    out = await _out(ctx.session, evidence_id, row)
    await ctx.session.commit()
    return out
