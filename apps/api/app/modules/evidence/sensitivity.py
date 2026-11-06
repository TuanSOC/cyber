"""Evidence-level sensitivity: TLP:RED by default for memory images, disk images and files
derived from them (M9 phase 1, RT2; implemented).

M8's `memory_sensitivity` table is evidence-scoped already, so M9 does **not** rename it: 0017
adds a `source` column (`memory` / `disk` / `derived`) and this module generalizes M8's
service. M8's routes (`/memory-sensitivity`), codes (`memory_sensitivity_*`) and audit actions
(`memory.*`) are unchanged and not deprecated; `memory_analysis.sensitivity.apply_memory_default`
is a one-line wrapper over `apply_restricted_default(..., source="memory")`.

- `apply_restricted_default(session, org_id, evidence_id, actor_id, source) -> bool` (frozen
  signature; the caller's transaction): M8's body with the source written. It inserts the row
  (`restricted`) when the evidence has none and upserts its M6 share policy to
  `ai_excluded = ti_excluded = true` (never loosening). Audited `memory.sensitivity_defaulted`
  (memory; details unchanged from M8) or `disk.sensitivity_defaulted` (disk / derived; details
  carry `source`). Idempotent: an existing row (any source, any state) changes nothing.
- `get` / `release` back the generic routes `GET /evidence/{id}/sensitivity` and
  `POST …/sensitivity/release`: the same rules as M8's (`org.update`, acknowledged, reasoned,
  once), with the code and audit action chosen by the row's source. The batch arm (`job_id`:
  every restricted segment of a disk job, RT20) answers 501 until phase 9.

Both write paths first take the evidence's share-policy lock (`lock_evidence_for_policy`), as
in M8, so a concurrent share-policy PUT never clears flags the default has just set.
"""

import uuid
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.errors import AppError, NotFound
from app.core.rbac import OrgContext
from app.core.stubs import not_implemented
from app.modules.audit import service as audit
from app.modules.evidence import repository as evidence_repo
from app.modules.evidence.schemas import EvidenceSensitivityDetailOut, SensitivityReleaseIn
from app.modules.evidence.sensitivity_errors import (
    EvidenceSensitivityReleased,
    EvidenceSensitivityRestricted,
)
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis.errors import (
    AcknowledgementRequired,
    MemorySensitivityReleased,
    MemorySensitivityRestricted,
)
from app.modules.memory_analysis.models import (
    MemorySensitivity,
    SensitivitySource,
    SensitivityState,
)
from app.modules.users.models import User

Source = Literal["memory", "disk", "derived"]
RESTRICTED = SensitivityState.RESTRICTED.value
RELEASED = SensitivityState.RELEASED.value
_EXCLUDED = {"ai_excluded": True, "ti_excluded": True}


def _action(source: str, verb: str) -> str:
    """`memory.sensitivity_<verb>` for memory evidence (M8's actions), else `disk.…`."""
    prefix = "memory" if source == SensitivitySource.MEMORY.value else "disk"
    return f"{prefix}.sensitivity_{verb}"


def restricted_error(source: str) -> AppError:
    """The share-policy guard's answer for restricted evidence of this source."""
    if source == SensitivitySource.MEMORY.value:
        return MemorySensitivityRestricted()
    return EvidenceSensitivityRestricted()


def _released_error(source: str) -> AppError:
    if source == SensitivitySource.MEMORY.value:
        return MemorySensitivityReleased()
    return EvidenceSensitivityReleased()


async def apply_restricted_default(
    session: AsyncSession,
    org_id: uuid.UUID,
    evidence_id: uuid.UUID,
    actor_id: uuid.UUID,
    source: Source,
) -> bool:
    source = SensitivitySource(source).value  # type: ignore[assignment]
    await evidence_repo.lock_evidence_for_policy(session, org_id, evidence_id)
    m = MemorySensitivity
    inserted = await session.scalar(
        insert(m)
        .values(
            evidence_id=evidence_id,
            organization_id=org_id,
            state=RESTRICTED,
            defaulted_by=actor_id,
            source=source,
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
    details: dict[str, object] = {
        "state": RESTRICTED,
        "share_policy": {"from": was, "to": dict(_EXCLUDED)},
    }
    if source != SensitivitySource.MEMORY.value:
        details["source"] = source
    audit.record(
        session,
        action=_action(source, "defaulted"),
        org_id=org_id,
        actor_id=actor_id,
        target_type="evidence",
        target_id=evidence_id,
        details=details,
    )
    await session.flush()
    return True


async def restriction_of(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID
) -> str | None:
    """The source of the evidence's restriction, or None when it is not restricted."""
    found = (await evidence_repo.sensitivity_states(session, org_id, [evidence_id])).get(
        evidence_id
    )
    return found[1] if found is not None and found[0] == RESTRICTED else None


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
) -> EvidenceSensitivityDetailOut:
    if row is None:
        return EvidenceSensitivityDetailOut(evidence_id=evidence_id, state="none", source=None)
    name = None
    if row.released_by is not None:
        name = await session.scalar(select(User.display_name).where(User.id == row.released_by))
    return EvidenceSensitivityDetailOut.model_validate(
        {
            "evidence_id": evidence_id,
            "state": "released" if row.state == RELEASED else "restricted",
            "source": row.source,
            "defaulted_at": row.defaulted_at,
            "released_at": row.released_at,
            "released_by_name": name,
            "release_reason": row.release_reason,
        }
    )


async def get(ctx: OrgContext, evidence_id: uuid.UUID) -> EvidenceSensitivityDetailOut:
    if await evidence_repo.get_row(ctx.session, ctx.org_id, evidence_id) is None:
        raise NotFound()
    return await _out(ctx.session, evidence_id, await _row(ctx.session, ctx.org_id, evidence_id))


async def release(
    ctx: OrgContext,
    evidence_id: uuid.UUID,
    body: SensitivityReleaseIn,
    request: HTTPConnection,
) -> EvidenceSensitivityDetailOut:
    """Once per evidence. 404 when the evidence is unknown or was never marked; `422
    acknowledgement_required`; 409 `memory_sensitivity_released` (memory) or
    `evidence_sensitivity_released` (disk / derived). With `job_id`: 501 until phase 9."""
    if body.job_id is not None:
        raise not_implemented()  # the batch release of a disk job's segments (phase 9, RT20)
    evidence = await evidence_repo.lock_evidence_for_policy(ctx.session, ctx.org_id, evidence_id)
    if evidence is None:
        raise NotFound()
    if not body.acknowledge:
        raise AcknowledgementRequired()
    row = await _row(ctx.session, ctx.org_id, evidence_id, for_update=True)
    if row is None:
        raise NotFound()
    if row.state != RESTRICTED:
        raise _released_error(row.source)
    reason = body.reason.strip() or body.reason
    row.state = RELEASED
    row.released_by = ctx.user.id
    row.released_at = datetime.now(UTC)
    row.release_reason = reason
    details: dict[str, object] = {
        "from": RESTRICTED,
        "to": RELEASED,
        "reason": reason,
        "acknowledged": True,
    }
    if row.source != SensitivitySource.MEMORY.value:
        details["source"] = row.source
    audit.record(
        ctx.session,
        action=_action(row.source, "released"),
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="evidence",
        target_id=evidence_id,
        details=details,
        request=request,
    )
    await ctx.session.flush()
    out = await _out(ctx.session, evidence_id, row)
    await ctx.session.commit()
    return out
