"""The evidence share policy (M6): per-evidence "do not send to AI / TI" flags.

The flags live in `evidence_share_policies` (one row per evidence, upserted), so the
evidence row and its `evidence_immutable` trigger are never touched. Turning a flag on
needs `evidence.write` (the route); turning one off also needs `integrations.manage`.
Enforcement is `investigations.policy.load_policy` at the AI / TI choke points.

M8 (phase 8): while the evidence is a `restricted` memory image, a PUT that turns a flag off
answers `409 memory_sensitivity_restricted` (an admin releases it first,
`memory_analysis/sensitivity.release`); turning flags on is always allowed. The sensitivity
row is read after the evidence lock, which the memory default also takes.
"""

import uuid

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from starlette.requests import HTTPConnection

from app.core.errors import Forbidden, NotFound
from app.core.rbac import ROLE_PERMISSIONS, OrgContext, Permission
from app.modules.audit import service as audit
from app.modules.evidence import repository as repo
from app.modules.evidence.service import ensure_open_investigation
from app.modules.investigations import policy
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.investigations.schemas import (
    EvidenceSharePolicyIn,
    EvidenceSharePolicyOut,
    SharePolicyOut,
)
from app.modules.memory_analysis import sensitivity
from app.modules.memory_analysis.errors import MemorySensitivityRestricted


async def _out(
    ctx: OrgContext, evidence_id: uuid.UUID, row: EvidenceSharePolicy | None
) -> EvidenceSharePolicyOut:
    effective = await policy.load_policy(ctx.session, ctx.org_id, evidence_ids=(evidence_id,))
    return EvidenceSharePolicyOut(
        evidence_id=evidence_id,
        ai_excluded=row.ai_excluded if row else False,
        ti_excluded=row.ti_excluded if row else False,
        effective=SharePolicyOut(
            ai_blocked=effective.ai_blocked,
            ti_blocked=effective.ti_blocked,
            reasons=effective.reasons,
        ),
        updated_by=row.updated_by if row else None,
        updated_at=row.updated_at if row else None,
    )


async def get_policy(ctx: OrgContext, evidence_id: uuid.UUID) -> EvidenceSharePolicyOut:
    if await repo.get_row(ctx.session, ctx.org_id, evidence_id) is None:
        raise NotFound()
    row = await repo.get_share_policy(ctx.session, ctx.org_id, evidence_id)
    return await _out(ctx, evidence_id, row)


async def put_policy(
    ctx: OrgContext,
    evidence_id: uuid.UUID,
    data: EvidenceSharePolicyIn,
    request: HTTPConnection,
) -> EvidenceSharePolicyOut:
    evidence = await repo.lock_evidence_for_policy(ctx.session, ctx.org_id, evidence_id)
    if evidence is None:
        raise NotFound()
    await ensure_open_investigation(ctx, evidence.investigation_id)
    current = await repo.get_share_policy(ctx.session, ctx.org_id, evidence_id)
    before = {
        "ai_excluded": current.ai_excluded if current else False,
        "ti_excluded": current.ti_excluded if current else False,
    }
    after = {"ai_excluded": data.ai_excluded, "ti_excluded": data.ti_excluded}
    turned_off = any(before[flag] and not after[flag] for flag in before)
    if turned_off and Permission.INTEGRATIONS_MANAGE not in ROLE_PERMISSIONS[ctx.role]:
        raise Forbidden("Turning a share-policy exclusion off needs integrations.manage")
    if turned_off and await sensitivity.is_restricted(ctx.session, ctx.org_id, evidence_id):
        raise MemorySensitivityRestricted()
    if before == after:  # nothing changes: no write, no audit row
        return await _out(ctx, evidence_id, current)

    p = EvidenceSharePolicy
    stmt = insert(p).values(
        evidence_id=evidence_id,
        organization_id=ctx.org_id,
        updated_by=ctx.user.id,
        **after,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[p.evidence_id],
        set_={**after, "updated_by": ctx.user.id, "updated_at": func.now()},
    )
    await ctx.session.execute(stmt)
    audit.record(
        ctx.session,
        action="evidence.share_policy_updated",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="evidence",
        target_id=evidence_id,
        details={"from": before, "to": after},
        request=request,
    )
    await ctx.session.flush()
    # A fresh read of the upserted row (an earlier read may sit in the identity map).
    row = await repo.get_share_policy(ctx.session, ctx.org_id, evidence_id, fresh=True)
    out = await _out(ctx, evidence_id, row)
    await ctx.session.commit()
    return out
