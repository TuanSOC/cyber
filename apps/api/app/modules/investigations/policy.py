"""The share policy of cases and evidence (M6 phase 1, FROZEN; RT20).

A case carries `tlp`, `ai_excluded` and `ti_excluded`; an evidence item may have an
`evidence_share_policies` row with the same two flags. TLP:RED implies both exclusions
(computed, never stored). Enforcement goes through `load_policy` at the service choke
points, never the routers:

- `ai/service_runs` (run creation and preview) -> `409 policy_blocked` + `reason`;
- the incident / case builder skips AI-excluded evidence (`context_stats.policy_excluded`);
- `threat_intel/service_runs` for job-scope enrichments -> `409 policy_blocked`;
- the analyst worker before every provider request, the enrich worker before each slice
  (`failed` / `policy_blocked`, no provider call).

Manual TI lookups carry no case scope and are not checked (documented residual).

Resolution: the given jobs are mapped to their evidence, the evidence (given + of the jobs)
to their cases, and the given investigation joins them. Case flags and TLP:RED of any of
those cases block; the share-policy rows of the *targeted* evidence block too. With an
`investigation_id`, every excluded evidence item of that case is listed in
`excluded_evidence_ids` (AI) / `ti_excluded_evidence_ids` (TI) without blocking: the
builders skip those items. Unknown ids are ignored here (the callers 404 on them).
"""

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cyberlab_jobs.report import TLP, TLP_ORDER
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import Conflict
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import EvidenceSharePolicy, Investigation

CASE_AI_EXCLUDED = "case_ai_excluded"
CASE_TI_EXCLUDED = "case_ti_excluded"
EVIDENCE_AI_EXCLUDED = "evidence_ai_excluded"
EVIDENCE_TI_EXCLUDED = "evidence_ti_excluded"
TLP_RED = "tlp_red"
# Stable order of `reasons` (the first applicable one is the `reason` of a 409).
REASONS = (TLP_RED, CASE_AI_EXCLUDED, CASE_TI_EXCLUDED, EVIDENCE_AI_EXCLUDED, EVIDENCE_TI_EXCLUDED)
_ORDER = {reason: i for i, reason in enumerate(REASONS)}


@dataclass(frozen=True)
class SharePolicy:
    ai_blocked: bool = False
    ti_blocked: bool = False
    # Every reason that applies (stable order: tlp_red first), across both domains.
    reasons: list[str] = field(default_factory=list)
    # Evidence of the investigation scope excluded from AI (skipped by the builders).
    excluded_evidence_ids: frozenset[uuid.UUID] = frozenset()
    # The same for threat intel.
    ti_excluded_evidence_ids: frozenset[uuid.UUID] = frozenset()
    ai_reasons: list[str] = field(default_factory=list)
    ti_reasons: list[str] = field(default_factory=list)

    @property
    def ai_reason(self) -> str | None:
        return self.ai_reasons[0] if self.ai_reasons else None

    @property
    def ti_reason(self) -> str | None:
        return self.ti_reasons[0] if self.ti_reasons else None


ALLOW_ALL = SharePolicy()


class PolicyBlocked(Conflict):
    """`409 policy_blocked` with `reason` (`case_ai_excluded`, `evidence_ai_excluded`,
    `tlp_red`, `case_ti_excluded`, `evidence_ti_excluded`) in the error body."""

    code = "policy_blocked"
    message = "The share policy of this case or evidence does not allow this"

    def __init__(self, code: str = "policy_blocked", reason: str = TLP_RED) -> None:
        super().__init__(code=code, extra={"reason": reason})
        self.reason = reason


def tlp_at_least(a: str | TLP, b: str | TLP) -> bool:
    """True when `a` is at least as restrictive as `b` (TLP 2.0 order)."""
    return TLP_ORDER[TLP(a)] >= TLP_ORDER[TLP(b)]


def is_downgrade(new: str | TLP, current: str | TLP) -> bool:
    return not tlp_at_least(new, current)


def _sorted(reasons: Iterable[str]) -> list[str]:
    return sorted(set(reasons), key=lambda r: _ORDER.get(r, len(_ORDER)))


def case_policy(tlp: str, ai_excluded: bool, ti_excluded: bool) -> SharePolicy:
    """The case-level part only (no evidence rows): what `InvestigationOut.share_policy`
    shows."""
    ai: list[str] = []
    ti: list[str] = []
    if tlp == TLP.RED:
        ai.append(TLP_RED)
        ti.append(TLP_RED)
    if ai_excluded:
        ai.append(CASE_AI_EXCLUDED)
    if ti_excluded:
        ti.append(CASE_TI_EXCLUDED)
    return SharePolicy(
        ai_blocked=bool(ai),
        ti_blocked=bool(ti),
        reasons=_sorted([*ai, *ti]),
        ai_reasons=_sorted(ai),
        ti_reasons=_sorted(ti),
    )


async def load_policy(
    session: AsyncSession,
    org_id: uuid.UUID,
    *,
    investigation_id: uuid.UUID | None = None,
    job_ids: Sequence[uuid.UUID] = (),
    evidence_ids: Sequence[uuid.UUID] = (),
) -> SharePolicy:
    """Resolve the policy in the caller's session (tenant or worker session; RLS applies and
    every query also filters on the org)."""
    targeted: set[uuid.UUID] = set(evidence_ids)
    if job_ids:
        job_evidence = await session.scalars(
            select(AnalysisJob.evidence_id).where(
                AnalysisJob.organization_id == org_id, AnalysisJob.id.in_(list(job_ids))
            )
        )
        targeted.update(job_evidence)
    cases: set[uuid.UUID] = {investigation_id} if investigation_id is not None else set()
    if targeted:
        evidence_cases = await session.scalars(
            select(Evidence.investigation_id).where(
                Evidence.organization_id == org_id, Evidence.id.in_(list(targeted))
            )
        )
        cases.update(evidence_cases)
    if not cases and not targeted:
        return ALLOW_ALL

    ai: list[str] = []
    ti: list[str] = []
    if cases:
        flags = await session.execute(
            select(Investigation.tlp, Investigation.ai_excluded, Investigation.ti_excluded).where(
                Investigation.organization_id == org_id, Investigation.id.in_(list(cases))
            )
        )
        for tlp, ai_excluded, ti_excluded in flags.all():
            case = case_policy(tlp, ai_excluded, ti_excluded)
            ai += case.ai_reasons
            ti += case.ti_reasons

    p = EvidenceSharePolicy
    if targeted:
        targeted_rows = await session.execute(
            select(p.ai_excluded, p.ti_excluded).where(
                p.organization_id == org_id, p.evidence_id.in_(list(targeted))
            )
        )
        for ai_excluded, ti_excluded in targeted_rows.all():
            if ai_excluded:
                ai.append(EVIDENCE_AI_EXCLUDED)
            if ti_excluded:
                ti.append(EVIDENCE_TI_EXCLUDED)

    excluded_ai: set[uuid.UUID] = set()
    excluded_ti: set[uuid.UUID] = set()
    if investigation_id is not None:
        case_rows = await session.execute(
            select(p.evidence_id, p.ai_excluded, p.ti_excluded)
            .join(
                Evidence,
                (Evidence.id == p.evidence_id) & (Evidence.organization_id == p.organization_id),
            )
            .where(
                p.organization_id == org_id,
                Evidence.investigation_id == investigation_id,
                (p.ai_excluded | p.ti_excluded),
            )
        )
        for evidence_id, ai_excluded, ti_excluded in case_rows.all():
            if ai_excluded:
                excluded_ai.add(evidence_id)
            if ti_excluded:
                excluded_ti.add(evidence_id)

    return SharePolicy(
        ai_blocked=bool(ai),
        ti_blocked=bool(ti),
        reasons=_sorted([*ai, *ti]),
        excluded_evidence_ids=frozenset(excluded_ai),
        ti_excluded_evidence_ids=frozenset(excluded_ti),
        ai_reasons=_sorted(ai),
        ti_reasons=_sorted(ti),
    )


def raise_if_ai_blocked(policy: SharePolicy) -> None:
    if policy.ai_blocked:
        raise PolicyBlocked("policy_blocked", policy.ai_reason or TLP_RED)


def raise_if_ti_blocked(policy: SharePolicy) -> None:
    if policy.ti_blocked:
        raise PolicyBlocked("policy_blocked", policy.ti_reason or TLP_RED)
