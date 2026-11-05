"""ATT&CK suggestions of a case (frozen entry point of M6 phase 1; implemented by phase 5):
capa capabilities and finding ATT&CK ids of the latest jobs, and AI `attack_techniques` of
completed runs with at least one verified citation. Never confirmed automatically.

- capabilities: the `attack` ids of capa matches of the latest succeeded static job per
  evidence of the case;
- findings: the `attack` / `attack_ids` attribute of the findings of the latest succeeded
  pcap and static jobs per evidence;
- AI: `attack_techniques` entries of completed runs of the case (its own runs and runs of its
  jobs) whose verdict in `ai_outputs.verification.claims["attack:<id>"]` is `supported`,
  which the M5 verifier sets only with at least one verified citation.

Ids missing from the v20 index, revoked or deprecated are dropped. One suggestion per
technique, with every source (up to `MAX_SOURCES`), and `already_mapped` when the case has
a mapping of any status for it (a rejected suggestion stays visible as mapped).
"""

import uuid
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import AiRunStatus, ClaimStatus
from app.modules.ai.models import AiOutput, AiRun
from app.modules.analysis.models import Analyzer
from app.modules.case_attack import labels
from app.modules.case_attack.models import MAX_SOURCES, CaseAttackMapping
from app.modules.case_attack.schemas import AttackSuggestion, SourceDescriptor
from app.modules.case_attack.sources import Resolved, case_job_map, path
from app.modules.investigations.timeline import latest_succeeded_jobs
from app.modules.pcap_analysis.models import AnalysisFinding
from app.modules.static_analysis.models import MalwareCapability

# Bounds on the rows scanned per source (a case with more is summarized by its newest).
MAX_ROWS = 5_000
MAX_AI_RUNS = 200
FINDING_ATTACK_KEYS = ("attack", "attack_ids")


class _Collector:
    def __init__(self, org_id: uuid.UUID) -> None:
        self.org_id = org_id
        self.by_tid: dict[str, list[SourceDescriptor]] = {}

    def add(self, tid: str, row: Resolved, citation_status: str | None = None) -> None:
        if not labels.is_mappable(tid):
            return
        found = self.by_tid.setdefault(tid, [])
        if len(found) >= MAX_SOURCES or any(
            s.kind == row.kind and s.ref_id == row.ref_id for s in found
        ):
            return
        found.append(
            SourceDescriptor(
                kind=row.kind,  # one of the SourceKind literals
                ref_id=row.ref_id,
                job_id=row.job_id,
                run_id=row.run_id,
                path=path(self.org_id, row),
                citation_status=citation_status,
            )
        )


async def _capabilities(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, out: _Collector
) -> None:
    static = latest_succeeded_jobs(org_id, investigation_id, Analyzer.STATIC)
    m = MalwareCapability
    rows = await session.execute(
        select(m.id, m.job_id, m.attack)
        .join(static, static.c.id == m.job_id)
        .where(m.organization_id == org_id)
        .order_by(m.job_id, m.id)
        .limit(MAX_ROWS)
    )
    for row_id, job_id, attack in rows:
        for tid in labels.technique_ids_in(attack):
            out.add(tid, Resolved("capability", str(row_id), job_id, None, "static"))


async def _findings(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, out: _Collector
) -> None:
    f = AnalysisFinding
    for analyzer in (Analyzer.PCAP, Analyzer.STATIC):
        latest = latest_succeeded_jobs(org_id, investigation_id, analyzer)
        rows = await session.execute(
            select(f.id, f.job_id, f.attributes)
            .join(latest, latest.c.id == f.job_id)
            .where(f.organization_id == org_id)
            .order_by(f.job_id, f.id)
            .limit(MAX_ROWS)
        )
        for row_id, job_id, attributes in rows:
            if not isinstance(attributes, dict):
                continue
            for key in FINDING_ATTACK_KEYS:
                for tid in labels.technique_ids_in(attributes.get(key)):
                    out.add(tid, Resolved("finding", str(row_id), job_id, None, analyzer.value))


def _verified_techniques(body: Any, verification: Any) -> list[str]:
    """The M5 rule: an `attack_techniques` entry counts only when its stored verdict is
    `supported` (at least one verified citation)."""
    if not isinstance(body, dict) or not isinstance(verification, dict):
        return []
    claims = verification.get("claims")
    techniques = body.get("attack_techniques")
    if not isinstance(claims, dict) or not isinstance(techniques, list):
        return []
    found: list[str] = []
    for technique in techniques:
        tid = technique.get("technique_id") if isinstance(technique, dict) else None
        if not isinstance(tid, str) or tid in found:
            continue
        verdict = claims.get(f"attack:{tid}")
        if isinstance(verdict, dict) and verdict.get("status") == ClaimStatus.SUPPORTED.value:
            found.append(tid)
    return found


async def _ai(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, out: _Collector
) -> None:
    jobs = await case_job_map(session, org_id, investigation_id)
    in_case = [AiRun.investigation_id == investigation_id]
    if jobs:
        in_case.append(AiRun.job_id.in_(list(jobs)))
    rows = await session.execute(
        select(AiRun.id, AiRun.job_id, AiOutput.body, AiOutput.verification)
        .join(
            AiOutput,
            (AiOutput.run_id == AiRun.id) & (AiOutput.organization_id == AiRun.organization_id),
        )
        .where(
            AiRun.organization_id == org_id,
            AiRun.status == AiRunStatus.COMPLETED.value,
            or_(*in_case),
        )
        .order_by(AiRun.created_at.desc(), AiRun.id)
        .limit(MAX_AI_RUNS)
    )
    for run_id, job_id, body, verification in rows:
        analyzer = jobs.get(job_id) if job_id else None
        row = Resolved(
            "ai_run",
            str(run_id),
            job_id,
            run_id,
            str(getattr(analyzer, "value", analyzer)) if analyzer else None,
        )
        for tid in _verified_techniques(body, verification):
            out.add(tid, row, citation_status="verified")


async def suggestions(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> list[AttackSuggestion]:
    """Deduplicated by technique (sorted by id); the caller has checked the case exists."""
    out = _Collector(org_id)
    await _capabilities(session, org_id, investigation_id, out)
    await _findings(session, org_id, investigation_id, out)
    await _ai(session, org_id, investigation_id, out)
    mapped = set(
        (
            await session.scalars(
                select(CaseAttackMapping.technique_id).where(
                    CaseAttackMapping.organization_id == org_id,
                    CaseAttackMapping.investigation_id == investigation_id,
                )
            )
        ).all()
    )
    return [
        AttackSuggestion(
            technique_id=tid,
            label=labels.technique_label(tid),
            sources=found,
            already_mapped=tid in mapped,
        )
        for tid, found in sorted(out.by_tid.items())
    ]
