"""Source refs of case ATT&CK mappings: scope checks and deep-link descriptors.

A source names the evidence behind a mapping: a capa capability row, a finding row, or a
completed AI run. On write every ref is re-checked in the org and the case (the row's job
must belong to evidence of the case; an AI run must be a `completed` run, the case's own or
one of its jobs'), else `422 ref_out_of_scope`. On read each stored ref is resolved again; a ref
that no longer resolves keeps its ids but loses its path.
"""

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.modules.ai.contracts import AiRunStatus
from app.modules.ai.models import AiRun
from app.modules.analysis.models import AnalysisJob, Analyzer, analyzer_route
from app.modules.case_attack.schemas import AttackSourceRef, SourceDescriptor
from app.modules.evidence.models import Evidence
from app.modules.pcap_analysis.models import AnalysisFinding
from app.modules.static_analysis.models import MalwareCapability


class RefOutOfScope(AppError):
    status_code = 422
    code = "ref_out_of_scope"
    message = "A source does not belong to this case"


@dataclass(frozen=True)
class Resolved:
    kind: str
    ref_id: str
    job_id: uuid.UUID | None
    run_id: uuid.UUID | None
    analyzer: str | None  # of the row's job (path building)


def case_jobs(org_id: uuid.UUID, investigation_id: uuid.UUID) -> Select[uuid.UUID, Analyzer]:
    """Every analysis job on evidence of the case: `(id, analyzer)`."""
    return (
        select(AnalysisJob.id, AnalysisJob.analyzer)
        .join(
            Evidence,
            (Evidence.id == AnalysisJob.evidence_id)
            & (Evidence.organization_id == AnalysisJob.organization_id),
        )
        .where(
            AnalysisJob.organization_id == org_id,
            Evidence.organization_id == org_id,
            Evidence.investigation_id == investigation_id,
        )
    )


async def case_job_map(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> dict[uuid.UUID, Analyzer]:
    rows = await session.execute(case_jobs(org_id, investigation_id))
    return {job_id: analyzer for job_id, analyzer in rows}


def _as_uuid(value: object) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


def _analyzer(value: object) -> str:
    return str(getattr(value, "value", value))


async def resolve(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    refs: Iterable[tuple[str, str]],
) -> dict[tuple[str, str], Resolved]:
    """(kind, ref_id) -> the in-scope row; refs that do not resolve are absent."""
    wanted: dict[str, set[uuid.UUID]] = {"capability": set(), "finding": set(), "ai_run": set()}
    for kind, ref_id in refs:
        parsed = _as_uuid(ref_id)
        if kind in wanted and parsed is not None:
            wanted[kind].add(parsed)
    if not any(wanted.values()):
        return {}
    jobs = await case_job_map(session, org_id, investigation_id)
    out: dict[tuple[str, str], Resolved] = {}
    for kind, model in (("capability", MalwareCapability), ("finding", AnalysisFinding)):
        if not wanted[kind] or not jobs:
            continue
        rows = await session.execute(
            select(model.id, model.job_id).where(
                model.organization_id == org_id,
                model.id.in_(wanted[kind]),
                model.job_id.in_(list(jobs)),
            )
        )
        for row_id, job_id in rows:
            out[(kind, str(row_id))] = Resolved(
                kind, str(row_id), job_id, None, _analyzer(jobs[job_id])
            )
    if wanted["ai_run"]:
        in_case = [AiRun.investigation_id == investigation_id]
        if jobs:
            in_case.append(AiRun.job_id.in_(list(jobs)))
        rows = await session.execute(
            select(AiRun.id, AiRun.job_id).where(
                AiRun.organization_id == org_id,
                AiRun.id.in_(wanted["ai_run"]),
                AiRun.status == AiRunStatus.COMPLETED.value,
                or_(*in_case),
            )
        )
        for run_id, job_id in rows:
            out[("ai_run", str(run_id))] = Resolved(
                "ai_run", str(run_id), job_id, run_id, _analyzer(jobs[job_id]) if job_id else None
            )
    return out


def _key(ref: AttackSourceRef) -> tuple[str, str]:
    """The canonical (kind, ref_id) of a request ref: AI runs are named by their run id."""
    if ref.kind == "ai_run":
        ref_uuid = _as_uuid(ref.ref_id)
        if ref.run_id is not None and ref_uuid is not None and ref_uuid != ref.run_id:
            raise RefOutOfScope()
        run_id = ref.run_id or ref_uuid
        if run_id is None:
            raise RefOutOfScope()
        return ("ai_run", str(run_id))
    parsed = _as_uuid(ref.ref_id)
    if parsed is None or ref.run_id is not None:
        raise RefOutOfScope()
    return (ref.kind, str(parsed))


async def check(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    refs: Sequence[AttackSourceRef],
) -> list[dict[str, Any]]:
    """Every ref resolved in the case scope (`422 ref_out_of_scope` otherwise), returned in
    the stored shape (de-duplicated, ids taken from the resolved rows)."""
    keys: list[tuple[str, str]] = []
    for ref in refs:
        key = _key(ref)
        if key not in keys:
            keys.append(key)
    found = await resolve(session, org_id, investigation_id, keys)
    stored: list[dict[str, Any]] = []
    for ref in refs:
        row = found.get(_key(ref))
        if row is None or (ref.job_id is not None and ref.job_id != row.job_id):
            raise RefOutOfScope()
    for key in keys:
        row = found[key]
        stored.append(
            {
                "kind": row.kind,
                "ref_id": row.ref_id,
                "job_id": str(row.job_id) if row.job_id else None,
                "run_id": str(row.run_id) if row.run_id else None,
            }
        )
    return stored


def path(org_id: uuid.UUID, row: Resolved) -> str | None:
    """The in-app path of a resolved ref, from ids only (never a URL)."""
    if row.kind == "ai_run" and row.run_id is not None:
        return f"/o/{org_id}/ai-analyst/{row.run_id}"
    if row.job_id is None:
        return None
    if row.kind == "capability":
        return f"/o/{org_id}/malware/{row.job_id}?tab=capabilities&ref={row.ref_id}"
    if row.kind == "finding":
        # Every analyzer's own page (M8 RT1: memory findings link to /memory).
        route = analyzer_route(row.analyzer)
        if route is None:
            return None
        return f"/o/{org_id}/{route}/{row.job_id}?tab=findings&ref={row.ref_id}"
    return None


def descriptor(
    org_id: uuid.UUID,
    stored: dict[str, Any],
    found: dict[tuple[str, str], Resolved],
) -> SourceDescriptor:
    kind = str(stored.get("kind"))
    ref_id = str(stored.get("ref_id"))
    row = found.get((kind, ref_id))
    return SourceDescriptor(
        kind=kind,  # written by `check` only (a SourceKind)
        ref_id=ref_id,
        job_id=_as_uuid(stored.get("job_id")) if stored.get("job_id") else None,
        run_id=_as_uuid(stored.get("run_id")) if stored.get("run_id") else None,
        path=path(org_id, row) if row is not None else None,
    )
