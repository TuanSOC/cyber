"""Note refs re-checked in the org and the case scope (M6).

A ref is `{kind, ref_id, job_id?}`. `evidence` and `job` refs name those rows; every other
kind names a result row of a job (`analysis_findings`, `network_alerts`, `iocs`,
`analysis_timeline`, `malware_capabilities`, `malware_signature_matches`). The row must
exist in the org and belong to this case (the evidence, or the job's evidence, is in the
case); a given `job_id` must be the row's job. Anything else is `422 ref_out_of_scope`, the
same answer for an unknown id and for another case's or org's row.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence
from app.modules.notes.schemas import NoteRef
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc, NetworkAlert, TimelineEntry
from app.modules.static_analysis.models import MalwareCapability, MalwareSignatureMatch

_RESULT_MODELS: dict[str, Any] = {
    "finding": AnalysisFinding,
    "alert": NetworkAlert,
    "ioc": Ioc,
    "timeline": TimelineEntry,
    "capability": MalwareCapability,
    "signature": MalwareSignatureMatch,
}


class RefOutOfScope(AppError):
    status_code = 422
    code = "ref_out_of_scope"
    message = "A note reference is not a row of this case"

    def __init__(self, index: int) -> None:
        super().__init__(extra={"index": index})


def _uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


async def _in_case(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, ref: NoteRef
) -> bool:
    ref_id = _uuid(ref.ref_id)
    if ref_id is None:
        return False
    in_case = (Evidence.organization_id == org_id) & (Evidence.investigation_id == investigation_id)
    if ref.kind == "evidence":
        if ref.job_id is not None:
            return False
        found = await session.scalar(select(Evidence.id).where(Evidence.id == ref_id, in_case))
        return found is not None
    job = AnalysisJob
    job_in_case = (
        select(job.id)
        .join(
            Evidence,
            (Evidence.id == job.evidence_id) & (Evidence.organization_id == job.organization_id),
        )
        .where(job.organization_id == org_id, in_case)
    )
    if ref.kind == "job":
        if ref.job_id is not None and ref.job_id != ref_id:
            return False
        found = await session.scalar(job_in_case.where(job.id == ref_id))
        return found is not None
    model = _RESULT_MODELS[ref.kind]
    stmt = select(model.job_id).where(
        model.id == ref_id,
        model.organization_id == org_id,
        model.job_id.in_(job_in_case.scalar_subquery()),
    )
    if ref.job_id is not None:
        stmt = stmt.where(model.job_id == ref.job_id)
    return (await session.scalar(stmt)) is not None


async def check_refs(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    refs: list[NoteRef],
) -> None:
    """Raise `422 ref_out_of_scope` (with the first bad index) unless every ref is a row
    of this case."""
    for index, ref in enumerate(refs):
        if not await _in_case(session, org_id, investigation_id, ref):
            raise RefOutOfScope(index)


def dump(refs: list[NoteRef]) -> list[dict[str, Any]]:
    """The stored JSON form: `job_id` only when given."""
    return [ref.model_dump(mode="json", exclude_none=True) for ref in refs]


def load(raw: object) -> list[NoteRef]:
    if not isinstance(raw, list):
        return []
    return [NoteRef.model_validate(item) for item in raw if isinstance(item, dict)]
