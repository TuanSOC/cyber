"""Read queries over one job's results; every query is bounded to (org, job).

Totals are counted over at most TOTAL_CAP rows (one past the deepest reachable offset), so a
page request never scans a whole 100k-row table just to count it. Pagination stays
offset-based with the shared MAX_OFFSET cap; keyset pagination is out of scope for now.
"""

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import ColumnElement, case, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import AnalysisJob
from app.modules.investigations.repository import escape_like
from app.modules.pcap_analysis.models import (
    AnalysisFinding,
    Ioc,
    NetworkAlert,
    NetworkFlow,
    NetworkRecord,
    TimelineEntry,
)
from app.modules.pcap_analysis.schemas import (
    TOTAL_CAP,
    FindingSeverity,
    FlowProto,
    FlowSort,
    IocType,
    RecordKind,
)

_SEVERITY_RANK = case(
    {"high": 4, "medium": 3, "low": 2, "info": 1}, value=AnalysisFinding.severity, else_=0
)


async def ensure_job(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> None:
    """404 unless the job belongs to the org (RLS alone would just return empty pages)."""
    found = await session.scalar(
        select(AnalysisJob.id).where(
            AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id
        )
    )
    if found is None:
        raise NotFound()


async def _page[M](
    session: AsyncSession,
    model: type[M],
    where: Sequence[ColumnElement[bool]],
    order_by: Sequence[Any],
    page: PageParams,
    *,
    ref: object | None = None,
) -> tuple[Sequence[M], int]:
    """One page and its capped total. With `ref` (a row id, or a flow's `flow_ref`), the page
    holds just that row of the job (combined with the other filters); 404 when it has none,
    so a citation deep link never silently shows an unrelated page."""
    if ref is not None:
        where = [*where, _ref_column(model) == ref]
    capped = select(literal(1)).select_from(model).where(*where).limit(TOTAL_CAP).subquery()
    total = await session.scalar(select(func.count()).select_from(capped))
    stmt = select(model).where(*where).order_by(*order_by).limit(page.limit).offset(page.offset)
    rows = (await session.scalars(stmt)).all()
    if ref is not None and not total:
        raise NotFound()
    return rows, int(total or 0)


def _ref_column(model: Any) -> Any:
    # Flows are cited by (job, flow_ref) (RT16): the job comes from the path.
    return model.flow_ref if model is NetworkFlow else model.id


def _contains(column: Any, term: str) -> ColumnElement[bool]:
    return column.ilike(f"%{escape_like(term)}%", escape="\\")  # type: ignore[no-any-return]


async def findings(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    severity: FindingSeverity | None,
    type_: str | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[AnalysisFinding], int]:
    m = AnalysisFinding
    where = [m.organization_id == org_id, m.job_id == job_id]
    if severity is not None:
        where.append(m.severity == severity.value)
    if type_ is not None:
        where.append(m.type == type_)
    return await _page(session, m, where, (_SEVERITY_RANK.desc(), m.ts, m.id), page, ref=ref)


async def flows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    ip: str | None,
    port: int | None,
    proto: FlowProto | None,
    sort: FlowSort,
    ref: str | None = None,
) -> tuple[Sequence[NetworkFlow], int]:
    m = NetworkFlow
    where = [m.organization_id == org_id, m.job_id == job_id]
    if ip is not None:
        where.append(or_(m.src_ip == ip, m.dst_ip == ip))
    if port is not None:
        where.append(or_(m.src_port == port, m.dst_port == port))
    if proto is not None:
        where.append(m.proto == proto.value)
    order = (m.total_bytes.desc(), m.ts, m.id) if sort == FlowSort.BYTES else (m.ts, m.id)
    return await _page(session, m, where, order, page, ref=ref)


async def records(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    kind: RecordKind | None,
    q: str | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[NetworkRecord], int]:
    m = NetworkRecord
    where = [m.organization_id == org_id, m.job_id == job_id]
    if kind is not None:
        where.append(m.kind == kind.value)
    if q:
        where.append(_contains(m.summary, q))
    return await _page(session, m, where, (m.ts, m.id), page, ref=ref)


async def alerts(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    severity: int | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[NetworkAlert], int]:
    m = NetworkAlert
    where = [m.organization_id == org_id, m.job_id == job_id]
    if severity is not None:
        where.append(m.severity == severity)
    # Suricata severity 1 is the most severe.
    return await _page(session, m, where, (m.severity, m.ts, m.id), page, ref=ref)


async def iocs(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    type_: IocType | None,
    q: str | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[Ioc], int]:
    m = Ioc
    where = [m.organization_id == org_id, m.job_id == job_id]
    if type_ is not None:
        where.append(m.type == type_.value)
    if q:
        where.append(_contains(m.value, q))
    return await _page(session, m, where, (m.count.desc(), m.first_seen, m.id), page, ref=ref)


async def timeline(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[TimelineEntry], int]:
    m = TimelineEntry
    where = [m.organization_id == org_id, m.job_id == job_id]
    return await _page(session, m, where, (m.ts, m.id), page, ref=ref)
