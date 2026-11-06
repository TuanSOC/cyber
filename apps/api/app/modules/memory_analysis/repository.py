"""Read queries over one memory job's results (M8 phase 7); every query is bounded to
(org, job) on top of RLS.

Pages and capped totals work exactly like the pcap and static result reads
(`pcap_analysis.repository._page`: offset pages under the shared `MAX_OFFSET`, totals counted
up to `TOTAL_CAP`, `ref=<row id>` pages of one row or 404). The orderings follow the
per-job indexes of migration 0016: (job, pid) for processes, connections and injections,
(job, type, id) for artifacts.
"""

import uuid
from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy import ColumnElement, case, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import AnalysisJob, Analyzer
from app.modules.evidence.models import Evidence, EvidenceHash, HashAlgorithm
from app.modules.memory_analysis.models import (
    SOURCE_BITS,
    MemoryArtifact,
    MemoryConnection,
    MemoryImage,
    MemoryInjection,
    MemoryProcess,
)
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc, TimelineEntry
from app.modules.pcap_analysis.repository import _contains, _page

# Rows of one kind attached to a process detail (the plan's per-kind cap).
DETAIL_CAP = 200

# Row orders (the 0016 per-job indexes lead each one).
CONNECTION_ORDER = (MemoryConnection.pid, MemoryConnection.local_port, MemoryConnection.id)
INJECTION_ORDER = (MemoryInjection.pid, MemoryInjection.start, MemoryInjection.id)
ARTIFACT_ORDER = (MemoryArtifact.type, MemoryArtifact.id)

# The tables whose rows the summary counts (live, per job).
COUNTED: dict[str, Any] = {
    "processes": MemoryProcess,
    "connections": MemoryConnection,
    "injections": MemoryInjection,
    "artifacts": MemoryArtifact,
    "findings": AnalysisFinding,
    "iocs": Ioc,
    "timeline": TimelineEntry,
}


async def ensure_memory_job(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AnalysisJob:
    """404 unless the job belongs to the org AND is a memory analysis."""
    job = await session.scalar(
        select(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
    )
    if job is None or job.analyzer != Analyzer.MEMORY:
        raise NotFound()
    return job


def _scope(model: Any, org_id: uuid.UUID, job_id: uuid.UUID) -> list[ColumnElement[bool]]:
    return [model.organization_id == org_id, model.job_id == job_id]


async def image(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> MemoryImage | None:
    row: MemoryImage | None = await session.scalar(
        select(MemoryImage).where(
            MemoryImage.organization_id == org_id, MemoryImage.job_id == job_id
        )
    )
    return row


async def evidence_facts(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID
) -> tuple[int, str | None]:
    """The trusted size and sha256 of the evidence record (never the worker's image line)."""
    size = await session.scalar(
        select(Evidence.size_bytes).where(
            Evidence.organization_id == org_id, Evidence.id == evidence_id
        )
    )
    sha256 = await session.scalar(
        select(EvidenceHash.value).where(
            EvidenceHash.organization_id == org_id,
            EvidenceHash.evidence_id == evidence_id,
            EvidenceHash.algorithm == HashAlgorithm.SHA256,
        )
    )
    return int(size or 0), sha256


async def live_counts(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> dict[str, int]:
    """Rows per result table of the job, in one statement (each count uses a job index)."""
    columns = [
        select(func.count())
        .select_from(model)
        .where(*_scope(model, org_id, job_id))
        .scalar_subquery()
        .label(name)
        for name, model in COUNTED.items()
    ]
    row = (await session.execute(select(*columns))).one()
    return {name: int(row._mapping[name] or 0) for name in COUNTED}


def _hidden(hidden: bool) -> ColumnElement[bool]:
    """`hidden`: seen by a pool scan but not in the active process list."""
    in_list = MemoryProcess.sources.op("&")(SOURCE_BITS["pslist"])
    return (in_list == 0) if hidden else (in_list != 0)


async def processes(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    q: str | None,
    ppid: int | None,
    hidden: bool | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[MemoryProcess], int]:
    m = MemoryProcess
    where = _scope(m, org_id, job_id)
    if q:
        where.append(or_(_contains(m.name, q), _contains(m.image_path, q), _contains(m.cmdline, q)))
    if ppid is not None:
        where.append(m.ppid == ppid)
    if hidden is not None:
        where.append(_hidden(hidden))
    return await _page(session, m, where, (m.pid, m.create_time, m.id), page, ref=ref)


async def tree_rows(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, cap: int
) -> Sequence[MemoryProcess]:
    """At most `cap + 1` processes of the job (one more than the tree takes: the caller knows
    the job is too large for a tree)."""
    m = MemoryProcess
    stmt = (
        select(m)
        .where(*_scope(m, org_id, job_id))
        .order_by(m.pid, m.create_time, m.id)
        .limit(cap + 1)
    )
    return (await session.scalars(stmt)).all()


async def children_counts(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, pids: Iterable[int]
) -> dict[int, int]:
    """Processes of the job whose ppid is each pid (a self-parented row is not its child)."""
    wanted = sorted(set(pids))
    if not wanted:
        return {}
    m = MemoryProcess
    stmt = (
        select(m.ppid, func.count())
        .where(*_scope(m, org_id, job_id), m.ppid.in_(wanted), m.pid != m.ppid)
        .group_by(m.ppid)
    )
    return {int(ppid): int(count) for ppid, count in (await session.execute(stmt)).all()}


def _instance_order() -> tuple[Any, ...]:
    """The instance shown for a pid first: in the active list, still running, newest."""
    m = MemoryProcess
    in_list = case((m.sources.op("&")(SOURCE_BITS["pslist"]) != 0, 0), else_=1)
    running = case((m.exit_time.is_(None), 0), else_=1)
    return (in_list, running, m.create_time.desc().nulls_last(), m.id)


async def instances(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, pid: int
) -> Sequence[MemoryProcess]:
    """Every pslist / psscan instance with this pid (pids are reused), best first."""
    m = MemoryProcess
    stmt = (
        select(m)
        .where(*_scope(m, org_id, job_id), m.pid == pid)
        .order_by(*_instance_order())
        .limit(DETAIL_CAP)
    )
    return (await session.scalars(stmt)).all()


async def instance_count(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, pid: int
) -> int:
    m = MemoryProcess
    stmt = select(func.count()).select_from(m).where(*_scope(m, org_id, job_id), m.pid == pid)
    return int(await session.scalar(stmt) or 0)


async def children_of(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, pid: int
) -> Sequence[MemoryProcess]:
    m = MemoryProcess
    stmt = (
        select(m)
        .where(*_scope(m, org_id, job_id), m.ppid == pid, m.pid != pid)
        .order_by(m.create_time, m.pid, m.id)
        .limit(DETAIL_CAP)
    )
    return (await session.scalars(stmt)).all()


async def rows_of_pid[M](
    session: AsyncSession,
    model: type[M],
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    pid: int,
    order_by: Sequence[Any],
) -> Sequence[M]:
    """At most DETAIL_CAP rows of one table that reference the pid."""
    m: Any = model
    stmt = (
        select(model)
        .where(*_scope(m, org_id, job_id), m.pid == pid)
        .order_by(*order_by)
        .limit(DETAIL_CAP)
    )
    return (await session.scalars(stmt)).all()


async def connections(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    pid: int | None,
    q: str | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[MemoryConnection], int]:
    """`q`: substring of either address, the owner or the state."""
    m = MemoryConnection
    where = _scope(m, org_id, job_id)
    if pid is not None:
        where.append(m.pid == pid)
    if q:
        where.append(
            or_(
                _contains(func.host(m.local_addr), q),
                _contains(func.host(m.remote_addr), q),
                _contains(m.owner, q),
                _contains(m.state, q),
            )
        )
    return await _page(session, m, where, CONNECTION_ORDER, page, ref=ref)


async def injections(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    pid: int | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[MemoryInjection], int]:
    m = MemoryInjection
    where = _scope(m, org_id, job_id)
    if pid is not None:
        where.append(m.pid == pid)
    return await _page(session, m, where, INJECTION_ORDER, page, ref=ref)


def _attribute_contains(term: str) -> ColumnElement[bool]:
    """Some attribute VALUE contains the term (keys never match: `q=path` must not match every
    module). Attributes are flat scalars (0016 check), so `jsonb_each_text` sees them all."""
    each = func.jsonb_each_text(MemoryArtifact.attributes).table_valued("key", "value")
    return select(literal(1)).select_from(each).where(_contains(each.c.value, term)).exists()


async def artifacts(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    type_: str | None,
    pid: int | None,
    q: str | None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[MemoryArtifact], int]:
    m = MemoryArtifact
    where = _scope(m, org_id, job_id)
    if type_ is not None:
        where.append(m.type == type_)
    if pid is not None:
        where.append(m.pid == pid)
    if q:
        where.append(_attribute_contains(q))
    return await _page(session, m, where, ARTIFACT_ORDER, page, ref=ref)
