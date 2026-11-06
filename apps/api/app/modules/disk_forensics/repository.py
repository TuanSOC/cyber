"""Read queries over one disk job's results (M9 phase 8); every query is bounded to (org, job)
on top of RLS.

Pages and capped totals work like the pcap / static / memory result reads
(`pcap_analysis.repository._page`: offset pages under the shared `MAX_OFFSET`, totals counted
up to `TOTAL_CAP`, `ref=<row id>` pages of one row or 404). The orderings follow the per-job
indexes of migration 0017:
- files: (job, partition, meta_addr) then id;
- one directory: (job, partition, parent_addr, id) (RT13: no path hash, no collision check);
- events: (job, ts, id), or (job, artifact, ts, id) with an artifact filter;
- the merged timeline: one stream per file-system time column, each read through its
  (job, <column>, id) index, plus the events through (job, ts, id) (RT14). A page reads at
  most `offset + limit` rows of each stream (each stream is index-ordered and LIMITed, the
  per-stream cap), then orders that bounded union by (ts, stream, id).

The streamed interop exports read in batches of `EXPORT_BATCH` rows: the body file and the
md5 list through one server-side cursor each, the merged timeline through keyset batches of
its five index-ordered streams merged in order (`exports_interop`).
"""

import uuid
from collections.abc import AsyncIterator, Iterable, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from cyberlab_jobs.disk import FILE_FLAG_BITS
from sqlalchemy import (
    ColumnElement,
    Row,
    String,
    Text,
    and_,
    cast,
    func,
    literal,
    literal_column,
    null,
    or_,
    select,
    tuple_,
    union_all,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import AnalysisJob, Analyzer, JobProfile
from app.modules.disk_forensics.models import (
    AnalysisJobSegment,
    DiskEvent,
    DiskFile,
    DiskImage,
    DiskPartition,
)
from app.modules.disk_forensics.schemas import TimeColumn
from app.modules.evidence.models import Evidence, EvidenceHash, HashAlgorithm
from app.modules.investigations.models import Investigation
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc, TimelineEntry
from app.modules.pcap_analysis.repository import _contains, _page
from app.modules.pcap_analysis.schemas import TOTAL_CAP

# Rows of one kind attached to a file detail (other names, streams).
DETAIL_CAP = 200
# Rows per export batch (server-side cursor partitions, keyset batches).
EXPORT_BATCH = 5_000
# Findings read to find the files they cite (the disk findings cap).
FINDING_REF_CAP = 5_000

# The second key of the merged order: a file time column's name or `event` (constant per
# stream, so each stream's own (ts, id) index order is the merged order restricted to it).
TimelineStream = Literal["mtime", "atime", "ctime", "crtime", "event"]
TIME_COLUMNS: tuple[TimelineStream, ...] = ("mtime", "atime", "ctime", "crtime")
EVENT_STREAM: TimelineStream = "event"

FILE_ORDER = (DiskFile.partition_index, DiskFile.meta_addr, DiskFile.id)
EVENT_ORDER = (DiskEvent.ts, DiskEvent.id)
PARTITION_ORDER = (DiskPartition.index, DiskPartition.id)

COUNTED: dict[str, Any] = {
    "partitions": DiskPartition,
    "files": DiskFile,
    "events": DiskEvent,
    "findings": AnalysisFinding,
    "iocs": Ioc,
    "timeline": TimelineEntry,
}

FileFlag = Literal["deleted", "orphan", "hard_linked", "stream", "known", "notable", "yara"]


def _scope(model: Any, org_id: uuid.UUID, job_id: uuid.UUID) -> list[ColumnElement[bool]]:
    return [model.organization_id == org_id, model.job_id == job_id]


async def ensure_disk_job(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AnalysisJob:
    """404 unless the job belongs to the org AND is a disk analysis (an `extract` job is a
    file export, never a listing: 404 too)."""
    job = await session.scalar(
        select(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
    )
    if job is None or job.analyzer != Analyzer.DISK or job.profile == JobProfile.EXTRACT:
        raise NotFound()
    return job


# --- Summary -------------------------------------------------------------------------------


async def image(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> DiskImage | None:
    row: DiskImage | None = await session.scalar(
        select(DiskImage).where(DiskImage.organization_id == org_id, DiskImage.job_id == job_id)
    )
    return row


async def segments(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> Sequence[Row[Any]]:
    """The ordered segment set with the API-computed (trusted) size and sha256 (RT17)."""
    s, e, h = AnalysisJobSegment, Evidence, EvidenceHash
    stmt = (
        select(s.ordinal, e.id, e.original_filename, e.size_bytes, h.value)
        .join(e, (e.id == s.evidence_id) & (e.organization_id == s.organization_id))
        .outerjoin(
            h,
            (h.evidence_id == e.id)
            & (h.organization_id == e.organization_id)
            & (h.algorithm == HashAlgorithm.SHA256),
        )
        .where(s.organization_id == org_id, s.job_id == job_id)
        .order_by(s.ordinal)
    )
    return (await session.execute(stmt)).all()


async def segment_evidence_ids(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob
) -> list[uuid.UUID]:
    found = list(
        (
            await session.scalars(
                select(AnalysisJobSegment.evidence_id)
                .where(
                    AnalysisJobSegment.organization_id == org_id,
                    AnalysisJobSegment.job_id == job.id,
                )
                .order_by(AnalysisJobSegment.ordinal)
            )
        ).all()
    )
    return found or [job.evidence_id]


async def investigation_of(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID
) -> Investigation | None:
    row: Investigation | None = await session.scalar(
        select(Investigation)
        .join(
            Evidence,
            (Evidence.investigation_id == Investigation.id)
            & (Evidence.organization_id == Investigation.organization_id),
        )
        .where(Evidence.organization_id == org_id, Evidence.id == evidence_id)
    )
    return row


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


# --- Partitions ----------------------------------------------------------------------------


async def partitions(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, page: PageParams
) -> tuple[Sequence[DiskPartition], int]:
    return await _page(
        session, DiskPartition, _scope(DiskPartition, org_id, job_id), PARTITION_ORDER, page
    )


async def partition_fs_type(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, index: int
) -> str | None:
    found: str | None = await session.scalar(
        select(DiskPartition.fs_type).where(
            *_scope(DiskPartition, org_id, job_id), DiskPartition.index == index
        )
    )
    return found


# --- Files ---------------------------------------------------------------------------------


def _flag_set(bit: str) -> ColumnElement[bool]:
    return DiskFile.flags.op("&")(FILE_FLAG_BITS[bit]) != 0


def flag_filter(flag: FileFlag) -> ColumnElement[bool]:
    """`known`: a known-bad set match; `notable`: a notable set match; `stream`: an NTFS
    named stream; `yara`: at least one rule matched."""
    if flag in ("deleted", "orphan", "hard_linked"):
        return _flag_set(flag)
    if flag == "stream":
        return DiskFile.stream.is_not(None)
    if flag == "known":
        return DiskFile.known == "bad"
    if flag == "notable":
        return DiskFile.known == "notable"
    return func.cardinality(DiskFile.yara_rules) > 0


def hash_filter(value: str) -> ColumnElement[bool]:
    """md5 / sha1 / sha256 by length (32 / 40 / 64 hex characters, checked by the route)."""
    digest = value.lower()
    column = {32: DiskFile.md5, 40: DiskFile.sha1, 64: DiskFile.sha256}[len(digest)]
    return column == digest


async def files(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    q: str | None = None,
    partition: int | None = None,
    flag: FileFlag | None = None,
    magic: str | None = None,
    digests: Sequence[str] = (),
    ext: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    include_known: bool = False,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[DiskFile], int]:
    """`q`: substring of the path (one job's rows: a bounded sequential scan); `since` /
    `until`: any of the four times in the range; known-good files are hidden unless
    `include_known` (RT18)."""
    m = DiskFile
    where = _scope(m, org_id, job_id)
    if q:
        where.append(_contains(m.path, q))
    if partition is not None:
        where.append(m.partition_index == partition)
    if flag is not None:
        where.append(flag_filter(flag))
    if magic is not None:
        where.append(m.magic == magic)
    where.extend(hash_filter(d) for d in digests)
    if ext is not None:
        where.append(func.lower(m.ext) == ext.lower())
    if since is not None or until is not None:
        where.append(or_(*(_in_range(getattr(m, c), since, until) for c in TIME_COLUMNS)))
    if not include_known:
        where.append(or_(m.known.is_(None), m.known != "good"))
    return await _page(session, m, where, FILE_ORDER, page, ref=ref)


def _in_range(column: Any, since: datetime | None, until: datetime | None) -> ColumnElement[bool]:
    parts: list[ColumnElement[bool]] = [column.is_not(None)]
    if since is not None:
        parts.append(column >= since)
    if until is not None:
        parts.append(column <= until)
    return and_(*parts)


async def file_row(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, file_id: uuid.UUID
) -> DiskFile | None:
    row: DiskFile | None = await session.scalar(
        select(DiskFile).where(*_scope(DiskFile, org_id, job_id), DiskFile.id == file_id)
    )
    return row


async def same_inode(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, row: DiskFile
) -> Sequence[Row[Any]]:
    """The other rows of the same inode (other names, RT7, and named streams): at most
    `DETAIL_CAP`, through the (job, partition, meta_addr) index."""
    m = DiskFile
    stmt = (
        select(m.path, m.stream)
        .where(
            *_scope(m, org_id, job_id),
            m.partition_index == row.partition_index,
            m.meta_addr == row.meta_addr,
            m.id != row.id,
        )
        .order_by(m.path, m.id)
        .limit(DETAIL_CAP)
    )
    return (await session.execute(stmt)).all()


# --- Directories ---------------------------------------------------------------------------


async def first_partition(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> int | None:
    found = await session.scalar(
        select(func.min(DiskFile.partition_index)).where(*_scope(DiskFile, org_id, job_id))
    )
    return None if found is None else int(found)


async def root_addr(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, partition: int
) -> Decimal | None:
    """The root directory's address: the parent of a top-level entry (a path without `/`).
    The root itself is not a listed row (TSK walks from it)."""
    m = DiskFile
    found: Decimal | None = await session.scalar(
        select(m.parent_addr)
        .where(
            *_scope(m, org_id, job_id),
            m.partition_index == partition,
            m.parent_addr.is_not(None),
            m.path.not_like("%/%"),
        )
        .limit(1)
    )
    return found


async def children(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    partition: int,
    parent: int | Decimal,
) -> tuple[Sequence[DiskFile], int]:
    """The rows whose `parent_addr` is the directory's address in that partition (RT13)."""
    m = DiskFile
    where = [*_scope(m, org_id, job_id), m.partition_index == partition, m.parent_addr == parent]
    return await _page(session, m, where, (m.id,), page)


# --- Events --------------------------------------------------------------------------------


async def events(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    q: str | None = None,
    artifact: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[DiskEvent], int]:
    m = DiskEvent
    where = _scope(m, org_id, job_id)
    if q:
        where.append(_contains(m.message, q))
    if artifact is not None:
        where.append(m.artifact == artifact)
    if since is not None:
        where.append(m.ts >= since)
    if until is not None:
        where.append(m.ts <= until)
    return await _page(session, m, where, EVENT_ORDER, page, ref=ref)


# --- Merged timeline -----------------------------------------------------------------------


def timeline_streams(
    source: Literal["file", "event"] | None,
    time: TimeColumn | None,
    artifact: str | None,
) -> tuple[TimelineStream, ...]:
    """The streams a timeline read covers: `time` narrows the file columns, `artifact`
    implies events only (file rows have no artifact)."""
    columns: tuple[TimelineStream, ...] = (time,) if time is not None else TIME_COLUMNS
    files_on = source in (None, "file") and artifact is None
    events_on = source in (None, "event")
    return (*(columns if files_on else ()), *((EVENT_STREAM,) if events_on else ()))


def _stream_select(
    stream: TimelineStream,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    *,
    since: datetime | None,
    until: datetime | None,
    artifact: str | None,
    after: tuple[datetime, uuid.UUID] | None = None,
) -> Any:
    """One stream as (ts, stream, id, path, partition, time_basis, artifact, message,
    ts_desc, file_id), in its index order; `after` continues a keyset read."""
    tag = literal_column(f"'{stream}'", String).label("stream")
    if stream == EVENT_STREAM:
        e = DiskEvent
        ts: Any = e.ts
        stmt = select(
            e.ts.label("ts"),
            tag,
            e.id.label("id"),
            e.path.label("path"),
            e.partition_index.label("partition"),
            cast(literal_column("'utc'"), String).label("time_basis"),
            cast(e.artifact, String).label("artifact"),
            cast(e.message, Text).label("message"),
            cast(e.ts_desc, String).label("ts_desc"),
            e.file_id.label("file_id"),
        ).where(*_scope(e, org_id, job_id))
        if artifact is not None:
            stmt = stmt.where(e.artifact == artifact)
        row_id: Any = e.id
    else:
        f = DiskFile
        ts = getattr(f, stream)
        stmt = select(
            ts.label("ts"),
            tag,
            f.id.label("id"),
            f.path.label("path"),
            f.partition_index.label("partition"),
            cast(f.time_basis, String).label("time_basis"),
            cast(null(), String).label("artifact"),
            cast(null(), Text).label("message"),
            cast(null(), String).label("ts_desc"),
            f.id.label("file_id"),
        ).where(*_scope(f, org_id, job_id), ts.is_not(None))
        row_id = f.id
    if since is not None:
        stmt = stmt.where(ts >= since)
    if until is not None:
        stmt = stmt.where(ts <= until)
    if after is not None:
        last = tuple_(literal(after[0], ts.type), literal(after[1], row_id.type))
        stmt = stmt.where(tuple_(ts, row_id) > last)
    return stmt.order_by(ts, row_id)


async def timeline_page(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    streams: Sequence[TimelineStream],
    since: datetime | None = None,
    until: datetime | None = None,
    artifact: str | None = None,
) -> tuple[Sequence[Row[Any]], int]:
    """One page of the merged order (ts, stream, id) and its capped total. Each stream is
    LIMITed to `offset + limit` rows in its own index order before the union is ordered, so
    the sort is bounded by 5 x (MAX_OFFSET + MAX_LIMIT) rows whatever the job's size."""
    if not streams:
        return [], 0
    take = page.offset + page.limit
    parts = [
        select(
            _stream_select(s, org_id, job_id, since=since, until=until, artifact=artifact)
            .limit(take)
            .subquery()
        )
        for s in streams
    ]
    merged = union_all(*parts).subquery()
    stmt = (
        select(merged)
        .order_by(merged.c.ts, merged.c.stream, merged.c.id)
        .offset(page.offset)
        .limit(page.limit)
    )
    rows = (await session.execute(stmt)).all()
    totals = [
        select(func.count())
        .select_from(
            _stream_select(s, org_id, job_id, since=since, until=until, artifact=artifact)
            .order_by(None)
            .limit(TOTAL_CAP)
            .subquery()
        )
        .scalar_subquery()
        for s in streams
    ]
    counted = (await session.execute(select(*totals))).one()
    return rows, min(sum(int(c or 0) for c in counted), TOTAL_CAP)


async def timeline_stream_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    stream: TimelineStream,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    artifact: str | None = None,
    batch: int = EXPORT_BATCH,
) -> AsyncIterator[Row[Any]]:
    """Every row of one stream in its index order, read in keyset batches of `batch`."""
    after: tuple[datetime, uuid.UUID] | None = None
    while True:
        stmt = _stream_select(
            stream, org_id, job_id, since=since, until=until, artifact=artifact, after=after
        ).limit(batch)
        rows = (await session.execute(stmt)).all()
        for row in rows:
            yield row
        if len(rows) < batch:
            return
        after = (rows[-1].ts, rows[-1].id)


async def timeline_count(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    streams: Iterable[TimelineStream],
) -> int:
    """Rows of a full timeline export (exact; result tables are written once)."""
    totals = [
        select(func.count())
        .select_from(
            _stream_select(s, org_id, job_id, since=None, until=None, artifact=None)
            .order_by(None)
            .subquery()
        )
        .scalar_subquery()
        for s in streams
    ]
    counted = (await session.execute(select(*totals))).one()
    return sum(int(c or 0) for c in counted)


# --- Interop export reads ------------------------------------------------------------------

BODYFILE_COLUMNS = (
    DiskFile.partition_index,
    DiskFile.meta_addr,
    DiskFile.meta_seq,
    DiskFile.stream,
    DiskFile.path,
    DiskFile.type,
    DiskFile.flags,
    DiskFile.size,
    DiskFile.mode,
    DiskFile.uid,
    DiskFile.gid,
    DiskFile.md5,
    DiskFile.atime,
    DiskFile.mtime,
    DiskFile.ctime,
    DiskFile.crtime,
)


async def bodyfile_rows(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AsyncIterator[Row[Any]]:
    """Every listed entry of the job (columns only: no identity map), through one
    server-side cursor read in partitions of `EXPORT_BATCH`."""
    stmt = (
        select(*BODYFILE_COLUMNS)
        .where(*_scope(DiskFile, org_id, job_id))
        .order_by(*FILE_ORDER)
        .execution_options(yield_per=EXPORT_BATCH)
    )
    result = await session.stream(stmt)
    async for partition in result.partitions(EXPORT_BATCH):
        for row in partition:
            yield row


async def file_count(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> int:
    return int(
        await session.scalar(
            select(func.count()).select_from(DiskFile).where(*_scope(DiskFile, org_id, job_id))
        )
        or 0
    )


def parse_file_refs(refs: Iterable[str]) -> tuple[set[uuid.UUID], set[tuple[int, str]]]:
    """The listed files a finding cites: `file:<row id>` (the ingest's resolved form) or the
    worker's natural form `file:<partition>:<path>`; every other ref kind is ignored."""
    ids: set[uuid.UUID] = set()
    paths: set[tuple[int, str]] = set()
    for ref in refs:
        if not isinstance(ref, str) or not ref.startswith("file:"):
            continue
        body = ref.removeprefix("file:")
        try:
            ids.add(uuid.UUID(body))
            continue
        except ValueError:
            pass
        head, sep, path = body.partition(":")
        if sep and head.isdigit() and path:
            paths.add((int(head), path))
    return ids, paths


async def finding_file_refs(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> tuple[set[uuid.UUID], set[tuple[int, str]]]:
    rows = await session.scalars(
        select(AnalysisFinding.evidence_refs)
        .where(*_scope(AnalysisFinding, org_id, job_id))
        .limit(FINDING_REF_CAP)
    )
    refs: list[str] = []
    for value in rows.all():
        if isinstance(value, list):
            refs.extend(v for v in value if isinstance(v, str))
    return parse_file_refs(refs)


def _notable_stmt(
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    ids: set[uuid.UUID],
    paths: set[tuple[int, str]],
) -> Any:
    m = DiskFile
    flagged: list[ColumnElement[bool]] = [
        m.known.in_(("bad", "notable")),
        func.cardinality(m.yara_rules) > 0,
    ]
    if ids:
        flagged.append(m.id.in_(sorted(ids)))
    if paths:
        flagged.append(tuple_(m.partition_index, m.path).in_(sorted(paths)))
    digest = func.lower(m.md5).label("md5")
    return (
        select(digest)
        .where(*_scope(m, org_id, job_id), m.md5.is_not(None), or_(*flagged))
        .group_by(digest)
        .order_by(digest)
    )


async def notable_md5_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    ids: set[uuid.UUID],
    paths: set[tuple[int, str]],
) -> AsyncIterator[str]:
    """Distinct lowercase md5s of the flagged files, through one server-side cursor."""
    stmt = _notable_stmt(org_id, job_id, ids, paths).execution_options(yield_per=EXPORT_BATCH)
    result = await session.stream(stmt)
    async for partition in result.partitions(EXPORT_BATCH):
        for row in partition:
            yield str(row.md5)


async def notable_md5_count(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    ids: set[uuid.UUID],
    paths: set[tuple[int, str]],
) -> int:
    inner = _notable_stmt(org_id, job_id, ids, paths).order_by(None).subquery()
    return int(await session.scalar(select(func.count()).select_from(inner)) or 0)
