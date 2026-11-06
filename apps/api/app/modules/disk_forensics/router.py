"""Read API over one disk analysis job's persisted results (evidence.read; M9 phase 8 on the
phase-1 frozen paths and schemas).

Every route answers 404 for unknown or foreign jobs, for jobs of another analyzer and for
`extract` jobs, and `409 analysis_not_ready` while the job is queued or running. Findings,
IOCs and the shared timeline of disk jobs are served by the shared per-job routes
(pcap_analysis.router: /findings, /iocs, /timeline). Pages are not audited (the M7 evidence
view audit covers the job page); the interop exports (`GET …/disk/exports/*`: a TSK body file
for `mactime`, the timeline as CSV / JSONL in Timesketch's columns, the flagged files' md5
list for an Autopsy hash set; RT12) are audited downloads (`exports_interop`).

`from` / `to` are aware datetimes (422 otherwise, and when `from` is after `to`); `q` is
1-128 characters; `hash` is an md5, sha1 or sha256 (32 / 40 / 64 hex characters).
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import StreamingResponse
from pydantic import AwareDatetime

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.case_timeline.service import InvalidRange
from app.modules.disk_forensics import exports_interop, service
from app.modules.disk_forensics import repository as repo
from app.modules.disk_forensics.schemas import (
    DirPage,
    DiskSummaryOut,
    EventPage,
    FileDetailOut,
    FilePage,
    PartitionPage,
    TimeColumn,
    TimelinePage,
)

router = APIRouter(prefix="/orgs/{org_id}/analyses/{job_id}/disk", tags=["disk-forensics"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Search = Annotated[SearchTerm | None, Query(min_length=1, max_length=128)]
# `ref=<row id>`: a page with just that row of the job (citation deep links; 404 otherwise).
RowRef = Annotated[uuid.UUID | None, Query()]
PartitionFilter = Annotated[int | None, Query(ge=0, le=127)]
# An unsigned 64-bit inode number as DECIMAL TEXT (the schema says string: a JSON / JS number
# loses its low bits above 2**53; M9 phase 10 for the web's directory browser).
Address = Annotated[str | None, Query(pattern=r"^[0-9]{1,20}$", examples=["1234"])]
U64_MAX = 2**64 - 1


def _u64(value: str | None) -> int | None:
    if value is None:
        return None
    number = int(value)
    if number > U64_MAX:
        raise RequestValidationError(
            [{"type": "less_than_equal", "loc": ("query", "parent"), "msg": "above 2**64 - 1"}]
        )
    return number


Since = Annotated[AwareDatetime | None, Query(alias="from")]
Until = Annotated[AwareDatetime | None, Query(alias="to")]
ArtifactFilter = Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")]
HashFilter = Annotated[
    str | None, Query(pattern=r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
]
ExtFilter = Annotated[str | None, Query(min_length=1, max_length=32, pattern=r"^[^\x00]+$")]
MagicFilter = Literal["pe", "elf", "script", "archive", "document", "other", "empty"]


def _range(since: AwareDatetime | None, until: AwareDatetime | None) -> None:
    if since is not None and until is not None and since > until:
        raise InvalidRange()


@router.get("", response_model=DiskSummaryOut)
async def get_disk_summary(job_id: uuid.UUID, ctx: EvidenceRead) -> DiskSummaryOut:
    """Image facts (segments with the API's own sha256, format, the worker-reported media
    hash status), per-stage and per-partition status, artifact counts and the hash sets used;
    `404 results_not_available` for a terminal job without a stored image."""
    job = await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await service.summary(ctx.session, ctx.org_id, job)


@router.get("/partitions", response_model=PartitionPage)
async def list_partitions(
    job_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep
) -> PartitionPage:
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.partitions(ctx.session, ctx.org_id, job_id, page)
    return PartitionPage(items=[service.partition_out(r) for r in rows], total=total)


@router.get("/files", response_model=FilePage)
async def list_files(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    partition: PartitionFilter = None,
    flag: Annotated[repo.FileFlag | None, Query()] = None,
    magic: Annotated[MagicFilter | None, Query()] = None,
    sha256: Annotated[str | None, Query(pattern=r"^[0-9a-fA-F]{64}$")] = None,
    hash: HashFilter = None,  # noqa: A002 - API name
    ext: ExtFilter = None,
    since: Since = None,
    until: Until = None,
    include_known: Annotated[bool, Query()] = False,
    ref: RowRef = None,
) -> FilePage:
    """`q`: substring of the path; `flag`: `deleted`, `orphan`, `hard_linked`, `stream` (an
    NTFS named stream), `known` (a known-bad set match), `notable`, `yara`; `hash`: md5,
    sha1 or sha256; `from` / `to`: any of the four times in the range. Known-good files are
    hidden unless `include_known` (labelled "known (reference set)", RT18). Ordered by
    partition, inode, id."""
    _range(since, until)
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.files(
        ctx.session,
        ctx.org_id,
        job_id,
        page,
        q=q,
        partition=partition,
        flag=flag,
        magic=magic,
        digests=[d for d in (sha256, hash) if d is not None],
        ext=ext,
        since=since,
        until=until,
        include_known=include_known,
        ref=ref,
    )
    return FilePage(items=[service.file_out(r) for r in rows], total=total)


@router.get("/files/{file_id}", response_model=FileDetailOut)
async def get_file(job_id: uuid.UUID, file_id: uuid.UUID, ctx: EvidenceRead) -> FileDetailOut:
    """Every column, the inode's other names (RT7) and named streams, and whether "Export"
    is offered (with the reason when not); 404 for a file id of another job."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await service.file_detail(ctx.session, ctx.org_id, job_id, file_id)


@router.get("/dirs", response_model=DirPage)
async def list_dir(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    partition: PartitionFilter = None,
    parent: Address = None,
) -> DirPage:
    """The entries listed in one directory (`parent` = the directory's `meta_addr`; the root
    when omitted; the lowest partition with files when `partition` is omitted; RT13)."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await service.dir_page(
        ctx.session, ctx.org_id, job_id, page, partition=partition, parent=_u64(parent)
    )


@router.get("/events", response_model=EventPage)
async def list_events(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    artifact: ArtifactFilter = None,
    since: Since = None,
    until: Until = None,
    ref: RowRef = None,
) -> EventPage:
    """The parsed artifact events in time order; `q`: substring of the message."""
    _range(since, until)
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.events(
        ctx.session,
        ctx.org_id,
        job_id,
        page,
        q=q,
        artifact=artifact,
        since=since,
        until=until,
        ref=ref,
    )
    return EventPage(items=[service.event_out(r) for r in rows], total=total)


@router.get("/timeline", response_model=TimelinePage)
async def merged_timeline(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    source: Annotated[Literal["file", "event"] | None, Query()] = None,
    time: Annotated[TimeColumn | None, Query()] = None,
    artifact: ArtifactFilter = None,
    since: Since = None,
    until: Until = None,
) -> TimelinePage:
    """File-system MACB times (one row per set time column) merged with the events, ordered
    by (ts, stream, id) where the stream is the time column or `event` (index order per
    stream, RT14). `time` narrows the file columns; `artifact` implies events only."""
    _range(since, until)
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    items, total = await service.timeline_page(
        ctx.session,
        ctx.org_id,
        job_id,
        page,
        source=source,
        time=time,
        artifact=artifact,
        since=since,
        until=until,
    )
    return TimelinePage(items=items, total=total)


@router.get(
    "/exports/{name}",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/plain": {}, "text/csv": {}, "application/x-ndjson": {}}}},
)
async def interop_export(
    job_id: uuid.UUID,
    name: exports_interop.InteropExport,
    ctx: EvidenceRead,
    request: Request,
    excel: Annotated[bool, Query()] = False,
) -> StreamingResponse:
    """Audited download: `bodyfile` (TSK body file for `mactime`), `timeline.csv` /
    `timeline.jsonl` (Timesketch columns `message`, `datetime`, `timestamp_desc`, plus ours;
    `excel=1` adds a UTF-8 BOM to the CSV), `notable-hashes.txt` (one md5 per line: an
    Autopsy hash-set import). The label is in `X-CyberLab-Sensitivity` and the file name."""
    job = await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await exports_interop.export(ctx, job, name, request, excel=excel)
