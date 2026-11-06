"""Read API over one disk analysis job's persisted results (evidence.read; M9 phase 1 stubs on
the frozen paths and models, phase 8 implements them).

Every route will answer 404 for unknown or foreign jobs and for jobs of another analyzer, and
`409 analysis_not_ready` while the job is queued or running. Findings, IOCs and the shared
timeline of disk jobs are served by the shared per-job routes (pcap_analysis.router). The
interop exports (`GET …/disk/exports/*`: a TSK body file for `mactime`, the timeline as CSV /
JSONL in Timesketch's columns, the flagged files' md5 list for an Autopsy hash set; RT12) are
audited downloads. Until phase 8 every route answers `501 not_implemented`.
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.core.validation import SearchTerm
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
Search = Annotated[SearchTerm | None, Query()]
# `ref=<row id>`: a page with just that row of the job (citation deep links; 404 otherwise).
RowRef = Annotated[uuid.UUID | None, Query()]
PartitionFilter = Annotated[int | None, Query(ge=0, le=127)]
Address = Annotated[int | None, Query(ge=0, le=2**64 - 1)]
InteropExport = Literal["bodyfile", "timeline.csv", "timeline.jsonl", "notable-hashes.txt"]
FileFlag = Literal["deleted", "orphan", "hard_linked", "stream", "known", "notable", "yara"]
MagicFilter = Literal["pe", "elf", "script", "archive", "document", "other", "empty"]


@router.get("", response_model=DiskSummaryOut)
async def get_disk_summary(job_id: uuid.UUID, ctx: EvidenceRead) -> DiskSummaryOut:
    """Image facts (segments, format, worker-reported media hash status), per-stage and
    per-partition status, artifact counts and the hash sets used."""
    raise not_implemented()


@router.get("/partitions", response_model=PartitionPage)
async def list_partitions(
    job_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep
) -> PartitionPage:
    raise not_implemented()


@router.get("/files", response_model=FilePage)
async def list_files(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    partition: PartitionFilter = None,
    flag: Annotated[FileFlag | None, Query()] = None,
    magic: Annotated[MagicFilter | None, Query()] = None,
    sha256: Annotated[str | None, Query(pattern=r"^[0-9a-fA-F]{64}$")] = None,
    include_known: Annotated[bool, Query()] = False,
    ref: RowRef = None,
) -> FilePage:
    """`q`: substring of the path; known-good files are hidden unless `include_known`
    (labelled "known (reference set)", RT18)."""
    raise not_implemented()


@router.get("/files/{file_id}", response_model=FileDetailOut)
async def get_file(job_id: uuid.UUID, file_id: uuid.UUID, ctx: EvidenceRead) -> FileDetailOut:
    raise not_implemented()


@router.get("/dirs", response_model=DirPage)
async def list_dir(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    partition: PartitionFilter = None,
    parent: Address = None,
) -> DirPage:
    """The entries listed in one directory (`parent` = the directory's `meta_addr`; the root
    when omitted; RT13)."""
    raise not_implemented()


@router.get("/events", response_model=EventPage)
async def list_events(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    artifact: Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")] = None,
    ref: RowRef = None,
) -> EventPage:
    raise not_implemented()


@router.get("/timeline", response_model=TimelinePage)
async def merged_timeline(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    source: Annotated[Literal["file", "event"] | None, Query()] = None,
    time: Annotated[TimeColumn | None, Query()] = None,
) -> TimelinePage:
    """File-system MACB times merged with the Plaso events (index order per column, RT14)."""
    raise not_implemented()


@router.get("/exports/{name}", response_class=StreamingResponse)
async def interop_export(job_id: uuid.UUID, name: InteropExport, ctx: EvidenceRead) -> None:
    """Audited download: `bodyfile` (TSK body file for `mactime`), `timeline.csv` /
    `timeline.jsonl` (Timesketch columns `message`, `datetime`, `timestamp_desc`, plus ours),
    `notable-hashes.txt` (one md5 per line: an Autopsy hash-set import)."""
    raise not_implemented()
