"""Read API and file-export schemas of disk forensics (M9 phase 1, FROZEN; filled by phases 8
and 10).

Worker-reported values are labelled as such (RT17): `media_hash_status` is "consistent with
the hash stored at acquisition", never "verified"; `worker_sha256` of an export is display only
(promotion re-hashes on the trusted side). Paths, names, EWF acquisition values and messages
come from the image: inert text.
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.core.pagination import Page



def _to_decimal_text(value: object) -> object:
    """An unsigned 64-bit number (NUMERIC(20,0) in the database) as decimal text: a JSON number
    above 2**53 loses its low bits in the browser (the M8 review lesson for addresses)."""
    if isinstance(value, Decimal):
        value = int(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if not 0 <= value < 2**64:
            raise ValueError("value outside the unsigned 64-bit range")
        return str(value)
    return value


# Inode numbers (`meta_addr`, `parent_addr`) and sector numbers are sent as decimal strings.
U64Text = Annotated[
    str, BeforeValidator(_to_decimal_text), Field(pattern=r"^[0-9]{1,20}$", examples=["1234"])
]
MediaHashStatus = Literal["matched", "mismatch", "absent", "not_verified"]
FsStatus = Literal["ok", "unsupported", "encrypted", "undetermined", "error", "truncated"]
ExportState = Literal["pending", "ready", "failed", "promoted", "expired"]
TimeColumn = Literal["mtime", "atime", "ctime", "crtime"]


class DiskStageOut(BaseModel):
    stage: str
    partition_index: int | None = None
    status: str
    reason: str | None = None
    rows: int = 0
    truncated: bool = False
    duration_ms: int = 0
    error_code: str | None = None


class DiskArtifactStatOut(BaseModel):
    artifact: str
    files: int = 0
    bytes: int = 0
    events_read: int = 0
    events_stored: int = 0


class DiskHashSetOut(BaseModel):
    name: str
    kind: Literal["known_good", "known_bad", "notable"]
    count: int
    manifest_sha256: str


class DiskSegmentOut(BaseModel):
    ordinal: int
    evidence_id: uuid.UUID
    original_filename: str
    size_bytes: int
    sha256: str  # computed by the API at upload: the only trusted image hash (RT17)


class DiskSummaryOut(BaseModel):
    """`GET /analyses/{job}/disk`."""

    job_id: uuid.UUID
    profile: Literal["triage", "full"]
    format: Literal["raw", "split_raw", "ewf"]
    segments: list[DiskSegmentOut]
    media_size: U64Text
    sector_size: int
    media_sha256: str | None = None  # worker-reported
    ewf_md5: str | None = None
    ewf_sha1: str | None = None
    media_hash_status: MediaHashStatus | None = None  # worker-reported (RT17)
    ewf_meta: dict[str, str] = {}
    volume_system: str | None = None
    engine: str
    timeline_engine: Literal["plaso", "replay", "none"]
    tool_versions: dict[str, str] = {}
    stages: list[DiskStageOut] = []
    artifacts: list[DiskArtifactStatOut] = []
    hashsets: list[DiskHashSetOut] = []
    counts: dict[str, int] = {}
    truncated: bool = False


class PartitionOut(BaseModel):
    id: uuid.UUID
    index: int
    start_sector: U64Text
    length_sectors: U64Text
    description: str | None = None
    vs_flags: str
    fs_type: str | None = None
    fs_status: FsStatus
    fs_label: str | None = None
    fs_uuid: str | None = None
    block_size: int | None = None
    os: Literal["windows", "linux", "none"]
    os_name: str | None = None
    error_code: str | None = None
    counts: dict[str, int] = {}


class PartitionPage(Page[PartitionOut]):
    pass


class FileOut(BaseModel):
    id: uuid.UUID
    partition_index: int
    meta_addr: U64Text
    meta_seq: int | None = None
    stream: str | None = None
    path: str
    parent_addr: U64Text | None = None
    name: str
    ext: str | None = None
    type: Literal["reg", "dir", "lnk", "other"]
    flags: list[str] = []  # names of the set FILE_FLAG_BITS
    size: int | None = None
    mtime: datetime | None = None
    atime: datetime | None = None
    ctime: datetime | None = None
    crtime: datetime | None = None
    time_basis: Literal["utc", "local_unknown"] = "utc"
    magic: str | None = None
    hash_status: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    known: Literal["good", "bad", "notable"] | None = None
    known_set: str | None = None
    yara_rules: list[str] = []


class FilePage(Page[FileOut]):
    pass


class FileDetailOut(FileOut):
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    # Every other name of the same inode (hard links, RT7) and the file's named streams.
    other_names: list[str] = []
    streams: list[str] = []
    # Whether "Export" is offered (allocated regular file ≤ DISK_EXPORT_MAX_BYTES, no name on
    # the never-collected list) and why not.
    exportable: bool = False
    not_exportable_reason: str | None = None


class DirPage(Page[FileOut]):
    """`GET …/disk/dirs?partition=&parent=`: the entries listed in one directory."""

    partition_index: int | None = None
    parent_addr: U64Text | None = None


class EventOut(BaseModel):
    id: uuid.UUID
    ts: datetime
    ts_desc: str
    artifact: str
    parser: str
    data_type: str
    partition_index: int
    path: str
    file_id: uuid.UUID | None = None
    message: str
    attributes: dict[str, Any] = {}


class EventPage(Page[EventOut]):
    pass


class TimelineItemOut(BaseModel):
    """The merged timeline: file-system MACB times and Plaso events, in time order."""

    ts: datetime
    source: Literal["file", "event"]
    kind: str  # `mtime` / `atime` / `ctime` / `crtime`, or the event's artifact
    description: str
    path: str
    file_id: uuid.UUID | None = None
    event_id: uuid.UUID | None = None


class TimelinePage(Page[TimelineItemOut]):
    pass


class ExportRequestIn(BaseModel):
    """`POST /analyses/{job}/disk/file-exports` (RT29): 1..20 listed files of the job."""

    model_config = ConfigDict(extra="forbid")

    file_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=20)]


class DiskExportOut(BaseModel):
    id: uuid.UUID
    export_job_id: uuid.UUID
    source_job_id: uuid.UUID
    file_id: uuid.UUID
    path: str
    state: ExportState
    size: int | None = None
    worker_sha256: str | None = None  # untrusted, display only
    evidence_id: uuid.UUID | None = None
    error_code: str | None = None
    created_at: datetime
    promoted_at: datetime | None = None


class DiskExportList(BaseModel):
    items: list[DiskExportOut]


__all__ = [
    "U64Text",
    "DirPage",
    "DiskExportList",
    "DiskExportOut",
    "DiskSummaryOut",
    "EventOut",
    "EventPage",
    "ExportRequestIn",
    "FileDetailOut",
    "FileOut",
    "FilePage",
    "PartitionOut",
    "PartitionPage",
    "TimeColumn",
    "TimelineItemOut",
    "TimelinePage",
]
