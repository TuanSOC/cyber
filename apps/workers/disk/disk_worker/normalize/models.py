"""Per-stage probe row models (root side): pydantic, `extra="forbid"`, bounded.

Every probe row is re-validated here before it becomes a `disk.v1` record; a row that fails
counts as bad (`engine_errors`) and is dropped. The probe's own counts are never trusted for
caps. Integers the image controls (mode, uid, gid) are taken as plain bounded ints here and
clamped to the contract's ranges in `records`, so a hostile value costs a field, not the row.
"""

from typing import Annotated, Literal

from cyberlab_jobs.disk import FsType, PartitionOs
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

U64 = Annotated[StrictInt, Field(ge=0, le=2**64 - 1)]
I64 = Annotated[StrictInt, Field(ge=-(2**63), le=2**63 - 1)]
Code = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
Text = Annotated[StrictStr, Field(max_length=4096)]
Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Hex40 = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
TimePair = Annotated[list[I64], Field(min_length=2, max_length=2)]
TIME_KEYS = ("mtime", "atime", "ctime", "crtime")


class _Row(BaseModel):
    # Not `strict=True` globally: enums (FsType) must accept their JSON strings; ints and
    # bools are Strict* per field.
    model_config = ConfigDict(extra="forbid", frozen=True)


class PartitionRow(_Row):
    index: Annotated[StrictInt, Field(ge=0, lt=128)]
    start_sector: U64
    length_sectors: U64
    sector_size: Annotated[StrictInt, Field(ge=1, le=65_536)]
    volume_system: Literal["gpt", "dos", "none"]
    description: Text | None = None
    fs_type: FsType | None = None
    fs_status: Literal["ok", "unsupported", "encrypted", "undetermined", "error", "truncated"]
    reason: Code | None = None
    block_size: Annotated[StrictInt, Field(ge=1, le=2**31 - 1)] | None = None
    os: PartitionOs = "none"
    os_name: Text | None = None
    counts: Annotated[dict[Code, U64], Field(max_length=16)] = {}


HashStatusRow = Literal[
    "hashed", "pending", "too_large", "budget", "not_allocated", "not_regular", "error"
]
MagicRow = Literal["pe", "elf", "script", "archive", "document", "other", "empty"]


class FileRow(_Row):
    n: Annotated[StrictInt, Field(ge=0)]
    meta_addr: U64
    meta_seq: I64 | None = None
    stream: Text | None = None
    path: Text
    path_truncated: StrictBool
    parent_addr: U64 | None = None
    name: Text
    name_lossy: StrictBool
    ext: Text | None = None
    type: Literal["reg", "dir", "lnk", "other"]
    allocated: StrictBool
    deleted: StrictBool
    orphan: StrictBool
    reallocated: StrictBool
    hard_linked: StrictBool
    size: I64 | None = None
    mode: I64 | None = None
    uid: I64 | None = None
    gid: I64 | None = None
    times: Annotated[
        dict[Literal["mtime", "atime", "ctime", "crtime"], TimePair | None], Field(max_length=4)
    ] = {}
    time_basis: Literal["utc", "local_unknown"]
    magic: MagicRow | None = None
    hash_status: HashStatusRow | None = None
    md5: Hex32 | None = None
    sha1: Hex40 | None = None
    sha256: Hex64 | None = None


class HashRow(_Row):
    n: Annotated[StrictInt, Field(ge=0)]
    hash_status: Literal["hashed", "budget", "error"]
    md5: Hex32 | None = None
    sha1: Hex40 | None = None
    sha256: Hex64 | None = None


class CollectedRow(_Row):
    n: Annotated[StrictInt, Field(ge=0)]
    status: Literal["ok", "refused", "error"]
    reason: Code | None = None
    target: Text | None = None
    meta_addr: U64 | None = None
    meta_seq: I64 | None = None
    stream: Text | None = None
    path: Text | None = None
    artifact: Code | None = None
    size: U64 | None = None


class StageStatusDoc(_Row):
    """`status.json` of a probe stage (root reads it bounded and validates it here)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    stage: Code | None = None
    status: Literal["ok", "failed", "unsupported"]
    error: Annotated[str, Field(max_length=64)] | None = None
    error_code: Code | None = None
    reason: Code | None = None
    rows: Annotated[StrictInt, Field(ge=0)] = 0
    truncated: StrictBool = False
    counts: Annotated[dict[Code, Annotated[StrictInt, Field(ge=0)]], Field(max_length=32)] = {}
    facts: dict[str, object] = {}
    audit: Annotated[dict[Code, Annotated[StrictInt, Field(ge=0)]], Field(max_length=16)] = {}


__all__ = [
    "TIME_KEYS",
    "CollectedRow",
    "FileRow",
    "HashRow",
    "PartitionRow",
    "StageStatusDoc",
]
