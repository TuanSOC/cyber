"""Interop exports of one disk job (M9 phase 8; RT12: Autopsy imports hash sets, not
timelines), served by `GET /analyses/{job}/disk/exports/{name}`:

- `bodyfile`: a TSK body file 3.x for `mactime` and body-file tools (not an Autopsy import),
  one line per listed entry: `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|
  crtime` (times in epoch seconds, 0 when unknown; md5 `0` when not hashed).
  - `name` is `/p<partition>/<path>` (a stream as `<path>:<stream>`; ` (deleted)` /
    ` (deleted-realloc)` appended as TSK does);
  - `inode` is `<meta_addr>[-<meta_seq>][-<stream>]`;
  - `|`, `\\` and control characters in a name or a stream are written as `\\xNN` (`|` ->
    `\\x7c`, newline -> `\\x0a`), so no image-supplied name can add a field or a line. TSK's
    own `fls -m` does not escape (documented in DISK_FORENSICS.md).
- `timeline.csv` / `timeline.jsonl`: the merged timeline (file-system MACB times and the
  events, in the read API's (ts, stream, id) order) with Timesketch's required columns
  first (`message`, `datetime` ISO 8601 UTC, `timestamp_desc`), then `source`, `artifact`,
  `partition`, `path`, `time_basis`. CSV cells go through `core.csv_safe` (formula-safe,
  RFC 4180), UTF-8 without a BOM (Timesketch's importer expects none) unless `?excel=1`; no
  comment line (it would break both importers): the label travels in the
  `X-CyberLab-Sensitivity` header and the file name instead.
- `notable-hashes.txt`: one lowercase md5 per line for the files with a finding, a YARA
  match or a `known_bad` / `notable` set match (Autopsy's plain-text hash-set import).

Every download is audited `disk.interop_exported` (kind, job, row count, label) and committed
before the first byte (the result tables are written once, so the count taken then is the
count streamed). The body is streamed from its own tenant session (membership re-checked,
`statement_timeout` 120 s) in batches of `repository.EXPORT_BATCH` rows: nothing buffers the
whole result. Restricted evidence (TLP:RED by default, RT2) answers like any other read for
`evidence.read`, labelled `X-CyberLab-Sensitivity: restricted` and `-TLP-RED` in the name.
"""

import heapq
import json
import re
import uuid
from collections.abc import AsyncIterator, Callable, Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from cyberlab_jobs.disk import FILE_FLAG_BITS
from cyberlab_jobs.report import TLP, TLP_LABELS
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.csv_safe import write_csv
from app.core.deps import CurrentUser
from app.core.filenames import content_disposition
from app.core.rbac import OrgContext, Permission, org_session
from app.modules.analysis.models import AnalysisJob
from app.modules.audit import service as audit
from app.modules.disk_forensics import repository as repo
from app.modules.evidence import repository as evidence_repo
from app.modules.investigations.schemas import case_ref
from app.modules.memory_analysis.models import SensitivityState

InteropExport = Literal["bodyfile", "timeline.csv", "timeline.jsonl", "notable-hashes.txt"]

EXPORT_TIMEOUT = "SET LOCAL statement_timeout = '120s'"
AUDIT_ACTION = "disk.interop_exported"
SENSITIVITY_HEADER = "X-CyberLab-Sensitivity"
RESTRICTED_LABEL = "restricted"
EXPORT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "sandbox",
}
UTF8_BOM = b"\xef\xbb\xbf"
CHUNK_BYTES = 64 * 1024
# (base name, extension, media type) per export.
FILES: dict[str, tuple[str, str, str]] = {
    "bodyfile": ("bodyfile", "body", "text/plain; charset=utf-8"),
    "timeline.csv": ("timeline", "csv", "text/csv; charset=utf-8"),
    "timeline.jsonl": ("timeline", "jsonl", "application/x-ndjson"),
    "notable-hashes.txt": ("notable-hashes", "txt", "text/plain; charset=utf-8"),
}

# --- Body file -----------------------------------------------------------------------------

BODYFILE_FIELDS = 11
_ESCAPED = re.compile(r"[|\\\x00-\x1f\x7f]")
_UNESCAPE = re.compile(r"\\x([0-9a-f]{2})")
TYPE_CHARS = {"reg": "r", "dir": "d", "lnk": "l", "other": "-"}


def escape_field(value: str) -> str:
    """`|`, `\\` and control characters as `\\xNN` (lowercase hex): a field can never hold
    the separator or a line break, and the escape itself is unambiguous."""
    return _ESCAPED.sub(lambda m: f"\\x{ord(m.group()):02x}", value)


def unescape_field(value: str) -> str:
    return _UNESCAPE.sub(lambda m: chr(int(m.group(1), 16)), value)


def mode_string(file_type: str, mode: int | None) -> str:
    """TSK's `mode_as_string`: `<name type>/<meta type><rwx x 3>` (e.g. `r/rrwxr-xr-x`),
    with setuid / setgid / sticky shown as `s` / `S` and `t` / `T`."""
    kind = TYPE_CHARS.get(file_type, "-")
    bits = (mode or 0) & 0o7777
    perms = []
    for shift in (6, 3, 0):
        triple = (bits >> shift) & 0o7
        perms += [c if triple & bit else "-" for c, bit in (("r", 4), ("w", 2), ("x", 1))]
    for special, index, char in ((0o4000, 2, "s"), (0o2000, 5, "s"), (0o1000, 8, "t")):
        if bits & special:
            perms[index] = char if perms[index] == "x" else char.upper()
    return f"{kind}/{kind}{''.join(perms)}"


def _epoch(value: datetime | None) -> int:
    return 0 if value is None else int(value.timestamp())


def bodyfile_name(partition: int, path: str, stream: str | None, flags: int) -> str:
    name = f"/p{partition}/{path}"
    if stream:
        name = f"{name}:{stream}"
    name = escape_field(name)
    if flags & FILE_FLAG_BITS["reallocated"]:
        name += " (deleted-realloc)"
    elif flags & FILE_FLAG_BITS["deleted"]:
        name += " (deleted)"
    return name


def bodyfile_inode(meta_addr: object, meta_seq: int | None, stream: str | None) -> str:
    inode = str(int(str(meta_addr)))  # NUMERIC(20, 0) -> plain decimal text
    if meta_seq is not None:
        inode += f"-{meta_seq}"
    if stream:
        inode += f"-{escape_field(stream)}"
    return inode


def bodyfile_line(row: Any) -> str:
    """One entry of a `repository.BODYFILE_COLUMNS` row as a body file line (with `\\n`)."""
    fields = [
        row.md5.lower() if row.md5 else "0",
        bodyfile_name(row.partition_index, row.path, row.stream, row.flags),
        bodyfile_inode(row.meta_addr, row.meta_seq, row.stream),
        mode_string(row.type, row.mode),
        str(row.uid or 0),
        str(row.gid or 0),
        str(row.size or 0),
        str(_epoch(row.atime)),
        str(_epoch(row.mtime)),
        str(_epoch(row.ctime)),
        str(_epoch(row.crtime)),
    ]
    return "|".join(fields) + "\n"


def parse_bodyfile_line(line: str) -> list[str]:
    """Our reference parser (tests and docs): the 11 fields, names unescaped."""
    fields = line.rstrip("\n").split("|")
    if len(fields) != BODYFILE_FIELDS:
        raise ValueError(f"a body file line has {BODYFILE_FIELDS} fields, not {len(fields)}")
    fields[1] = unescape_field(fields[1])
    return fields


# --- Timeline ------------------------------------------------------------------------------

TIMELINE_COLUMNS: tuple[str, ...] = (
    "message",
    "datetime",
    "timestamp_desc",
    "source",
    "artifact",
    "partition",
    "path",
    "time_basis",
)
# Plaso's descriptions of the file-system times.
TIME_DESCRIPTIONS = {
    "mtime": "Content Modification Time",
    "atime": "Last Access Time",
    "ctime": "Metadata Modification Time",
    "crtime": "Creation Time",
}
LOCAL_UNKNOWN = "local_unknown"
LOCAL_UNKNOWN_NOTE = " (local time, zone unknown)"


def iso_utc(value: datetime) -> str:
    """ISO 8601 in UTC (`2026-10-01T08:00:00+00:00`), as Timesketch's importer reads it."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def time_description(stream: str, time_basis: str | None) -> str:
    """A file time's description; FAT times of unknown zone (stored as if UTC) say so."""
    desc = TIME_DESCRIPTIONS[stream]
    return desc + LOCAL_UNKNOWN_NOTE if time_basis == LOCAL_UNKNOWN else desc


def timeline_record(row: Any) -> dict[str, Any]:
    """One merged-timeline row (`repository._stream_select` columns) in the export columns."""
    if row.stream == repo.EVENT_STREAM:
        message, desc, source, artifact = row.message, row.ts_desc, "event", row.artifact
    else:
        message = row.path
        desc = time_description(row.stream, row.time_basis)
        source, artifact = "file", None
    return {
        "message": message,
        "datetime": iso_utc(row.ts),
        "timestamp_desc": desc,
        "source": source,
        "artifact": artifact,
        "partition": row.partition,
        "path": row.path,
        "time_basis": row.time_basis,
    }


def timeline_csv_cells(record: dict[str, Any]) -> list[object]:
    return ["" if record[c] is None else record[c] for c in TIMELINE_COLUMNS]


def timeline_jsonl_line(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"


def _merge_key(row: Any) -> tuple[datetime, str, uuid.UUID]:
    return (row.ts, row.stream, row.id)


async def merge_streams(streams: Sequence[AsyncIterator[Any]]) -> AsyncIterator[Any]:
    """K-way merge of index-ordered streams by (ts, stream, id): one row buffered per
    stream (the streams themselves read in batches)."""
    heap: list[tuple[tuple[datetime, str, uuid.UUID], int, Any]] = []
    for index, stream in enumerate(streams):
        first = await anext(stream, None)
        if first is not None:
            heap.append((_merge_key(first), index, first))
    heapq.heapify(heap)
    while heap:
        _, index, row = heapq.heappop(heap)
        yield row
        following = await anext(streams[index], None)
        if following is not None:
            heapq.heappush(heap, (_merge_key(following), index, following))


# --- Streaming -----------------------------------------------------------------------------


async def _chunked(lines: AsyncIterator[str]) -> AsyncIterator[bytes]:
    pending: list[str] = []
    size = 0
    async for line in lines:
        pending.append(line)
        size += len(line)
        if size >= CHUNK_BYTES:
            yield "".join(pending).encode("utf-8")
            pending.clear()
            size = 0
    if pending:
        yield "".join(pending).encode("utf-8")


async def _bodyfile(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AsyncIterator[str]:
    async for row in repo.bodyfile_rows(session, org_id, job_id):
        yield bodyfile_line(row)


async def _timeline_rows(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AsyncIterator[Any]:
    streams = [
        repo.timeline_stream_rows(session, org_id, job_id, s)
        for s in repo.timeline_streams(None, None, None)
    ]
    async for row in merge_streams(streams):
        yield row


async def _timeline_jsonl(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AsyncIterator[str]:
    async for row in _timeline_rows(session, org_id, job_id):
        yield timeline_jsonl_line(timeline_record(row))


async def _timeline_csv(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, *, excel: bool
) -> AsyncIterator[bytes]:
    if excel:
        yield UTF8_BOM
    for chunk in write_csv([list(TIMELINE_COLUMNS)]):
        yield chunk
    batch: list[list[object]] = []
    async for row in _timeline_rows(session, org_id, job_id):
        batch.append(timeline_csv_cells(timeline_record(row)))
        if len(batch) >= repo.EXPORT_BATCH:
            for chunk in write_csv(batch):
                yield chunk
            batch = []
    if batch:
        for chunk in write_csv(batch):
            yield chunk


async def _notable(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    refs: tuple[set[uuid.UUID], set[tuple[int, str]]],
) -> AsyncIterator[str]:
    async for md5 in repo.notable_md5_rows(session, org_id, job_id, *refs):
        yield md5 + "\n"


Body = Callable[[AsyncSession], AsyncIterator[bytes]]


async def _stream(org_id: uuid.UUID, user: CurrentUser, body: Body) -> AsyncIterator[bytes]:
    """The body from its own tenant session (the request's is closed before the first byte),
    with the membership re-checked and the export statement timeout."""
    async with org_session(org_id, user, Permission.EVIDENCE_READ) as stream_ctx:
        await stream_ctx.session.execute(text(EXPORT_TIMEOUT))
        async for chunk in body(stream_ctx.session):
            yield chunk


def _body(
    name: InteropExport,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    *,
    excel: bool,
    refs: tuple[set[uuid.UUID], set[tuple[int, str]]],
) -> Body:
    def build(session: AsyncSession) -> AsyncIterator[bytes]:
        if name == "bodyfile":
            return _chunked(_bodyfile(session, org_id, job_id))
        if name == "timeline.csv":
            return _timeline_csv(session, org_id, job_id, excel=excel)
        if name == "timeline.jsonl":
            return _chunked(_timeline_jsonl(session, org_id, job_id))
        return _chunked(_notable(session, org_id, job_id, refs))

    return build


# --- Labels and the response ---------------------------------------------------------------


def label_tag(label: str) -> str:
    """The file-name form of a label: `restricted` -> `TLP-RED`, `TLP:AMBER+STRICT` ->
    `TLP-AMBER-STRICT`."""
    if label == RESTRICTED_LABEL:
        return "TLP-RED"
    return label.replace("TLP:", "TLP-").replace("+", "-")


def export_filename(case: str | None, job_id: uuid.UUID, name: InteropExport, label: str) -> str:
    base, ext, _ = FILES[name]
    prefix = f"{case}-" if case else ""
    return f"{prefix}disk-{str(job_id)[:8]}-{base}-{label_tag(label)}.{ext}"


async def _label(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob
) -> tuple[str, str | None]:
    """`restricted` when any segment is restricted (RT2), else the case's TLP label; and
    the case reference."""
    evidence_ids = await repo.segment_evidence_ids(session, org_id, job)
    states = await evidence_repo.sensitivity_states(session, org_id, evidence_ids)
    restricted = any(state == SensitivityState.RESTRICTED.value for state, _ in states.values())
    inv = await repo.investigation_of(session, org_id, job.evidence_id)
    case = case_ref(inv.case_number) if inv is not None else None
    if restricted:
        return RESTRICTED_LABEL, case
    tlp = TLP(inv.tlp) if inv is not None else TLP.AMBER
    return TLP_LABELS[tlp], case


async def _row_count(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    name: InteropExport,
    refs: tuple[set[uuid.UUID], set[tuple[int, str]]],
) -> int:
    if name == "bodyfile":
        return await repo.file_count(session, org_id, job_id)
    if name in ("timeline.csv", "timeline.jsonl"):
        return await repo.timeline_count(
            session, org_id, job_id, repo.timeline_streams(None, None, None)
        )
    return await repo.notable_md5_count(session, org_id, job_id, *refs)


async def export(
    ctx: OrgContext,
    job: AnalysisJob,
    name: InteropExport,
    request: HTTPConnection,
    *,
    excel: bool = False,
) -> StreamingResponse:
    """Audit (committed), then stream the export from a fresh tenant session."""
    session = ctx.session
    refs: tuple[set[uuid.UUID], set[tuple[int, str]]] = (set(), set())
    if name == "notable-hashes.txt":
        refs = await repo.finding_file_refs(session, ctx.org_id, job.id)
    label, case = await _label(session, ctx.org_id, job)
    rows = await _row_count(session, ctx.org_id, job.id, name, refs)
    audit.record(
        session,
        action=AUDIT_ACTION,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="analysis_job",
        target_id=job.id,
        details={
            "kind": name,
            "job_id": str(job.id),
            "rows": rows,
            "sensitivity": label,
            "excel": excel if name == "timeline.csv" else None,
        },
        request=request,
    )
    await session.commit()
    _, _, media_type = FILES[name]
    filename = export_filename(case, job.id, name, label)
    return StreamingResponse(
        _stream(ctx.org_id, ctx.user, _body(name, ctx.org_id, job.id, excel=excel, refs=refs)),
        media_type=media_type,
        headers={
            **EXPORT_HEADERS,
            SENSITIVITY_HEADER: label,
            "Content-Disposition": content_disposition(filename),
        },
    )
