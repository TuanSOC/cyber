"""Case timeline export (M6 phase 5): the merged timeline as a streamed CSV or JSON
attachment.

- At most `TIMELINE_EXPORT_MAX_ROWS` entries in timeline order; when capped, the CSV ends
  with a truncation marker row and the JSON says `truncated: true`.
- CSV: a `# TLP:<label> CASE-xxxxx exported <ts>` line, the column header, then RFC 4180
  rows through `csv_safe.write_csv` (formula cells neutralized, RT19).
- JSON: `TimelineExportJson` (`tlp`, `case`, `exported_at`, `truncated`, `entries`),
  streamed entry by entry.
- Served with nosniff, no-store and CSP sandbox; audited `investigation.timeline_exported`
  (format, count, truncation, filters) before the first byte.

The rows are read while the request's tenant session is open; only serialization streams.
"""

import uuid
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime

from cyberlab_jobs.report import TLP, TLP_LABELS
from fastapi.responses import StreamingResponse
from starlette.requests import HTTPConnection

from app.core.config import get_settings
from app.core.csv_safe import write_csv
from app.core.errors import AppError
from app.core.filenames import content_disposition
from app.core.rbac import OrgContext
from app.modules.audit import service as audit
from app.modules.case_timeline.schemas import (
    CSV_COLUMNS,
    TimelineExportFormat,
    TimelineExportJson,
)
from app.modules.investigations import timeline
from app.modules.investigations.schemas import TimelineEntryOut, case_ref

EXPORT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "sandbox",
}
MEDIA_TYPES: dict[str, str] = {"csv": "text/csv; charset=utf-8", "json": "application/json"}
JSON_CHUNK = 500
TRUNCATED_KIND = "truncated"


class InvalidRange(AppError):
    status_code = 422
    code = "invalid_range"
    message = "`from` must not be after `to`"


def _ts(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _csv_rows(entries: Sequence[timeline.Entry], truncated: bool, cap: int) -> Iterator[list[str]]:
    yield list(CSV_COLUMNS)
    for e in entries:
        yield [
            _ts(e.ts),
            e.ts_source,
            e.kind,
            e.title,
            e.severity or "",
            str(e.evidence_id) if e.evidence_id else "",
            str(e.job_id) if e.job_id else "",
            e.ref_kind,
            str(e.ref_id),
        ]
    if truncated:
        marker = f"[truncated: the export is capped at {cap} rows; narrow kinds / from / to]"
        yield ["", "", TRUNCATED_KIND, marker, "", "", "", "", ""]


def _json_chunks(head: TimelineExportJson, entries: Sequence[timeline.Entry]) -> Iterator[bytes]:
    # Every field but `entries` (the model's last), then the entries streamed in chunks.
    shell = head.model_dump_json(exclude={"entries"})
    yield (shell.removesuffix("}") + ',"entries":[').encode()
    for start in range(0, len(entries), JSON_CHUNK):
        chunk = entries[start : start + JSON_CHUNK]
        body = ",".join(
            TimelineEntryOut.model_validate(e, from_attributes=True).model_dump_json()
            for e in chunk
        )
        yield (("," if start else "") + body).encode()
    yield b"]}"


async def export(
    ctx: OrgContext,
    investigation_id: uuid.UUID,
    request: HTTPConnection,
    *,
    fmt: TimelineExportFormat,
    kinds: Sequence[timeline.TimelineKind] | None,
    since: datetime | None,
    until: datetime | None,
) -> StreamingResponse:
    inv = await timeline.ensure_investigation(ctx.session, ctx.org_id, investigation_id)
    if since is not None and until is not None and timeline.as_utc(since) > timeline.as_utc(until):
        raise InvalidRange()
    cap = get_settings().timeline_export_max_rows
    entries = await timeline.export_entries(
        ctx.session,
        ctx.org_id,
        investigation_id,
        limit=cap + 1,
        kinds=kinds,
        since=since,
        until=until,
    )
    truncated = len(entries) > cap
    entries = entries[:cap]
    tlp = TLP(inv.tlp)
    ref = case_ref(inv.case_number)
    exported_at = datetime.now(UTC)
    kind_values = sorted({str(k) for k in kinds}) if kinds else []
    audit.record(
        ctx.session,
        action="investigation.timeline_exported",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="investigation",
        target_id=inv.id,
        details={
            "case_ref": ref,
            "format": fmt,
            "count": len(entries),
            "truncated": truncated,
            "tlp": tlp.value,
            "filters": {
                "kinds": kind_values,
                "from": _ts(timeline.as_utc(since)) if since else None,
                "to": _ts(timeline.as_utc(until)) if until else None,
            },
        },
        request=request,
    )
    await ctx.session.commit()

    label = TLP_LABELS[tlp]
    if fmt == "csv":
        header = f"# {label} {ref} exported {_ts(exported_at)}"
        body: Iterator[bytes] = write_csv(_csv_rows(entries, truncated, cap), header)
    else:
        head = TimelineExportJson(
            tlp=tlp, case=ref, exported_at=exported_at, truncated=truncated, entries=[]
        )
        body = _json_chunks(head, entries)
    tag = label.replace("TLP:", "TLP_").replace("+", "_")
    filename = f"{ref}-timeline-{tag}.{fmt}"
    return StreamingResponse(
        body,
        media_type=MEDIA_TYPES[fmt],
        headers={**EXPORT_HEADERS, "Content-Disposition": content_disposition(filename)},
    )
