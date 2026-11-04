"""Write a validated result stream into the tenant tables (inside the caller's transaction).

Postgres refuses COPY into tables with row-level security, so rows go in as batched
multi-row executemany INSERTs through the RLS-bound session. The stream is re-read from the
local file in batches (parsed in a worker thread), so memory stays bounded by one batch
(BATCH_LINES records or BATCH_BYTES of raw lines, whichever comes first) no matter how many
flows the result holds or how long its lines are.
"""

import uuid
from collections import Counter, defaultdict
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any, cast

import anyio
from cyberlab_jobs.results import (
    AlertRecord,
    DnsRecord,
    FindingRecord,
    FlowRecord,
    HttpRecord,
    IocRecord,
    RecordLine,
    TimelineEvent,
    TlsRecord,
)
from sqlalchemy import Table, insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.pcap_analysis import stream
from app.modules.pcap_analysis.models import (
    AnalysisFinding,
    Ioc,
    NetworkAlert,
    NetworkFlow,
    NetworkRecord,
    TimelineEntry,
)

BATCH_LINES = 1000
BATCH_BYTES = 8 * 1024**2
MAX_BIGINT = 2**63 - 1
SUMMARY_MAX = 4096

# Summary counter name per record kind.
COUNT_NAMES = {
    "flow": "flows",
    "dns": "dns",
    "http": "http",
    "tls": "tls",
    "alert": "alerts",
    "finding": "findings",
    "ioc": "iocs",
    "timeline": "timeline",
}
FLOWS = cast(Table, NetworkFlow.__table__)
RECORDS = cast(Table, NetworkRecord.__table__)
ALERTS = cast(Table, NetworkAlert.__table__)
FINDINGS = cast(Table, AnalysisFinding.__table__)
IOCS = cast(Table, Ioc.__table__)
TIMELINE = cast(Table, TimelineEntry.__table__)

_ENDPOINT_FIELDS = {"kind", "ts", "src_ip", "src_port", "dst_ip", "dst_port", "flow_ref"}


def _ip(value: IPv4Address | IPv6Address | None) -> str | None:
    return None if value is None else str(value)


Located = FlowRecord | DnsRecord | HttpRecord | TlsRecord | AlertRecord | FindingRecord


def _endpoints(r: Located) -> dict[str, Any]:
    return {
        "ts": r.ts,
        "src_ip": _ip(r.src_ip),
        "src_port": r.src_port,
        "dst_ip": _ip(r.dst_ip),
        "dst_port": r.dst_port,
        "flow_ref": r.flow_ref,
    }


def _join(*parts: object) -> str:
    return " ".join(str(p) for p in parts if p not in (None, "", []))[:SUMMARY_MAX]


def summary_text(r: DnsRecord | HttpRecord | TlsRecord) -> str:
    """One searchable line per record (the `q` filter matches it with ILIKE)."""
    if isinstance(r, DnsRecord):
        return _join(r.qtype, r.query, r.rcode, ", ".join(r.answers))
    if isinstance(r, HttpRecord):
        target = f"{r.host or ''}{r.uri or ''}"
        return _join(r.method, target, r.status_code, r.user_agent)
    return _join(r.server_name, r.version, r.cipher, r.ja3 and f"ja3={r.ja3}", r.cert_subject)


def to_row(record: RecordLine) -> tuple[Table, dict[str, Any]]:
    if isinstance(record, FlowRecord):
        return FLOWS, {
            **_endpoints(record),
            "proto": record.proto,
            "service": record.service,
            "duration_s": record.duration_s,
            "orig_bytes": record.orig_bytes,
            "resp_bytes": record.resp_bytes,
            "total_bytes": min(record.orig_bytes + record.resp_bytes, MAX_BIGINT),
            "orig_pkts": record.orig_pkts,
            "resp_pkts": record.resp_pkts,
            "conn_state": record.conn_state,
            "community_id": record.community_id,
        }
    if isinstance(record, DnsRecord | HttpRecord | TlsRecord):
        return RECORDS, {
            **_endpoints(record),
            "kind": record.kind,
            "summary": summary_text(record),
            "details": record.model_dump(mode="json", exclude=_ENDPOINT_FIELDS),
        }
    if isinstance(record, AlertRecord):
        return ALERTS, {
            **_endpoints(record),
            "proto": record.proto,
            "signature_id": record.signature_id,
            "rev": record.rev,
            "signature": record.signature,
            "category": record.category,
            "severity": record.severity,
            "community_id": record.community_id,
        }
    if isinstance(record, FindingRecord):
        return FINDINGS, {
            **_endpoints(record),
            "finding_id": record.finding_id,
            "type": record.type,
            "title": record.title,
            "description": record.description,
            "severity": record.severity,
            "confidence": record.confidence,
            "detection_method": record.detection_method,
            "last_seen": record.last_seen,
            "protocol": record.protocol,
            "evidence_refs": list(record.evidence_refs),
            "attributes": dict(record.attributes),
        }
    if isinstance(record, IocRecord):
        return IOCS, {
            "type": record.type,
            "value": record.value,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
            "count": record.count,
            "source": record.source,
        }
    if isinstance(record, TimelineEvent):
        return TIMELINE, {
            "ts": record.ts,
            "event": record.event,
            "title": record.title,
            "severity": record.severity,
            "ref": record.ref,
            "src_ip": _ip(record.src_ip),
            "dst_ip": _ip(record.dst_ip),
        }
    raise TypeError(f"no table for record kind {record.kind!r}")


Batch = dict[Table, list[dict[str, Any]]]


def _next_batch(
    records: Iterator[tuple[RecordLine, int]], scope: dict[str, Any], written: Counter[str]
) -> Batch:
    """Parse records into rows grouped by table until a batch cap is hit (worker thread)."""
    batch: Batch = defaultdict(list)
    size = 0
    for count, (record, line_bytes) in enumerate(records, start=1):
        table, row = to_row(record)
        batch[table].append({**row, **scope})
        written[record.kind] += 1
        size += line_bytes
        if count >= BATCH_LINES or size >= BATCH_BYTES:
            break
    return batch


async def insert_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    path: Path,
    caps: stream.Caps,
) -> Counter[str]:
    """Insert every record of a validated stream; returns the rows written per kind."""
    written: Counter[str] = Counter()
    records = stream.records(path, caps)
    scope = {"organization_id": org_id, "job_id": job_id}
    while batch := await anyio.to_thread.run_sync(_next_batch, records, scope, written):
        for table, rows in batch.items():
            await session.execute(insert(table), rows)  # executemany (pipelined by asyncpg)
    return written


def build_summary(result: stream.Validated, written: Counter[str]) -> dict[str, Any]:
    header = result.header.model_dump(mode="json")
    return {
        "schema_version": header["schema_version"],
        "capture_format": header["capture_format"],
        "tool_versions": header["tool_versions"],
        "engine_errors": header["engine_errors"],
        "truncated": header["truncated"],
        "capture": result.stats.model_dump(mode="json", exclude={"kind", "counts"}),
        "engine_counts": result.stats.counts,
        "counts": {name: written[kind] for kind, name in COUNT_NAMES.items()},
    }
