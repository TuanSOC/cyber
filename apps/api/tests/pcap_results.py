"""Synthetic `pcap.v1` result streams for ingest tests (built with the contract models).

`lines()` gives the header + stats + records as raw NDJSON lines, so tests can splice in
hostile lines; `encode()` appends a matching trailer (or a given one) and gzips the lot.
"""

import gzip
import hashlib
import io
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.results import (
    AlertRecord,
    CaptureStats,
    DnsRecord,
    FindingRecord,
    FlowRecord,
    HttpRecord,
    IocRecord,
    ResultHeader,
    ResultTrailer,
    TimelineEvent,
    TlsRecord,
)
from pydantic import BaseModel

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisJob
from app.workers import ingest

T0 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
WORKER = "pcap-worker/test"
TOOLS = {"zeek": "8.0.10", "tshark": "4.4.0", "suricata": "7.0.10"}


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def header(job_id: uuid.UUID | str, **fields: Any) -> ResultHeader:
    return ResultHeader(
        job_id=uuid.UUID(str(job_id)),
        capture_format="pcap",
        tool_versions=TOOLS,
        **fields,
    )


def stats(**fields: Any) -> CaptureStats:
    values: dict[str, Any] = {
        "packets": 120,
        "bytes": 64_000,
        "first_ts": T0,
        "last_ts": at(3600),
        "duration_s": 3600.0,
        "link_type": "Ethernet",
        "protocol_hierarchy": [{"path": "eth:ip:tcp", "frames": 100, "bytes": 60_000}],
        "top_sources": [{"ip": "10.0.0.5", "bytes": 50_000, "packets": 90, "flows": 3}],
        "top_destinations": [],
        "top_ports": [{"port": 443, "proto": "tcp", "flows": 2, "bytes": 40_000}],
        "counts": {"flows": 3},
        **fields,
    }
    return CaptureStats.model_validate(values)


def flow(i: int, **fields: Any) -> FlowRecord:
    values: dict[str, Any] = {
        "ts": at(i),
        "src_ip": "10.0.0.5",
        "src_port": 40_000 + i,
        "dst_ip": f"192.0.2.{i % 250 + 1}",
        "dst_port": 443,
        "flow_ref": f"C{i:08d}",
        "proto": "tcp",
        "service": "ssl",
        "duration_s": 1.5,
        "orig_bytes": 100 * i,
        "resp_bytes": 1_000,
        "orig_pkts": 3,
        "resp_pkts": 4,
        "conn_state": "SF",
        "community_id": f"1:{i:028d}",
        **fields,
    }
    return FlowRecord.model_validate(values)


def sample_records() -> list[BaseModel]:
    """A small but complete analysis: every record kind, with filterable variety."""
    finding_a, finding_b = uuid.UUID(int=1), uuid.UUID(int=2)
    return [
        flow(1),
        flow(2, proto="udp", dst_port=53, service="dns", dst_ip="192.0.2.53"),
        flow(3, orig_bytes=50_000, src_ip="10.0.0.9"),
        DnsRecord(
            ts=at(10),
            src_ip="10.0.0.5",
            dst_ip="192.0.2.53",
            src_port=5353,
            dst_port=53,
            flow_ref="C00000002",
            query="example.com",
            qtype="A",
            rcode="NOERROR",
            answers=["93.184.216.34"],
            ttls=[60.0],
        ),
        DnsRecord(ts=at(11), query="under_score.test", qtype="TXT", rcode="NXDOMAIN"),
        HttpRecord(
            ts=at(20),
            src_ip="10.0.0.5",
            dst_ip="192.0.2.80",
            method="GET",
            host="shop.test",
            uri="/deal?x=100%_off",
            status_code=200,
            user_agent="curl/8",
        ),
        TlsRecord(
            ts=at(30),
            src_ip="10.0.0.5",
            dst_ip="192.0.2.1",
            flow_ref="C00000001",
            version="TLSv12",
            server_name="secure.test",
            ja3="a" * 32,
            self_signed=True,
        ),
        AlertRecord(
            ts=at(40),
            src_ip="10.0.0.5",
            dst_ip="192.0.2.80",
            proto="TCP",
            signature_id=2_000_001,
            rev=3,
            signature="ET POLICY test signature",
            category="Policy",
            severity=3,
        ),
        AlertRecord(
            ts=at(41), signature_id=2_000_002, signature="ET SCAN probe", severity=1, rev=1
        ),
        FindingRecord(
            ts=at(50),
            src_ip="10.0.0.5",
            dst_ip="192.0.2.1",
            finding_id=finding_a,
            type="beaconing",
            title="Periodic connections",
            description="Regular interval to one destination",
            severity="medium",
            confidence=0.8,
            detection_method="heuristic:beaconing@1",
            last_seen=at(900),
            protocol="tcp",
            evidence_refs=["C00000001"],
            attributes={"interval_s": 60.0, "count": 15},
        ),
        FindingRecord(
            ts=at(5),
            finding_id=finding_b,
            type="port_scan",
            title="Port scan",
            description="Many ports on one host",
            severity="high",
            confidence=0.9,
            detection_method="heuristic:port_scan@1",
        ),
        IocRecord(
            type="domain",
            value="example.com",
            first_seen=at(10),
            last_seen=at(10),
            count=1,
            source="dns",
        ),
        IocRecord(
            type="ip", value="192.0.2.1", first_seen=at(1), last_seen=at(30), count=4, source="conn"
        ),
        TimelineEvent(ts=T0, event="capture_start", title="Capture start"),
        TimelineEvent(
            ts=at(50), event="finding", title="Periodic connections", severity="medium", ref="1"
        ),
        TimelineEvent(ts=at(3600), event="capture_end", title="Capture end"),
    ]


SAMPLE_COUNTS = {
    "flows": 3,
    "dns": 2,
    "http": 1,
    "tls": 1,
    "alerts": 2,
    "findings": 2,
    "iocs": 2,
    "timeline": 3,
}


def line(model: BaseModel | dict[str, Any]) -> bytes:
    if isinstance(model, BaseModel):
        return model.model_dump_json().encode() + b"\n"
    return json.dumps(model).encode() + b"\n"


def lines(
    job_id: uuid.UUID | str, records: list[BaseModel] | None = None, **header_fields: Any
) -> list[bytes]:
    body = sample_records() if records is None else records
    return [line(header(job_id, **header_fields)), line(stats()), *(line(r) for r in body)]


def encode(
    raw: list[bytes], *, trailer: dict[str, Any] | None = None, add_trailer: bool = True
) -> bytes:
    body = b"".join(raw)
    if add_trailer:
        values = {"line_count": len(raw), "sha256": hashlib.sha256(body).hexdigest()}
        body += line(ResultTrailer.model_validate({**values, **(trailer or {})}))
    return gzip.compress(body, compresslevel=6)


def stream(job_id: uuid.UUID | str, records: list[BaseModel] | None = None) -> bytes:
    return encode(lines(job_id, records))


def put_result(org_id: uuid.UUID, job_id: uuid.UUID, data: bytes) -> str:
    stored = get_minio().put_object(
        get_settings().results_bucket,
        dispatch.result_key(org_id, job_id),
        io.BytesIO(data),
        len(data),
    )
    return str(stored.version_id)


def finished(item: dispatch.DispatchInput, version_id: str) -> dict[str, Any]:
    return {
        "job_id": str(item.job_id),
        "organization_id": str(item.organization_id),
        "ingest_token": item.ingest_token,
        "event": "finished",
        "outcome": "succeeded",
        "result_version_id": version_id,
        "worker_version": WORKER,
    }


async def deliver(item: dispatch.DispatchInput, data: bytes) -> dict[str, Any]:
    """Upload a result for the job and hand ingest the analyzer's success report."""
    message = finished(item, put_result(item.organization_id, item.job_id, data))
    await ingest.handle_event(message)
    return message


async def seed_results(org_id: uuid.UUID, job_id: uuid.UUID, data: bytes | None = None) -> None:
    """Ingest a result for a job whose token the test does not know (already authenticated)."""
    version_id = put_result(org_id, job_id, data or stream(job_id))
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None
    message = IngestMessageV1(
        job_id=job_id,
        organization_id=org_id,
        ingest_token="t" * 43,
        event="finished",
        outcome="succeeded",
        result_version_id=version_id,
        worker_version=WORKER,
    )
    await ingest.ingest_success(job, message)
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None and job.status == "succeeded", job and job.error_code
