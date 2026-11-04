"""PCAP analysis: run every engine as the tool uid, normalize into the `pcap.v1` stream.

Memory stays bounded by the job limits, not by the capture: each log is read once, flows
are kept in a fixed-size heap (largest by bytes), other kinds are spooled to root-owned
temp files, statistics are accumulated with a cap on distinct keys. Anything capped,
skipped or not run is reported in the header (`truncated`, `engine_errors`).
"""

import heapq
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberlab_jobs import JobLimits, PcapJobV1
from cyberlab_jobs.capture import CaptureFormat, capture_format, compression
from cyberlab_jobs.results import (
    RECORD_ADAPTER,
    AlertRecord,
    CaptureStats,
    FlowRecord,
    HostStat,
    PortStat,
    ProtocolStat,
    ResultHeader,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.parsing import RECORD_ERRORS, JsonLines
from cyberlab_worker.result_writer import ResultWriter, Spool
from cyberlab_worker.transfer import download
from pydantic import BaseModel

from pcap_worker.config import tool_versions
from pcap_worker.detections.run import Detection
from pcap_worker.engines import capture_info, suricata, zeek

# Slack for housekeeping after the last tool (normalize, write, upload, report).
RESERVE_S = 30
MIN_TOOL_S = 5
TOP_N = 10
MAX_STAT_KEYS = 100_000
# A flow and an alert/TLS event belong together if the event falls inside the flow's span.
LINK_SLACK_S = 2.0


def check_format(capture: Path) -> CaptureFormat:
    with open(capture, "rb") as f:
        head = f.read(16)
    fmt = capture_format(head)
    if fmt is None:
        packed = compression(head)
        raise JobFailed("unsupported_capture_format", f"compressed ({packed})" if packed else "")
    return fmt


class Budget:
    def __init__(self, limits: JobLimits) -> None:
        self._deadline = time.monotonic() + limits.timeout_s - RESERVE_S
        self._tool = limits.tool_timeout_s

    def tool(self) -> float | None:
        """Seconds for the next engine, or None when too little time is left to run one."""
        remaining = self._deadline - time.monotonic()
        return min(self._tool, remaining) if remaining >= MIN_TOOL_S else None


@dataclass
class Totals:
    bytes: int = 0
    packets: int = 0
    flows: int = 0

    def add(self, b: int, p: int) -> None:
        self.bytes += b
        self.packets += p
        self.flows += 1


@dataclass
class StatsAccumulator:
    """Statistics over every flow read; distinct keys are capped (flagged as truncated)."""

    flows: int = 0
    capped: bool = False
    sources: dict[str, Totals] = field(default_factory=dict)
    destinations: dict[str, Totals] = field(default_factory=dict)
    ports: dict[tuple[int, str], Totals] = field(default_factory=dict)

    def _bump[K](self, table: dict[K, Totals], key: K | None, b: int, p: int) -> None:
        if key is None:
            return
        totals = table.get(key)
        if totals is None:
            if len(table) >= MAX_STAT_KEYS:
                self.capped = True
                return
            totals = table[key] = Totals()
        totals.add(b, p)

    def add(self, flow: FlowRecord) -> None:
        self.flows += 1
        b, p = flow.orig_bytes + flow.resp_bytes, flow.orig_pkts + flow.resp_pkts
        self._bump(self.sources, str(flow.src_ip) if flow.src_ip else None, b, p)
        self._bump(self.destinations, str(flow.dst_ip) if flow.dst_ip else None, b, p)
        port = (flow.dst_port, flow.proto) if flow.dst_port is not None else None
        self._bump(self.ports, port, b, p)

    @staticmethod
    def hosts(table: dict[str, Totals]) -> list[HostStat]:
        top = heapq.nsmallest(TOP_N, table.items(), key=lambda kv: (-kv[1].bytes, kv[0]))
        return [HostStat(ip=a, bytes=t.bytes, packets=t.packets, flows=t.flows) for a, t in top]

    def top_ports(self) -> list[PortStat]:
        top = heapq.nsmallest(TOP_N, self.ports.items(), key=lambda kv: (-kv[1].flows, kv[0]))
        return [PortStat(port=p, proto=pr, flows=t.flows, bytes=t.bytes) for (p, pr), t in top]


class FlowLinks:
    """community id -> [(start, end, uid)] of kept flows; picks the flow containing `ts`."""

    def __init__(self, flows: list[FlowRecord]) -> None:
        self._spans: dict[str, list[tuple[float, float, str]]] = {}
        for f in flows:
            if f.community_id and f.flow_ref:
                start = f.ts.timestamp()
                end = start + (f.duration_s or 0.0)
                self._spans.setdefault(f.community_id, []).append((start, end, f.flow_ref))

    def __call__(self, community: str | None, ts: datetime) -> str | None:
        when = ts.timestamp()
        for start, end, uid in self._spans.get(community or "", ()):
            if start - LINK_SLACK_S <= when <= end + LINK_SLACK_S:
                return uid
        return None


Fingerprints = tuple[str | None, str | None]


class JA3Lookup:
    """JA3/JA3S per community id, from the TLS event closest in time (reused 5-tuples)."""

    def __init__(self, limit: int) -> None:
        self._entries: dict[str, list[tuple[float, str | None, str | None]]] = {}
        self._limit = limit
        self._size = 0

    def add(self, community: str, ts: datetime, fingerprints: Fingerprints) -> None:
        if self._size < self._limit:
            self._entries.setdefault(community, []).append((ts.timestamp(), *fingerprints))
            self._size += 1

    def __call__(self, community: str | None, ts: datetime) -> Fingerprints:
        candidates = self._entries.get(community or "")
        if not candidates:
            return None, None
        when = ts.timestamp()
        best = min(candidates, key=lambda c: abs(c[0] - when))
        return (best[1], best[2]) if abs(best[0] - when) <= LINK_SLACK_S else (None, None)


def analyze(job: PcapJobV1, dirs: sandbox.JobDirs) -> Path:
    budget = Budget(job.limits)
    download(
        job.evidence_url,
        dirs.capture,
        expected_sha256=job.expected_sha256,
        size_bytes=job.size_bytes,
        max_bytes=job.limits.max_bytes,
        too_large_code="capture_too_large",
    )
    return analyze_file(dirs, job.job_id, job.limits, budget)


def _time(budget: Budget, engine: str) -> float:
    seconds = budget.tool()
    if seconds is None:
        raise JobFailed("timed_out", f"no time left for {engine}")
    return seconds


def _run_engines(
    dirs: sandbox.JobDirs, budget: Budget, errors: list[str], *, cut_short: bool
) -> list[ProtocolStat]:
    capture = dirs.capture
    hierarchy: list[ProtocolStat] = []
    try:
        hierarchy = capture_info.protocol_hierarchy(capture, dirs, _time(budget, "tshark"))
    except sandbox.ToolTimeout:
        errors.append("tshark_timeout")
    except sandbox.ToolFailed:
        errors.append("tshark_failed")
    sandbox.kill_tool_processes()  # nothing an engine left behind runs during the next

    # Zeek is the primary source: without it the result would look clean but be empty.
    try:
        zeek.run(capture, dirs, _time(budget, "zeek"))
    except sandbox.ToolTimeout as exc:
        raise JobFailed("zeek_timeout") from exc
    except sandbox.ToolFailed as exc:
        # A capture cut short mid-packet ends Zeek with a fatal read error after it logged
        # everything before the cut: that partial result is still worth keeping.
        if not (cut_short and "truncated dump file" in exc.stderr_tail):
            raise JobFailed("zeek_failed", exc.stderr_tail[-200:]) from exc
        errors.append("zeek_cut_short")
    sandbox.kill_tool_processes()

    seconds = budget.tool()
    if seconds is None:
        errors.append("suricata_skipped")
        return hierarchy
    try:
        suricata.run(capture, dirs, seconds)
    except sandbox.ToolTimeout:
        errors.append("suricata_timeout")
    except sandbox.ToolFailed:
        errors.append("suricata_failed")
    sandbox.kill_tool_processes()
    return hierarchy


@dataclass
class Collected:
    flows: list[FlowRecord]
    stats: StatsAccumulator
    spools: dict[str, Spool]
    truncated: dict[str, bool]
    skipped: Counter[str]
    detection: Detection


def _collect(dirs: sandbox.JobDirs, job_id: uuid.UUID, limits: JobLimits) -> Collected:
    per_kind = limits.max_records_per_kind
    truncated: dict[str, bool] = {}
    skipped: Counter[str] = Counter()

    # Flows: one pass, fixed-size heap of the largest flows, statistics over all of them.
    conn = JsonLines(dirs, "conn.log", max_lines=limits.max_flows * 4)
    stats = StatsAccumulator()
    detection = Detection(job_id, ioc_limit=per_kind)
    heap: list[tuple[int, int, FlowRecord]] = []
    for seq, flow in enumerate(zeek.flows(conn)):
        stats.add(flow)
        detection.flow(flow)  # detectors see every flow, not just the ones kept
        item = (flow.orig_bytes + flow.resp_bytes, -seq, flow)
        if len(heap) < limits.max_flows:
            heapq.heappush(heap, item)
        else:
            heapq.heappushpop(heap, item)
    flows = [entry[2] for entry in sorted(heap, key=lambda e: (-e[0], -e[1]))]
    truncated |= {"flows": stats.flows > limits.max_flows, "conn_log": conn.capped}
    truncated["stats_keys"] = stats.capped
    skipped["conn"] = conn.skipped
    links = FlowLinks(flows)

    def spool(kind: str) -> Spool:
        return Spool(dirs.root / f"{kind}.spool", per_kind)

    # eve.json: one pass for alerts and TLS fingerprints.
    spools = {"alert": spool("alert")}
    ja3 = JA3Lookup(per_kind)
    # eve carries only alert + tls events (suricata-cyberlab.yaml).
    eve = JsonLines(dirs, "eve.json", max_lines=per_kind * 2 + 1000)
    for event in eve:
        try:
            kind = event.get("event_type")
            if kind == "alert" and (alert := suricata.alert(event, links)) is not None:
                spools["alert"].add(alert)
            elif kind == "tls" and (entry := suricata.tls_fingerprints(event)) is not None:
                ja3.add(*entry)
        except RECORD_ERRORS:
            eve.skipped += 1
    truncated["eve_log"] = eve.capped
    skipped["eve"] = eve.skipped

    x509 = JsonLines(dirs, "x509.log", max_lines=per_kind)
    certs = zeek.certificates(x509)
    truncated["x509_log"] = x509.capped

    parsers: dict[str, tuple[str, Callable[[JsonLines], Iterator[BaseModel]]]] = {
        "dns": ("dns.log", zeek.dns),
        "http": ("http.log", zeek.http),
        "tls": ("ssl.log", lambda source: zeek.tls(source, certs, ja3)),
    }
    observe: dict[str, Callable[[Any], None]] = {
        "dns": detection.dns,
        "http": detection.http,
        "tls": detection.tls,
    }
    for kind, (log, parse) in parsers.items():
        source = JsonLines(dirs, log, max_lines=per_kind * 2)
        out = spools[kind] = spool(kind)
        for record in parse(source):
            observe[kind](record)
            out.add(record)
        truncated[f"{kind}_log"] = source.capped
        skipped[kind] = source.skipped
    files = JsonLines(dirs, "files.log", max_lines=per_kind * 2)
    detection.files(files)
    truncated["files_log"] = files.capped
    for kind, out in spools.items():
        out.finish()
        truncated[kind] = out.truncated
    truncated["detector_state"] = detection.capped
    return Collected(flows, stats, spools, truncated, skipped, detection)


def analyze_file(
    dirs: sandbox.JobDirs, job_id: uuid.UUID, limits: JobLimits, budget: Budget
) -> Path:
    """Analyze the capture already in `dirs.input` (verified by the caller)."""
    fmt = check_format(dirs.capture)
    try:
        meta = capture_info.capinfos(dirs.capture, dirs, _time(budget, "capinfos"))
    except sandbox.ToolTimeout as exc:
        raise JobFailed("tool_timeout", "capinfos") from exc
    except sandbox.ToolFailed as exc:
        raise JobFailed("unparseable_capture", exc.stderr_tail[-200:]) from exc
    errors: list[str] = ["capture_cut_short"] if meta.cut_short else []
    hierarchy = _run_engines(dirs, budget, errors, cut_short=meta.cut_short)
    got = _collect(dirs, job_id, limits)

    findings, got.truncated["findings"] = got.detection.findings(limits.max_findings)
    iocs = got.detection.ioc_records()
    got.truncated["iocs"] = got.detection.iocs.capped
    alerts = (
        record
        for line in got.spools["alert"].lines()
        if isinstance(record := RECORD_ADAPTER.validate_json(line), AlertRecord)
    )
    timeline = got.detection.timeline(
        meta.first_ts, meta.last_ts, findings, alerts, limits.max_records_per_kind
    )

    counts = {"flows": got.stats.flows, **{k: s.count for k, s in got.spools.items()}}
    counts |= {"findings": len(findings), "iocs": len(iocs), "timeline": len(timeline)}
    counts |= {f"skipped_{k}": v for k, v in got.skipped.items() if v}
    capture_stats = CaptureStats(
        packets=meta.packets,
        bytes=meta.data_bytes,
        first_ts=meta.first_ts,
        last_ts=meta.last_ts,
        duration_s=meta.duration_s,
        link_type=meta.link_type,
        protocol_hierarchy=hierarchy,
        top_sources=got.stats.hosts(got.stats.sources),
        top_destinations=got.stats.hosts(got.stats.destinations),
        top_ports=got.stats.top_ports(),
        counts=counts,
    )
    header = ResultHeader(
        job_id=job_id,
        capture_format=fmt,
        tool_versions=tool_versions(),
        engine_errors=errors,
        truncated={k: True for k, v in got.truncated.items() if v},
    )
    result = dirs.root / "result.ndjson.gz"
    with ResultWriter(result) as writer:
        writer.write(header)
        writer.write(capture_stats)
        for flow in got.flows:
            writer.write(flow)
        for kind in ("dns", "http", "tls", "alert"):
            for line in got.spools[kind].lines():
                writer.write_line(line)
        for line_model in (*findings, *iocs, *timeline):
            writer.write(line_model)
    if result.stat().st_size > limits.max_result_bytes:
        raise JobFailed("result_too_large")
    return result
