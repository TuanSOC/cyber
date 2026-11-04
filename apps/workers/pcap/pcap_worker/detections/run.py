"""Wires the detectors into the analyzer's single read pass and builds the result lines."""

import heapq
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from cyberlab_jobs.results import (
    AlertRecord,
    DnsRecord,
    FindingRecord,
    FlowRecord,
    HttpRecord,
    IocRecord,
    TimelineEvent,
    TlsRecord,
)

from pcap_worker.detections.base import Finding, is_local
from pcap_worker.detections.flow_detectors import BeaconDetector, ScanDetector
from pcap_worker.detections.iocs import IocCollector
from pcap_worker.detections.record_detectors import DnsDetector, SuspiciousTraffic
from pcap_worker.engines.common import JsonLines

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
ALERT_SEVERITY = {1: "high", 2: "medium", 3: "low", 4: "info"}
MAX_FIRST_CONTACTS = 100
MAX_TIMELINE_ALERTS = 1_000
MAX_CONTACT_KEYS = 100_000


@dataclass
class Contact:
    ts: datetime
    src: str | None
    ref: str | None


@dataclass
class Detection:
    job_id: uuid.UUID
    ioc_limit: int
    beacon: BeaconDetector = field(default_factory=BeaconDetector)
    scan: ScanDetector = field(default_factory=ScanDetector)
    dns_detector: DnsDetector = field(default_factory=DnsDetector)
    suspicious: SuspiciousTraffic = field(default_factory=SuspiciousTraffic)
    contacts: dict[str, Contact] = field(default_factory=dict)
    contacts_capped: bool = False
    iocs: IocCollector = field(init=False)

    def __post_init__(self) -> None:
        self.iocs = IocCollector(self.ioc_limit)

    # --- observation (every record read, before any output cap) ---------------------------

    def flow(self, f: FlowRecord) -> None:
        self.beacon.observe(f)
        self.scan.observe(f)
        self.suspicious.flow(f)
        self.iocs.flow(f)
        dst = None if f.dst_ip is None else str(f.dst_ip)
        if dst and not is_local(dst):
            known = self.contacts.get(dst)
            if known is None and len(self.contacts) >= MAX_CONTACT_KEYS:
                self.contacts_capped = True
            elif known is None or f.ts < known.ts:
                src = None if f.src_ip is None else str(f.src_ip)
                self.contacts[dst] = Contact(f.ts, src, f.flow_ref)

    def dns(self, r: DnsRecord) -> None:
        self.dns_detector.observe(r)
        self.iocs.dns(r)

    def http(self, r: HttpRecord) -> None:
        self.suspicious.http(r)
        self.iocs.http(r)

    def tls(self, r: TlsRecord) -> None:
        self.suspicious.tls(r)
        self.iocs.tls(r)

    def files(self, source: JsonLines) -> None:
        self.iocs.files(source)

    @property
    def capped(self) -> bool:
        return (
            self.beacon.capped or self.scan.capped or self.dns_detector.capped
            or self.contacts_capped
        )  # fmt: skip

    # --- results ---------------------------------------------------------------------------

    def findings(self, limit: int) -> tuple[list[FindingRecord], bool]:
        raw: list[Finding] = [
            *self.beacon.findings(),
            *self.scan.findings(),
            *self.dns_detector.findings(),
            *self.suspicious.findings(),
        ]
        top = heapq.nsmallest(
            limit,
            raw,
            key=lambda f: (-SEVERITY_RANK[f.severity], -f.confidence, f.first_seen, f.type),
        )
        records = [
            FindingRecord(
                finding_id=f.key(self.job_id),
                type=f.type,
                title=f.title[:255],
                description=f.description[:2048],
                severity=f.severity,
                confidence=f.confidence,
                detection_method=f.method,
                ts=f.first_seen,
                last_seen=f.last_seen,
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                dst_port=f.dst_port,
                protocol=f.protocol,
                flow_ref=f.refs[0] if f.refs else None,
                evidence_refs=f.refs,
                attributes={k[:64]: v for k, v in list(f.attributes.items())[:20]},
            )
            for f in top
        ]
        return records, len(raw) > limit

    def ioc_records(self) -> list[IocRecord]:
        return [
            IocRecord(
                type=kind,
                value=value,
                first_seen=seen.first,
                last_seen=seen.last,
                count=seen.count,
                source=seen.source,
            )
            for (kind, value), seen in sorted(self.iocs.entries.items())
        ]

    def timeline(
        self,
        first_ts: datetime | None,
        last_ts: datetime | None,
        findings: list[FindingRecord],
        alerts: Iterable[AlertRecord],
        limit: int,
    ) -> list[TimelineEvent]:
        events: list[TimelineEvent] = []
        if first_ts:
            events.append(TimelineEvent(ts=first_ts, event="capture_start", title="Capture starts"))
        if last_ts:
            events.append(TimelineEvent(ts=last_ts, event="capture_end", title="Capture ends"))
        events += [
            TimelineEvent(
                ts=f.ts, event="finding", title=f.title, severity=f.severity,
                ref=str(f.finding_id), src_ip=f.src_ip, dst_ip=f.dst_ip,
            )
            for f in findings
        ]  # fmt: skip
        serious = [a for a in alerts if a.severity <= 2][:MAX_TIMELINE_ALERTS]
        events += [
            TimelineEvent(
                ts=a.ts, event="alert", title=a.signature[:255],
                severity=ALERT_SEVERITY[a.severity],
                ref=str(a.signature_id), src_ip=a.src_ip, dst_ip=a.dst_ip,
            )
            for a in serious
        ]  # fmt: skip
        first = heapq.nsmallest(MAX_FIRST_CONTACTS, self.contacts.items(), key=lambda kv: kv[1].ts)
        events += [
            TimelineEvent(
                ts=c.ts, event="first_contact", title=f"First contact with {dst}",
                ref=c.ref, src_ip=c.src, dst_ip=dst,
            )
            for dst, c in first
        ]  # fmt: skip
        events.sort(key=lambda e: (e.ts, e.event))
        return events[:limit]
