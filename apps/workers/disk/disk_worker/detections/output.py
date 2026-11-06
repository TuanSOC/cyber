"""IOCs and the shared timeline of a disk run (M9 phase 6). Observables only, never verdicts.

IOCs (`cyberlab_worker.iocs` for text; plan "Correlation"):
- sha256 / sha1 / md5 of every listed file a kept finding references (source `file`);
- source IPs of remote-logon findings (source `logon`);
- URLs, domains and IPs in the command lines / registry values / service paths quoted by kept
  findings, extracted from the **masked** text (source `command`), so a secret in a URL never
  becomes an IOC value.
Nothing from the unflagged file listing or browser history.

Timeline (at most `limits.max_timeline`): one `finding` entry per kept finding, then one typed
entry (`logon`, `service_install`, `log_cleared`, `account_change`, `persistence`,
`file_executed`) per event those findings cite; when the cap bites, finding-linked entries come
first, then higher severity. Times outside 1970..2100 (FAT / NTFS oddities) are placed at the
run's reference time.
"""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from typing import cast

from cyberlab_jobs.disk import DiskTimelineEvent, DiskTimelineKind
from cyberlab_jobs.results import FindingRecord, IocRecord, IocType
from cyberlab_worker.iocs import IocCollector

from disk_worker.detections.base import SEVERITY_RANK, CitedEvent, Finding, shared_ts

TEXT_KINDS = frozenset({"ip", "domain", "url"})
MAX_PER_TEXT = 64


@dataclass
class _Seen:
    first: datetime
    last: datetime
    count: int
    source: str


class IocTable:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.entries: dict[tuple[str, str], _Seen] = {}
        self.capped = False

    def add(self, kind: str, value: str, source: str, ts: datetime, count: int = 1) -> None:
        key = (kind, value[:2048])
        seen = self.entries.get(key)
        if seen is not None:
            seen.first = min(seen.first, ts)
            seen.last = max(seen.last, ts)
            seen.count += count
        elif len(self.entries) >= self.limit:
            self.capped = True
        else:
            self.entries[key] = _Seen(ts, ts, count, source)

    def text(self, masked: str, ts: datetime) -> None:
        collector = IocCollector(MAX_PER_TEXT)
        collector.observe(masked, "command")
        for (kind, found), seen in collector.entries.items():
            if kind in TEXT_KINDS:
                self.add(kind, found, "command", ts, seen.count)

    def records(self) -> list[IocRecord]:
        return [
            IocRecord(
                type=cast(IocType, kind),
                value=value,
                first_seen=seen.first,
                last_seen=seen.last,
                count=seen.count,
                source=seen.source,
            )
            for (kind, value), seen in sorted(self.entries.items())
        ]


def iocs(kept: list[tuple[Finding, FindingRecord]], limit: int) -> tuple[list[IocRecord], bool]:
    table = IocTable(limit)
    for finding, record in kept:
        ts = record.ts
        seen_files: set[int] = set()
        for file in finding.files:
            if id(file) in seen_files:
                continue
            seen_files.add(id(file))
            for kind, value in (
                ("file_sha256", file.sha256),
                ("file_sha1", file.sha1),
                ("file_md5", file.md5),
            ):
                if value:
                    table.add(kind, value, "file", ts)
        if finding.src_ip is not None:
            table.add("ip", str(finding.src_ip), "logon", ts)
        for text in finding.texts:
            table.text(text, ts)
    return table.records(), table.capped


def timeline(
    kept: list[tuple[Finding, FindingRecord]], limit: int, fallback: datetime
) -> tuple[list[DiskTimelineEvent], bool]:
    def ts_of(value: datetime | None) -> datetime:
        return shared_ts(value) or fallback

    ranked = sorted(kept, key=lambda pair: -SEVERITY_RANK[pair[1].severity])
    head = [
        DiskTimelineEvent(
            ts=record.ts,
            event="finding",
            title=record.title,
            severity=record.severity,
            ref=str(record.finding_id),
            src_ip=finding.src_ip,
        )
        for finding, record in ranked
    ]
    seen: set[int] = set()
    tail: list[DiskTimelineEvent] = []
    for finding, _record in ranked:
        for cited in finding.events:
            if cited.ordinal in seen:
                continue
            seen.add(cited.ordinal)
            tail.append(_event_entry(cited, ts_of(cited.ts)))
    ordered = [*head, *tail]
    truncated = len(ordered) > limit
    ordered = ordered[:limit]
    ordered.sort(key=lambda e: (e.ts, e.event, e.ref or ""))
    return ordered, truncated


def _event_entry(cited: CitedEvent, ts: datetime) -> DiskTimelineEvent:
    src_ip = None
    if cited.src_ip:
        try:
            src_ip = ip_address(cited.src_ip)
        except ValueError:
            src_ip = None
    return DiskTimelineEvent(
        ts=ts,
        event=cast(DiskTimelineKind, cited.kind),
        title=cited.title[:255],
        severity="info",
        ref=f"event:{cited.ordinal}",
        src_ip=src_ip,
    )


__all__ = ["IocTable", "iocs", "timeline"]
