"""IOCs of a memory run: observables only, never verdicts (enrichment happens later).

- `connection`: remote addresses of connections (internal ones kept: the M6 normalizer marks
  them non-TI-eligible at ingest); loopback and unspecified addresses are not observables.
- `cmdline` / `bash`: URLs, domains and IPs in command lines and bash history, through the
  shared extractor `cyberlab_worker.iocs`, run over the **masked** text (RT13). What the
  masker recognizes is masked before extraction, so it never reaches an IOC value: URL
  userinfo (`https://u:pw@host`), `password=` / `pwd=` / `pass=` parameters and the query
  parameters of `mask._URL_QUERY` (`token`, `access_token`, `api_key`, `key`, `sig`,
  `secret`, `X-Amz-Signature`, ...). A secret under any other parameter name (`?q=`,
  `?session=`) is not recognized and stays in the URL value.

Each IOC records first / last seen (connection `created`, else the owning process's create
time; history line time; process create time; else the image time), count and first source.
"""

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from cyberlab_jobs.results import IocRecord, IocType
from cyberlab_worker.iocs import IocCollector

from memory_worker.detections.base import Context
from memory_worker.detections.mask import mask
from memory_worker.view import MemoryView

KINDS = frozenset({"ip", "domain", "url"})
MAX_PER_TEXT = 256  # distinct observables taken from one command line / history line
# The contract's timestamp window (results.Timestamp).
EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
LATEST = datetime(2100, 1, 1, tzinfo=UTC)


@dataclass
class Seen:
    first: datetime
    last: datetime
    count: int
    source: str


class IocTable:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.entries: dict[tuple[str, str], Seen] = {}
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
            self.entries[key] = Seen(ts, ts, count, source)

    def text(self, value: str, source: str, ts: datetime) -> None:
        collector = IocCollector(MAX_PER_TEXT)
        collector.observe(mask(value), source)
        for (kind, found), seen in collector.entries.items():
            if kind in KINDS:
                self.add(kind, found, source, ts, seen.count)

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


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    parsed = parsed.astimezone(UTC)
    return parsed if EARLIEST <= parsed < LATEST else None


def _create_time(ctx: Context, pid: int | None) -> datetime | None:
    procs = ctx.by_pid.get(pid, []) if pid is not None else []
    times = [p.create_time for p in procs if p.create_time is not None]
    return min(times) if times else None


def build(view: MemoryView, ctx: Context, limit: int) -> tuple[list[IocRecord], bool]:
    table = IocTable(limit)
    for conn in view.connections:
        address = conn.remote_addr
        if address is None or address.is_loopback or address.is_unspecified:
            continue
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
            if address.is_loopback or address.is_unspecified:
                continue
        ts = conn.created or _create_time(ctx, conn.pid) or ctx.observed_at
        table.add("ip", str(address), "connection", ts)
    for procs in ctx.by_pid.values():
        for proc in procs:
            if proc.cmdline:
                table.text(proc.cmdline, "cmdline", proc.create_time or ctx.observed_at)
    for artifact in view.artifacts:
        if artifact.type != "bash":
            continue
        command = artifact.attributes.get("command")
        if isinstance(command, str) and command:
            ts = (
                _parse_time(artifact.attributes.get("time"))
                or _create_time(ctx, artifact.pid)
                or ctx.observed_at
            )
            table.text(command, "bash", ts)
    return table.records(), table.capped
