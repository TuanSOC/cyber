"""IOC extraction: observables seen in the capture (not verdicts), with first/last seen."""

from dataclasses import dataclass
from datetime import datetime

from cyberlab_jobs.results import DnsRecord, FlowRecord, HttpRecord, TlsRecord
from cyberlab_worker.parsing import JsonLines, clip, epoch

from pcap_worker.detections.base import is_local

HEX = set("0123456789abcdef")


@dataclass
class Seen:
    first: datetime
    last: datetime
    count: int
    source: str


class IocCollector:
    """Deduplicated (type, value) -> first/last seen; capped at `limit` distinct entries."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.entries: dict[tuple[str, str], Seen] = {}
        self.capped = False

    def add(self, kind: str, value: str | None, ts: datetime, source: str) -> None:
        if not value:
            return
        key = (kind, value[:2048])
        seen = self.entries.get(key)
        if seen is None:
            if len(self.entries) >= self.limit:
                self.capped = True
                return
            self.entries[key] = Seen(ts, ts, 1, source)
            return
        seen.first, seen.last = min(seen.first, ts), max(seen.last, ts)
        seen.count += 1

    def flow(self, f: FlowRecord) -> None:
        for address in (f.src_ip, f.dst_ip):
            if address is not None and not is_local(str(address)):
                self.add("ip", str(address), f.ts, "flow")

    def dns(self, r: DnsRecord) -> None:
        if r.query:
            self.add("domain", r.query.lower().rstrip("."), r.ts, "dns")

    def http(self, r: HttpRecord) -> None:
        if r.host:
            host = r.host.lower()
            self.add("domain" if not _looks_like_ip(host) else "ip", host.split(":")[0], r.ts,
                     "http")  # fmt: skip
            self.add("url", f"http://{host}{r.uri or '/'}", r.ts, "http")

    def tls(self, r: TlsRecord) -> None:
        if r.server_name:
            self.add("domain", r.server_name.lower(), r.ts, "tls")
        self.add("ja3", r.ja3, r.ts, "tls")
        self.add("ja3s", r.ja3s, r.ts, "tls")
        self.add("cert_sha256", r.cert_sha256, r.ts, "tls")

    def files(self, source: JsonLines) -> None:
        """Hashes of files Zeek saw transferred (files.log; hash-all-files policy)."""
        for item in source:
            ts = epoch(item.get("ts"))
            if ts is None:
                continue
            for kind in ("md5", "sha1", "sha256"):
                value = clip(item.get(kind), 64)
                if value and set(value) <= HEX:
                    self.add(f"file_{kind}", value, ts, "files")


def _looks_like_ip(host: str) -> bool:
    return host.replace(".", "").replace(":", "").isdigit() or host.startswith("[")
