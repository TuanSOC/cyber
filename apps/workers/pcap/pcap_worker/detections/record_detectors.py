"""Detectors over DNS / HTTP / TLS records and flows (suspicious, not verdicts)."""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from cyberlab_jobs.results import DnsRecord, FlowRecord, HttpRecord, TlsRecord

from pcap_worker.detections.base import (
    MAX_REFS,
    Finding,
    Severity,
    bounded_refs,
    is_local,
    shannon_entropy,
)

MAX_GROUPS = 50_000


def registered_domain(name: str) -> str:
    """Last two labels (no public-suffix list: an approximation, documented as such)."""
    labels = [label for label in name.lower().rstrip(".").split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else name.lower()


@dataclass(frozen=True)
class DnsConfig:
    version: int = 1
    min_queries: int = 10
    long_label: int = 40
    entropy_label_min_len: int = 20
    entropy_threshold: float = 3.5
    min_suspicious_labels: int = 10
    min_nxdomain: int = 10
    min_nxdomain_ratio: float = 0.5


@dataclass
class _DnsGroup:
    queries: int = 0
    suspicious: int = 0
    nxdomain: int = 0
    txt: int = 0
    subdomains: set[str] = field(default_factory=set)
    first: datetime | None = None
    last: datetime | None = None
    refs: list[str] = field(default_factory=list)
    example: str = ""


class DnsDetector:
    """Tunneling-like names (long / high-entropy labels) or NXDOMAIN bursts per domain."""

    def __init__(self, config: DnsConfig | None = None) -> None:
        self.config = config or DnsConfig()
        self.groups: dict[tuple[str, str], _DnsGroup] = {}
        self.capped = False

    def observe(self, r: DnsRecord) -> None:
        c = self.config
        if not r.query or r.src_ip is None:
            return
        key = (str(r.src_ip), registered_domain(r.query))
        g = self.groups.get(key)
        if g is None:
            if len(self.groups) >= MAX_GROUPS:
                self.capped = True
                return
            g = self.groups[key] = _DnsGroup()
        g.queries += 1
        first_label = r.query.split(".", 1)[0]
        if len(first_label) >= c.long_label or (
            len(first_label) >= c.entropy_label_min_len
            and shannon_entropy(first_label) >= c.entropy_threshold
        ):
            g.suspicious += 1
            g.example = g.example or r.query
        g.nxdomain += r.rcode == "NXDOMAIN"
        g.txt += r.qtype == "TXT"
        if len(g.subdomains) < 1000:
            g.subdomains.add(r.query.lower())
        g.first = r.ts if g.first is None else min(g.first, r.ts)
        g.last = r.ts if g.last is None else max(g.last, r.ts)
        if r.flow_ref and len(g.refs) < MAX_REFS:
            g.refs.append(r.flow_ref)

    def findings(self) -> list[Finding]:
        c = self.config
        out: list[Finding] = []
        for (src, domain), g in self.groups.items():
            if g.queries < c.min_queries or g.first is None:
                continue
            nx_ratio = g.nxdomain / g.queries
            attributes: dict[str, str | int | float | bool] = {
                "domain": domain,
                "queries": g.queries,
                "unique_names": len(g.subdomains),
                "suspicious_labels": g.suspicious,
                "nxdomain_ratio": round(nx_ratio, 3),
                "txt_queries": g.txt,
            }
            common = {
                "method": f"heuristic:dns_anomaly@{c.version}",
                "first_seen": g.first,
                "last_seen": g.last,
                "src_ip": src,
                "protocol": "dns",
                "refs": bounded_refs(g.refs),
                "attributes": attributes,
            }
            if g.suspicious >= c.min_suspicious_labels:
                out.append(
                    Finding(
                        type="dns_tunneling_like",
                        title=f"Tunneling-like DNS names under {domain}",
                        description=(
                            f"{src} queried {g.queries} names under {domain}, "
                            f"{g.suspicious} of them with long or high-entropy first labels "
                            f"(e.g. {g.example[:80]}); {g.txt} TXT queries, NXDOMAIN ratio "
                            f"{nx_ratio:.0%}. Encoded data in DNS names is used by tunneling "
                            "and some exfiltration tools, but also by CDNs and anti-virus "
                            "lookups."
                        ),
                        severity="medium",
                        confidence=round(min(0.9, 0.5 + g.suspicious / g.queries * 0.4), 2),
                        **common,  # type: ignore[arg-type]
                    )
                )
            elif g.nxdomain >= c.min_nxdomain and nx_ratio >= c.min_nxdomain_ratio:
                out.append(
                    Finding(
                        type="dns_nxdomain_burst",
                        title=f"Many failed lookups under {domain}",
                        description=(
                            f"{g.nxdomain} of {g.queries} lookups by {src} under {domain} "
                            "returned NXDOMAIN. Bursts of non-existent names can come from "
                            "domain generation algorithms, misconfiguration or typos."
                        ),
                        severity="low",
                        confidence=round(min(0.8, 0.4 + nx_ratio * 0.4), 2),
                        **common,  # type: ignore[arg-type]
                    )
                )
        return out


EXECUTABLE_MIME = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-elf",
    "application/x-mach-o-executable",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
}
LEGACY_TLS = {"SSLv2", "SSLv3", "TLSv10", "TLSv11"}
STANDARD_PORTS: dict[str, set[int]] = {
    "http": {80, 8080, 8000, 8008, 8888, 3128},
    "ssl": {443, 8443, 993, 995, 465, 636, 853, 5061},
    "ssh": {22},
    "dns": {53},
}


@dataclass
class _Group:
    finding: Finding
    count: int = 1


class SuspiciousTraffic:
    """Collects one finding per (type, src, dst[, port]) with the number of occurrences."""

    VERSION = 1

    def __init__(self) -> None:
        self.groups: dict[tuple[str, str | None, str | None, int | None], _Group] = {}

    def add(
        self,
        kind: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        *,
        ts: datetime,
        src: str | None,
        dst: str | None,
        port: int | None = None,
        protocol: str | None = None,
        ref: str | None = None,
        attributes: dict[str, str | int | float | bool] | None = None,
    ) -> None:
        key = (kind, src, dst, port)
        group = self.groups.get(key)
        if group is None:
            if len(self.groups) >= MAX_GROUPS:
                return
            self.groups[key] = _Group(
                Finding(
                    type=kind, title=title, description=description, severity=severity,
                    confidence=confidence, method=f"heuristic:suspicious_traffic@{self.VERSION}",
                    first_seen=ts, last_seen=ts, src_ip=src, dst_ip=dst, dst_port=port,
                    protocol=protocol, refs=bounded_refs([ref]), attributes=attributes or {},
                )
            )  # fmt: skip
            return
        group.count += 1
        f = group.finding
        f.first_seen, f.last_seen = min(f.first_seen, ts), max(f.last_seen or ts, ts)
        if ref and ref not in f.refs and len(f.refs) < MAX_REFS:
            f.refs.append(ref)

    def http(self, r: HttpRecord) -> None:
        src, dst = _s(r.src_ip), _s(r.dst_ip)
        host = (r.host or "").split(":")[0].strip("[]")
        if host and _is_ip_literal(host):
            self.add(
                "http_to_ip_literal",
                "HTTP request to a bare IP address",
                f"{src} sent HTTP requests with Host '{host}' (no domain name), e.g. "
                f"{(r.method or '?')} {(r.uri or '/')[:120]}. Common for malware staging and "
                "scanners, also for appliances and internal tools.",
                "low", 0.6, ts=r.ts, src=src, dst=dst, port=r.dst_port, protocol="http",
                ref=r.flow_ref, attributes={"host": host},
            )  # fmt: skip
        mimes = EXECUTABLE_MIME.intersection(r.resp_mime_types)
        if mimes:
            self.add(
                "executable_over_http",
                "Executable downloaded over cleartext HTTP",
                f"{src} received {', '.join(sorted(mimes))} content from "
                f"{r.host or dst} ({(r.uri or '/')[:120]}) without TLS: the file could have "
                "been tampered with in transit and its origin is unauthenticated.",
                "medium", 0.7, ts=r.ts, src=src, dst=dst, port=r.dst_port, protocol="http",
                ref=r.flow_ref, attributes={"uri": (r.uri or "")[:255]},
            )  # fmt: skip

    def tls(self, r: TlsRecord) -> None:
        src, dst = _s(r.src_ip), _s(r.dst_ip)
        name = r.server_name or dst or "?"
        if r.self_signed:
            self.add(
                "tls_self_signed",
                "TLS server presented a self-signed certificate",
                f"{name} ({dst}) presented a self-signed certificate ({r.cert_subject}). "
                "Normal for test and internal services; on the internet it defeats "
                "server authentication.",
                "low", 0.7, ts=r.ts, src=src, dst=dst, port=r.dst_port, protocol="tls",
                ref=r.flow_ref, attributes={"subject": (r.cert_subject or "")[:255]},
            )  # fmt: skip
        expired = r.cert_not_after is not None and r.cert_not_after < r.ts
        not_yet = r.cert_not_before is not None and r.cert_not_before > r.ts
        if expired or not_yet:
            self.add(
                "tls_expired_certificate",
                "TLS certificate outside its validity period",
                f"{name} ({dst}) presented a certificate valid from {r.cert_not_before} to "
                f"{r.cert_not_after}, used at {r.ts}.",
                "low", 0.8, ts=r.ts, src=src, dst=dst, port=r.dst_port, protocol="tls",
                ref=r.flow_ref, attributes={"not_after": str(r.cert_not_after)},
            )  # fmt: skip
        if r.version in LEGACY_TLS:
            self.add(
                "tls_legacy_version",
                f"Legacy protocol version {r.version}",
                f"{src} and {name} ({dst}) negotiated {r.version}, which is deprecated "
                "(RFC 8996) and lacks modern protections.",
                "low", 0.9, ts=r.ts, src=src, dst=dst, port=r.dst_port, protocol="tls",
                ref=r.flow_ref, attributes={"version": r.version or ""},
            )  # fmt: skip

    def flow(self, f: FlowRecord) -> None:
        if not f.service or f.dst_port is None:
            return
        for service in f.service.split(","):
            standard = STANDARD_PORTS.get(service.strip())
            if standard is not None and f.dst_port not in standard:
                self.add(
                    "service_on_nonstandard_port",
                    f"{service.upper()} on non-standard port {f.dst_port}",
                    f"Zeek identified {service} between {_s(f.src_ip)} and {_s(f.dst_ip)} on "
                    f"port {f.dst_port}. Services on unusual ports can be benign (custom "
                    "deployments) or used to evade port-based filtering.",
                    "low", 0.5, ts=f.ts, src=_s(f.src_ip), dst=_s(f.dst_ip), port=f.dst_port,
                    protocol=service.strip(), ref=f.flow_ref, attributes={"service": service},
                )  # fmt: skip

    def findings(self) -> list[Finding]:
        out = []
        for group in self.groups.values():
            group.finding.attributes["occurrences"] = group.count
            out.append(group.finding)
        return out


def _s(value: object) -> str | None:
    return None if value is None else str(value)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


__all__ = ["DnsConfig", "DnsDetector", "SuspiciousTraffic", "is_local", "registered_domain"]
