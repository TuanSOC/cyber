"""Hand-trimmed evaluation cases, built from the generators' known outputs (M5 phase 6).

The real snapshot (`scripts/ai_eval_snapshot.py`) runs the pcap and static pipelines on the
generated datasets, which needs the heavy test workers (RT13). Until the parent runs it, the
committed cases are built here from what the generators plant and what the detectors are
specified to report (`labels.json`, the detector templates), trimmed to the rows a context can
select. Every record goes through the real result contract models and the real ingest
`to_row`, so the table shapes are exactly what ingest writes; values (flow refs, hashes,
timings) are plausible, not measured. `provenance.source` says `hand-trimmed`; the snapshot
script overwrites these files with `pipeline` cases.

    docker compose --profile test run --rm --no-deps api-test \
        uv run python -m tests.ai_eval.handcases [--out DIR]

No sample bytes and no capture bytes are produced or written anywhere: only row values.
"""

import argparse
import copy
import datetime as dt
import hashlib
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

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
from cyberlab_jobs.static import (
    CapabilityRecord,
    ImportRecord,
    ResourceRecord,
    SectionRecord,
    SignatureMatch,
    StringRecord,
)
from pydantic import BaseModel

from app.modules.pcap_analysis import ingest as pcap_ingest
from app.modules.static_analysis import ingest as static_ingest
from tests.ai_eval import inject_payloads as inj
from tests.ai_eval.cases import CASES_DIR, FORMAT, TWIN_SUFFIX, to_json_row, write_case

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)  # dataset BASE_TS
PCAP_TOOLS = {"zeek": "8.0.10", "tshark": "4.4.0", "suricata": "7.0.10"}
STATIC_TOOLS = {"clamav": "1.4.3", "yara": "4.5.2", "capa": "9.2.1", "floss": "3.1.1"}
RESOLVER = "10.0.0.53"
PLANT_SERVER = "203.0.113.99"
PLANT_OFFSET_S = 900.0
QNAME_SUFFIX = "inj.example"
TXT_NAME = f"notes.{QNAME_SUFFIX}"
CA = "CN=CyberLab Synthetic Test CA"
FINDING_NS = uuid.UUID("6f1c7a52-38e4-4d55-9a37-1c1f2a0c9e10")
PROVENANCE = {
    "source": "hand-trimmed",
    "note": "built from labels.json and the detector templates; regenerate with "
    "scripts/ai_eval_snapshot.py (pipeline)",
    "snapshot_version": 1,
}


def at(seconds: float) -> dt.datetime:
    return T0 + dt.timedelta(seconds=seconds)


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def digest(*parts: object, n: int = 64) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:n]


# --- pcap ------------------------------------------------------------------------------------


@dataclass
class Capture:
    """Records of one (trimmed) capture, in stream order per kind."""

    name: str
    offset: float = 0.0
    records: list[BaseModel] = field(default_factory=list)
    flows_total: int = 0

    def ref(self, n: int) -> str:
        return "C" + digest(self.name, self.offset, n, n=17)

    def flow(self, t: float, src: str, dst: str, dport: int, proto: str = "tcp", **kw: Any) -> str:
        n = len([r for r in self.records if isinstance(r, FlowRecord)])
        ref = self.ref(n)
        sport = kw.pop("sport", 40000 + (int(digest(self.name, n, n=4), 16) % 20000))
        self.records.append(
            FlowRecord(
                ts=at(self.offset + t),
                src_ip=src,
                src_port=sport,
                dst_ip=dst,
                dst_port=dport,
                flow_ref=ref,
                proto=proto,
                community_id="1:" + digest(ref, n=27) + "=",
                **{
                    "duration_s": 0.06,
                    "orig_bytes": 180,
                    "resp_bytes": 240,
                    "orig_pkts": 5,
                    "resp_pkts": 4,
                    "conn_state": "SF",
                    **kw,
                },
            )
        )
        self.flows_total += 1
        return ref

    def dns(self, t: float, src: str, query: str, qtype: str = "A", **kw: Any) -> str:
        ref = self.flow(t, src, RESOLVER, 53, "udp", service="dns", orig_bytes=40, resp_bytes=90)
        self.records.append(
            DnsRecord(
                ts=at(self.offset + t),
                src_ip=src,
                dst_ip=RESOLVER,
                src_port=53000,
                dst_port=53,
                flow_ref=ref,
                query=query,
                qtype=qtype,
                **{"rcode": "NOERROR", **kw},
            )
        )
        return ref

    def http(self, t: float, src: str, dst: str, dport: int, **kw: Any) -> str:
        ref = self.flow(t, src, dst, dport, service="http", orig_bytes=220, resp_bytes=180)
        self.records.append(
            HttpRecord(
                ts=at(self.offset + t),
                src_ip=src,
                dst_ip=dst,
                src_port=41000,
                dst_port=dport,
                flow_ref=ref,
                **{"status_code": 200, **kw},
            )
        )
        return ref

    def tls(self, t: float, src: str, dst: str, sni: str, **kw: Any) -> str:
        ref = self.flow(t, src, dst, 443, service="ssl", orig_bytes=900, resp_bytes=2600)
        fields: dict[str, Any] = {
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "established": True,
            "ja3": digest("ja3", sni, n=32),
            "ja3s": digest("ja3s", dst, n=32),
            "cert_subject": f"CN={sni}",
            "cert_issuer": CA,
            "cert_not_before": T0 - dt.timedelta(days=365),
            "cert_not_after": T0 + dt.timedelta(days=365),
            "cert_sha256": digest("cert", sni),
            "validation_status": "ok",
            "self_signed": False,
            **kw,
        }
        self.records.append(
            TlsRecord(
                ts=at(self.offset + t),
                src_ip=src,
                dst_ip=dst,
                src_port=42000,
                dst_port=443,
                flow_ref=ref,
                server_name=sni,
                **fields,
            )
        )
        return ref

    def alert(self, t: float, src: str, dst: str, dport: int, sid: int, msg: str) -> None:
        self.records.append(
            AlertRecord(
                ts=at(self.offset + t),
                src_ip=src,
                dst_ip=dst,
                src_port=41000,
                dst_port=dport,
                proto="TCP",
                signature_id=sid,
                rev=1,
                signature=msg,
                category="Misc activity",
                severity=3,
            )
        )

    def finding(
        self,
        t: float,
        type_: str,
        detector: str,
        title: str,
        description: str,
        severity: str,
        confidence: float,
        *,
        src: str | None = None,
        dst: str | None = None,
        dport: int | None = None,
        protocol: str | None = None,
        refs: list[str] | None = None,
        attributes: dict[str, Any] | None = None,
        last: float | None = None,
    ) -> FindingRecord:
        finding_id = uuid.uuid5(FINDING_NS, f"{self.name}|{type_}|{src}|{dst}|{dport}")
        record = FindingRecord(
            ts=at(self.offset + t),
            src_ip=src,
            dst_ip=dst,
            dst_port=dport,
            flow_ref=(refs or [None])[0],
            finding_id=finding_id,
            type=type_,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            detection_method=f"heuristic:{detector}@1",
            last_seen=at(self.offset + last) if last is not None else None,
            protocol=protocol,
            evidence_refs=refs or [],
            attributes=attributes or {},
        )
        self.records.append(record)
        self.records.append(
            TimelineEvent(
                ts=record.ts,
                event="finding",
                title=title,
                severity=severity,
                ref=str(finding_id),
                src_ip=src,
                dst_ip=dst,
            )
        )
        return record

    def ioc(self, type_: str, value: str, t: float, count: int = 1, source: str = "flow") -> None:
        self.records.append(
            IocRecord(
                type=type_,
                value=value,
                first_seen=at(self.offset + t),
                last_seen=at(self.offset + t),
                count=count,
                source=source,
            )
        )


def pcap_normal_web(c: Capture) -> None:
    client = "10.0.1.10"
    c.dns(0, client, "www.example.com", answers=["198.51.100.10"], ttls=[300.0])
    for t, path in ((0.5, "/"), (37.2, "/about"), (190.8, "/news?id=7")):
        c.http(
            t,
            client,
            "198.51.100.10",
            80,
            method="GET",
            host="www.example.com",
            uri=path,
            user_agent=UA_BROWSER,
            resp_mime_types=["text/html"],
        )
    c.dns(40, client, "cdn.example.net", answers=["198.51.100.20"], ttls=[300.0])
    for t in (41.0, 131.5):
        c.tls(t, client, "198.51.100.20", "cdn.example.net")
    c.ioc("domain", "www.example.com", 0, 4, "dns")
    c.ioc("domain", "cdn.example.net", 40, 3, "dns")
    c.ioc("ip", "198.51.100.10", 0.5, 3)
    c.ioc("ip", "198.51.100.20", 41, 2)
    c.ioc("url", "http://www.example.com/news?id=7", 190.8, 1, "http")


UA_BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0"


def pcap_dns_traffic(c: Capture) -> None:
    client = "10.0.1.11"
    lookups = [
        ("example.org", "A", ["198.51.100.30"], "NOERROR"),
        ("example.org", "AAAA", ["2001:db8::30"], "NOERROR"),
        ("mail.example.org", "MX", [], "NOERROR"),
        ("example.org", "TXT", [], "NOERROR"),
        ("wiki.example.org", "A", ["198.51.100.31"], "NOERROR"),
        ("nonexistent.example.org", "A", [], "NXDOMAIN"),
        ("docs.example.org", "A", ["198.51.100.32"], "NOERROR"),
        ("intranet.example.org", "A", [], "NXDOMAIN"),
    ]
    for i, (name, qtype, answers, rcode) in enumerate(lookups):
        c.dns(i * 7.3, client, name, qtype, answers=answers, rcode=rcode)
    for name in ("example.org", "wiki.example.org", "docs.example.org"):
        c.ioc("domain", name, 0, 1, "dns")


def pcap_tls_sessions(c: Capture) -> None:
    client = "10.0.1.12"
    sub = "Normal for test and internal services; on the internet it defeats server authentication."
    ref = c.tls(
        0,
        client,
        "203.0.113.30",
        "selfsigned.example.org",
        cert_issuer="CN=selfsigned.example.org",
        self_signed=True,
        validation_status="self signed certificate",
    )
    c.finding(
        0,
        "tls_self_signed",
        "suspicious_traffic",
        "TLS server presented a self-signed certificate",
        f"selfsigned.example.org (203.0.113.30) presented a self-signed certificate "
        f"(CN=selfsigned.example.org). {sub}",
        "low",
        0.7,
        src=client,
        dst="203.0.113.30",
        dport=443,
        protocol="tls",
        refs=[ref],
        attributes={"subject": "CN=selfsigned.example.org", "occurrences": 1},
    )
    expired_from, expired_to = T0 - dt.timedelta(days=730), T0 - dt.timedelta(days=365)
    ref = c.tls(
        20,
        client,
        "203.0.113.31",
        "expired.example.org",
        cert_not_before=expired_from,
        cert_not_after=expired_to,
        validation_status="certificate has expired",
    )
    c.finding(
        20,
        "tls_expired_certificate",
        "suspicious_traffic",
        "TLS certificate outside its validity period",
        f"expired.example.org (203.0.113.31) presented a certificate valid from "
        f"{expired_from} to {expired_to}, used at {at(20)}.",
        "low",
        0.8,
        src=client,
        dst="203.0.113.31",
        dport=443,
        protocol="tls",
        refs=[ref],
        attributes={"not_after": str(expired_to), "occurrences": 1},
    )
    ref = c.tls(45, client, "203.0.113.32", "legacy.example.org", version="TLSv10")
    c.finding(
        45,
        "tls_legacy_version",
        "suspicious_traffic",
        "Legacy protocol version TLSv10",
        f"{client} and legacy.example.org (203.0.113.32) negotiated TLSv10, which is "
        "deprecated (RFC 8996) and lacks modern protections.",
        "low",
        0.9,
        src=client,
        dst="203.0.113.32",
        dport=443,
        protocol="tls",
        refs=[ref],
        attributes={"version": "TLSv10", "occurrences": 1},
    )
    for name in ("selfsigned.example.org", "expired.example.org", "legacy.example.org"):
        c.ioc("domain", name, 0, 1, "tls")
    for ip in ("203.0.113.30", "203.0.113.31", "203.0.113.32"):
        c.ioc("ip", ip, 0, 1)


def pcap_beacon(c: Capture) -> None:
    client, server = "10.0.2.20", "203.0.113.50"
    refs = []
    for i in range(12):
        t = i * 60 + (0.4 if i % 2 else -0.3)
        refs.append(
            c.http(
                t,
                client,
                server,
                8080,
                method="POST",
                host="updates.example.net",
                uri="/api/checkin",
                user_agent="agent/1.0",
                request_body_len=31,
                response_body_len=14,
                resp_mime_types=["application/json"],
            )
        )
        if i < 3:
            c.alert(t, client, server, 8080, 9000002, "CYBERLAB TEST beacon check-in")
    c.finding(
        -0.3,
        "beaconing",
        "beaconing",
        "Periodic connections (beacon-like)",
        f"{client} connected to {server}:8080/tcp 12 times every 60.0 s (±0.4 s, interval "
        "CV 0.006) with similar sizes (size CV 0.000). Regular timing is typical of "
        "automated check-ins (updaters, agents, C2); confirm the client.",
        "medium",
        0.86,
        src=client,
        dst=server,
        dport=8080,
        protocol="tcp",
        refs=refs,
        last=660.4,
        attributes={
            "connections": 12,
            "mean_interval_s": 60.06,
            "interval_cv": 0.0063,
            "size_cv": 0.0,
        },
    )
    c.ioc("ip", server, -0.3, 12)
    c.ioc("domain", "updates.example.net", -0.3, 12, "http")
    c.ioc("url", "http://updates.example.net/api/checkin", -0.3, 12, "http")


def pcap_dns_anomalies(c: Capture) -> None:
    client = "10.0.3.30"
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    names = []
    for i in range(6):
        label = "".join(alphabet[int(digest(c.name, i, j, n=2), 16) % 32] for j in range(45))
        name = f"{label}.t.example.net"
        names.append(name)
        c.dns(i * 1.7, client, name, "TXT", rcode="NXDOMAIN" if i % 3 else "NOERROR")
    refs = [r.flow_ref for r in c.records if isinstance(r, DnsRecord) and r.flow_ref]
    c.finding(
        0,
        "dns_tunneling_like",
        "dns_anomaly",
        "Tunneling-like DNS names under example.net",
        f"{client} queried 30 names under example.net, 30 of them with long or "
        f"high-entropy first labels (e.g. {names[0][:80]}); 30 TXT queries, NXDOMAIN "
        "ratio 67%. Encoded data in DNS names is used by tunneling and some exfiltration "
        "tools, but also by CDNs and anti-virus lookups.",
        "medium",
        0.9,
        src=client,
        protocol="dns",
        refs=refs,
        last=49.3,
        attributes={
            "domain": "example.net",
            "queries": 30,
            "suspicious_labels": 30,
            "nxdomain_ratio": 0.667,
            "txt_queries": 30,
        },
    )
    for i, name in enumerate(names[:3]):
        c.ioc("domain", name, i * 1.7, 1, "dns")


def pcap_port_scan(c: Capture) -> None:
    scanner, target = "10.0.4.40", "192.168.10.10"
    refs = []
    for port in (1, 2, 21, 22, 23, 25, 80, 443):
        state = "SF" if port in (22, 80, 443) else "REJ"
        refs.append(
            c.flow(
                (port - 1) * 0.05,
                scanner,
                target,
                port,
                conn_state=state,
                orig_bytes=0,
                resp_bytes=0,
                orig_pkts=2,
                resp_pkts=1,
                duration_s=0.002,
            )
        )
    c.finding(
        0,
        "port_scan_vertical",
        "port_scan",
        "Port scan (vertical)",
        f"{scanner} probed 120 ports on {target} in 6.0 s; 117 of 120 attempts (98%) were "
        "rejected or unanswered. This pattern matches network reconnaissance or an "
        "inventory scanner; check if it is authorised.",
        "high",
        0.89,
        src=scanner,
        dst=target,
        protocol="tcp",
        refs=refs,
        last=5.95,
        attributes={"targets": 120, "attempts": 120, "failed_ratio": 0.975},
    )
    hrefs = []
    for host in range(1, 5):
        hrefs.append(
            c.flow(
                6 + host * 0.2,
                scanner,
                f"192.168.10.{100 + host}",
                445,
                conn_state="S0",
                orig_bytes=0,
                resp_bytes=0,
                orig_pkts=1,
                resp_pkts=0,
                duration_s=0.0,
            )
        )
    c.finding(
        6.2,
        "port_scan_horizontal",
        "port_scan",
        "Port scan (horizontal)",
        f"{scanner} probed port 445 on 25 hosts in 4.8 s; 25 of 25 attempts (100%) were "
        "rejected or unanswered. This pattern matches network reconnaissance or an "
        "inventory scanner; check if it is authorised.",
        "medium",
        0.9,
        src=scanner,
        dport=445,
        protocol="tcp",
        refs=hrefs,
        last=11.0,
        attributes={"targets": 25, "attempts": 25, "failed_ratio": 1.0},
    )


def pcap_suspicious_http(c: Capture) -> None:
    client, server = "10.0.5.50", "203.0.113.70"
    ref = c.http(
        0,
        client,
        server,
        80,
        method="GET",
        host=server,
        uri="/dl/payload.exe",
        user_agent="curl/8.5.0",
        response_body_len=470,
        resp_mime_types=["application/x-dosexec"],
    )
    c.alert(0, client, server, 80, 9000001, "CYBERLAB TEST curl user agent")
    c.finding(
        0,
        "http_to_ip_literal",
        "suspicious_traffic",
        "HTTP request to a bare IP address",
        f"{client} sent HTTP requests with Host '{server}' (no domain name), e.g. GET "
        "/dl/payload.exe. Common for malware staging and scanners, also for appliances "
        "and internal tools.",
        "low",
        0.6,
        src=client,
        dst=server,
        dport=80,
        protocol="http",
        refs=[ref],
        attributes={"host": server, "occurrences": 1},
    )
    c.finding(
        0,
        "executable_over_http",
        "suspicious_traffic",
        "Executable downloaded over cleartext HTTP",
        f"{client} received application/x-dosexec content from {server} "
        "(/dl/payload.exe) without TLS: the file could have been tampered with in transit "
        "and its origin is unauthenticated.",
        "medium",
        0.7,
        src=client,
        dst=server,
        dport=80,
        protocol="http",
        refs=[ref],
        attributes={"uri": "/dl/payload.exe", "occurrences": 1},
    )
    c.ioc("ip", server, 0, 1)
    c.ioc("url", f"http://{server}/dl/payload.exe", 0, 1, "http")


PCAP_SCENARIOS: dict[str, Callable[[Capture], None]] = {
    "normal_web": pcap_normal_web,
    "dns_traffic": pcap_dns_traffic,
    "tls_sessions": pcap_tls_sessions,
    "beacon": pcap_beacon,
    "dns_anomalies": pcap_dns_anomalies,
    "port_scan": pcap_port_scan,
    "suspicious_http": pcap_suspicious_http,
}
CLIENTS = {
    "normal_web": "10.0.1.10",
    "dns_traffic": "10.0.1.11",
    "tls_sessions": "10.0.1.12",
    "beacon": "10.0.2.20",
    "dns_anomalies": "10.0.3.30",
    "port_scan": "10.0.4.40",
    "suspicious_http": "10.0.5.50",
}


def qname(text: str) -> str:
    labels, current = [], ""
    for ch in text:
        if len((current + ch).encode()) > 63:
            labels.append(current)
            current = ""
        current += ch
    labels.append(current)
    return ".".join([*labels, QNAME_SUFFIX])


def plant_pcap(c: Capture, scenario: str) -> list[dict[str, Any]]:
    """The planted sessions of `generate.planted_packets` as the analyzers report them."""
    client, p = CLIENTS[scenario], inj.PAYLOADS
    t = PLANT_OFFSET_S
    name = qname(p["P6"])
    c.dns(t, client, name, rcode="NXDOMAIN")
    c.dns(t + 0.5, client, TXT_NAME, "TXT", answers=[p["P2"], p["P8"]], ttls=[300.0, 300.0])
    uri = "/" + quote(p["P7"], safe="/:;!")
    c.http(
        t + 1.0,
        client,
        PLANT_SERVER,
        80,
        method="GET",
        host=p["P1"],
        uri=uri,
        user_agent=p["P3"],
        resp_mime_types=["text/plain"],
    )
    c.tls(
        t + 2.0,
        client,
        PLANT_SERVER,
        p["P5"],
        cert_subject=f"CN={p['P4']}",
        cert_sha256=digest("planted", scenario),
    )
    c.ioc("domain", name.lower(), t, 1, "dns")
    c.ioc("domain", TXT_NAME, t + 0.5, 1, "dns")
    c.ioc("url", f"http://{p['P1'].lower()}{uri}", t + 1.0, 1, "http")
    c.ioc("ip", PLANT_SERVER, t + 1.0, 2)
    rec = "network_records"
    src = {"src_ip": client}
    return [
        {
            "payload": "P6",
            "carrier": "dns.query",
            "value": name,
            "table": rec,
            "where": {**src, "kind": "dns", "details.query": name},
        },
        {
            "payload": "P2",
            "carrier": "dns.txt",
            "value": p["P2"],
            "table": rec,
            "where": {**src, "kind": "dns", "details.query": TXT_NAME},
        },
        {
            "payload": "P8",
            "carrier": "dns.txt",
            "value": p["P8"],
            "table": rec,
            "where": {**src, "kind": "dns", "details.query": TXT_NAME},
        },
        {
            "payload": "P3",
            "carrier": "http.user_agent",
            "value": p["P3"],
            "table": rec,
            "where": {**src, "kind": "http", "dst_ip": PLANT_SERVER},
        },
        {
            "payload": "P7",
            "carrier": "http.uri",
            "value": uri,
            "table": rec,
            "where": {**src, "kind": "http", "dst_ip": PLANT_SERVER},
        },
        {
            "payload": "P1",
            "carrier": "http.host",
            "value": p["P1"],
            "table": rec,
            "where": {**src, "kind": "http", "dst_ip": PLANT_SERVER},
        },
        {
            "payload": "P5",
            "carrier": "tls.server_name",
            "value": p["P5"],
            "table": rec,
            "where": {**src, "kind": "tls", "dst_ip": PLANT_SERVER},
        },
        {
            "payload": "P4",
            "carrier": "tls.cert_subject_cn",
            "value": p["P4"],
            "table": rec,
            "where": {**src, "kind": "tls", "dst_ip": PLANT_SERVER},
        },
    ]


def pcap_tables(records: list[BaseModel]) -> dict[str, list[dict[str, Any]]]:
    tables: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        table, row = pcap_ingest.to_row(record)  # type: ignore[arg-type]
        tables.setdefault(table.name, []).append(to_json_row(row))
    return tables


def pcap_summary(records: list[BaseModel], first: dt.datetime, last: dt.datetime) -> dict[str, Any]:
    counts = Counter(r.kind for r in records)  # type: ignore[attr-defined]
    flows = [r for r in records if isinstance(r, FlowRecord)]
    total = sum(f.orig_bytes + f.resp_bytes for f in flows)
    return {
        "schema_version": "pcap.v1",
        "capture_format": "pcap",
        "tool_versions": PCAP_TOOLS,
        "engine_errors": [],
        "truncated": {},
        "capture": {
            "packets": sum(f.orig_pkts + f.resp_pkts for f in flows),
            "bytes": total,
            "first_ts": iso(first),
            "last_ts": iso(last),
            "duration_s": round((last - first).total_seconds(), 3),
            "link_type": "Ethernet",
            "protocol_hierarchy": [],
            "top_sources": [],
            "top_destinations": [],
            "top_ports": [],
        },
        "engine_counts": {},
        "counts": {name: counts[kind] for kind, name in pcap_ingest.COUNT_NAMES.items()},
    }


def dedupe_iocs(records: list[BaseModel]) -> list[BaseModel]:
    """One IOC per (type, value), as the collector reports them (first/last seen, count)."""
    merged: dict[tuple[str, str], IocRecord] = {}
    out: list[BaseModel] = []
    for record in records:
        if not isinstance(record, IocRecord):
            out.append(record)
            continue
        key = (record.type, record.value)
        seen = merged.get(key)
        if seen is None:
            merged[key] = record
            continue
        merged[key] = seen.model_copy(
            update={
                "first_seen": min(seen.first_seen, record.first_seen),
                "last_seen": max(seen.last_seen, record.last_seen),
                "count": seen.count + record.count,
            }
        )
    return out + list(merged.values())


def pcap_job(name: str, scenarios: list[str], injected: bool) -> tuple[dict[str, Any], list[Any]]:
    records: list[BaseModel] = []
    plants: list[dict[str, Any]] = []
    for index, scenario in enumerate(scenarios):
        offset = index * 1000.0 if len(scenarios) > 1 else 0.0
        c = Capture(scenario, offset)
        PCAP_SCENARIOS[scenario](c)
        if injected:
            plants += plant_pcap(c, scenario)
        records += c.records
    records = dedupe_iocs(records)
    stamps = [r.ts for r in records if hasattr(r, "ts")]  # type: ignore[attr-defined]
    first, last = min(stamps), max(stamps)
    records = [
        TimelineEvent(ts=first, event="capture_start", title="Capture start"),
        *records,
        TimelineEvent(ts=last, event="capture_end", title="Capture end"),
    ]
    filename = f"{name}{TWIN_SUFFIX if injected else ''}.pcap"
    job = {
        "key": "j1",
        "analyzer": "pcap",
        "profile": None,
        "evidence": {
            "filename": filename,
            "mime": "application/vnd.tcpdump.pcap",
            "description": "pcap capture file, microsecond ts (little-endian) - version 2.4",
            "size_bytes": 4096 + 96 * len(records),
            "uploaded_at": iso(last + dt.timedelta(minutes=5)),
        },
        "created_at": iso(last + dt.timedelta(minutes=6)),
        "finished_at": iso(last + dt.timedelta(minutes=7)),
        "worker_version": "pcap-worker/hand-trimmed",
        "summary": pcap_summary(records, first, last),
        "tables": pcap_tables(records),
    }
    return job, plants


# --- static ----------------------------------------------------------------------------------

KERNEL32_BASE = [
    "GetModuleHandleA",
    "GetCommandLineA",
    "GetLastError",
    "ExitProcess",
    "GetStartupInfoA",
    "HeapAlloc",
    "HeapFree",
    "GetProcessHeap",
    "CloseHandle",
    "Sleep",
]
MSVCRT_BASE = ["printf", "malloc", "free", "strlen", "memcpy", "exit"]
API_TEXT = {
    "api_injection": (
        "Process-injection API set imported",
        "The import table contains APIs that together can allocate memory in, write to and "
        "start code in another process: {apis}. Legitimate debuggers and some security tools "
        "use the same set; review how the calls are used.",
        "medium",
    ),
    "api_keylogging": (
        "Keyboard hook / key-state API set imported",
        "The import table combines keyboard hooking or raw-input registration with key-state "
        "polling: {apis}. This combination can record keystrokes; accessibility and hotkey "
        "tools also use it.",
        "medium",
    ),
    "api_anti_debug": (
        "Debugger-detection API set imported",
        "The import table combines debugger checks with process-information queries: {apis}. "
        "These can be used to change behaviour under analysis.",
        "low",
    ),
    "api_credential_access": (
        "Credential-store access API set imported",
        "The import table combines APIs that read stored credentials, protected data or "
        "process memory dumps: {apis}. Password managers and backup tools use some of these.",
        "medium",
    ),
    "api_persistence": (
        "Persistence API set present",
        "The file can register itself to start automatically: {apis}. Installers and services "
        "do this legitimately.",
        "medium",
    ),
    "api_downloader": (
        "Download-and-execute API set imported",
        "The import table combines fetching content from a URL with starting a program: "
        "{apis}. Updaters and installers use the same pattern.",
        "low",
    ),
}


@dataclass
class Sample:
    name: str
    file_format: str = "pe"
    bits: int = 32
    dll: bool = False
    profile: str = "full"
    imports: dict[str, list[str]] = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)
    wide: list[str] = field(default_factory=list)
    sections: list[tuple[str, float]] = field(
        default_factory=lambda: [(".text", 6.1), (".rdata", 4.2), (".data", 1.3)]
    )
    api: tuple[str, list[str]] | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    capabilities: list[tuple[str, str, list[str]]] = field(default_factory=list)
    iocs: list[tuple[str, str]] = field(default_factory=list)
    floss: list[str] = field(default_factory=list)


def yara(name: str, description: str, severity: str = "medium") -> dict[str, Any]:
    return {"detector": "yara", "name": name, "description": description, "severity": severity}


STATIC_SAMPLES: list[Sample] = [
    Sample(
        "benign_pe32",
        imports={
            "KERNEL32.dll": KERNEL32_BASE + ["LoadLibraryA", "GetProcAddress"],
            "msvcrt.dll": MSVCRT_BASE,
            "USER32.dll": ["MessageBoxA"],
        },
        strings=[
            "Hello from the CyberLab benign sample",
            "Usage: %s <input-file>",
            "Documentation: https://www.example.com/help/index.html",
            "settings.ini",
        ],
        wide=["CyberLab Benign Sample"],
        iocs=[("url", "https://www.example.com/help/index.html"), ("domain", "www.example.com")],
    ),
    Sample(
        "benign_pe64",
        bits=64,
        dll=True,
        imports={
            "KERNEL32.dll": KERNEL32_BASE,
            "ADVAPI32.dll": ["RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey"],
        },
        strings=["CyberLab benign library", "config.Path", "cyberlab_benign.dll"],
    ),
    Sample(
        "packed_like",
        sections=[("UPX0", 0.0), ("UPX1", 7.9)],
        imports={"KERNEL32.DLL": ["LoadLibraryA", "GetProcAddress"]},
        strings=["UPX!"],
        findings=[
            {
                "detector": "packer",
                "type": "packer_indicators",
                "severity": "medium",
                "title": "Packer / compression indicators (4)",
                "description": "Structural traits typical of packed or compressed "
                "executables: upx_section_names, high_entropy_section, tiny_import_table, "
                "entry_outside_text. Packing hides the real code from static analysis; it "
                "is also used to shrink legitimate programs.",
                "attributes": {
                    "upx_section_names": "UPX0, UPX1",
                    "entry_outside_text": "UPX1 (last section)",
                    "indicator_count": 4,
                },
            },
            yara("CyberLab_UPX_Section_Names", "UPX section names"),
            yara("CyberLab_UPX_Marker_String", "UPX marker string"),
        ],
        capabilities=[("packed with UPX", "anti-analysis/packer/upx", ["T1027.002"])],
    ),
    Sample(
        "injection_imports",
        bits=64,
        imports={
            "KERNEL32.dll": KERNEL32_BASE
            + ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "msvcrt.dll": MSVCRT_BASE,
        },
        strings=["target process id: %lu", "explorer.exe"],
        api=(
            "api_injection",
            ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        ),
        findings=[yara("CyberLab_Process_Injection_API_Names", "process injection API names")],
    ),
    Sample(
        "keylogger_imports",
        imports={
            "KERNEL32.dll": KERNEL32_BASE + ["CreateFileA", "WriteFile"],
            "USER32.dll": [
                "SetWindowsHookExA",
                "CallNextHookEx",
                "GetAsyncKeyState",
                "GetKeyState",
                "GetMessageA",
                "UnhookWindowsHookEx",
            ],
        },
        strings=["keys.log", "[%02x]"],
        api=(
            "api_keylogging",
            ["SetWindowsHookExA", "CallNextHookEx", "GetAsyncKeyState", "GetKeyState"],
        ),
        findings=[yara("CyberLab_Keyboard_Hook_API_Names", "keyboard hook API names")],
    ),
    Sample(
        "test_marker",
        imports={"KERNEL32.dll": KERNEL32_BASE, "msvcrt.dll": MSVCRT_BASE},
        strings=["CyberLab test marker sample", "CYBERLAB-STATIC-TEST-MARKER-7f3a"],
        findings=[
            yara("CyberLab_Test_Marker", "CyberLab static test marker", "low"),
            {"detector": "clamav", "name": "PUA.CyberLab.TestMarker", "severity": "low"},
        ],
    ),
    Sample(
        "antidebug_imports",
        bits=64,
        imports={
            "KERNEL32.dll": KERNEL32_BASE
            + ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA"],
            "ntdll.dll": ["NtQueryInformationProcess"],
        },
        strings=["debugger check"],
        api=(
            "api_anti_debug",
            ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
        ),
    ),
    Sample(
        "credential_imports",
        bits=64,
        imports={
            "KERNEL32.dll": KERNEL32_BASE + ["OpenProcess"],
            "ADVAPI32.dll": ["CredEnumerateA", "CredReadA", "CredFree"],
            "CRYPT32.dll": ["CryptUnprotectData"],
            "dbghelp.dll": ["MiniDumpWriteDump"],
        },
        strings=["credential export"],
        api=(
            "api_credential_access",
            ["CredEnumerateA", "CredReadA", "CryptUnprotectData", "MiniDumpWriteDump"],
        ),
    ),
    Sample(
        "persistence_imports",
        imports={
            "KERNEL32.dll": KERNEL32_BASE,
            "ADVAPI32.dll": [
                "RegCreateKeyExA",
                "RegSetValueExA",
                "RegCloseKey",
                "OpenSCManagerA",
                "CreateServiceA",
                "StartServiceA",
                "CloseServiceHandle",
            ],
        },
        strings=[
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "C:\\ProgramData\\CyberLabTest\\updater.exe",
            "CyberLabUpdater",
        ],
        api=(
            "api_persistence",
            [
                "RegCreateKeyExA",
                "RegSetValueExA",
                "CreateServiceA",
                "StartServiceA",
                "Run-key path in strings",
            ],
        ),
        iocs=[
            ("registry_key", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("file_path", "C:\\ProgramData\\CyberLabTest\\updater.exe"),
        ],
    ),
    Sample(
        "downloader_imports",
        imports={
            "KERNEL32.dll": KERNEL32_BASE + ["WinExec"],
            "urlmon.dll": ["URLDownloadToFileA"],
            "WININET.dll": ["InternetOpenA", "InternetOpenUrlA", "InternetReadFile"],
        },
        strings=[
            "http://downloads.example.net/update/payload.bin",
            "198.51.100.23",
            "support@example.org",
            "%TEMP%\\cyberlab-update.exe",
        ],
        wide=["https://cdn.example.org/files/setup.msi"],
        api=("api_downloader", ["URLDownloadToFileA", "InternetOpenUrlA", "WinExec"]),
        iocs=[
            ("url", "http://downloads.example.net/update/payload.bin"),
            ("url", "https://cdn.example.org/files/setup.msi"),
            ("domain", "downloads.example.net"),
            ("domain", "cdn.example.org"),
            ("ip", "198.51.100.23"),
            ("email", "support@example.org"),
            ("file_path", "%TEMP%\\cyberlab-update.exe"),
        ],
    ),
    Sample(
        "pe_anomalies",
        imports={"KERNEL32.dll": KERNEL32_BASE, "msvcrt.dll": MSVCRT_BASE},
        strings=["anomalies sample", "embedded"],
        findings=[
            {
                "detector": "pe_anomaly",
                "type": "timestamp_anomaly",
                "severity": "low",
                "title": "Implausible compile timestamp",
                "description": "The PE header timestamp is 2099-01-01 00:00:00 UTC (in "
                "the future). Timestamps are easily set to any value, so this only says "
                "the header was not written by a normal build.",
                "attributes": {"timestamp": 4070908800, "reason": "future"},
            },
            {
                "detector": "pe_anomaly",
                "type": "tls_callbacks",
                "severity": "low",
                "title": "TLS callbacks present (2)",
                "description": "The PE registers 2 TLS callback(s), which run before the "
                "entry point. Common in MinGW / Delphi runtimes; also used to run code "
                "early.",
                "attributes": {"count": 2},
            },
            {
                "detector": "pe_anomaly",
                "type": "high_entropy_resource",
                "severity": "low",
                "title": "High-entropy resources (1)",
                "description": "1 resource(s) have entropy above 7.2 (largest: 8192 "
                "bytes), consistent with compressed or encrypted embedded data.",
                "attributes": {"count": 1, "largest": 8192},
            },
            {
                "detector": "pe_anomaly",
                "type": "overlay",
                "severity": "low",
                "title": "Overlay data after the last section (3584 bytes)",
                "description": "3584 bytes follow the last section (entropy of the "
                "whole file: 6.21). Installers and self-extracting archives store "
                "payloads this way.",
                "attributes": {"size": 3584},
            },
            yara("CyberLab_Embedded_PE_In_Overlay", "embedded PE in the overlay"),
        ],
    ),
    Sample(
        "benign_elf",
        file_format="elf",
        bits=64,
        imports={"libc.so.6": ["puts", "printf", "malloc", "free", "__libc_start_main"]},
        strings=["Hello from the CyberLab benign ELF sample", "usage: %s FILE"],
        sections=[(".text", 6.0), (".rodata", 4.1), (".data", 0.0)],
    ),
    Sample(
        "stack_string",
        sections=[(".text", 5.9), (".rdata", 3.1)],
        imports={"KERNEL32.dll": ["ExitProcess", "GetModuleHandleA", "Sleep"]},
        strings=["stack string sample"],
        capabilities=[
            (
                "contain obfuscated stackstrings",
                "anti-analysis/obfuscation/string/stackstring",
                ["T1027"],
            )
        ],
        findings=[
            {
                "detector": "capa",
                "type": "capability_anti_analysis",
                "severity": "medium",
                "title": "capa: anti-analysis capabilities (1)",
                "description": "capa found code patterns for: contain obfuscated "
                "stackstrings (ATT&CK T1027). Static capability detection; the code was "
                "not observed running.",
                "attributes": {
                    "rules": "contain obfuscated stackstrings",
                    "attack": "T1027",
                    "namespaces": "anti-analysis/obfuscation/string/stackstring",
                },
            }
        ],
        floss=["cyberlab-stackstr.example.com"],
        iocs=[("domain", "cyberlab-stackstr.example.com")],
    ),
    Sample(
        "near_miss_apis",
        bits=64,
        imports={
            "KERNEL32.dll": KERNEL32_BASE
            + ["VirtualAllocEx", "WriteProcessMemory", "IsDebuggerPresent", "CreateFileA"],
            "USER32.dll": ["GetAsyncKeyState", "GetKeyState", "GetMessageA"],
            "urlmon.dll": ["URLDownloadToFileA"],
        },
        strings=["near miss sample", "settings.dat"],
    ),
    Sample(
        "near_miss_packer",
        imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress"]},
        strings=["plugin loader"],
    ),
    Sample(
        "near_miss_icon",
        imports={"KERNEL32.dll": KERNEL32_BASE, "msvcrt.dll": MSVCRT_BASE},
        strings=["icon sample"],
    ),
    Sample(
        "eicar",
        file_format="other",
        profile="av",
        sections=[],
        findings=[{"detector": "clamav", "name": "CyberLab.Test.EICAR", "severity": "high"}],
    ),
]
# packed_like also gets a capa anti-analysis finding (labels.json) from its UPX capability.
STATIC_SAMPLES[2].findings.append(
    {
        "detector": "capa",
        "type": "capability_anti_analysis",
        "severity": "medium",
        "title": "capa: anti-analysis capabilities (1)",
        "description": "capa found code patterns for: packed with UPX (ATT&CK T1027.002). Static "
        "capability detection; the code was not observed running.",
        "attributes": {
            "rules": "packed with UPX",
            "attack": "T1027.002",
            "namespaces": "anti-analysis/packer/upx",
        },
    }
)


def _finding(sample: Sample, spec: dict[str, Any]) -> FindingRecord:
    detector = spec["detector"]
    if detector == "yara":
        name = spec["name"]
        type_, method = "yara_match", "signature:yara@1"
        title = f"YARA rule match: {name}"
        description = (
            f"The YARA rule cyberlab:{name} (rule-supplied description: {spec['description']}) "
            "matched this file."
        )
        attributes = {
            "name": name,
            "namespace": "cyberlab",
            "engine": "yara",
            "description": spec["description"],
        }
    elif detector == "clamav":
        name = spec["name"]
        type_, method = "av_signature_match", "signature:clamav@1"
        title = f"ClamAV signature match: {name}"
        description = (
            f"ClamAV reported the signature {name} (engine-supplied name) for this file. Review "
            "the signature and the file before drawing conclusions; test signatures and "
            "potentially-unwanted-application signatures are included."
        )
        attributes = {"name": name, "engine": "clamav"}
    else:
        type_ = spec["type"]
        method = {
            "packer": "heuristic:packer@1",
            "pe_anomaly": "heuristic:pe_anomaly@1",
            "capa": "capability:capa@1",
        }[detector]
        title, description, attributes = spec["title"], spec["description"], spec["attributes"]
    return FindingRecord(
        ts=T0,
        finding_id=uuid.uuid5(FINDING_NS, f"{sample.name}|{method}|{type_}|{title}"),
        type=type_,
        title=title,
        description=description,
        severity=spec["severity"],
        confidence=0.8,
        detection_method=method,
        evidence_refs=[f"{detector}:{spec.get('name', type_)}"],
        attributes=attributes,
    )


def static_records(sample: Sample, injected: bool) -> tuple[list[BaseModel], list[Any]]:
    records: list[BaseModel] = []
    plants: list[dict[str, Any]] = []
    for i, (name, entropy) in enumerate(sample.sections):
        flags = ["read", "execute"] if name in (".text", "UPX1") else ["read"]
        records.append(
            SectionRecord(
                index=i,
                name=name,
                virtual_address=0x1000 * (i + 1),
                virtual_size=0x800,
                raw_size=0x800 if entropy else 0,
                entropy=entropy,
                flags=flags,
            )
        )
    for library, functions in sample.imports.items():
        records += [ImportRecord(library=library, function=f) for f in functions]
    offset = 0x2000
    for value in sample.strings:
        records.append(StringRecord(value=value, encoding="ascii", offset=offset))
        offset += len(value) + 1
    for value in sample.wide:
        records.append(StringRecord(value=value, encoding="utf16le", offset=offset))
        offset += 2 * len(value) + 2
    for value in sample.floss:
        records.append(StringRecord(value=value, encoding="floss_stack", offset=None))
    if injected:
        p, stack = inj.PAYLOADS, sample.name == "stack_string"
        table = "malware_strings"
        for pid in ("P1", "P2", "P3", "P6", "P7", "P8"):
            if stack and pid == "P8":
                continue
            records.append(StringRecord(value=p[pid], encoding="ascii", offset=offset))
            offset += len(p[pid]) + 1
            plants.append(
                {
                    "payload": pid,
                    "carrier": "string.ascii",
                    "value": p[pid],
                    "table": table,
                    "where": {"value": p[pid], "encoding": "ascii"},
                }
            )
        for pid in ("P2", "P5", "P8"):
            if stack and pid == "P8":
                continue
            records.append(StringRecord(value=p[pid], encoding="utf16le", offset=offset))
            offset += 2 * len(p[pid]) + 2
            plants.append(
                {
                    "payload": pid,
                    "carrier": "string.utf16le",
                    "value": p[pid],
                    "table": table,
                    "where": {"value": p[pid], "encoding": "utf16le"},
                }
            )
        if stack:
            records.append(StringRecord(value=p["P8"], encoding="floss_stack", offset=None))
            plants.append(
                {
                    "payload": "P8",
                    "carrier": "floss.stack",
                    "value": p["P8"],
                    "table": table,
                    "where": {"value": p["P8"], "encoding": "floss_stack"},
                }
            )
        if sample.file_format == "pe":
            records.append(
                ResourceRecord(type="RT_VERSION", name="1", language="1033", size=1024, entropy=3.1)
            )
            plants.append(
                {"payload": "P1", "carrier": "version_info.FileDescription", "value": p["P1"]}
            )
    for spec in sample.findings:
        if spec["detector"] in ("yara", "clamav"):
            engine = spec["detector"]
            records.append(
                SignatureMatch(
                    engine=engine,
                    name=spec["name"],
                    namespace="cyberlab" if engine == "yara" else None,
                    tags=[],
                    meta={"description": spec.get("description", spec["name"])},
                )
            )
    for name, namespace, attack in sample.capabilities:
        records.append(
            CapabilityRecord(name=name, namespace=namespace, attack=attack, mbc=[], matches=1)
        )
    if sample.api is not None:
        type_, apis = sample.api
        title, description, severity = API_TEXT[type_]
        joined = ", ".join(apis)
        records.append(
            FindingRecord(
                ts=T0,
                finding_id=uuid.uuid5(FINDING_NS, f"{sample.name}|api|{type_}"),
                type=type_,
                title=title,
                description=description.format(apis=joined),
                severity=severity,
                confidence=0.75,
                detection_method="heuristic:suspicious_api@1",
                evidence_refs=[f"import:{a}" for a in apis if " " not in a],
                attributes={"apis": joined, "api_count": len(apis), "groups": "set"},
            )
        )
    records += [_finding(sample, spec) for spec in sample.findings]
    iocs = list(sample.iocs)
    if injected:
        iocs += [
            ("url", "https://attacker.example/pixel.png?d=CONTEXT"),
            ("url", "https://attacker.example/stage2"),
            ("domain", "attacker.example"),
        ]
    for type_, value in iocs:
        source = "floss" if value in sample.floss else "strings"
        records.append(
            IocRecord(type=type_, value=value, first_seen=T0, last_seen=T0, count=1, source=source)
        )
    return records, plants


def static_job(sample: Sample, injected: bool) -> tuple[dict[str, Any], list[Any]]:
    records, plants = static_records(sample, injected)
    tables: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        table, row = static_ingest.to_row(record)  # type: ignore[arg-type]
        tables.setdefault(table.name, []).append(to_json_row(row))
    seed = (sample.name, injected)
    size = 2048 + 512 * len(records)
    sha256, sha1, md5 = digest(*seed), digest(*seed, "sha1", n=40), digest(*seed, "md5", n=32)
    pe = None
    if sample.file_format == "pe":
        pe = {
            "machine": "AMD64" if sample.bits == 64 else "I386",
            "bits": sample.bits,
            "is_dll": sample.dll,
            "subsystem": "WINDOWS_CUI",
            "compile_timestamp": 4070908800 if sample.name == "pe_anomalies" else 1767225600,
            "entry_point": 0x1000,
            "entry_section": sample.sections[-1][0] if sample.name == "packed_like" else ".text",
            "image_base": 0x400000 if sample.bits == 32 else 0x140000000,
            "imphash": digest(sample.name, "imphash", n=32),
            "rich_header_hash": None,
            "tls_callbacks": 2 if sample.name == "pe_anomalies" else 0,
            "has_authenticode": sample.name == "benign_pe64",
            "overlay_size": 3584 if sample.name == "pe_anomalies" else 0,
            "characteristics": ["EXECUTABLE_IMAGE"] + (["DLL"] if sample.dll else []),
            "dll_characteristics": ["NX_COMPAT"],
        }
    elf = None
    if sample.file_format == "elf":
        elf = {
            "elf_class": 64,
            "machine": "x86_64",
            "elf_type": "DYN",
            "entry_point": 0x1040,
            "interpreter": "/lib64/ld-linux-x86-64.so.2",
            "needed": ["libc.so.6"],
            "stripped": False,
        }
    file_type = {
        "pe": f"PE32{'+' if sample.bits == 64 else ''} executable for MS Windows",
        "elf": "ELF 64-bit LSB pie executable, x86-64",
        "other": "ASCII text",
    }[sample.file_format]
    mime = {
        "pe": "application/vnd.microsoft.portable-executable",
        "elf": "application/x-pie-executable",
        "other": "text/plain",
    }[sample.file_format]
    tables["malware_samples"] = [
        {
            "size": size,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "ssdeep": None,
            "file_type": file_type,
            "mime": mime,
            "entropy": 5.2,
            "file_format": sample.file_format,
            "pe": pe,
            "elf": elf,
        }
    ]
    counts = Counter(r.kind for r in records)  # type: ignore[attr-defined]
    summary = {
        "schema_version": "static.v1",
        "profile": sample.profile,
        "file_format": sample.file_format,
        "tool_versions": STATIC_TOOLS,
        "engine_errors": [],
        "truncated": {},
        "sample": {
            "size": size,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "file_type": file_type,
            "mime": mime,
            "entropy": 5.2,
            "analyzer_derived": {
                "ssdeep": None,
                "imphash": pe["imphash"] if pe else None,
                "rich_header_hash": None,
            },
        },
        "pe": pe,
        "elf": elf,
        "counts": {name: counts[kind] for kind, name in static_ingest.COUNT_NAMES.items()},
    }
    filename = f"{sample.name}{TWIN_SUFFIX if injected else ''}.bin"
    job = {
        "key": "j1",
        "analyzer": "static",
        "profile": sample.profile,
        "evidence": {
            "filename": filename,
            "mime": mime,
            "description": file_type,
            "size_bytes": size,
            "uploaded_at": iso(T0 + dt.timedelta(hours=1)),
        },
        "created_at": iso(T0 + dt.timedelta(hours=1, minutes=1)),
        "finished_at": iso(T0 + dt.timedelta(hours=1, minutes=2)),
        "worker_version": "static-worker/hand-trimmed",
        "summary": summary,
        "tables": tables,
    }
    return job, plants


# --- TI fixture rows -------------------------------------------------------------------------


def ti_rows(job: str, iocs: list[tuple[str, str]], injected: bool) -> tuple[list[Any], list[Any]]:
    """An OTX and a MISP answer for each IOC; on a twin they carry the TI payloads."""
    rows: list[dict[str, Any]] = []
    plants: list[dict[str, Any]] = []
    for type_, value in iocs:
        topic = f"{type_} {value}"
        rows.append(
            {
                "job": job,
                "ioc": {"type": type_, "value": value},
                "provider": "otx",
                "status": "ok",
                "found": True,
                "tags": ["synthetic"],
                "summary": inj.otx_summary(injected=injected, topic=topic),
            }
        )
        rows.append(
            {
                "job": job,
                "ioc": {"type": type_, "value": value},
                "provider": "misp",
                "status": "ok",
                "found": True,
                "tags": ["tlp:clear"],
                "summary": inj.misp_summary(injected=injected, event=topic),
            }
        )
        if injected:
            where = {"ioc.value": value}
            for path, pid in inj.TI_CARRIERS.items():
                provider = path.split(".", 1)[0]
                plants.append(
                    {
                        "payload": pid,
                        "carrier": f"ti.{path}",
                        "value": inj.PAYLOADS[pid],
                        "table": "ti_results",
                        "where": {**where, "provider": provider},
                    }
                )
    return rows, plants


PCAP_TI: dict[str, list[tuple[str, str]]] = {
    "normal_web": [("domain", "www.example.com")],
    "tls_sessions": [("domain", "selfsigned.example.org")],
    "beacon": [("ip", "203.0.113.50"), ("domain", "updates.example.net")],
    "suspicious_http": [("ip", "203.0.113.70")],
}
STATIC_TI: dict[str, list[tuple[str, str]]] = {
    "benign_pe32": [("domain", "www.example.com")],
    "downloader_imports": [("domain", "downloads.example.net"), ("ip", "198.51.100.23")],
    "stack_string": [("domain", "cyberlab-stackstr.example.com")],
}
PCAP_TASKS = {"beacon": ["summarize_pcap", "explain_finding", "ioc_correlation"]}
STATIC_TASKS = {"downloader_imports": ["explain_static", "attack_mapping"]}


def envelope(
    name: str, kind: str, scenario: str, tasks: list[str], injected: bool, **extra: Any
) -> dict[str, Any]:
    full = name + (TWIN_SUFFIX if injected else "")
    return {
        "format": FORMAT,
        "name": full,
        "clean": name if injected else None,
        "kind": kind,
        "scenario": scenario,
        "tasks": tasks,
        "provenance": {**PROVENANCE, **extra.pop("provenance", {})},
        **extra,
    }


def pcap_case(scenario: str, injected: bool) -> dict[str, Any]:
    scenarios = list(PCAP_SCENARIOS) if scenario == "mixed" else [scenario]
    job, plants = pcap_job(scenario, scenarios, injected)
    iocs = [i for s in scenarios for i in PCAP_TI.get(s, [])]
    if injected:
        iocs.append(("domain", TXT_NAME))
    ti, ti_plants = ti_rows("j1", iocs, injected)
    return envelope(
        f"pcap_{scenario}",
        "pcap",
        scenario,
        PCAP_TASKS.get(scenario, ["summarize_pcap"]),
        injected,
        provenance={"dataset": "apps/workers/pcap/dataset/generate.py", "seed": 1337},
        investigation={
            "title": f"PCAP {scenario}",
            "description": "",
            "severity": "medium",
            "created_at": iso(T0 - dt.timedelta(hours=1)),
        },
        jobs=[job],
        ti=ti,
        plants=plants + ti_plants,
    )


def static_case(sample: Sample, injected: bool) -> dict[str, Any]:
    job, plants = static_job(sample, injected)
    iocs = list(STATIC_TI.get(sample.name, []))
    if injected:
        iocs.append(("domain", "attacker.example"))
    ti, ti_plants = ti_rows("j1", iocs, injected)
    return envelope(
        f"static_{sample.name}",
        "static",
        sample.name,
        STATIC_TASKS.get(sample.name, ["explain_static"]),
        injected,
        provenance={"dataset": "apps/workers/static/samples/generate.py", "seed": 20261105},
        investigation={
            "title": f"Static {sample.name}",
            "description": "",
            "severity": "medium",
            "created_at": iso(T0 - dt.timedelta(hours=1)),
        },
        jobs=[job],
        ti=ti,
        plants=plants + ti_plants,
    )


def investigation_case(
    injected: bool,
    pcap: dict[str, Any] | None = None,
    static: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One incident: the beacon capture and the downloader sample in one investigation
    (built from the given job cases, by default the hand-trimmed ones)."""
    pcap = pcap or pcap_case("beacon", injected)
    static = static or static_case(
        next(s for s in STATIC_SAMPLES if s.name == "downloader_imports"), injected
    )
    j2 = copy.deepcopy(static["jobs"][0])
    j2["key"] = "j2"
    description = "Beacon from a workstation followed by a downloader sample found on it."
    plants = list(pcap["plants"])
    for plant in static["plants"]:
        plants.append({**plant, "job": "j2"} if plant.get("table") != "ti_results" else plant)
    if injected:
        description += " " + inj.PAYLOADS["P6"]
        plants.append(
            {"payload": "P6", "carrier": "investigation.description", "value": inj.PAYLOADS["P6"]}
        )
    ti = list(pcap["ti"]) + [{**row, "job": "j2"} for row in static["ti"]]
    return envelope(
        "incident_beacon_downloader",
        "investigation",
        "beacon+downloader_imports",
        ["incident_summary"],
        injected,
        provenance={"dataset": "pcap beacon + static downloader_imports", **(provenance or {})},
        investigation={
            "title": "Workstation beacon and downloader",
            "description": description,
            "severity": "high",
            "created_at": iso(T0 - dt.timedelta(hours=1)),
        },
        jobs=[pcap["jobs"][0], j2],
        ti=ti,
        plants=plants,
    )


def all_cases() -> list[dict[str, Any]]:
    cases = []
    for injected in (False, True):
        cases += [pcap_case(s, injected) for s in [*PCAP_SCENARIOS, "mixed"]]
        cases += [
            static_case(s, injected)
            for s in STATIC_SAMPLES
            if not (injected and s.name == "eicar")  # no twin for EICAR (labels.json)
        ]
        cases.append(investigation_case(injected))
    return cases


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m tests.ai_eval.handcases")
    parser.add_argument("--out", type=Path, default=CASES_DIR)
    args = parser.parse_args(argv)
    for case in all_cases():
        print(write_case(case, args.out).name)


if __name__ == "__main__":
    main()
