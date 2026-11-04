"""Zeek: flows, DNS, HTTP, TLS (+ x509) from JSON logs in the job's out/ directory."""

import base64
import hashlib
import ipaddress
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberlab_jobs.results import DnsRecord, FlowRecord, HttpRecord, TlsRecord

from pcap_worker import sandbox
from pcap_worker.engines.common import (
    RECORD_ERRORS,
    JsonLines,
    clip,
    clip_list,
    count,
    epoch,
    ip,
    opt_count,
    port,
    seconds,
)

POLICY = Path(__file__).with_name("cyberlab.zeek")
PROTOS = {"tcp", "udp", "icmp"}
TCP = 6

Fingerprints = tuple[str | None, str | None]
JA3For = Callable[[str | None, datetime], Fingerprints]


def run(capture: Path, dirs: sandbox.JobDirs, timeout_s: float) -> None:
    sandbox.run_tool(["zeek", "-C", "-r", str(capture), str(POLICY)], dirs, timeout_s=timeout_s)


def community_id(
    src: str | None, sport: int | None, dst: str | None, dport: int | None, proto: int
) -> str | None:
    """Community ID v1 (seed 0) of a TCP/UDP 5-tuple, as Zeek and Suricata compute it."""
    if src is None or dst is None or sport is None or dport is None:
        return None
    a, b = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    if len(a) != len(b):
        return None
    if (a, sport) > (b, dport):
        a, b, sport, dport = b, a, dport, sport
    data = bytes(2) + a + b + bytes([proto, 0]) + sport.to_bytes(2, "big")
    data += dport.to_bytes(2, "big")
    return "1:" + base64.b64encode(hashlib.sha1(data, usedforsecurity=False).digest()).decode()


def _endpoints(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "src_ip": ip(item.get("id.orig_h")),
        "src_port": port(item.get("id.orig_p")),
        "dst_ip": ip(item.get("id.resp_h")),
        "dst_port": port(item.get("id.resp_p")),
        "flow_ref": clip(item.get("uid"), 64),
    }


def _ts(item: dict[str, Any]) -> datetime:
    ts = epoch(item.get("ts"))
    if ts is None:
        raise ValueError("no usable timestamp")
    return ts


def flows(source: JsonLines) -> Iterator[FlowRecord]:
    for item in source:
        try:
            proto = item.get("proto")
            yield FlowRecord(
                ts=_ts(item),
                **_endpoints(item),
                proto=proto if proto in PROTOS else "other",
                service=clip(item.get("service"), 64),
                duration_s=seconds(item.get("duration")),
                orig_bytes=count(item.get("orig_bytes")),
                resp_bytes=count(item.get("resp_bytes")),
                orig_pkts=count(item.get("orig_pkts")),
                resp_pkts=count(item.get("resp_pkts")),
                conn_state=clip(item.get("conn_state"), 16),
                community_id=clip(item.get("community_id"), 64),
            )
        except RECORD_ERRORS:
            source.skipped += 1


def dns(source: JsonLines) -> Iterator[DnsRecord]:
    for item in source:
        try:
            ttls = item.get("TTLs")
            yield DnsRecord(
                ts=_ts(item),
                **_endpoints(item),
                query=clip(item.get("query"), 255),
                qtype=clip(item.get("qtype_name"), 16),
                rcode=clip(item.get("rcode_name"), 64),
                answers=clip_list(item.get("answers"), 255, 20),
                ttls=[t for t in map(seconds, ttls[:20]) if t is not None]
                if isinstance(ttls, list)
                else [],
            )
        except RECORD_ERRORS:
            source.skipped += 1


def http(source: JsonLines) -> Iterator[HttpRecord]:
    for item in source:
        try:
            status = item.get("status_code")
            yield HttpRecord(
                ts=_ts(item),
                **_endpoints(item),
                method=clip(item.get("method"), 16),
                host=clip(item.get("host"), 255),
                uri=clip(item.get("uri"), 2048),
                status_code=status if isinstance(status, int) and 0 <= status <= 999 else None,
                user_agent=clip(item.get("user_agent"), 512),
                referrer=clip(item.get("referrer"), 2048),
                resp_mime_types=clip_list(item.get("resp_mime_types"), 128, 8),
                request_body_len=opt_count(item.get("request_body_len")),
                response_body_len=opt_count(item.get("response_body_len")),
            )
        except RECORD_ERRORS:
            source.skipped += 1


@dataclass(frozen=True)
class Cert:
    subject: str | None
    issuer: str | None
    not_before: datetime | None
    not_after: datetime | None


def certificates(source: JsonLines) -> dict[str, Cert]:
    out: dict[str, Cert] = {}
    for item in source:
        fingerprint = clip(item.get("fingerprint"), 64)
        if fingerprint:
            out[fingerprint] = Cert(
                subject=clip(item.get("certificate.subject"), 512),
                issuer=clip(item.get("certificate.issuer"), 512),
                not_before=epoch(item.get("certificate.not_valid_before")),
                not_after=epoch(item.get("certificate.not_valid_after")),
            )
    return out


def tls(source: JsonLines, certs: dict[str, Cert], ja3_for: JA3For) -> Iterator[TlsRecord]:
    for item in source:
        try:
            ts = _ts(item)
            chain = item.get("cert_chain_fps")
            fingerprint = clip(chain[0], 64) if isinstance(chain, list) and chain else None
            leaf = certs.get(fingerprint) if fingerprint else None
            endpoints = _endpoints(item)
            cid = community_id(
                endpoints["src_ip"],
                endpoints["src_port"],
                endpoints["dst_ip"],
                endpoints["dst_port"],
                TCP,
            )
            ja3, ja3s = ja3_for(cid, ts)
            established = item.get("established")
            yield TlsRecord(
                ts=ts,
                **endpoints,
                version=clip(item.get("version"), 16),
                cipher=clip(item.get("cipher"), 128),
                server_name=clip(item.get("server_name"), 255),
                established=established if isinstance(established, bool) else None,
                ja3=ja3,
                ja3s=ja3s,
                cert_subject=leaf.subject if leaf else None,
                cert_issuer=leaf.issuer if leaf else None,
                cert_not_before=leaf.not_before if leaf else None,
                cert_not_after=leaf.not_after if leaf else None,
                cert_sha256=fingerprint if leaf else None,
                validation_status=clip(item.get("validation_status"), 128),
                self_signed=(leaf.subject == leaf.issuer) if leaf and leaf.subject else None,
            )
        except RECORD_ERRORS:
            source.skipped += 1
