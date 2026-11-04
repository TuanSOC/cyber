"""Synthetic, labeled PCAP dataset for tests and detector evaluation.

No real traffic: RFC 5737 / RFC 1918 addresses and example.* names only. TCP sessions are
complete (handshake, sequenced data, FIN) so Zeek and Suricata parse them like real
captures; TLS handshakes carry real DER certificates (self-signed / expired / CA-signed).
Every scenario comes with ground-truth labels (labels.json) for precision/recall.

    python -m dataset.generate /path/to/out [--inject]

`--inject` (off by default; the default output is unchanged) also writes an adversarial twin
`<scenario>__injected.pcap` per scenario and for `mixed`: the clean capture, same seed, plus
planted sessions whose DNS / HTTP / TLS fields carry the prompt-injection payloads of
`dataset/inject.py`. labels.json then gains the twins (same detector labels) and an
`_injections` entry recording which field of which twin carries which payload.
"""

import argparse
import datetime as dt
import json
import random
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Packet, Raw, wrpcap

from dataset import inject as injection

BASE_TS = 1_767_225_600.0  # 2026-01-01T00:00:00Z
RESOLVER = "10.0.0.53"
CA_CN = "CyberLab Synthetic Test CA"
TWIN_SUFFIX = "__injected"
MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


@dataclass
class Capture:
    rng: random.Random
    packets: list[Packet] = field(default_factory=list)

    def add(self, pkt: Packet, ts: float) -> None:
        pkt.time = ts
        self.packets.append(pkt)

    def frame(self, src: str, dst: str) -> Packet:
        return Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst)


# --- protocols -----------------------------------------------------------------------------


def tcp_session(
    cap: Capture,
    ts: float,
    client: str,
    server: str,
    dport: int,
    exchanges: Iterable[tuple[str, bytes]],
    *,
    sport: int | None = None,
) -> float:
    """A full TCP session; exchanges are ("c"|"s", payload). Returns the end timestamp."""
    rng = cap.rng
    sport = sport or rng.randint(40000, 60999)
    c_seq, s_seq = rng.randint(1, 2**31), rng.randint(1, 2**31)

    def up(flags: str, **kw: int) -> Packet:
        return cap.frame(client, server) / TCP(
            sport=sport, dport=dport, flags=flags, window=64240, **kw
        )

    def down(flags: str, **kw: int) -> Packet:
        return cap.frame(server, client) / TCP(
            sport=dport, dport=sport, flags=flags, window=65160, **kw
        )

    cap.add(up("S", seq=c_seq), ts)
    cap.add(down("SA", seq=s_seq, ack=c_seq + 1), ts + 0.010)
    c_seq += 1
    s_seq += 1
    cap.add(up("A", seq=c_seq, ack=s_seq), ts + 0.011)
    ts += 0.012
    for direction, payload in exchanges:
        for offset in range(0, len(payload), 1400):
            chunk = payload[offset : offset + 1400]
            if direction == "c":
                cap.add(up("PA", seq=c_seq, ack=s_seq) / Raw(chunk), ts)
                c_seq += len(chunk)
                cap.add(down("A", seq=s_seq, ack=c_seq), ts + 0.005)
            else:
                cap.add(down("PA", seq=s_seq, ack=c_seq) / Raw(chunk), ts)
                s_seq += len(chunk)
                cap.add(up("A", seq=c_seq, ack=s_seq), ts + 0.005)
            ts += 0.008
    cap.add(up("FA", seq=c_seq, ack=s_seq), ts)
    cap.add(down("FA", seq=s_seq, ack=c_seq + 1), ts + 0.005)
    cap.add(up("A", seq=c_seq + 1, ack=s_seq + 1), ts + 0.006)
    return ts + 0.006


def dns_lookup(
    cap: Capture,
    ts: float,
    client: str,
    name: str,
    *,
    qtype: str = "A",
    answers: list[str] | None = None,
    rcode: int = 0,
    ttl: int = 300,
) -> None:
    qid = cap.rng.randint(1, 65535)
    sport = cap.rng.randint(30000, 60999)
    query = DNS(id=qid, rd=1, qd=[DNSQR(qname=name, qtype=qtype)])
    cap.add(cap.frame(client, RESOLVER) / UDP(sport=sport, dport=53) / query, ts)
    records = [DNSRR(rrname=name, type=qtype, ttl=ttl, rdata=a) for a in answers or []]
    response = DNS(
        id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=[DNSQR(qname=name, qtype=qtype)], an=records
    )
    cap.add(cap.frame(RESOLVER, client) / UDP(sport=53, dport=sport) / response, ts + 0.02)


def http_request(method: str, host: str, path: str, ua: str, body: bytes = b"") -> bytes:
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n"
    if body:
        head += f"Content-Type: application/octet-stream\r\nContent-Length: {len(body)}\r\n"
    return head.encode() + b"\r\n" + body


def http_response(status: int, mime: str, body: bytes) -> bytes:
    reason = {200: "OK", 404: "Not Found"}.get(status, "OK")
    head = f"HTTP/1.1 {status} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {len(body)}\r\n"
    return head.encode() + b"\r\n" + body


# --- TLS (records built by hand: exactly what the parsers see on the wire) -----------------


def _u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _u24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def _record(content_type: int, version: int, body: bytes) -> bytes:
    return bytes([content_type]) + _u16(version) + _u16(len(body)) + body


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + _u24(len(body)) + body


def client_hello(rng: random.Random, sni: str, version: int) -> bytes:
    ciphers = b"".join(_u16(c) for c in (0xC02F, 0xC030, 0x009C, 0x002F))
    name = sni.encode()
    server_name_list = bytes([0]) + _u16(len(name)) + name
    sni_ext = _u16(0x0000) + _u16(len(server_name_list) + 2) + _u16(len(server_name_list))
    sni_ext += server_name_list
    groups = _u16(0x000A) + _u16(6) + _u16(4) + _u16(0x0017) + _u16(0x001D)
    point_formats = _u16(0x000B) + _u16(2) + bytes([1, 0])
    extensions = sni_ext + groups + point_formats
    body = _u16(version) + rng.randbytes(32) + bytes([0]) + _u16(len(ciphers)) + ciphers
    body += bytes([1, 0]) + _u16(len(extensions)) + extensions
    return _record(22, 0x0301, _handshake(1, body))


def server_flight(rng: random.Random, version: int, chain: list[bytes]) -> bytes:
    hello = _u16(version) + rng.randbytes(32) + bytes([0]) + _u16(0xC02F) + bytes([0])
    certs = b"".join(_u24(len(der)) + der for der in chain)
    messages = (
        _handshake(2, hello)
        + _handshake(11, _u24(len(certs)) + certs)
        + _handshake(14, b"")  # ServerHelloDone
    )
    return _record(22, version, messages)


def tls_session(
    cap: Capture,
    ts: float,
    client: str,
    server: str,
    sni: str,
    chain: list[bytes],
    *,
    version: int = 0x0303,
    dport: int = 443,
    app_bytes: int = 600,
) -> float:
    rng = cap.rng
    key_exchange = _record(22, version, _handshake(16, bytes([65]) + rng.randbytes(65)))
    change_cipher = _record(20, version, bytes([1]))
    exchanges = [
        ("c", client_hello(rng, sni, version)),
        ("s", server_flight(rng, version, chain)),
        ("c", key_exchange + change_cipher + _record(22, version, rng.randbytes(40))),
        ("s", change_cipher + _record(22, version, rng.randbytes(40))),
        ("c", _record(23, version, rng.randbytes(app_bytes))),
        ("s", _record(23, version, rng.randbytes(app_bytes * 3))),
    ]
    return tcp_session(cap, ts, client, server, dport, exchanges)


@dataclass(frozen=True)
class Certs:
    ca: bytes
    valid: bytes
    self_signed: bytes
    expired: bytes
    legacy: bytes
    ca_private: bytes = b""  # raw Ed25519 seed of the CA (signs the planted --inject leaf)


def _cert(
    cn: str,
    key: ed25519.Ed25519PrivateKey,
    *,
    issuer_cn: str,
    issuer_key: ed25519.Ed25519PrivateKey,
    not_before: dt.datetime,
    not_after: dt.datetime,
    serial: int,
    ca: bool = False,
    san: str | None = None,  # defaults to the CN
) -> bytes:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san or cn)]), critical=False
        )
    # Ed25519: deterministic signatures, so the dataset is byte-for-byte reproducible.
    return builder.sign(issuer_key, None).public_bytes(serialization.Encoding.DER)


def make_certs(rng: random.Random) -> Certs:
    start = dt.datetime.fromtimestamp(BASE_TS, dt.UTC)
    year = dt.timedelta(days=365)
    ca_private = rng.randbytes(32)
    ca_key = ed25519.Ed25519PrivateKey.from_private_bytes(ca_private)
    leaf = ed25519.Ed25519PrivateKey.from_private_bytes(rng.randbytes(32))
    ca_cn = CA_CN
    before, after = start - year, start + year

    def signed(
        cn: str, serial: int, not_before: dt.datetime = before, not_after: dt.datetime = after
    ) -> bytes:
        return _cert(
            cn,
            leaf,
            issuer_cn=ca_cn,
            issuer_key=ca_key,
            serial=serial,
            not_before=not_before,
            not_after=not_after,
        )

    return Certs(
        ca=_cert(
            ca_cn,
            ca_key,
            issuer_cn=ca_cn,
            issuer_key=ca_key,
            serial=1,
            ca=True,
            not_before=before,
            not_after=after,
        ),
        valid=signed("cdn.example.net", 2),
        self_signed=_cert(
            "selfsigned.example.org",
            leaf,
            issuer_cn="selfsigned.example.org",
            issuer_key=leaf,
            serial=3,
            not_before=before,
            not_after=after,
        ),
        expired=signed("expired.example.org", 4, start - 2 * year, start - year),
        legacy=signed("legacy.example.org", 5),
        ca_private=ca_private,
    )


# --- scenarios -------------------------------------------------------------------------------

UA_BROWSER = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0"
Labels = list[dict[str, Any]]


def normal_web(cap: Capture, t0: float, certs: Certs) -> Labels:
    client = "10.0.1.10"
    dns_lookup(cap, t0, client, "www.example.com", answers=["198.51.100.10"])
    for offset, path in ((0.5, "/"), (37.2, "/about"), (190.8, "/news?id=7")):
        page = b"<html><body>" + cap.rng.randbytes(200).hex().encode() + b"</body></html>"
        tcp_session(
            cap,
            t0 + offset,
            client,
            "198.51.100.10",
            80,
            [
                ("c", http_request("GET", "www.example.com", path, UA_BROWSER)),
                ("s", http_response(200, "text/html", page)),
            ],
        )
    dns_lookup(cap, t0 + 40, client, "cdn.example.net", answers=["198.51.100.20"])
    for offset in (41.0, 131.5):
        tls_session(
            cap, t0 + offset, client, "198.51.100.20", "cdn.example.net", [certs.valid, certs.ca]
        )
    return []


def dns_traffic(cap: Capture, t0: float, certs: Certs) -> Labels:
    client = "10.0.1.11"
    lookups: list[tuple[str, str, list[str], int]] = [
        ("example.org", "A", ["198.51.100.30"], 0),
        ("example.org", "AAAA", ["2001:db8::30"], 0),
        ("mail.example.org", "MX", [], 0),
        ("example.org", "TXT", [], 0),
        ("wiki.example.org", "A", ["198.51.100.31"], 0),
        ("nonexistent.example.org", "A", [], 3),  # NXDOMAIN
        ("docs.example.org", "A", ["198.51.100.32"], 0),
        ("intranet.example.org", "A", [], 3),
    ]
    for i, (name, qtype, answers, rcode) in enumerate(lookups):
        dns_lookup(cap, t0 + i * 7.3, client, name, qtype=qtype, answers=answers, rcode=rcode)
    return []


def tls_sessions(cap: Capture, t0: float, certs: Certs) -> Labels:
    client = "10.0.1.12"
    tls_session(cap, t0, client, "203.0.113.30", "selfsigned.example.org", [certs.self_signed])
    tls_session(
        cap, t0 + 20, client, "203.0.113.31", "expired.example.org", [certs.expired, certs.ca]
    )
    tls_session(
        cap,
        t0 + 45,
        client,
        "203.0.113.32",
        "legacy.example.org",
        [certs.legacy, certs.ca],
        version=0x0301,
    )
    return [
        {
            "detector": "suspicious_traffic",
            "type": "tls_self_signed",
            "src": client,
            "dst": "203.0.113.30",
        },
        {
            "detector": "suspicious_traffic",
            "type": "tls_expired_certificate",
            "src": client,
            "dst": "203.0.113.31",
        },
        {
            "detector": "suspicious_traffic",
            "type": "tls_legacy_version",
            "src": client,
            "dst": "203.0.113.32",
        },
    ]


def beacon(cap: Capture, t0: float, certs: Certs) -> Labels:
    client, server = "10.0.2.20", "203.0.113.50"
    body = b'{"id":"c0ffee","status":"idle"}'
    for i in range(12):
        ts = t0 + i * 60 + cap.rng.uniform(-0.8, 0.8)
        tcp_session(
            cap,
            ts,
            client,
            server,
            8080,
            [
                (
                    "c",
                    http_request("POST", "updates.example.net", "/api/checkin", "agent/1.0", body),
                ),
                ("s", http_response(200, "application/json", b'{"cmd":"none"}')),
            ],
        )
    return [
        {"detector": "beaconing", "type": "beaconing", "src": client, "dst": server, "dport": 8080}
    ]


def dns_anomalies(cap: Capture, t0: float, certs: Certs) -> Labels:
    client = "10.0.3.30"
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(30):
        label = "".join(cap.rng.choice(alphabet) for _ in range(45))
        rcode = 3 if i % 3 else 0
        dns_lookup(cap, t0 + i * 1.7, client, f"{label}.t.example.net", qtype="TXT", rcode=rcode)
    return [
        {
            "detector": "dns_anomaly",
            "type": "dns_tunneling_like",
            "src": client,
            "domain": "example.net",
        }
    ]


def port_scan(cap: Capture, t0: float, certs: Certs) -> Labels:
    scanner, target = "10.0.4.40", "192.168.10.10"
    open_ports = {22, 80, 443}
    ts = t0
    for port in range(1, 121):
        sport = 50000 + port
        cap.add(cap.frame(scanner, target) / TCP(sport=sport, dport=port, flags="S", seq=1000), ts)
        if port in open_ports:
            cap.add(
                cap.frame(target, scanner)
                / TCP(sport=port, dport=sport, flags="SA", seq=5000, ack=1001),
                ts + 0.001,
            )
            cap.add(
                cap.frame(scanner, target) / TCP(sport=sport, dport=port, flags="R", seq=1001),
                ts + 0.002,
            )
        else:
            cap.add(
                cap.frame(target, scanner)
                / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=1001),
                ts + 0.001,
            )
        ts += 0.05
    for host in range(1, 26):
        cap.add(
            cap.frame(scanner, f"192.168.10.{100 + host}")
            / TCP(sport=40000 + host, dport=445, flags="S", seq=7),
            ts,
        )
        ts += 0.2
    return [
        {"detector": "port_scan", "type": "port_scan_vertical", "src": scanner, "dst": target},
        {"detector": "port_scan", "type": "port_scan_horizontal", "src": scanner, "dport": 445},
    ]


def suspicious_http(cap: Capture, t0: float, certs: Certs) -> Labels:
    client, server = "10.0.5.50", "203.0.113.70"
    fake_pe = b"MZ" + bytes(62) + b"PE" + bytes(2) + cap.rng.randbytes(400)  # inert bytes
    tcp_session(
        cap,
        t0,
        client,
        server,
        80,
        [
            ("c", http_request("GET", server, "/dl/payload.exe", "curl/8.5.0")),
            ("s", http_response(200, "application/octet-stream", fake_pe)),
        ],
    )
    return [
        {
            "detector": "suspicious_traffic",
            "type": "http_to_ip_literal",
            "src": client,
            "dst": server,
        },
        {
            "detector": "suspicious_traffic",
            "type": "executable_over_http",
            "src": client,
            "dst": server,
        },
    ]


SCENARIOS = {
    "normal_web": normal_web,
    "dns_traffic": dns_traffic,
    "tls_sessions": tls_sessions,
    "beacon": beacon,
    "dns_anomalies": dns_anomalies,
    "port_scan": port_scan,
    "suspicious_http": suspicious_http,
}
# The scenario's own client: planted --inject sessions come from it, so they sit next to the
# scenario's evidence (same host) without touching its detected flows.
CLIENTS = {
    "normal_web": "10.0.1.10",
    "dns_traffic": "10.0.1.11",
    "tls_sessions": "10.0.1.12",
    "beacon": "10.0.2.20",
    "dns_anomalies": "10.0.3.30",
    "port_scan": "10.0.4.40",
    "suspicious_http": "10.0.5.50",
}


# --- adversarial twins (--inject) ------------------------------------------------------------


def planted_packets(scenario: str, t0: float, certs: Certs, seed: int) -> list[Packet]:
    """The planted sessions of one scenario's injected twin.

    They use their own PRNG (seeded by the dataset seed and the scenario name), never the
    scenario's, so every clean packet of the twin stays byte-identical. One DNS A lookup whose
    name is a payload split into labels, one TXT lookup answered with payloads, one HTTP request
    with payloads in the URI / Host / User-Agent, and one TLS session with a payload SNI and a
    leaf certificate whose CN is a payload (signed by the test CA, so no self-signed finding).
    """
    client = CLIENTS[scenario]
    planted = Capture(random.Random(f"inject:{seed}:{scenario}"))
    values = {key: [v for _, v in pairs] for key, pairs in injection.planted_values().items()}
    ts = t0 + injection.PLANT_OFFSET_S
    [query] = values["dns.query"]
    dns_lookup(planted, ts, client, query, rcode=3)
    txt = values["dns.txt"]
    dns_lookup(planted, ts + 0.5, client, injection.TXT_NAME, qtype="TXT", answers=txt)
    [uri], [host], [ua] = values["http.uri"], values["http.host"], values["http.user_agent"]
    tcp_session(
        planted,
        ts + 1.0,
        client,
        injection.PLANT_SERVER,
        80,
        [
            ("c", http_request("GET", host, uri, ua)),
            ("s", http_response(200, "text/plain", b"ok\n")),
        ],
    )
    [sni], [cn] = values["tls.server_name"], values["tls.cert_subject_cn"]
    start = dt.datetime.fromtimestamp(BASE_TS, dt.UTC)
    year = dt.timedelta(days=365)
    leaf = _cert(
        cn,
        ed25519.Ed25519PrivateKey.from_private_bytes(planted.rng.randbytes(32)),
        issuer_cn=CA_CN,
        issuer_key=ed25519.Ed25519PrivateKey.from_private_bytes(certs.ca_private),
        not_before=start - year,
        not_after=start + year,
        serial=99,
        san=injection.PLANT_SAN,
    )
    tls_session(planted, ts + 2.0, client, injection.PLANT_SERVER, sni, [leaf, certs.ca])
    return planted.packets


def _write(path: Path, packets: list[Packet]) -> None:
    wrpcap(str(path), sorted(packets, key=lambda p: float(p.time)))


def generate(out_dir: Path, seed: int = 1337, *, inject: bool = False) -> dict[str, Path]:
    """Write every scenario plus `mixed` (all of them, time-shifted) and labels.json.

    With `inject`, also the `<name>__injected` twin of each (see the module docstring).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    certs = make_certs(random.Random(seed - 1))
    paths: dict[str, Path] = {}
    labels: dict[str, Labels] = {}
    plants: dict[str, list[dict[str, str]]] = {}
    mixed = Capture(random.Random(seed))
    mixed_labels: Labels = []
    mixed_planted: list[Packet] = []
    for index, (name, build) in enumerate(SCENARIOS.items()):
        cap = Capture(random.Random(seed + index))
        labels[name] = build(cap, BASE_TS, certs)
        paths[name] = out_dir / f"{name}.pcap"
        _write(paths[name], cap.packets)
        mixed_labels += build(mixed, BASE_TS + index * 1000, certs)
        if inject:
            twin = name + TWIN_SUFFIX
            paths[twin] = out_dir / f"{twin}.pcap"
            _write(paths[twin], cap.packets + planted_packets(name, BASE_TS, certs, seed))
            labels[twin] = labels[name]
            plants[twin] = injection.plant_records(name, CLIENTS[name], RESOLVER)
            mixed_planted += planted_packets(name, BASE_TS + index * 1000, certs, seed)
    paths["mixed"] = out_dir / "mixed.pcap"
    _write(paths["mixed"], mixed.packets)
    labels["mixed"] = mixed_labels
    document: dict[str, Any] = dict(labels)
    if inject:
        twin = "mixed" + TWIN_SUFFIX
        paths[twin] = out_dir / f"{twin}.pcap"
        _write(paths[twin], mixed.packets + mixed_planted)
        document[twin] = mixed_labels
        plants[twin] = [record for name in SCENARIOS for record in plants[name + TWIN_SUFFIX]]
        document["_injections"] = {
            "version": 1,
            "payloads": injection.catalog(),
            "twins": {
                twin: {"clean": twin.removesuffix(TWIN_SUFFIX), "plants": records}
                for twin, records in plants.items()
            },
        }
    (out_dir / "labels.json").write_text(json.dumps(document, indent=2))
    return paths


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m dataset.generate")
    parser.add_argument("out", nargs="?", default="dataset-out", type=Path)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--inject",
        action="store_true",
        help="also write prompt-injection twins (<name>__injected.pcap); off by default",
    )
    args = parser.parse_args(argv)
    for name, path in generate(args.out, args.seed, inject=args.inject).items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
