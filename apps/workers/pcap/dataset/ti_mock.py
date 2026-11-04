"""A small capture whose observables are aimed at the `mock` threat-intel provider (M4 e2e).

Not part of the labeled detector dataset (`generate.py` scenarios): it only feeds the e2e
enrichment flow. Names live under `example.com`, where `infra/ti-mock/server.py` picks its
behaviour from the first label; the addresses are RFC 5737 (never sent: not global).

- `hit.example.com` (DNS query and HTTP Host) and `http://hit.example.com/a?token=x` (HTTP;
  the query is removed before any lookup): hits;
- `ratelimit-ra-<run>.example.com` (DNS): a 429 with `Retry-After` on its first lookup, then a
  hit, so the enrichment run parks in `waiting` once. The run-specific label keeps a fresh
  first lookup on every e2e run (the mock remembers values it has seen);
- `notfound.example.com` (NXDOMAIN): a 404.

    python -m dataset.ti_mock /path/to/out [run-label]
"""

import random
import re
import sys
from pathlib import Path

from scapy.all import wrpcap

from dataset.generate import (
    BASE_TS,
    Capture,
    dns_lookup,
    http_request,
    http_response,
    tcp_session,
)

CLIENT = "10.0.6.60"
HIT_ADDRESS = "198.51.100.80"
UA = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0"


def build(cap: Capture, t0: float, run_label: str) -> None:
    dns_lookup(cap, t0, CLIENT, "hit.example.com", answers=[HIT_ADDRESS])
    tcp_session(
        cap,
        t0 + 0.5,
        CLIENT,
        HIT_ADDRESS,
        80,
        [
            ("c", http_request("GET", "hit.example.com", "/a?token=x", UA)),
            ("s", http_response(200, "text/plain", b"synthetic e2e page\n")),
        ],
    )
    dns_lookup(cap, t0 + 3.0, CLIENT, f"ratelimit-ra-{run_label}.example.com", answers=[])
    dns_lookup(cap, t0 + 4.0, CLIENT, "notfound.example.com", rcode=3)


def generate(out_dir: Path, run_label: str = "e2e") -> Path:
    if not re.fullmatch(r"[a-z0-9]{1,20}", run_label):
        raise ValueError("run label: 1-20 lowercase letters or digits")
    out_dir.mkdir(parents=True, exist_ok=True)
    cap = Capture(random.Random(4242))
    build(cap, BASE_TS, run_label)
    path = out_dir / "ti_iocs.pcap"
    wrpcap(str(path), sorted(cap.packets, key=lambda p: float(p.time)))
    return path


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "dataset-out")
    print(generate(out, sys.argv[2] if len(sys.argv) > 2 else "e2e"))
