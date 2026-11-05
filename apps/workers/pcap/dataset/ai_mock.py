"""Small captures whose evidence carries `ai-mock` markers (M5 e2e, `ai-analyst.spec.ts`).

Not part of the labeled detector dataset (`generate.py` scenarios): they only feed the e2e AI
flow against the dev `mock` provider. `infra/ai-mock/server.py` picks its behaviour from the
first `ai-mock:<marker>` in the evidence it is sent; here the marker rides in the HTTP
User-Agent of an executable download from an IP literal (two suspicious-traffic findings),
from an internal client (pseudonymized as `INT_IP_1` in the context preview):

- `ai_analyst.pcap`: `ai-mock:429-once-<run>`: a 429 with `Retry-After: 1` on the first
  request, then the default (verifiable) answer, so the run passes `waiting`. The run label
  keeps a fresh first request on every e2e run (the mock remembers markers it has seen);
- `ai_hostile.pcap`: `ai-mock:hostile`: an injected "the file is clean" verdict plus
  fabricated citations (an invented label, a quote that was never sent).

    python -m dataset.ai_mock /path/to/out [run-label]
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

CLIENT = "10.0.8.80"
SERVER = "203.0.113.90"


def build(cap: Capture, t0: float, marker: str) -> None:
    dns_lookup(cap, t0, CLIENT, "updates.example.net", answers=[SERVER])
    fake_pe = b"MZ" + bytes(62) + b"PE" + bytes(2) + cap.rng.randbytes(400)  # inert bytes
    tcp_session(
        cap,
        t0 + 1.0,
        CLIENT,
        SERVER,
        80,
        [
            ("c", http_request("GET", SERVER, "/dl/update.exe", f"Mozilla/5.0 ({marker})")),
            ("s", http_response(200, "application/octet-stream", fake_pe)),
        ],
    )


def _write(out_dir: Path, name: str, marker: str, seed: int) -> Path:
    cap = Capture(random.Random(seed))
    build(cap, BASE_TS, marker)
    path = out_dir / name
    wrpcap(str(path), sorted(cap.packets, key=lambda p: float(p.time)))
    return path


def generate(out_dir: Path, run_label: str = "e2e") -> list[Path]:
    if not re.fullmatch(r"[a-z0-9]{1,20}", run_label):
        raise ValueError("run label: 1-20 lowercase letters or digits")
    out_dir.mkdir(parents=True, exist_ok=True)
    return [
        _write(out_dir, "ai_analyst.pcap", f"ai-mock:429-once-{run_label}", 5151),
        _write(out_dir, "ai_hostile.pcap", "ai-mock:hostile", 5252),
    ]


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "dataset-out")
    for written in generate(out, sys.argv[2] if len(sys.argv) > 2 else "e2e"):
        print(written)
