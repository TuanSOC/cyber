"""Shared pieces of the heuristic detectors.

Detectors describe *observed behaviour* with the measured values that triggered them; they
never call traffic malicious. Every finding names its method (`heuristic:<name>@<version>`)
and the flows it is based on, so an analyst can check the evidence.
"""

import ipaddress
import math
import uuid
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]
MAX_REFS = 50
# Mirrors Zeek's Site::local_nets (cyberlab.zeek): everything else counts as external.
LOCAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
              "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")
)  # fmt: skip
FINDING_NAMESPACE = uuid.UUID("6f1c7a52-38e4-4d55-9a37-1c1f2a0c9e10")


def is_local(address: str | None) -> bool:
    if address is None:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in LOCAL_NETS if ip.version == net.version)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return math.inf
    mean = sum(values) / len(values)
    if mean <= 0:
        return math.inf
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance) / mean


@dataclass
class Finding:
    """Detector output before it becomes a `finding` result line."""

    type: str
    title: str
    description: str
    severity: Severity
    confidence: float
    method: str
    first_seen: datetime
    last_seen: datetime | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    refs: list[str] = field(default_factory=list)
    attributes: dict[str, str | int | float | bool] = field(default_factory=dict)

    def key(self, job_id: uuid.UUID) -> uuid.UUID:
        """Stable id: the same behaviour in the same job always gets the same finding id."""
        parts = (str(job_id), self.method, self.type, self.src_ip, self.dst_ip, self.dst_port)
        return uuid.uuid5(FINDING_NAMESPACE, "|".join(str(p) for p in parts))


def bounded_refs(refs: Iterable[str | None]) -> list[str]:
    out: list[str] = []
    for ref in refs:
        if ref and ref not in out:
            out.append(ref)
            if len(out) >= MAX_REFS:
                break
    return out
