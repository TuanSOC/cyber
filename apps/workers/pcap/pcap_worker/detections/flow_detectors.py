"""Detectors fed every flow during the single conn.log pass (before any flow cap applies).

State per key is small and the number of keys is capped (`capped` is reported as a
truncation), so a capture with millions of distinct endpoints cannot exhaust memory.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from cyberlab_jobs.results import FlowRecord

from pcap_worker.detections.base import (
    Finding,
    bounded_refs,
    coefficient_of_variation,
    is_local,
)

MAX_KEYS = 50_000


@dataclass(frozen=True)
class BeaconConfig:
    version: int = 1
    min_connections: int = 8
    min_mean_interval_s: float = 5.0
    max_interval_cv: float = 0.15
    max_size_cv: float = 0.25
    max_samples: int = 500


@dataclass
class _Series:
    times: list[float] = field(default_factory=list)
    sizes: list[float] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)


class BeaconDetector:
    """Regular, similar-sized connections from one host to one service (beacon-like)."""

    def __init__(self, config: BeaconConfig | None = None) -> None:
        self.config = config or BeaconConfig()
        self.series: dict[tuple[str, str, int, str], _Series] = {}
        self.capped = False

    def observe(self, flow: FlowRecord) -> None:
        if flow.src_ip is None or flow.dst_ip is None or flow.dst_port is None:
            return
        # Internal periodic traffic (resolvers, NTP, monitoring) is the norm, not a signal.
        if is_local(str(flow.dst_ip)):
            return
        key = (str(flow.src_ip), str(flow.dst_ip), flow.dst_port, flow.proto)
        series = self.series.get(key)
        if series is None:
            if len(self.series) >= MAX_KEYS:
                self.capped = True
                return
            series = self.series[key] = _Series()
        if len(series.times) < self.config.max_samples:
            series.times.append(flow.ts.timestamp())
            series.sizes.append(float(flow.orig_bytes + flow.resp_bytes))
            if flow.flow_ref and len(series.refs) < 50:
                series.refs.append(flow.flow_ref)

    def findings(self) -> list[Finding]:
        c = self.config
        out: list[Finding] = []
        for (src, dst, port, proto), s in self.series.items():
            if len(s.times) < c.min_connections:
                continue
            order = sorted(range(len(s.times)), key=s.times.__getitem__)
            times = [s.times[i] for i in order]
            intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
            mean = sum(intervals) / len(intervals)
            interval_cv = coefficient_of_variation(intervals)
            size_cv = coefficient_of_variation(s.sizes)
            if mean < c.min_mean_interval_s or interval_cv > c.max_interval_cv:
                continue
            if size_cv > c.max_size_cv:
                continue
            jitter = interval_cv * mean
            confidence = round(min(0.9, 0.5 + 0.4 * (1 - interval_cv / c.max_interval_cv)), 2)
            out.append(
                Finding(
                    type="beaconing",
                    title="Periodic connections (beacon-like)",
                    description=(
                        f"{src} connected to {dst}:{port}/{proto} {len(times)} times every "
                        f"{mean:.1f} s (±{jitter:.1f} s, interval CV {interval_cv:.3f}) with "
                        f"similar sizes (size CV {size_cv:.3f}). Regular timing is typical of "
                        "automated check-ins (updaters, agents, C2); confirm the client."
                    ),
                    severity="medium",
                    confidence=confidence,
                    method=f"heuristic:beaconing@{c.version}",
                    first_seen=datetime.fromtimestamp(times[0], tz=UTC),
                    last_seen=datetime.fromtimestamp(times[-1], tz=UTC),
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=port,
                    protocol=proto,
                    refs=bounded_refs(s.refs),
                    attributes={
                        "connections": len(times),
                        "mean_interval_s": round(mean, 2),
                        "interval_cv": round(interval_cv, 4),
                        "size_cv": round(size_cv, 4),
                    },
                )
            )
        return out


# Zeek conn_state values for attempts that never became a real conversation.
FAILED_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH", "SH", "SHR", "OTH"}


@dataclass(frozen=True)
class ScanConfig:
    version: int = 1
    min_ports: int = 20  # vertical: one target, many ports
    min_hosts: int = 15  # horizontal: one port, many targets
    min_failed_ratio: float = 0.7
    max_set: int = 2_000


@dataclass
class _Probe:
    targets: set[object] = field(default_factory=set)
    failed: int = 0
    total: int = 0
    first: float = float("inf")
    last: float = 0.0
    refs: list[str] = field(default_factory=list)


class ScanDetector:
    """Many failed connection attempts from one source (vertical or horizontal scan)."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.vertical: dict[tuple[str, str], _Probe] = {}
        self.horizontal: dict[tuple[str, int, str], _Probe] = {}
        self.capped = False

    def _probe[K](self, table: dict[K, _Probe], key: K) -> _Probe | None:
        probe = table.get(key)
        if probe is None:
            if len(table) >= MAX_KEYS:
                self.capped = True
                return None
            probe = table[key] = _Probe()
        return probe

    def observe(self, flow: FlowRecord) -> None:
        if flow.proto != "tcp" or flow.src_ip is None or flow.dst_ip is None:
            return
        if flow.dst_port is None:
            return
        src, dst, ts = str(flow.src_ip), str(flow.dst_ip), flow.ts.timestamp()
        failed = flow.conn_state in FAILED_STATES
        probes = (
            (self._probe(self.vertical, (src, dst)), flow.dst_port),
            (self._probe(self.horizontal, (src, flow.dst_port, flow.proto)), dst),
        )
        for probe, target in probes:
            if probe is None:
                continue
            if len(probe.targets) < self.config.max_set:
                probe.targets.add(target)
            probe.total += 1
            probe.failed += failed
            probe.first, probe.last = min(probe.first, ts), max(probe.last, ts)
            if flow.flow_ref and len(probe.refs) < 50:
                probe.refs.append(flow.flow_ref)

    def _finding(
        self, kind: str, probe: _Probe, src: str, dst: str | None, port: int | None
    ) -> Finding:
        ratio = probe.failed / probe.total
        span = probe.last - probe.first
        many = len(probe.targets)
        what = f"{many} ports on {dst}" if kind == "vertical" else f"port {port} on {many} hosts"
        return Finding(
            type=f"port_scan_{kind}",
            title="Port scan (vertical)" if kind == "vertical" else "Port scan (horizontal)",
            description=(
                f"{src} probed {what} in {span:.1f} s; {probe.failed} of {probe.total} "
                f"attempts ({ratio:.0%}) were rejected or unanswered. This pattern matches "
                "network reconnaissance or an inventory scanner; check if it is authorised."
            ),
            severity="high" if many >= 100 else "medium",
            confidence=round(min(0.95, 0.6 + 0.3 * ratio), 2),
            method=f"heuristic:port_scan@{self.config.version}",
            first_seen=datetime.fromtimestamp(probe.first, tz=UTC),
            last_seen=datetime.fromtimestamp(probe.last, tz=UTC),
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            protocol="tcp",
            refs=bounded_refs(probe.refs),
            attributes={"targets": many, "attempts": probe.total, "failed_ratio": round(ratio, 3)},
        )

    def findings(self) -> list[Finding]:
        c = self.config
        out: list[Finding] = []
        for (src, dst), probe in self.vertical.items():
            if (
                len(probe.targets) >= c.min_ports
                and probe.failed / probe.total >= c.min_failed_ratio
            ):
                out.append(self._finding("vertical", probe, src, dst, None))
        for (src, port, _proto), probe in self.horizontal.items():
            if (
                len(probe.targets) >= c.min_hosts
                and probe.failed / probe.total >= c.min_failed_ratio
            ):
                out.append(self._finding("horizontal", probe, src, None, port))
        return out
