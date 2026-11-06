"""Shared pieces of the memory detectors (M8 phase 3).

Findings describe *what was observed* in the image's normalized records, with the measured
values behind them. They never call a process or a region malicious: every title and
description comes from `TEMPLATES`, which `test_finding_wording.py` checks for verdict
wording (and for "injected code", RT21). Values from the image (names, paths, command lines,
history lines) are inserted into placeholders after `mask.excerpt` (RT13).

Severity policy: every M8 method is a heuristic (memory YARA is cut, RT8), so nothing exceeds
`medium`; each detector also has its own ceiling (`service_path` stops at `low`).
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from cyberlab_jobs.memory import MemoryProcessRecord

Severity = Literal["info", "low", "medium", "high"]
SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}
HEURISTIC_MAX: Severity = "medium"
FINDING_NAMESPACE = uuid.UUID("5c3f5d2e-8a41-4e0b-9f57-3b1d6c0a8e18")
MAX_REFS = 50
MAX_ATTRIBUTES = 20
# Detector working state (indexes, per-pid sets) is capped; beyond it `detector_state` is
# flagged and the remaining records are not indexed (RT9-style bound, never a failure).
MAX_DETECTOR_KEYS = 50_000
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

M_HIDDEN = "heuristic:mem_hidden_process@1"
M_INJECTED = "heuristic:mem_injected_code@1"
M_LINEAGE = "heuristic:mem_process_lineage@1"
M_MASQUERADE = "heuristic:mem_masquerade@1"
M_CMDLINE = "heuristic:mem_suspicious_cmdline@1"
M_UNLINKED = "heuristic:mem_unlinked_module@1"
M_SERVICE = "heuristic:mem_service_path@1"
M_NETWORK = "heuristic:mem_unexpected_network@1"
M_SHELL = "heuristic:mem_linux_shell_history@1"
M_CORRELATED = "heuristic:mem_correlated_indicators@1"

# Per-method severity ceiling (plan phase 3 table).
METHOD_MAX: dict[str, Severity] = {
    M_HIDDEN: "medium",
    M_INJECTED: "medium",
    M_LINEAGE: "medium",
    M_MASQUERADE: "medium",
    M_CMDLINE: "medium",
    M_UNLINKED: "medium",
    M_SERVICE: "low",
    M_NETWORK: "medium",
    M_SHELL: "medium",
    M_CORRELATED: "medium",
}

# type -> (method, title template, description template). Every finding text comes from here.
TEMPLATES: dict[str, tuple[str, str, str]] = {
    "mem_hidden_process": (
        M_HIDDEN,
        "Process found by pool scan but not in the active process list",
        "pid {pid} ({name}) appears in psscan only, has {threads} thread(s) and no exit time. "
        "Unlinking from the active list hides a process from most tools; a scan can also "
        "find a structure that is being torn down at capture time.",
    ),
    "mem_private_exec_pe": (
        M_INJECTED,
        "Private executable memory region with a PE header",
        "pid {pid} ({name}): a private {protection} region at {start}-{end} ({size} bytes) "
        "starts with {header}. Executables are normally mapped from files, not held in "
        "private memory; manual loaders, packers and some security products create such "
        "regions.",
    ),
    "mem_private_exec_region": (
        M_INJECTED,
        "Private writable and executable memory region",
        "pid {pid} ({name}): a private {protection} region at {start}-{end} ({size} bytes) "
        "with no PE header (first bytes {head}). JIT compilers, packers and loaders of "
        "position-independent code create such regions.",
    ),
    "mem_process_lineage": (
        M_LINEAGE,
        "{name} has an unexpected parent process",
        "pid {pid} ({name}) was started by pid {ppid} ({parent}); on Windows its parent is "
        "normally {expected}.",
    ),
    "mem_core_process_count": (
        M_LINEAGE,
        "More than one {name} process running",
        "{count} {name} processes have no exit time (pids {pids}); Windows normally runs one.",
    ),
    "mem_name_similar_to_core": (
        M_MASQUERADE,
        "Process name close to the Windows core process {core}",
        "pid {pid} is named {name}, {distance} edit(s) away from {core}. Look-alike names "
        "make a process blend into a process list.",
    ),
    "mem_core_name_unexpected_path": (
        M_MASQUERADE,
        "{name} runs from an unexpected directory",
        "pid {pid} ({name}) has the image path {path}; this Windows binary normally lives in "
        "{expected}.",
    ),
    "mem_suspicious_cmdline": (
        M_CMDLINE,
        "Command line matches download or execution patterns ({patterns})",
        "pid {pid} ({name}) command line (secrets masked): {cmdline}. Matched patterns: "
        "{patterns}. Administrators and installers use some of these too.",
    ),
    "mem_unlinked_module": (
        M_UNLINKED,
        "Mapped module missing from all three loader lists",
        "pid {pid} ({name}): {path} at {base} is mapped but absent from the load, init and "
        "memory-order module lists. Unlinking hides a module from list-walking tools.",
    ),
    "mem_service_user_writable_path": (
        M_SERVICE,
        "Service binary under a user-writable directory",
        "Service {service} ({state}) runs {binary}, under {marker}. Service binaries normally "
        "live in directories only administrators can write.",
    ),
    "mem_driver_unexpected_path": (
        M_SERVICE,
        "Kernel driver outside the drivers directory",
        "Driver service {service} ({state}) loads {binary}; drivers normally load from "
        "\\System32\\drivers\\ or the driver store.",
    ),
    "mem_unexpected_network": (
        M_NETWORK,
        "{name} holds an established connection to an external address",
        "pid {pid} ({name}) has {count} established connection(s) to external address(es): "
        "{remotes}. This program normally makes no network connections.",
    ),
    "mem_shell_history_pattern": (
        M_SHELL,
        "Shell history matches download-and-execute or reverse-shell patterns ({patterns})",
        "bash pid {pid} history line (secrets masked): {command}. Matched patterns: "
        "{patterns}.",
    ),
    "mem_correlated_indicators": (
        M_CORRELATED,
        "Several independent observations on one process ({count})",
        "pid {pid} ({name}) has {count} separate observations: {indicators}. Each is listed "
        "as its own finding; together they deserve a closer look.",
    ),
}


def cap(severity: Severity, ceiling: Severity) -> Severity:
    return severity if SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling] else ceiling


@dataclass
class Finding:
    """Detector output before it becomes a `finding` line."""

    type: str
    severity: Severity
    confidence: float
    values: dict[str, object]
    key: str  # discriminates findings of one type (stable id)
    pid: int | None = None  # the subject process (correlation, labels)
    refs: list[str] = field(default_factory=list)
    attributes: dict[str, str | int | float | bool] = field(default_factory=dict)
    dst_ip: IPv4Address | IPv6Address | None = None
    dst_port: int | None = None

    @property
    def method(self) -> str:
        return TEMPLATES[self.type][0]

    @property
    def title(self) -> str:
        return TEMPLATES[self.type][1].format(**self.values)[:255]

    @property
    def description(self) -> str:
        return TEMPLATES[self.type][2].format(**self.values)[:2048]

    @property
    def capped_severity(self) -> Severity:
        return cap(cap(self.severity, METHOD_MAX[self.method]), HEURISTIC_MAX)

    def finding_id(self, image_sha256: str) -> uuid.UUID:
        """Stable: the same observation on the same image always gets the same id (ids are
        unique per job: `(job_id, finding_id)`)."""
        return uuid.uuid5(
            FINDING_NAMESPACE, f"{image_sha256}|{self.method}|{self.type}|{self.key}"
        )


class Budget:
    """Counts detector-state keys across all detectors of one run."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self.exhausted = False

    def take(self, n: int = 1) -> bool:
        if self.used + n > self.limit:
            self.exhausted = True
            return False
        self.used += n
        return True


@dataclass
class Context:
    """What every detector receives: the run's indexes and its budget."""

    budget: Budget
    by_pid: dict[int, list[MemoryProcessRecord]]
    observed_at: datetime

    def name_of(self, pid: int | None) -> str | None:
        procs = self.by_pid.get(pid) if pid is not None else None
        return procs[0].name if procs else None

    def parent_of(self, proc: MemoryProcessRecord) -> MemoryProcessRecord | None:
        """The process that started `proc`: the `ppid` holder created before it (a later
        holder is a reused pid, i.e. the real parent is gone)."""
        if proc.ppid is None:
            return None
        candidates = [p for p in self.by_pid.get(proc.ppid, ()) if p is not proc]
        if proc.create_time is not None:
            candidates = [
                p for p in candidates if p.create_time is None or p.create_time <= proc.create_time
            ]
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.create_time or EPOCH)


def index_processes(
    processes: tuple[MemoryProcessRecord, ...], budget: Budget
) -> dict[int, list[MemoryProcessRecord]]:
    by_pid: dict[int, list[MemoryProcessRecord]] = {}
    for proc in processes:
        if not budget.take():
            break
        by_pid.setdefault(proc.pid, []).append(proc)
    return by_pid


def refs(values: list[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        ref = value[:64]
        if ref and ref not in out:
            out.append(ref)
            if len(out) >= MAX_REFS:
                break
    return out


def joined(values: list[str], limit: int = 255) -> str:
    text = ", ".join(values)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def hex_addr(value: int) -> str:
    return f"0x{value:x}"


def alive(proc: MemoryProcessRecord) -> bool:
    return proc.exit_time is None


def basename(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
