"""Assembling one `memory.v1` stream from the normalized records (root side, pure Python).

The analyzer (real engine or replay) collects per-plugin outcomes and rows; this module
turns them into the header, the image line, the `MemoryView` for the detections and the
gzip NDJSON stream with its hashed trailer:

    header, image, processes, connections, injections, artifacts, findings, iocs, timeline,
    trailer

A diagnostic stream (`symbols_missing`) is header (with `symbols.required`), image, trailer.
The header reports every plugin of the profile with its status, root's own row count,
`truncated` and duration; anything capped or skipped is in `truncated` / `engine_errors`.
"""

import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from cyberlab_jobs.memory import (
    KernelIdentity,
    LinuxBanner,
    MemoryImageRecord,
    MemoryLimits,
    MemoryOs,
    MemoryPlugin,
    MemoryProfile,
    MemoryResultHeader,
    PluginRunStatus,
    PluginStatus,
    SymbolsInfo,
    WindowsPdb,
    check_diagnostic_kinds,
)
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.result_writer import ResultWriter

from memory_worker import detections
from memory_worker.identify import Identified
from memory_worker.normalize import Normalized, normalize
from memory_worker.normalize.common import WindowsInfo
from memory_worker.normalize.reader import RowStats
from memory_worker.probe.guard import FAMILIES
from memory_worker.view import DetectionOutput, MemoryView

MAX_ENGINE_ERRORS = 32
MAX_TRUNCATED = 32
Engine = Literal["volatility3", "replay"]


@dataclass
class PluginOutcome:
    """What root concluded about one plugin run (never the probe's own claims)."""

    plugin: MemoryPlugin
    status: PluginRunStatus
    duration_ms: int = 0
    rows: int = 0
    truncated: bool = False  # rows capped (probe marker, root's cap) or a partial run
    error_code: str | None = None
    skipped_lines: int = 0  # lines the reader could not use

    def counted(self, stats: RowStats) -> None:
        """Root's own count of the rows the normalizers read (called by the row source)."""
        self.rows = stats.rows
        self.truncated = self.truncated or stats.truncated
        self.skipped_lines = stats.skipped

    def header(self) -> PluginStatus:
        return PluginStatus(
            plugin=self.plugin,
            status=self.status,
            rows=self.rows,
            truncated=self.truncated,
            duration_ms=self.duration_ms,
            error_code=self.error_code,
        )


@dataclass
class RunFacts:
    job_id: uuid.UUID
    profile: MemoryProfile
    os: MemoryOs
    engine: Engine
    tool_versions: dict[str, str]
    image: MemoryImageRecord
    isf_sha256: str | None = None
    audit: Counter[str] = field(default_factory=Counter)
    engine_errors: list[str] = field(default_factory=list)

    def error(self, code: str) -> None:
        if code not in self.engine_errors:
            self.engine_errors.append(code)


def key(plugin: MemoryPlugin) -> str:
    """A plugin as an error-code fragment (`windows.malware.malfind` -> `windows_malware_
    malfind`)."""
    return plugin.value.replace(".", "_")


def add_audit(total: Counter[str], counts: Mapping[str, int]) -> None:
    for family, n in counts.items():
        if family in FAMILIES and isinstance(n, int) and n > 0:
            total[family] += n


def image_record(
    identified: Identified, size: int, sha256: str, info: WindowsInfo | None = None
) -> MemoryImageRecord:
    identity = identified.identity
    return MemoryImageRecord(
        size_bytes=size,
        sha256=sha256,
        layer=identified.layer,
        arch=identified.arch,
        nt_build=info.nt_build if info else None,
        pdb=identity if isinstance(identity, WindowsPdb) else None,
        kernel_banner=identity.banner if isinstance(identity, LinuxBanner) else None,
        system_time=info.system_time if info else None,
    )


def _header(
    facts: RunFacts,
    symbols: SymbolsInfo,
    plugins: list[PluginStatus],
    truncated: dict[str, bool],
) -> MemoryResultHeader:
    flags = {k: True for k, v in truncated.items() if v}
    if len(flags) > MAX_TRUNCATED:
        flags = dict(list(flags.items())[: MAX_TRUNCATED - 1]) | {"engine_report": True}
    return MemoryResultHeader(
        job_id=facts.job_id,
        profile=facts.profile,
        os=facts.os,
        engine=facts.engine,
        tool_versions={k[:255]: v[:255] for k, v in list(facts.tool_versions.items())[:16]},
        symbols=symbols,
        plugins=plugins,
        audit_events={f: facts.audit.get(f, 0) for f in FAMILIES},
        engine_errors=facts.engine_errors[:MAX_ENGINE_ERRORS],
        truncated=flags,
    )


def write_diagnostic(path: Path, facts: RunFacts, required: KernelIdentity) -> Path:
    """The `symbols_missing` stream: header (symbols.required), image, trailer."""
    header = _header(facts, SymbolsInfo(status="missing", required=required), [], {})
    check_diagnostic_kinds(["header", "image", "trailer"])
    with ResultWriter(path) as writer:
        writer.write(header)
        writer.write(facts.image)
    return path


def build(
    facts: RunFacts,
    outcomes: list[PluginOutcome],
    rows: Mapping[MemoryPlugin, Iterable[Mapping[str, Any]]],
    limits: MemoryLimits,
) -> tuple[Normalized, MemoryView]:
    """Normalize the rows (consumes them; the readers update the outcomes' counters) and
    build the detections' view."""
    normalized = normalize(facts.os, rows, limits)
    if facts.os == "windows":
        facts.image = facts.image.model_copy(
            update={
                "nt_build": normalized.info.nt_build or facts.image.nt_build,
                "system_time": normalized.info.system_time or facts.image.system_time,
            }
        )
    partial = {o.plugin.value for o in outcomes if o.truncated}
    view = MemoryView(
        os=facts.os,
        profile=facts.profile,
        image=facts.image,
        processes=tuple(normalized.processes),
        connections=tuple(normalized.connections),
        injections=tuple(normalized.injections),
        artifacts=tuple(normalized.artifacts),
        truncated=frozenset(partial),
    )
    return normalized, view


def write_result(
    path: Path,
    facts: RunFacts,
    outcomes: list[PluginOutcome],
    normalized: Normalized,
    view: MemoryView,
    found: DetectionOutput,
    limits: MemoryLimits,
) -> Path:
    for outcome in outcomes:
        k = key(outcome.plugin)
        if outcome.status in ("failed", "timeout"):
            facts.error(f"{k}_{outcome.status}")
        if outcome.skipped_lines or normalized.skipped.get(outcome.plugin.value):
            facts.error(f"{k}_rows_skipped")
        if normalized.unknown_columns.get(outcome.plugin.value):
            facts.error(f"{k}_unknown_columns")
    truncated: dict[str, bool] = {kind: True for kind in sorted(normalized.capped)}
    truncated |= {o.plugin.value: True for o in outcomes if o.truncated}
    truncated |= found.truncated
    assert facts.isf_sha256 is not None  # noqa: S101 - resolved symbols only reach here
    header = _header(
        facts,
        SymbolsInfo(status="resolved", isf_sha256=facts.isf_sha256),
        [o.header() for o in outcomes],
        truncated,
    )
    with ResultWriter(path) as writer:
        writer.write(header)
        writer.write(view.image)
        for group in (view.processes, view.connections, view.injections, view.artifacts):
            for record in group:
                writer.write(record)
        for line in (*found.findings, *found.iocs, *found.timeline):
            writer.write(line)
    if path.stat().st_size > limits.max_result_bytes:
        raise JobFailed("result_too_large")
    return path


def assemble(
    path: Path,
    facts: RunFacts,
    outcomes: list[PluginOutcome],
    rows: Mapping[MemoryPlugin, Iterable[Mapping[str, Any]]],
    limits: MemoryLimits,
) -> Path:
    """Normalize, detect and write the full stream."""
    normalized, view = build(facts, outcomes, rows, limits)
    found = detections.run(view, limits)
    return write_result(path, facts, outcomes, normalized, view, found, limits)


__all__ = [
    "PluginOutcome",
    "RunFacts",
    "add_audit",
    "assemble",
    "build",
    "image_record",
    "key",
    "write_diagnostic",
    "write_result",
]
