"""Memory analysis of one image: download -> refuse compressed -> identify -> symbols ->
one probe per allow-listed plugin -> normalize -> detect -> `memory.v1` (M8 phase 2).

`analyze(job, dirs, config) -> Path` returns the written result, raises `DiagnosticResult`
(a written `symbols_missing` stream to upload with a failed report) or `JobFailed(code)`.

Root never parses image bytes: it hashes them during the download (`transfer.download`:
sha256 + size verified, root-owned 0444), reads the first 16 bytes for the compressed /
archive refusal (RT19), and reads only bounded probe output. `sandbox.prepare` ran once
for the job (pipeline); every probe gets a fresh out dir (`Workspace.fresh`, RT26).

Success rule: identify and the process list (`PROCESS_LIST_PLUGIN[os]`) are `ok`, else
`memory_parse_failed`. Every other plugin is best effort and reported in the header with
its status (`ok`, `failed`, `timeout`, `skipped`: no time left in the job budget,
`unsupported`: a requirement Volatility cannot satisfy).
"""

import functools
import os
import shutil
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any, Protocol

from cyberlab_jobs.memory import (
    PLUGINS_BY_PROFILE,
    PROCESS_LIST_PLUGIN,
    KernelIdentity,
    MemoryJobV1,
    MemoryLimits,
    MemoryPlugin,
    MemoryProfile,
    SymbolManifestV1,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.transfer import download
from pydantic import ValidationError

from memory_worker.config import Config
from memory_worker.engines import engine_for
from memory_worker.engines.base import Engine, ProbeRun
from memory_worker.engines.magic import image_format
from memory_worker.engines.workspace import ROWS, STATUS, Budget, Workspace
from memory_worker.identify import Identified, IdentifyRecord, IdentifyRefused, choose
from memory_worker.normalize.reader import ProbeStatus, RowSource, read_status
from memory_worker.probe.plugins import PLUGINS, max_rows
from memory_worker.result import (
    PluginOutcome,
    RunFacts,
    add_audit,
    assemble,
    image_record,
    write_diagnostic,
)
from memory_worker.symbols.store import SymbolHit, SymbolsCorrupt, SymbolStore

GIB = 1024**3
DISK_HEADROOM = GIB  # free space on /work beyond the image (plan: size + 1 GiB)
TEST_DISK_HEADROOM = 16 * 1024**2  # the test profile's 512 MiB tmpfs /work (RT6)
ENGINE_MISSING = frozenset({"ModuleNotFoundError", "ImportError", "ProbeSetupError"})
RESULT = "result.ndjson.gz"


class Symbols(Protocol):
    """The read-only symbol store as the analyzer uses it (`SymbolStore`, phase 5)."""

    root: Path

    def lookup(self, identity: KernelIdentity) -> SymbolHit | None: ...

    def manifest(self) -> SymbolManifestV1: ...


class DiagnosticResult(JobFailed):
    """Symbols are missing: `path` is the diagnostic stream to upload, then report failed /
    `symbols_missing` with its version id."""

    def __init__(self, path: Path) -> None:
        super().__init__("symbols_missing")
        self.path = path


def disk_headroom() -> int:
    return TEST_DISK_HEADROOM if os.environ.get("TEST_PROFILE") == "1" else DISK_HEADROOM


def check_disk(work_dir: Path, size: int) -> None:
    if shutil.disk_usage(work_dir).free < size + disk_headroom():
        raise JobFailed("insufficient_disk")


def analyze(job: MemoryJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    if job.size_bytes == 0:
        raise JobFailed("memory_image_empty")
    if job.size_bytes > job.limits.max_bytes:
        raise JobFailed("memory_image_too_large")
    check_disk(config.work_dir, job.size_bytes)
    ws = Workspace(dirs, config.symbols_dir)
    download(
        job.evidence_url,
        ws.image,
        expected_sha256=job.expected_sha256,
        size_bytes=job.size_bytes,
        max_bytes=job.limits.max_bytes,
        too_large_code="memory_image_too_large",
    )
    return analyze_image(
        ws,
        job,
        engine_for(config),
        SymbolStore(config.symbols_dir),
    )


def _status(run: ProbeRun) -> ProbeStatus | None:
    try:
        with sandbox.open_output(run.dirs, STATUS) as f:
            return read_status(f)
    except (OSError, ValueError):
        return None


def _identify(
    ws: Workspace, job: MemoryJobV1, engine: Engine, budget: Budget, facts_audit: Counter[str]
) -> Identified:
    seconds = budget.identify()
    if seconds is None:
        raise JobFailed("identify_timeout")
    run = engine.identify(ws, job.os_hint, seconds)
    if run.end == "timeout":
        raise JobFailed("identify_timeout")
    status = _status(run)
    if status is not None:
        add_audit(facts_audit, status.audit)
    if status is None or status.status != "ok" or status.identify is None:
        if status is not None and status.error in ENGINE_MISSING:
            raise JobFailed("engine_unavailable")
        raise JobFailed("memory_parse_failed", "identify produced no result")
    if not status.offline_verified(str(ws.symbols_dir)):
        raise JobFailed("engine_unavailable", "the probe did not run offline")
    try:
        record = IdentifyRecord.model_validate(status.identify)
    except ValidationError as exc:
        raise JobFailed("memory_parse_failed", "invalid identify output") from exc
    try:
        return choose(record, job.os_hint)
    except IdentifyRefused as exc:
        if exc.code == "unsupported_memory_format":
            raise JobFailed("unsupported_memory_format", exc.reason) from exc
        raise JobFailed("os_undetermined", exc.reason) from exc


def _lookup(store: Symbols, identified: Identified) -> SymbolHit | None:
    try:
        return store.lookup(identified.identity)
    except SymbolsCorrupt as exc:
        raise JobFailed("symbols_corrupt") from exc


def _outcome(
    plugin: MemoryPlugin, run: ProbeRun, status: ProbeStatus | None, ws: Workspace
) -> PluginOutcome:
    outcome = PluginOutcome(plugin=plugin, status="ok", duration_ms=run.duration_ms)
    if run.end == "timeout":
        outcome.status, outcome.error_code = "timeout", "plugin_timeout"
    elif status is None or not status.offline_verified(str(ws.symbols_dir)):
        outcome.status, outcome.error_code = "failed", "plugin_failed"
    elif status.status == "unsupported":
        outcome.status = "unsupported"
    elif status.status == "failed" or run.end == "failed":
        outcome.status, outcome.error_code = "failed", "plugin_failed"
    elif not sandbox.output_exists(run.dirs, ROWS):
        outcome.status, outcome.error_code = "failed", "plugin_failed"
    elif status.truncated:
        outcome.truncated = True
    return outcome


def _isf_sha256(store: Symbols, hit: SymbolHit, reported: list[str], facts: RunFacts) -> str:
    """The sha256 of the ISF the run actually loaded (resolved through the manifest)."""
    root = store.root.resolve()
    paths = []
    for uri in reported:
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme != "file":
            continue
        try:
            paths.append(Path(urllib.parse.unquote(parsed.path)).resolve().relative_to(root))
        except ValueError:
            continue
    if not paths:
        facts.error("isf_unreported")
        return hit.sha256
    expected = hit.path.resolve().relative_to(root)
    if paths[0] == expected:
        return hit.sha256
    facts.error("isf_mismatch")
    try:
        files = {f.path: f.sha256 for f in store.manifest().files}
    except SymbolsCorrupt as exc:
        raise JobFailed("symbols_corrupt") from exc
    return files.get(paths[0].as_posix(), hit.sha256)


def analyze_image(ws: Workspace, job: MemoryJobV1, engine: Engine, store: Symbols) -> Path:
    """Everything after the download (the image is at `ws.image`, hash-verified)."""
    limits: MemoryLimits = job.limits
    if image_format(ws.image) is not None:
        raise JobFailed("unsupported_memory_format", "compressed or archived file")
    budget = Budget(limits)
    audit: Counter[str] = Counter()
    identified = _identify(ws, job, engine, budget, audit)
    facts = RunFacts(
        job_id=job.job_id,
        profile=job.profile,
        os=identified.os,
        engine=engine.name,
        tool_versions=engine.tool_versions(),
        image=image_record(identified, job.size_bytes, job.expected_sha256),
        audit=audit,
    )
    hit = _lookup(store, identified)
    if hit is None:
        raise DiagnosticResult(write_diagnostic(ws.dirs.root / RESULT, facts, identified.identity))
    ws.isf_uri = hit.path.resolve().as_uri()

    outcomes: list[PluginOutcome] = []
    rows: dict[MemoryPlugin, Any] = {}
    reported_isf: list[str] = []
    for plugin in PLUGINS_BY_PROFILE[(identified.os, MemoryProfile(job.profile))]:
        seconds = budget.plugin()
        if seconds is None:
            outcomes.append(PluginOutcome(plugin=plugin, status="skipped"))
            continue
        spec = PLUGINS[plugin]
        cap = max_rows(spec, limits)
        run = engine.run(ws, plugin, seconds, cap)
        status = _status(run)
        if status is not None:
            add_audit(facts.audit, status.audit)
        outcome = _outcome(plugin, run, status, ws)
        outcomes.append(outcome)
        if plugin == PROCESS_LIST_PLUGIN[identified.os] and outcome.status != "ok":
            raise JobFailed("memory_parse_failed", f"{plugin.value} {outcome.status}")
        verified = status is None or status.offline_verified(str(ws.symbols_dir))
        if not verified:
            facts.error("probe_offline_unverified")
        if outcome.status in ("ok", "failed", "timeout") and verified:
            if status is not None:
                reported_isf += [u for u in status.isf if u not in reported_isf]
            # A failed or killed run keeps its rows, flagged as partial (never "complete").
            outcome.truncated = outcome.truncated or outcome.status != "ok"
            opener = functools.partial(sandbox.open_output, run.dirs, ROWS)
            rows[plugin] = RowSource(opener, cap, outcome.counted)
    sandbox.kill_tool_processes()
    facts.isf_sha256 = _isf_sha256(store, hit, reported_isf, facts)
    return assemble(ws.dirs.root / RESULT, facts, outcomes, rows, limits)


__all__ = ["DiagnosticResult", "analyze", "analyze_image", "check_disk"]
