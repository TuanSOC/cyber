"""Memory analysis of one image: download -> refuse compressed -> identify -> symbols ->
one probe per allow-listed plugin -> normalize -> detect -> `memory.v1` (M8 phase 2).

`analyze(job, dirs, config) -> Path` returns the written result, raises `DiagnosticResult`
(a written `symbols_missing` stream to upload with a failed report) or `JobFailed(code)`.

Root never parses image bytes: it hashes them during the download (`transfer.download`:
sha256 + size verified, root-owned 0444), reads the first 16 bytes for the compressed /
archive refusal (RT19), and reads only bounded probe output. `sandbox.prepare` ran once
for the job (pipeline); every probe gets a fresh out dir (`Workspace.fresh`, RT26).

Review fixes: the job budget starts before the download; a probe without a status (killed
on timeout) is not offline-verified, so its rows are dropped; after every probe the work
volume's free space and the job's probe output are checked (`insufficient_disk`); the ISF
files the probes report are re-hashed against the manifest after the run, and an ISF from
outside the store and Volatility's own symbol dirs, or one the manifest does not vouch for,
fails the job `symbols_corrupt`; the seeded identifier cache must match the manifest.

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
from memory_worker.symbols.manifest import StoreError, sha256_file
from memory_worker.symbols.store import SymbolHit, SymbolsCorrupt, SymbolStore

GIB = 1024**3
DISK_HEADROOM = GIB  # free space on /work beyond the image (plan: size + 1 GiB)
TEST_DISK_HEADROOM = 16 * 1024**2  # the test profile's 512 MiB tmpfs /work (RT6)
# Of the 1 GiB headroom: what every probe's out dir of one job may use together, and the free
# space that must stay for the result stream (<= max_result_bytes, 256 MiB) after any probe.
PROBE_OUTPUT_BUDGET = 768 * 1024**2
MIN_FREE_AFTER_PROBE = 256 * 1024**2
TEST_PROBE_OUTPUT_BUDGET = 8 * 1024**2
TEST_MIN_FREE_AFTER_PROBE = 4 * 1024**2
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


def _test_profile() -> bool:
    return os.environ.get("TEST_PROFILE") == "1"


def probe_output_budget() -> int:
    return TEST_PROBE_OUTPUT_BUDGET if _test_profile() else PROBE_OUTPUT_BUDGET


def min_free_after_probe() -> int:
    return TEST_MIN_FREE_AFTER_PROBE if _test_profile() else MIN_FREE_AFTER_PROBE


def check_probe_disk(ws: Workspace) -> None:
    """After every probe: a probe (bounded per file by RLIMIT_FSIZE only) must not fill the
    work volume. Over the job's output budget, or too little space left for the result, the
    job fails `insufficient_disk` before the next probe can write more."""
    if ws.output_bytes() > probe_output_budget():
        raise JobFailed("insufficient_disk", "probe output over the job's budget")
    if shutil.disk_usage(ws.dirs.root).free < min_free_after_probe():
        raise JobFailed("insufficient_disk", "the work volume is nearly full")


def analyze(job: MemoryJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    if job.size_bytes == 0:
        raise JobFailed("memory_image_empty")
    if job.size_bytes > job.limits.max_bytes:
        raise JobFailed("memory_image_too_large")
    check_disk(config.work_dir, job.size_bytes)
    # The job's wall clock starts now: the download of a large image counts against it.
    budget = Budget(job.limits)
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
        budget,
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
    check_probe_disk(ws)
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


def _uri_path(uri: str) -> Path | None:
    """The local file behind an ISF URI (`file:` or a `jar:file:...!` archive member's
    archive), resolved (symlinks followed), or None for any other scheme."""
    if uri.startswith("jar:"):
        uri = uri[4:].split("!", 1)[0]
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        return None
    return Path(urllib.parse.unquote(parsed.path)).resolve()


def _inside(path: Path, base: Path) -> bool:
    return path == base or base in path.parents


def _isf_sha256(
    store: Symbols,
    hit: SymbolHit,
    reported: list[str],
    builtin: set[str],
    facts: RunFacts,
) -> str:
    """The sha256 of the kernel ISF the run actually loaded, re-hashed now against the
    manifest (the lookup's hash was taken before the probes ran).

    Every reported ISF must be a store file the manifest lists with that hash, or lie in
    Volatility's own symbol dirs (`builtin`, from the offline-verified statuses); anything
    else (another location, another scheme, an unlisted or changed store file) fails the job
    `symbols_corrupt`. No store ISF reported: `isf_unreported` (the lookup's hash stands); a
    store ISF other than the one looked up: `isf_mismatch` and that file's hash."""
    root = store.root.resolve()
    builtin_dirs = [Path(d).resolve() for d in builtin]
    try:
        listed = {f.path: f.sha256 for f in store.manifest().files}
    except SymbolsCorrupt as exc:
        raise JobFailed("symbols_corrupt") from exc
    loaded: list[tuple[Path, str]] = []
    for uri in reported:
        path = _uri_path(uri)
        if path is None:
            raise JobFailed("symbols_corrupt", "an ISF from a non-file location")
        if _inside(path, root):
            rel = path.relative_to(root).as_posix()
            expected = listed.get(rel)
            if expected is None:
                raise JobFailed("symbols_corrupt", "an ISF the manifest does not list")
            try:
                actual = sha256_file(path)
            except (OSError, StoreError) as exc:
                raise JobFailed("symbols_corrupt", "an ISF is unreadable") from exc
            if actual != expected:
                raise JobFailed("symbols_corrupt", "an ISF does not match the manifest")
            loaded.append((path, actual))
        elif not any(_inside(path, d) for d in builtin_dirs):
            raise JobFailed("symbols_corrupt", "an ISF from outside the symbol store")
    if not loaded:
        facts.error("isf_unreported")
        return hit.sha256
    expected_path = hit.path.resolve()
    for path, digest in loaded:
        if path == expected_path:
            return digest
    facts.error("isf_mismatch")
    return loaded[0][1]


def analyze_image(
    ws: Workspace,
    job: MemoryJobV1,
    engine: Engine,
    store: Symbols,
    budget: Budget | None = None,
) -> Path:
    """Everything after the download (the image is at `ws.image`, hash-verified). `budget`
    started before the download (`analyze`); tests may leave it to start here."""
    limits: MemoryLimits = job.limits
    if image_format(ws.image) is not None:
        raise JobFailed("unsupported_memory_format", "compressed or archived file")
    budget = budget or Budget(limits)
    try:
        # Probes seed their identifier cache only from a file with the manifest's hash.
        ws.cache_sha256 = store.manifest().identifier_cache_sha256
    except SymbolsCorrupt as exc:
        raise JobFailed("symbols_corrupt") from exc
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
    builtin_dirs: set[str] = set()
    for plugin in PLUGINS_BY_PROFILE[(identified.os, MemoryProfile(job.profile))]:
        seconds = budget.plugin()
        if seconds is None:
            outcomes.append(PluginOutcome(plugin=plugin, status="skipped"))
            continue
        spec = PLUGINS[plugin]
        cap = max_rows(spec, limits)
        run = engine.run(ws, plugin, seconds, cap)
        check_probe_disk(ws)
        status = _status(run)
        if status is not None:
            add_audit(facts.audit, status.audit)
        outcome = _outcome(plugin, run, status, ws)
        outcomes.append(outcome)
        if plugin == PROCESS_LIST_PLUGIN[identified.os] and outcome.status != "ok":
            raise JobFailed("memory_parse_failed", f"{plugin.value} {outcome.status}")
        # No status (a probe killed on timeout) proves nothing about how it ran: its rows
        # are dropped like those of any probe that did not provably run offline.
        verified = status is not None and status.offline_verified(str(ws.symbols_dir))
        if not verified:
            facts.error("probe_offline_unverified")
            outcome.truncated = outcome.truncated or outcome.status in ("failed", "timeout")
        if outcome.status in ("ok", "failed", "timeout") and status is not None and verified:
            reported_isf += [u for u in status.isf if u not in reported_isf]
            builtin_dirs.update(status.symbol_paths[1:])
            # A failed or killed run keeps its rows, flagged as partial (never "complete").
            outcome.truncated = outcome.truncated or outcome.status != "ok"
            opener = functools.partial(sandbox.open_output, run.dirs, ROWS)
            rows[plugin] = RowSource(opener, cap, outcome.counted)
    sandbox.kill_tool_processes()
    facts.isf_sha256 = _isf_sha256(store, hit, reported_isf, builtin_dirs, facts)
    return assemble(ws.dirs.root / RESULT, facts, outcomes, rows, limits)


__all__ = ["DiagnosticResult", "analyze", "analyze_image", "check_disk", "check_probe_disk"]
