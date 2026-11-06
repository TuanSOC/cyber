"""The memory analyzer's latency and parse-success numbers on the synthetic images (M8 phase
11), collected inside `memory-worker-test` for `scripts/memory_metrics.py`:

    scripts/lane-test.sh 4 --service memory-worker-test --heavy \\
        python -m tests.fuzz.metrics_run --replays 3 [--sparse]

Every phase-4 image (benign raw / LiME / ELF, orphan-and-dup, wide, symbols-missing) runs
`--replays` times through root's `analyze_image` with the real engine (sandboxed probes,
offline) against a temp store holding our synthetic ISF. Per run: the outcome, the job's wall
time and each plugin's `duration_ms` from the result header. `--sparse` adds the probe-smoke
identify of a sparse 8 GiB file (holes cost nothing on the tmpfs /work). The numbers cover
synthetic Linux images only: no third-party image is ever run. One `METRICS {json}` line on
stdout.
"""

import argparse
import gzip
import json
import os
import resource
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from cyberlab_jobs.memory import MEMORY_LINE_ADAPTER, MemoryJobV1, OsHint
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from memory_worker import analyzer
from memory_worker.config import load
from memory_worker.engines.volatility import VolatilityEngine
from memory_worker.engines.workspace import Workspace
from memory_worker.symbols import import_isf, reindex
from memory_worker.symbols.store import SymbolStore
from samples.memgen import BANNER, build, isf_xz, scenario, wrap
from tests.replay_helpers import LIMITS
from tests.symbols_helpers import new_store

IMAGES = [
    ("linux_benign", "raw"),
    ("linux_benign", "lime"),
    ("linux_benign", "elf"),
    ("linux_orphan_and_dup", "raw"),
    ("linux_wide", "raw"),
    ("symbols_missing", "raw"),
]
SPARSE_BYTES = 8 * 1024**3


def _job(size: int) -> MemoryJobV1:
    return MemoryJobV1.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "evidence_id": str(uuid.uuid4()),
            "expected_sha256": "a" * 64,
            "size_bytes": size,
            "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=1",
            "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"k": "v"}},
            "ingest_token": "t" * 43,
            "profile": "triage",
            "os_hint": "auto",
            "limits": LIMITS.model_dump(),
        }
    )


def _store(base: Path) -> Path:
    root = new_store(base)
    source = base / "cyberlab.json.xz"
    source.write_bytes(isf_xz(BANNER))
    import_isf.import_file(root, source)
    source.unlink()
    reindex.reindex(root, required_root=Path(os.path.abspath(root)))
    return root


def run_image(work: Path, store: Path, name: str, fmt: str) -> dict[str, Any]:
    dirs = sandbox.prepare(work, f"m-{uuid.uuid4().hex[:8]}")
    try:
        data = wrap(build(scenario(name)), fmt)
        ws = Workspace(dirs, store)
        ws.image.write_bytes(data)
        os.chmod(ws.image, 0o444)
        config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
        started = time.monotonic()
        plugins: dict[str, int] = {}
        try:
            path = analyzer.analyze_image(
                ws, _job(len(data)), VolatilityEngine(config), SymbolStore(store)
            )
            header: Any = MEMORY_LINE_ADAPTER.validate_json(gzip.open(path).readline())
            outcome = "result"
            plugins = {str(p.plugin.value): p.duration_ms for p in header.plugins}
        except analyzer.DiagnosticResult:
            outcome = "symbols_missing"
        except JobFailed as exc:
            outcome = exc.code
        return {
            "image": f"{name}.{fmt}",
            "outcome": outcome,
            "job_ms": int((time.monotonic() - started) * 1000),
            "plugins_ms": plugins,
        }
    finally:
        sandbox.cleanup(dirs)


def sparse_identify(work: Path, store: Path) -> dict[str, Any]:
    dirs = sandbox.prepare(work, f"sparse-{uuid.uuid4().hex[:8]}")
    try:
        ws = Workspace(dirs, store)
        with open(ws.image, "wb") as f:
            f.truncate(SPARSE_BYTES)
        os.chmod(ws.image, 0o444)
        config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
        started = time.monotonic()
        run = VolatilityEngine(config).identify(ws, OsHint.AUTO, 1800)
        seconds = time.monotonic() - started
        peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss >> 10
        return {"end": run.end, "seconds": round(seconds, 1), "peak_child_rss_mib": peak}
    finally:
        sandbox.cleanup(dirs)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="metrics_run")
    parser.add_argument("--replays", type=int, default=3)
    parser.add_argument("--sparse", action="store_true")
    args = parser.parse_args(argv)
    base = Path(os.environ.get("WORK_DIR", "/work")) / f"metrics-{uuid.uuid4().hex[:8]}"
    base.mkdir(mode=0o755)
    work = base / "jobs"
    work.mkdir(mode=0o711)
    try:
        store = _store(base)
        runs = [
            run_image(work, store, name, fmt) | {"replay": r}
            for r in range(args.replays)
            for name, fmt in IMAGES
        ]
        record: dict[str, Any] = {"replays": args.replays, "runs": runs}
        if args.sparse:
            record["sparse_8gib_identify"] = sparse_identify(work, store)
        print("METRICS " + json.dumps(record, sort_keys=True), flush=True)
    finally:
        sandbox.kill_tool_processes()
        shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
