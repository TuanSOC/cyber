"""Recovery quality of the real engines on the synthetic set (M10 phase 4; run by the parent
after the group-B merge, heavy and alone: `lane-test.sh 9 --service re-worker-test --heavy
pytest -q -m engine tests/engine/test_recovery_quality.py`).

Every stripped build of `samples.generate` goes through the frozen `analyzer.analyze(job,
dirs, config)` (the sample is served from a loopback HTTP server inside the test container,
so the kit's hash-checked download runs unchanged); the `re.v1` stream is read back into a
`ReView` and measured against the unstripped build's truth (`samples/quality.py`).
Per engine: Ghidra (`profile = full`) and radare2 (`profile = quick`; skipped while the
quick profile answers `profile_unavailable`). The structural edge cases and `bulk_gen` only
have to end cleanly (a result, a diagnostic, or a classified `RE_ERROR_CODES` failure).

Thresholds are recorded, not tuned to pass. The test asserts sanity floors only (Ghidra
non-library function recall >= 0.8 on every -O0 build; every run ends cleanly) and writes
the whole table to `dataset/quality-<engine>.json` (or `$RE_QUALITY_DIR`; the dataset
mount is read-only in `re-worker-test`, so the parent copies the file out) for phase 12.
`RE_QUALITY_SAMPLES=a,b` limits the run to samples whose name starts with one of the
prefixes.
"""

import gzip
import json
import os
import shutil
import threading
import uuid
from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.reverse import (
    RE_ERROR_CODES,
    RE_LINE_ADAPTER,
    ReCallEdgeRecord,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReJobV1,
    ReProgramRecord,
    ReResultHeader,
    ReStringRecord,
    ReStringRefRecord,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from re_worker import config as worker_config
from re_worker.analyzer import DiagnosticResult, analyze
from re_worker.view import ReView
from samples.generate import CAVEAT, generate
from samples.quality import measure
from tests.conftest import WORK, in_container

pytestmark = [pytest.mark.engine, in_container]

OUT = Path("/tmp/re-samples")
DATASET = Path(__file__).resolve().parents[2] / "dataset"
LIMITS = {
    "max_bytes": 16 * 1024**2,
    "timeout_s": 3600,
    "tool_timeout_s": 1800,
    "analysis_timeout_s": 1500,
    "decompile_timeout_s": 30,
    "quick_timeout_s": 300,
    "max_functions": 20_000,
    "max_call_edges": 100_000,
    "max_imports": 10_000,
    "max_import_refs": 50_000,
    "max_strings": 20_000,
    "max_string_refs": 50_000,
    "max_decompiled": 300,
    "max_code_bytes": 64 * 1024,
    "max_code_total_bytes": 32 * 1024**2,
    "max_findings": 2_000,
    "max_iocs": 10_000,
    "max_result_bytes": 256 * 1024**2,
    "max_work_bytes": 2 * 1024**3,
}
RECALL_FLOOR = 0.8


class _Quiet(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        del format, args


@pytest.fixture(scope="module")
def sample_set() -> dict[str, Any]:
    shutil.rmtree(OUT, ignore_errors=True)
    return generate(OUT)


@pytest.fixture(scope="module")
def server(sample_set: dict[str, Any]) -> Iterator[str]:
    del sample_set
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), partial(_Quiet, directory=str(OUT)))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


def _selected(name: str) -> bool:
    prefixes = [p for p in os.environ.get("RE_QUALITY_SAMPLES", "").split(",") if p]
    return not prefixes or name.startswith(tuple(prefixes))


def _job(url: str, label: dict[str, Any], profile: str) -> ReJobV1:
    return ReJobV1.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "evidence_id": str(uuid.uuid4()),
            "source_job_id": str(uuid.uuid4()),
            "expected_sha256": label["sha256"],
            "size_bytes": label["size_bytes"],
            "evidence_url": f"{url}/{label['file']}",
            "result_post": {"url": "http://127.0.0.1:9/unused", "fields": {"key": "k"}},
            "ingest_token": "t" * 43,
            "profile": profile,
            "file_format": label["format"],
            "limits": LIMITS,
        }
    )


def _read(path: Path) -> tuple[ReResultHeader, ReView]:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    lines = [RE_LINE_ADAPTER.validate_json(line) for line in raw.splitlines() if line.strip()]

    def of(kind: type[Any]) -> list[Any]:
        return [line for line in lines if isinstance(line, kind)]

    (header,) = of(ReResultHeader)
    (program,) = of(ReProgramRecord)
    view = ReView.build(
        program, of(ReFunctionRecord), of(ReCallEdgeRecord), of(ReImportRecord),
        of(ReImportRefRecord), of(ReStringRecord), of(ReStringRefRecord), of(ReDecompiledRecord),
    )  # fmt: skip
    return header, view


def _run(url: str, label: dict[str, Any], profile: str) -> tuple[str, Path | None]:
    """("ok" | "diagnostic:<code>" | "failed:<code>", result path or None)."""
    env = {"BROKER_URL": "redis://unused:6379/0", **os.environ, "WORK_DIR": str(WORK)}
    config = worker_config.load(env)
    dirs = sandbox.prepare(WORK, f"quality-{uuid.uuid4().hex[:8]}")
    keep = OUT / "results"
    keep.mkdir(exist_ok=True)
    try:
        result = analyze(_job(url, label, profile), dirs, config)
        target = keep / f"{label['file']}.{profile}.re"
        shutil.copyfile(result, target)
        return "ok", target
    except DiagnosticResult as diagnostic:
        return f"diagnostic:{diagnostic.code}", None
    except JobFailed as exc:
        return f"failed:{exc.code}", None
    finally:
        sandbox.cleanup(dirs)


def _write(engine: str, table: dict[str, Any]) -> Path:
    directory = Path(os.environ.get("RE_QUALITY_DIR", str(DATASET)))
    target = directory / f"quality-{engine}.json"
    try:
        target.write_text(json.dumps(table, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:  # the read-only dataset mount: keep it next to the samples
        target = OUT / target.name
        target.write_text(json.dumps(table, indent=2, sort_keys=True), encoding="utf-8")
    return target


@pytest.mark.parametrize(("engine", "profile"), [("ghidra", "full"), ("radare2", "quick")])
def test_recovery_quality(
    engine: str, profile: str, sample_set: dict[str, Any], server: str
) -> None:
    samples = {
        name: label
        for name, label in sample_set.items()
        if not name.startswith("_") and label["stripped"] and _selected(name)
    }
    table: dict[str, Any] = {
        "engine": engine,
        "profile": profile,
        "caveat": CAVEAT,
        "skipped_builds": sample_set["_skipped"],
        "samples": {},
    }
    unclean, floors = [], []
    for name, label in sorted(samples.items()):
        outcome, path = _run(server, label, profile)
        if outcome == "failed:profile_unavailable":
            pytest.skip(f"{engine}: the {profile} profile is unavailable in this image")
        row: dict[str, Any] = {
            "outcome": outcome,
            "kind": label["kind"],
            "opt": label.get("opt"),
            "target": label.get("target"),
            "compiler": label.get("compiler"),
        }
        code = outcome.split(":", 1)[-1]
        if outcome != "ok" and code not in RE_ERROR_CODES:
            unclean.append(f"{name}: {outcome}")
        if path is not None:
            header, view = _read(path)
            table.setdefault("tool_versions", dict(header.tool_versions))
            if label["truth"] is not None:
                truth = json.loads((OUT / label["truth"]).read_text(encoding="utf-8"))
                row.update(measure(view, truth, header))
                recall = row["functions"]["recall_non_library"]
                if (engine == "ghidra" and label["kind"] == "build" and label["opt"] == "O0"
                        and (recall is None or recall < RECALL_FLOOR)):  # fmt: skip
                    floors.append(f"{name}: non-library recall {recall}")
            else:
                row["stages"] = {str(s.stage): s.status for s in header.stages}
        table["samples"][name] = row
    written = _write(engine, table)
    print(f"quality table: {written}")
    assert unclean == [], unclean
    assert floors == [], floors
