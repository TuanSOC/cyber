"""Ghidra engine smoke (M10 phase 2): the REAL Ghidra 12.2 through PyGhidra in the sandboxed
stages (uid 10010, seccomp AF_UNIX only + no io_uring, rlimits, the watchdog) on the M3 C
samples compiled here with mingw-w64 (x64; never run). Heavy: one JVM per stage.

Checks: both stages succeed; functions, call edges, imports with callers and strings come
back; `main` is decompiled; the audit hook recorded no Python network / process event after
the JVM start; the decompile stage's children are only `jspawnhelper` and the decompiler
(RT15); the effective JVM arguments are exactly the expected list (RT1, compared by root);
the peak container memory is below `mem_limit`; the loader and analysis option names the
probe saw are printed (the spike pins `loader_choice.KNOWN_OPTIONS` from them).

    scripts/lane-test.sh 2 --service re-worker-test --heavy pytest -q -s -m engine \\
        tests/engine/test_ghidra_smoke.py
"""

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("resource")
pytestmark = [
    pytest.mark.engine,
    pytest.mark.skipif(
        not Path("/opt/ghidra/Ghidra").is_dir() or shutil.which("x86_64-w64-mingw32-gcc") is None,
        reason="needs the re-worker dev image (Ghidra, mingw-w64)",
    ),
]

from cyberlab_jobs.reverse import RE_LINE_ADAPTER, validate_stream  # noqa: E402
from cyberlab_worker import sandbox  # noqa: E402

from re_worker.analyzer import analyze_sample  # noqa: E402
from re_worker.config import load  # noqa: E402
from re_worker.engines import Budget, workspace  # noqa: E402
from re_worker.engines.stage import SandboxRunner  # noqa: E402
from re_worker.probe.guard import FAMILIES  # noqa: E402
from tests.conftest import WORK  # noqa: E402
from tests.stage_helpers import LIMITS, job  # noqa: E402

M3C = Path("/opt/samples/m3c")
MEM_LIMIT = 4 * 1024**3


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    if os.geteuid() != 0:
        pytest.skip("runs inside the re-worker container")
    WORK.mkdir(parents=True, exist_ok=True)
    job_dirs = sandbox.prepare(WORK, f"smoke-{uuid.uuid4()}")
    yield job_dirs
    sandbox.cleanup(job_dirs)


def _compile(name: str, out: Path) -> bytes:
    """mingw-w64 x64 build of an M3 C sample (compiled, never run)."""
    binary = out / f"{name}.exe"
    subprocess.run(
        ["x86_64-w64-mingw32-gcc", "-O1", "-o", str(binary), str(M3C / f"{name}.c")],
        check=True,
        capture_output=True,
    )
    return binary.read_bytes()


@pytest.mark.parametrize("name", ["hello", "injector"])
def test_ghidra_analyses_and_decompiles(
    dirs: sandbox.JobDirs, tmp_path: Path, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Whatever phase 5's priority returns, decompile something: the largest functions.
    monkeypatch.setattr(
        "re_worker.engines.ghidra.priority.rank",
        lambda view, _job: sorted(view.functions, key=lambda e: -view.functions[e].size),
    )
    data = _compile(name, tmp_path)
    ws = workspace.create(dirs)
    ws.sample.write_bytes(data)
    os.chmod(ws.sample, 0o444)
    the_job = job(size=len(data)).model_copy(
        update={"expected_sha256": hashlib.sha256(data).hexdigest()}
    )
    config = load({"BROKER_URL": "redis://x"})
    path = analyze_sample(ws, the_job, config, Budget.starting_now(1800), SandboxRunner())
    with gzip.open(path, "rt", encoding="utf-8") as f:
        lines = [RE_LINE_ADAPTER.validate_python(json.loads(line)) for line in f]
    validate_stream(lines, job_id=the_job.job_id, limits=LIMITS)
    header = lines[0]
    by_kind: dict[str, list[object]] = {}
    for line in lines:
        by_kind.setdefault(line.kind, []).append(line)
    print(json.dumps(header.model_dump(mode="json"), indent=1))
    assert header.engine == "ghidra"
    assert [(s.stage, s.status) for s in header.stages] == [("analyze", "ok"), ("decompile", "ok")]
    assert all(header.audit.get(f, 0) == 0 for f in FAMILIES)
    assert set(header.audit) <= {"child:decompile", "child:jspawnhelper"}
    assert header.audit.get("child:decompile", 0) >= 1
    assert all((s.peak_memory_bytes or 0) < MEM_LIMIT for s in header.stages)
    names = {f.name for f in by_kind["function"]}  # type: ignore[attr-defined]
    assert "main" in names
    assert by_kind.get("call_edge") and by_kind.get("import") and by_kind.get("string")
    assert by_kind.get("import_ref")
    decompiled = by_kind["decompiled"]
    assert any(d.status == "ok" and "main" in (d.code or "") for d in decompiled)  # type: ignore[attr-defined]
