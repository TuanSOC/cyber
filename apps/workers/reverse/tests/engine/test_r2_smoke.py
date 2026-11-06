"""radare2 engine smoke (M10 phase 3): the REAL radare2 6.2.6 with the fixed script, then the
reducer probe, both sandboxed (uid 10010, seccomp AF_UNIX only + no io_uring, rlimits, the
watchdog), on the M3 C samples compiled here with mingw-w64 (x86 and x64; never run). One
lane slot (no JVM).

Checks: every `e` variable of the script exists in 6.2.6 (`e??` on an empty buffer, never on
a sample); a valid `re.v1` quick stream comes back in seconds with functions (incl. `main`),
call edges, imports with callers and strings with referencing functions, which proves the
`aflj` `callrefs` / `datarefs` fields the reducer reads [I]; no engine error; the audit hook
saw nothing.

    scripts/lane-test.sh 3 --service re-worker-test pytest -q -s -m engine \\
        tests/engine/test_r2_smoke.py
"""

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("resource")
pytestmark = [
    pytest.mark.engine,
    pytest.mark.skipif(
        not Path("/usr/bin/radare2").is_file()
        or shutil.which("x86_64-w64-mingw32-gcc") is None,
        reason="needs the re-worker dev image (radare2, mingw-w64)",
    ),
]

from cyberlab_jobs.reverse import RE_LINE_ADAPTER, validate_stream  # noqa: E402
from cyberlab_worker import sandbox  # noqa: E402

from re_worker.analyzer import analyze_sample  # noqa: E402
from re_worker.config import QUICK_SCRIPT, load  # noqa: E402
from re_worker.engines import Budget, workspace  # noqa: E402
from re_worker.engines.stage import SandboxRunner  # noqa: E402
from re_worker.probe.guard import FAMILIES  # noqa: E402
from tests.conftest import WORK  # noqa: E402
from tests.stage_helpers import LIMITS, job  # noqa: E402

M3C = Path("/opt/samples/m3c")
COMPILERS = {"x64": "x86_64-w64-mingw32-gcc", "x86": "i686-w64-mingw32-gcc"}


@pytest.fixture
def dirs() -> Iterator[sandbox.JobDirs]:
    if os.geteuid() != 0:
        pytest.skip("runs inside the re-worker container")
    WORK.mkdir(parents=True, exist_ok=True)
    job_dirs = sandbox.prepare(WORK, f"r2-smoke-{uuid.uuid4()}")
    yield job_dirs
    sandbox.cleanup(job_dirs)


def test_script_variables_exist() -> None:
    names = [
        line.split()[1].split("=")[0]
        for line in QUICK_SCRIPT.read_text().splitlines()
        if line.startswith("e ")
    ]
    listing = subprocess.run(
        ["/usr/bin/radare2", "-q", "-NN", "-c", "e??", "-"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    ).stdout
    missing = [n for n in names if n not in listing]
    assert missing == [], f"variables unknown to this radare2: {missing}"


@pytest.mark.parametrize(
    ("name", "arch"), [("hello", "x64"), ("injector", "x64"), ("injector", "x86")]
)
def test_quick_profile(dirs: sandbox.JobDirs, tmp_path: Path, name: str, arch: str) -> None:
    binary = tmp_path / f"{name}-{arch}.exe"
    subprocess.run(
        [COMPILERS[arch], "-O1", "-o", str(binary), str(M3C / f"{name}.c")],
        check=True,
        capture_output=True,
    )
    data = binary.read_bytes()
    ws = workspace.create(dirs)
    ws.sample.write_bytes(data)
    os.chmod(ws.sample, 0o444)
    the_job = job(profile="quick", size=len(data)).model_copy(
        update={"expected_sha256": hashlib.sha256(data).hexdigest()}
    )
    config = load({"BROKER_URL": "redis://x"})
    started = time.monotonic()
    path = analyze_sample(ws, the_job, config, Budget.starting_now(600), SandboxRunner())
    elapsed = time.monotonic() - started
    with gzip.open(path, "rt", encoding="utf-8") as f:
        lines = [RE_LINE_ADAPTER.validate_python(json.loads(line)) for line in f]
    validate_stream(lines, job_id=the_job.job_id, limits=LIMITS)
    header = lines[0]
    print(f"{name}-{arch}: {elapsed:.1f} s", json.dumps(header.model_dump(mode="json")))
    assert header.engine == "radare2" and header.code_kind == "disasm" and not header.jvm_args
    assert [(s.stage, s.status) for s in header.stages] == [("r2", "ok")]
    assert header.engine_errors == [] and not header.truncated
    assert all(header.audit.get(f, 0) == 0 for f in FAMILIES)
    by_kind: dict[str, list[object]] = {}
    for line in lines:
        by_kind.setdefault(line.kind, []).append(line)
    assert any("main" in f.name for f in by_kind["function"])  # type: ignore[attr-defined]
    for kind in ("call_edge", "import", "import_ref", "string", "string_ref"):
        assert by_kind.get(kind), f"no {kind} rows: check the aflj reference fields"
    assert "decompiled" not in by_kind
    assert elapsed < 120
