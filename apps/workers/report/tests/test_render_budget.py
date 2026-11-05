"""Render budget (RT1): a snapshot at REPORT_MAX_RENDER_UNITS renders within the sandbox.

`CALIBRATED_RENDER_UNITS` mirrors the API setting REPORT_MAX_RENDER_UNITS (the parent sets
both from the calibration below). The default test renders the worst shapes at the budget
through the real sandbox with the real limits and checks the time and memory headroom.

The calibration itself (slow, opt-in) sweeps budgets and shapes and prints peak RSS, peak
virtual size, CPU seconds, pages and bytes per render, plus the golden p50 / p95:

    scripts/lane-test.sh 4 --service report-worker-test \
        sh -c "REPORT_CALIBRATE=1 pytest -q -s tests/test_render_budget.py -k calibrate"
"""

import json
import os
import statistics
import sys
import time
from typing import Any

import pytest
from cyberlab_jobs.report import ReportSnapshot, canonical_json, render_units
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from report_worker import checks
from report_worker import sandbox as render_sandbox
from tests.conftest import WORK, in_container, load_snapshot, stage
from tests.worst_case import worst_case

pytestmark = in_container

CALIBRATED_RENDER_UNITS = 450_000
# The plan's targets for a render at the budget, under the sandbox limits (768 MiB address
# space, 75 s CPU): peak RSS about 600 MiB and 60 s CPU.
MAX_RSS_MIB = 600
MAX_CPU_S = 60

MEASURE = """
import json, os, resource, sys, time
from report_worker.render import main
start = time.monotonic()
code = main(sys.argv[1:])
usage = resource.getrusage(resource.RUSAGE_SELF)
status = dict(line.split(":", 1) for line in open("/proc/self/status").read().splitlines())
with open(os.path.join(os.environ["TMPDIR"], "usage.json"), "w") as f:
    json.dump({
        "code": code,
        "rss_mib": usage.ru_maxrss / 1024,
        "vm_peak_mib": int(status["VmPeak"].split()[0]) / 1024,
        "cpu_s": usage.ru_utime + usage.ru_stime,
        "wall_s": time.monotonic() - start,
    }, f)
sys.exit(code)
"""


def measure(
    snapshot: ReportSnapshot,
    fmt: str = "pdf",
    *,
    limits: sandbox.Rlimits | None = None,
    timeout_s: float | None = None,
) -> dict[str, Any]:
    dirs = sandbox.prepare(WORK, "budget")
    try:
        stage(dirs, snapshot, fmt)
        argv = render_sandbox.render_argv(fmt, dirs)
        argv = [argv[0], "-I", "-B", "-c", MEASURE, *argv[-3:]]
        error = None
        try:
            render_sandbox.run(
                argv,
                dirs,
                timeout_s=timeout_s or render_sandbox.WALL_TIMEOUT_S,
                rlimits=limits or render_sandbox.RENDER_RLIMITS,
            )
        except JobFailed as exc:
            error = exc.code
        try:
            with sandbox.open_output(dirs, "usage.json") as f:
                usage: dict[str, Any] = json.loads(f.read())
        except (OSError, ValueError):
            usage = {}
        usage["error"] = error
        if error is None:
            with sandbox.open_output(dirs, "render.json") as f:
                usage["pages"] = json.loads(f.read())["pages"]
            with sandbox.open_output(dirs, checks.OUTPUT_NAMES[fmt]) as f:
                usage["bytes"] = len(f.read())
        usage["units"] = render_units(snapshot)
        usage["snapshot_bytes"] = len(canonical_json(snapshot))
        return usage
    finally:
        sandbox.cleanup(dirs)


@pytest.mark.parametrize(("shape", "style"), [("caps", "mixed"), ("citations", "run")])
def test_a_snapshot_at_the_budget_renders_within_the_sandbox(shape: str, style: str) -> None:
    snapshot = worst_case(CALIBRATED_RENDER_UNITS, shape, style)
    assert abs(render_units(snapshot) - CALIBRATED_RENDER_UNITS) < 20_000
    usage = measure(snapshot)
    assert usage["error"] is None, usage
    assert usage["rss_mib"] < MAX_RSS_MIB, usage
    assert usage["cpu_s"] < MAX_CPU_S, usage
    assert 1 <= usage["pages"] <= 300 and usage["bytes"] <= 32 * 1024 * 1024, usage


@pytest.mark.skipif(not os.environ.get("REPORT_CALIBRATE"), reason="REPORT_CALIBRATE=1 only")
def test_calibrate() -> None:
    roomy = sandbox.Rlimits(
        as_bytes=1536 * 1024 * 1024,
        cpu_s=600,
        fsize_bytes=64 * 1024 * 1024,
        nofile=64,
        nproc=16,
    )
    budgets = [
        int(b)
        for b in os.environ.get("REPORT_CALIBRATE_BUDGETS", "250000,500000,750000,1000000").split(
            ","
        )
    ]
    shapes = os.environ.get(
        "REPORT_CALIBRATE_SHAPES", "caps:mixed,caps:prose,citations:run,iocs:run,timeline:mixed"
    ).split(",")
    rows = []
    for units in budgets:
        for item in shapes:
            shape, style = item.split(":")
            usage = measure(worst_case(units, shape, style), limits=roomy, timeout_s=650)
            row = {"budget": units, "shape": shape, "style": style, **usage}
            rows.append(row)
            print(json.dumps(row), flush=True)
    golden = load_snapshot("golden_snapshot.json")
    for fmt in ("pdf", "html", "md"):
        walls = []
        for _ in range(int(os.environ.get("REPORT_CALIBRATE_RUNS", "20"))):
            start = time.monotonic()
            usage = measure(golden, fmt)
            walls.append(time.monotonic() - start)
            assert usage["error"] is None
        walls.sort()
        p95 = walls[max(0, int(len(walls) * 0.95) - 1)]
        print(
            json.dumps(
                {
                    "golden": fmt,
                    "p50_s": statistics.median(walls),
                    "p95_s": p95,
                    "render_cpu_s": usage["cpu_s"],
                    "rss_mib": usage["rss_mib"],
                }
            ),
            flush=True,
        )
    print(json.dumps({"python": sys.version.split()[0]}))
