"""Stage isolation and offline proofs inside a real pipeline run (M9 phase 13; RT3-RT5).

`tests/unit/test_stage_isolation.py` and `test_offline.py` prove each property on single
stages; this module proves them where they matter, inside `pipeline.run_job` on a generated
image (phase 4's `ext4_linux`, from `DISK_ENGINE_IMAGES`), through the fuzz harness
(`tests/fuzz/harness.py`: local segments instead of the presigned download, the stream decoded
instead of uploaded, every stage result recorded and checked):

- a test-only **hook stage**, run through the real `stage.run_stage` between the sealed
  `collect` stage and the next stage of the same job, `setsid`-forks a sleeper and tries to
  write into the sealed collect tree: the write fails (`EACCES`), the sleeper is gone before
  the next stage starts, and the job still posts its result;
- a hook stage writing past its write budget is killed and reported `truncated`
  (`write_budget`), and the job still posts its result;
- a job whose deadline leaves too little time ends with `skipped` (`deadline`) stages and a
  posted result, never a `timed_out` (the reaper's outcome);
- every stage of these runs records zero audit-hook events (socket, urllib, subprocess, exec,
  spawn, system, fork, dlopen), Plaso included;
- seccomp inside a stage refuses every socket family but AF_UNIX (INET, INET6, NETLINK,
  PACKET) and the io_uring syscalls (`EACCES`).

The hook stages are injected by the test (no production seam): the harness calls
`before_stage` from its `stage.run_stage` wrapper. Run inside the disk worker image as root:

    docker compose --profile test run --rm --no-deps -v cyberlab_e2e_samples:/samples:ro \
        -e DISK_ENGINE_IMAGES=/samples/disk disk-worker-test \
        pytest -q -p no:cacheprovider tests/engine/test_stage_proofs.py
"""

import errno
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.disk import DiskLimits, StageLimits, StageStatus
from cyberlab_worker import sandbox

from disk_worker import stage
from disk_worker.budget import Budget
from tests.fuzz import harness

pytestmark = pytest.mark.engine
ROOT = os.environ.get("DISK_ENGINE_IMAGES")
IMAGE = Path(ROOT) / "ext4_linux" if ROOT else None
REAL_RUN_STAGE = stage.run_stage
MIB = 1024**2

if IMAGE is None or not (IMAGE / "image.raw").is_file():
    pytest.skip("DISK_ENGINE_IMAGES with ext4_linux (disk:gen) not set", allow_module_level=True)
if not hasattr(os, "geteuid") or os.geteuid() != 0:
    pytest.skip("runs as root inside the disk worker image", allow_module_level=True)
pytest.importorskip("pytsk3")

STATUS = (
    "import json, os\n"
    "def done(out, **facts):\n"
    "    fd = os.open(os.path.join(out, 'status.json'),"
    " os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n"
    "    os.write(fd, json.dumps({'status': 'ok', 'facts': facts}).encode())\n"
    "    os.close(fd)\n"
)


def _segments() -> list[Path]:
    assert IMAGE is not None
    return [IMAGE / "image.raw"]


def _hook(
    job_root: Path, name: str, body: str, lim: DiskLimits, budget: Budget
) -> stage.StageResult:
    jd = sandbox.JobDirs(root=job_root, input=job_root / "input", out=job_root / "out")
    sd = stage.fresh(jd, name)
    script = STATUS + body.replace("OUT", repr(str(sd.out)))
    return REAL_RUN_STAGE([sys.executable, "-I", "-c", script], sd, "layout", lim, budget)


def _tight(lim: DiskLimits) -> DiskLimits:
    data = lim.model_dump(mode="json")
    data["stages"]["layout"] = StageLimits(
        rlimit_as=1024 * MIB, rlimit_fsize=512 * MIB, write_budget=8 * MIB, timeout_s=120
    ).model_dump()
    return DiskLimits.model_validate(data)


def test_hook_stages_inside_a_pipeline_run_are_contained() -> None:
    hooks: dict[str, Any] = {}

    def before(run: harness.Run, key: str, dirs: sandbox.JobDirs, budget: Any) -> None:
        if hooks or not any(s.stage == "collect" for s in run.stages):
            return
        root = dirs.root
        collected = sorted(root.glob("collect-p*-out"))
        hooks["collect_dirs"] = [p.name for p in collected]
        target = str(collected[0] / "artifacts") if collected else str(root / "missing")
        body = (
            "import errno, time\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    time.sleep(600)\n"
            "    os._exit(0)\n"
            "codes = []\n"
            f"for p in ({target + '/planted'!r}, {target + '/../collected.jsonl'!r}):\n"
            "    try:\n"
            "        open(p, 'a').write('x')\n"
            "        codes.append(0)\n"
            "    except OSError as exc:\n"
            "        codes.append(exc.errno)\n"
            "done(OUT, codes=codes, sleeper=pid)\n"
        )
        lim = budget.limits
        hostile = _hook(root, "hook-hostile", body, lim, budget)
        hooks["hostile"] = hostile
        hooks["survivors_after_hostile"] = sandbox.tool_pids()
        flood_body = (
            "import time\n"
            "with open(os.path.join(OUT, 'flood'), 'wb') as f:\n"
            "    for _ in range(64):\n"
            "        f.write(b'x' * (1024 * 1024))\n"
            "        f.flush()\n"
            "        os.fsync(f.fileno())\n"
            "    time.sleep(30)\n"
            "done(OUT)\n"
        )
        flood = _hook(root, "hook-flood", flood_body, _tight(lim), budget)
        hooks["flood"] = flood
        hooks["survivors_after_flood"] = sandbox.tool_pids()
        hooks["next_stage"] = key

    run = harness.run_case("proof/hook_stages", _segments(), before_stage=before)
    harness.record("proofs", run)

    assert hooks, f"no collect stage ran: {[(s.stage, s.status) for s in run.stages]}"
    assert hooks["collect_dirs"], "the Linux tree was not collected"
    hostile: stage.StageResult = hooks["hostile"]
    assert hostile.status == StageStatus.OK, hostile
    assert hostile.facts["codes"] == [errno.EACCES, errno.EACCES]
    assert hooks["survivors_after_hostile"] == []
    flood: stage.StageResult = hooks["flood"]
    assert flood.status == StageStatus.TRUNCATED and flood.reason == "write_budget", flood
    assert hooks["survivors_after_flood"] == []
    assert run.outcome == "result", (run.outcome, run.problems)
    assert run.clean, run.problems
    assert run.header is not None and run.header.stages


def test_a_short_deadline_skips_stages_and_still_posts_a_result() -> None:
    # 300 s of budget after the reserve: layout / walk / collect fit, log2timeline (600 s
    # minimum) cannot and is skipped with `deadline`, never started; the job ends on time.
    lim = harness.limits(timeout_s=1200, deadline_reserve_s=60)
    run = harness.run_case(
        "proof/short_deadline", _segments(), lim=lim, deadline=timedelta(seconds=360)
    )
    harness.record("proofs", run)
    assert run.outcome == "result", (run.outcome, run.problems)
    assert run.code != "timed_out"
    assert run.header is not None
    skipped = [
        (s.stage.value, s.reason)
        for s in run.header.stages
        if s.status == StageStatus.SKIPPED and s.reason == "deadline"
    ]
    assert skipped, [(s.stage, s.status, s.reason) for s in run.header.stages]
    assert run.clean, run.problems


def test_every_stage_of_a_full_run_records_no_audit_event() -> None:
    run = harness.run_case("proof/offline", _segments())
    harness.record("proofs", run)
    assert run.outcome == "result", (run.outcome, run.problems)
    assert run.stages, "no stage ran"
    for result in run.stages:
        if result.has_status:
            assert result.audit_counts, result  # the hook reported its families
            assert not any(result.audit_counts.values()), (result.stage, result.audit_counts)
    assert run.clean, run.problems


def test_seccomp_refuses_every_other_socket_family_and_io_uring() -> None:
    jobs = harness.FUZZ_ROOT / "proof-jobs"
    jobs.mkdir(parents=True, exist_ok=True)
    dirs = sandbox.prepare(jobs, "seccomp")
    try:
        lim = harness.limits()
        budget = Budget(datetime.now(UTC) + timedelta(hours=1), lim)
        body = (
            "import ctypes, socket\n"
            "res = {}\n"
            "for name in ('AF_INET', 'AF_INET6', 'AF_NETLINK', 'AF_PACKET'):\n"
            "    try:\n"
            "        socket.socket(getattr(socket, name), socket.SOCK_DGRAM).close()\n"
            "        res[name] = 0\n"
            "    except OSError as exc:\n"
            "        res[name] = exc.errno\n"
            "a, b = socket.socketpair(socket.AF_UNIX)\n"
            "a.close(); b.close()\n"
            "res['AF_UNIX'] = 0\n"
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "rc = libc.syscall(425, 8, ctypes.c_void_p(0))\n"  # io_uring_setup
            "res['io_uring'] = ctypes.get_errno() if rc < 0 else 0\n"
            "done(OUT, res=res)\n"
        )
        result = _hook(dirs.root, "seccomp", body, lim, budget)
    finally:
        sandbox.cleanup(dirs)
    res = result.facts["res"]
    for family in ("AF_INET", "AF_INET6", "AF_NETLINK", "AF_PACKET"):
        assert res[family] == errno.EACCES, (family, res)
    assert res["AF_UNIX"] == 0
    assert res["io_uring"] == errno.EACCES, res
