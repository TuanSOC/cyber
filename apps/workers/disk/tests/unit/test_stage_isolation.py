"""Stage isolation (M9 phase 2; RT3 / RT4 / RT5), with real processes as the tool uid.

Run inside the disk worker container as root (the `dirs` fixture skips elsewhere):

  scripts/lane-test.sh <lane> --service disk-worker-test \
    pytest -q tests/unit/test_stage_isolation.py

- a stage that `setsid`-forks a sleeper: no tool process survives the stage, the next stage
  sees none;
- a later stage cannot write into a sealed earlier out dir (`EACCES`), and a planted symlink
  is removed by the seal, never followed;
- a stage writing past its write budget is killed and reported `truncated` (`write_budget`);
- a stage the deadline budget cannot fit is `skipped` (`deadline`) and never started.
"""

import errno
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from cyberlab_jobs.disk import DiskLimits, StageLimits, StageStatus
from cyberlab_worker import sandbox

from disk_worker import stage
from disk_worker.budget import Budget
from tests.unit.phase2_helpers import limits, limits_dict

MIB = 1024**2

STATUS_OK = (
    "import json, os, pathlib\n"
    "def done(out, **facts):\n"
    "    fd = os.open(str(pathlib.Path(out) / 'status.json'),"
    " os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\n"
    "    os.write(fd, json.dumps({'status': 'ok', 'facts': facts}).encode())\n"
    "    os.close(fd)\n"
)


def _budget(hours: float = 4) -> Budget:
    return Budget(datetime.now(UTC) + timedelta(hours=hours), limits())


def _run(
    dirs: sandbox.JobDirs, name: str, body: str, lim: DiskLimits | None = None
) -> stage.StageResult:
    sd = stage.fresh(dirs, name)
    script = STATUS_OK + body.replace("OUT", repr(str(sd.out)))
    argv = [sys.executable, "-I", "-c", script]
    return stage.run_stage(argv, sd, "layout", lim or limits(), _budget())


def test_a_setsid_sleeper_does_not_survive_its_stage(dirs: sandbox.JobDirs) -> None:
    body = (
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    os.setsid()\n"
        "    import time\n"
        "    time.sleep(120)\n"
        "    os._exit(0)\n"
        "done(OUT)\n"
    )
    result = _run(dirs, "sleeper", body)
    assert result.status == StageStatus.OK
    assert sandbox.tool_pids() == []
    nxt = _run(dirs, "next", "done(OUT)\n")
    assert nxt.status == StageStatus.OK and sandbox.tool_pids() == []


def test_a_sealed_out_dir_cannot_be_changed_by_a_later_stage(dirs: sandbox.JobDirs) -> None:
    first = _run(
        dirs,
        "first",
        "open(os.path.join(OUT, 'rows.jsonl'), 'w').write('{}\\n')\n"
        "os.symlink('/etc/passwd', os.path.join(OUT, 'planted'))\n"
        "done(OUT)\n",
    )
    assert first.status == StageStatus.OK
    assert not (first.out_dir / "planted").exists() and not (first.out_dir / "planted").is_symlink()
    target = str(first.out_dir)
    body = (
        "import errno\n"
        "codes = []\n"
        f"for p in ({target + '/rows.jsonl'!r}, {target + '/new'!r}):\n"
        "    try:\n"
        "        open(p, 'a').write('x')\n"
        "        codes.append(0)\n"
        "    except OSError as exc:\n"
        "        codes.append(exc.errno)\n"
        "done(OUT, codes=codes)\n"
    )
    second = _run(dirs, "second", body)
    assert second.facts["codes"] == [errno.EACCES, errno.EACCES]
    assert (first.out_dir / "rows.jsonl").read_text() == "{}\n"
    info = first.out_dir.stat()
    assert (info.st_uid, info.st_mode & 0o777) == (0, 0o555)
    assert ((first.out_dir / "rows.jsonl").stat().st_mode & 0o777) == 0o444


def test_writing_past_the_write_budget_is_killed_and_truncated(dirs: sandbox.JobDirs) -> None:
    data = limits_dict()
    data["stages"]["layout"] = StageLimits(
        rlimit_as=1024 * MIB, rlimit_fsize=512 * MIB, write_budget=8 * MIB, timeout_s=600
    ).model_dump()
    tight = DiskLimits.model_validate(data)
    body = (
        "import time\n"
        "with open(os.path.join(OUT, 'flood'), 'wb') as f:\n"
        "    for _ in range(64):\n"
        "        f.write(b'x' * (1024 * 1024))\n"
        "        f.flush()\n"
        "        os.fsync(f.fileno())\n"
        "    time.sleep(30)\n"
        "done(OUT)\n"
    )
    result = _run(dirs, "flood", body, tight)
    assert result.status == StageStatus.TRUNCATED and result.reason == "write_budget"
    assert result.duration_ms < 25_000
    assert sandbox.tool_pids() == []


def test_a_stage_the_budget_cannot_fit_is_skipped_and_never_started(
    dirs: sandbox.JobDirs,
) -> None:
    sd = stage.fresh(dirs, "late")
    marker = sd.out / "started"
    budget = Budget(datetime.now(UTC) + timedelta(minutes=20), limits())
    result = stage.run_stage(
        [sys.executable, "-I", "-c", f"open({str(marker)!r}, 'w')"],
        sd,
        "log2timeline",
        limits(),
        budget,
    )
    assert result.status == StageStatus.SKIPPED and result.reason == "deadline"
    assert not marker.exists()


def test_a_stage_without_a_status_is_failed(dirs: sandbox.JobDirs) -> None:
    sd = stage.fresh(dirs, "silent")
    result = stage.run_stage(
        [sys.executable, "-I", "-c", "pass"], sd, "layout", limits(), _budget()
    )
    assert result.status == StageStatus.FAILED and result.reason == "no_status"
    assert not result.usable


def test_status_json_is_read_bounded(dirs: sandbox.JobDirs) -> None:
    body = (
        "fd = os.open(os.path.join(OUT, 'status.json'), os.O_WRONLY | os.O_CREAT, 0o600)\n"
        "os.write(fd, b'{' + b' ' * (1024 * 1024) + b'}')\n"
    )
    result = _run(dirs, "huge", body)
    assert not result.has_status


@pytest.fixture(autouse=True)
def _no_leftovers() -> Iterator[None]:
    yield
    sandbox.kill_tool_processes()
