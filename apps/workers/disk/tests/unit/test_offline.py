"""Offline proof of the probe (M9 phase 2), with the real probe as the tool uid.

Run inside the disk worker container as root (needs pytsk3 / pyewf and the `dirs` fixture):
- the probe's `layout` on a blank raw image runs, reports `undetermined`, and its audit-hook
  counts are all zero;
- the probe imports nothing that opens sockets (no `socket` / `http` / `urllib.request` /
  `ssl` module loaded after its own imports);
- seccomp refuses AF_INET inside a stage (`socket.socket()` fails), and the audit hook counts
  the attempt.
"""

import json
import os
import sys

import pytest
from cyberlab_jobs.disk import StageStatus
from cyberlab_worker import sandbox

from disk_worker import stage
from disk_worker.budget import Budget
from disk_worker.probe.guard import FAMILIES
from tests.unit.phase2_helpers import limits

pytest.importorskip("pytsk3")
pytest.importorskip("pyewf")

NETWORK_MODULES = ("socket", "ssl", "http.client", "urllib.request", "asyncio")


def _budget() -> Budget:
    from datetime import UTC, datetime, timedelta

    return Budget(datetime.now(UTC) + timedelta(hours=4), limits())


def _write_args(dirs: sandbox.JobDirs, name: str, args: dict[str, object]) -> str:
    path = dirs.input / f"{name}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, "w") as f:
        json.dump(args, f)
    return str(path)


def test_the_layout_probe_runs_offline_on_a_blank_image(dirs: sandbox.JobDirs) -> None:
    image = dirs.input / "image.raw"
    with open(image, "wb") as f:
        f.truncate(8 * 1024**2)
    os.chmod(image, 0o444)
    sd = stage.fresh(dirs, "layout")
    args = {
        "out": str(sd.out),
        "image": {"format": "raw", "paths": [str(image)], "max_media": 2**40},
        "max_partitions": 128,
        "max_filesystems": 32,
        "deadline_s": 60,
    }
    argv = [
        sys.executable,
        "-I",
        "-s",
        "-B",
        "-m",
        "disk_worker.probe",
        "layout",
        _write_args(dirs, "layout", args),
    ]
    result = stage.run_stage(argv, sd, "layout", limits(), _budget())
    assert result.status == StageStatus.OK, result
    assert set(result.audit_counts) == set(FAMILIES)
    assert sum(result.audit_counts.values()) == 0
    rows = (sd.out / "partitions.jsonl").read_text().splitlines()
    assert [json.loads(r)["fs_status"] for r in rows] == ["undetermined"]


def test_the_probe_modules_import_no_network_module() -> None:
    code = (
        "import sys\n"
        "before = set(sys.modules)\n"
        "import disk_worker.probe.main, disk_worker.probe.layout, disk_worker.probe.walk\n"
        "import disk_worker.probe.collect, disk_worker.probe.verify, disk_worker.probe.image\n"
        "import pytsk3, pyewf\n"
        f"bad = [m for m in {NETWORK_MODULES!r} if m in sys.modules and m not in before]\n"
        "print(','.join(bad))\n"
    )
    import subprocess

    out = subprocess.run(  # noqa: S603 - fixed argv, test only
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == ""


def test_seccomp_refuses_inet_sockets_inside_a_stage(dirs: sandbox.JobDirs) -> None:
    sd = stage.fresh(dirs, "inet")
    script = (
        "import json, os, socket\n"
        "from disk_worker.probe.guard import GUARD, Refused\n"
        "errors = []\n"
        "try:\n"
        "    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    errors.append('created')\n"
        "except OSError as exc:\n"
        "    errors.append(f'seccomp:{exc.errno}')\n"
        "GUARD.install()\n"
        "try:\n"
        "    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "except Refused:\n"
        "    errors.append('hook')\n"
        "except OSError:\n"
        "    errors.append('seccomp')\n"
        f"fd = os.open({str(sd.out / 'status.json')!r},"
        " os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
        "os.write(fd, json.dumps({'status': 'ok', 'facts': {'errors': errors},"
        " 'audit': GUARD.snapshot()}).encode())\n"
    )
    result = stage.run_stage(
        [sys.executable, "-I", "-c", script], sd, "layout", limits(), _budget()
    )
    errors = result.facts["errors"]
    assert errors[0].startswith("seccomp:") and errors[1] == "hook"
    assert result.audit_counts["socket"] >= 1
