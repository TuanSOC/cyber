"""Fuzz-lite of the artifact timeline (M9 phase 13; RT10, RT11): 10 hostile mirrored trees.

    docker compose --profile test run --rm --no-deps -e DISK_FUZZ=1 disk-worker-test \
        pytest -q -p no:cacheprovider tests/fuzz/test_fuzz_timeline.py

Each tree is laid out exactly as phase 2's `collect` stage leaves it (`collect-p1-out/artifacts/
p1/...`, `collected.jsonl`, root's `input/collect-p1.json`) and sealed, then the real Plaso
runner (`timeline.run_timeline`: log2timeline and the event export, both through
`stage.run_stage`) and the normalizer read it, as in `tests/engine/test_plaso_engine.py`. The
collect stage's own per-file caps are bypassed on purpose: the trees reach Plaso as written.

Trees: a truncated syslog, a corrupt syslog (NULs, invalid UTF-8, a 1 MiB line), a 200 MiB
single-line log (sparse: it costs no tmpfs), a gzip bomb (1 GiB of zeros) in a `full` run, a
gzip stream named `auth.log` in `triage` (skipped: no event, RT11), a malformed wtmp, hostile
names (newline, `|`, RTLO, 255-byte UTF-8, invalid UTF-8), a hostile bash history, a dpkg log
with impossible dates, and a tree of empty files under a ~3 600-byte path.

Every run must end cleanly: both stages report a known status (a per-stage error is fine), the
normalizer reads whatever was exported without raising, no tool process survives a stage and
the audit hooks count nothing. Outcomes go to the fuzz report (`timeline` group).
"""

import gzip
import json
import os
import random
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cyberlab_jobs.disk import DiskArtifact, DiskPartitionRecord
from cyberlab_worker import sandbox

from disk_worker import stage, timeline
from disk_worker.budget import Budget
from disk_worker.normalize.events import EventSource
from tests.fuzz import harness

if os.environ.get("DISK_FUZZ") != "1":
    pytest.skip("heavy: DISK_FUZZ=1 in disk-worker-test, alone", allow_module_level=True)
if not hasattr(os, "geteuid") or os.geteuid() != 0:
    pytest.skip("runs as root inside the disk worker image", allow_module_level=True)
if not Path("/opt/plaso/bin/python").exists():
    pytest.skip("/opt/plaso (the disk worker image) not present", allow_module_level=True)

MIB = 1024**2
MTIME = datetime(2026, 10, 2, 12, 0, tzinfo=UTC).timestamp()
Writer = Callable[[Path], None]
A = DiskArtifact


def text(value: str | bytes) -> Writer:
    data = value.encode("utf-8", "surrogateescape") if isinstance(value, str) else value

    def write(path: Path) -> None:
        path.write_bytes(data)

    return write


def sparse_line(size: int, prefix: bytes) -> Writer:
    """A `size`-byte file that is one line: the prefix, then a hole (NULs, no newline)."""

    def write(path: Path) -> None:
        with path.open("wb") as f:
            f.write(prefix)
            f.truncate(size)

    return write


def gzip_bomb(uncompressed: int) -> Writer:
    def write(path: Path) -> None:
        zeros = bytes(MIB)
        with gzip.GzipFile(path, "wb", compresslevel=9, mtime=0) as f:
            for _ in range(uncompressed // MIB):
                f.write(zeros)

    return write


def _random_bytes(seed: str, size: int) -> bytes:
    return random.Random(seed).randbytes(size)


GOOD_SYSLOG = "Oct  1 10:00:00 srv-01 CRON[901]: (root) CMD (/tmp/.x/miner)\n"
DEEP = "/".join(f"d{i:02d}".ljust(59, "x") for i in range(60))  # ~3 600 bytes

# name -> (profile, {relative path: (artifact, writer)}, paths that must give no event)
TREES: dict[str, tuple[str, dict[str, tuple[DiskArtifact, Writer]], tuple[str, ...]]] = {
    "truncated_syslog": (
        "triage",
        {
            "var/log/syslog": (A.SYSLOG, text(GOOD_SYSLOG * 50 + "Oct  1 10:0")),
            "var/log/auth.log": (A.AUTH_LOG, text("Oct  1 10:01:00 srv-01 sshd[811]: Accep")),
        },
        (),
    ),
    "corrupt_syslog": (
        "triage",
        {
            "var/log/syslog": (
                A.SYSLOG,
                text(
                    GOOD_SYSLOG.encode()
                    + b"\x00" * 4096
                    + b"\xff\xfe\xc3\x28 invalid utf-8\n"
                    + b"Oct  1 10:00:01 h x: "
                    + b"A" * MIB
                    + b"\n"
                    + _random_bytes("corrupt_syslog", 256 * 1024)
                ),
            ),
        },
        (),
    ),
    "single_line_200mib": (
        "triage",
        {
            "var/log/syslog": (
                A.SYSLOG,
                sparse_line(200 * MIB, b"Oct  1 10:00:00 srv-01 kernel: "),
            ),
        },
        (),
    ),
    "gzip_bomb_full": (
        "full",
        {
            "var/log/syslog": (A.SYSLOG, text(GOOD_SYSLOG)),
            "var/log/syslog.2.gz": (A.SYSLOG, gzip_bomb(1024 * MIB)),
        },
        (),
    ),
    "gzip_auth_log_triage": (
        "triage",
        {
            "var/log/syslog": (A.SYSLOG, text(GOOD_SYSLOG)),
            "var/log/auth.log": (
                A.AUTH_LOG,
                text(
                    gzip.compress(
                        b"Oct  1 10:02:00 srv-01 sshd[812]: Accepted password for root from "
                        b"198.51.100.7 port 50122 ssh2\n",
                        mtime=0,
                    )
                ),
            ),
        },
        ("var/log/auth.log",),
    ),
    "malformed_wtmp": (
        "triage",
        {
            "var/log/wtmp": (A.UTMP, text(_random_bytes("wtmp", 384 * 3 + 17))),
            "var/log/btmp": (A.UTMP, text(b"\xff" * 384)),  # every field at its maximum
        },
        (),
    ),
    "hostile_names": (
        "triage",
        {
            "var/log/auth.log\nOct  1 10:00:00 fake": (A.AUTH_LOG, text(GOOD_SYSLOG)),
            "var/log/sys|log": (A.SYSLOG, text(GOOD_SYSLOG)),
            "var/log/‮gol.syslog": (A.SYSLOG, text(GOOD_SYSLOG)),
            "var/log/" + "€" * 85: (A.SYSLOG, text(GOOD_SYSLOG)),
            "var/log/bad\udcffname.log": (A.SYSLOG, text(GOOD_SYSLOG)),
        },
        (),
    ),
    "hostile_bash_history": (
        "triage",
        {
            "root/.bash_history": (
                A.SHELL_HISTORY,
                text(
                    "#99999999999999999999\nid\n#-5\nwhoami\n#1790000660\n"
                    + "\x1b[31m\x1b]0;title\x07"
                    + "x" * MIB
                    + "\n"
                ),
            ),
        },
        (),
    ),
    "dpkg_impossible_dates": (
        "triage",
        {
            "var/log/dpkg.log": (
                A.PACKAGES,
                text(
                    "9999-99-99 99:99:99 status installed x:amd64 1\n"
                    "0000-00-00 00:00:00 status installed y:amd64 1\n"
                    "1969-12-31 23:59:59 status installed z:amd64 1\n"
                    "2026-10-01 10:04:00 status installed netcat-openbsd:amd64 1.226-1\n"
                ),
            ),
        },
        (),
    ),
    "empty_and_deep": (
        "triage",
        {
            "var/log/syslog": (A.SYSLOG, text(b"")),
            "var/log/auth.log": (A.AUTH_LOG, text(b"")),
            "var/log/wtmp": (A.UTMP, text(b"")),
            "etc/timezone": (A.PREPROCESS, text(b"Not/AZone\x00\n")),
            f"var/log/{DEEP}/syslog": (A.SYSLOG, text(GOOD_SYSLOG)),
        },
        (),
    ),
}


@pytest.fixture
def job_dirs() -> Iterator[sandbox.JobDirs]:
    jobs = harness.FUZZ_ROOT / "timeline-jobs"
    jobs.mkdir(parents=True, exist_ok=True)
    dirs = sandbox.prepare(jobs, f"fuzz-{uuid.uuid4()}")
    yield dirs
    sandbox.cleanup(dirs)


def _seal_tree(dirs: sandbox.JobDirs, tree: dict[str, tuple[DiskArtifact, Writer]]) -> None:
    """Phase 2's collect output for partition 1, sealed (the engine test's layout)."""
    sd = stage.fresh(dirs, stage.collect_name(1))
    mirror = sd.out / "artifacts" / "p1"
    items, rows = [], []
    for n, (rel, (artifact, write)) in enumerate(sorted(tree.items())):
        path = mirror / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        write(path)
        os.utime(path, (MTIME, MTIME))
        size = path.stat().st_size
        item = {
            "n": n,
            "meta_addr": 100 + n,
            "meta_seq": 1,
            "stream": None,
            "path": rel,
            "artifact": artifact.value,
            "max_bytes": max(size, 1),
        }
        items.append(item)
        row = {k: v for k, v in item.items() if k != "max_bytes"}
        rows.append({**row, "status": "ok", "target": rel, "size": size})
    manifest = "".join(json.dumps(r, ensure_ascii=True) + "\n" for r in rows)
    (sd.out / "collected.jsonl").write_text(manifest, encoding="ascii")
    (dirs.input / f"{stage.collect_name(1)}.json").write_text(
        json.dumps({"partition_index": 1, "items": items}, ensure_ascii=True), encoding="ascii"
    )
    stage.seal(sd.out)


@pytest.mark.parametrize("name", sorted(TREES))
def test_a_hostile_tree_ends_cleanly(name: str, job_dirs: sandbox.JobDirs) -> None:
    profile, tree, silent = TREES[name]
    _seal_tree(job_dirs, tree)
    part = DiskPartitionRecord(
        index=1,
        start_sector=2048,
        length_sectors=1_000_000,
        fs_type="ext4",
        fs_status="ok",
        os="linux",
    )
    lim = harness.limits(profile)
    budget = Budget(datetime.now(UTC) + harness.DEADLINE, lim)
    run = harness.Run(f"timeline/{name}")
    real_run_stage = stage.run_stage

    def recording(*args: object) -> stage.StageResult:
        result = real_run_stage(*args)  # type: ignore[arg-type]
        run.stages.append(result)
        harness.check_stage(run, result)
        return result

    events = 0
    paths: set[str] = set()
    with harness.patched(stage, "run_stage", recording):
        try:
            out = timeline.run_timeline(job_dirs, [part], profile, lim, budget)
        except Exception as exc:  # noqa: BLE001 - recorded as the unclean outcome
            run.problems.append(f"run_timeline raised {type(exc).__name__}: {exc}"[:300])
            out = None
    if out is not None:
        run.outcome = ",".join(f"{s.stage}:{s.status.value}" for s in out.stages) or "no_stage"
        if out.events_path is not None:
            try:
                for event in EventSource(out.events_path, lim).events():
                    events += 1
                    if event.path is not None:
                        paths.add(event.path)
            except Exception as exc:  # noqa: BLE001
                run.problems.append(f"normalizer raised {type(exc).__name__}: {exc}"[:300])
    if sandbox.tool_pids():
        run.problems.append("tool processes alive after the timeline")
    leaked = sorted(p for p in silent if p in paths)
    if leaked:
        run.problems.append(f"events from paths that must stay silent: {leaked}")
    harness.record("timeline", run, profile=profile, events=events)
    assert run.clean, run.problems
