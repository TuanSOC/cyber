"""The synthetic Linux scenarios (M8 phase 4). Benign and hand-written: plausible process trees
of a small server, nothing taken from a real machine.

- `linux_benign`: about 30 processes (kernel threads under kthreadd, systemd and its services,
  an SSH session, nginx and PostgreSQL workers);
- `linux_orphan_and_dup`: the benign tree plus a process whose parent exited (its ppid names
  no listed process) and a second process named `systemd` (a user manager, uid 1000);
- `linux_wide`: 2 000 processes (the row-cap and tree tests);
- `symbols_missing`: `linux_benign` with a banner no symbol store has an ISF for.
"""

from __future__ import annotations

from collections.abc import Callable

from samples.memgen.image import Proc, Scenario
from samples.memgen.kernel import UNKNOWN_BANNER

EXITED_PARENT = 4242


def _kernel_threads() -> list[Proc]:
    kt = [Proc(2, 0, "kthreadd", kthread=True)]
    names = ["rcu_gp", "rcu_par_gp", "kworker/0:0H", "mm_percpu_wq", "ksoftirqd/0",
             "rcu_preempt", "migration/0", "cpuhp/0", "kdevtmpfs", "kauditd", "khungtaskd",
             "oom_reaper", "kswapd0"]  # fmt: skip
    kt += [Proc(3 + i, 2, name, kthread=True) for i, name in enumerate(names)]
    return kt


def linux_benign() -> Scenario:
    procs = [
        Proc(1, 0, "systemd", args=("/sbin/init", "splash"), start_s=1),
        *_kernel_threads(),
        Proc(310, 1, "systemd-journal", args=("/lib/systemd/systemd-journald",), start_s=3),
        Proc(345, 1, "systemd-udevd", args=("/lib/systemd/systemd-udevd",), start_s=3),
        Proc(512, 1, "systemd-network", uid=100, gid=102,
             args=("/lib/systemd/systemd-networkd",), start_s=4),
        Proc(530, 1, "dbus-daemon", uid=101, gid=103,
             args=("/usr/bin/dbus-daemon", "--system", "--address=systemd:",
                   "--nofork", "--nopidfile", "--systemd-activation"), start_s=4),
        Proc(541, 1, "cron", args=("/usr/sbin/cron", "-f"), start_s=4),
        Proc(560, 1, "rsyslogd", uid=104, gid=110,
             args=("/usr/sbin/rsyslogd", "-n", "-iNONE"), start_s=4),
        Proc(602, 1, "sshd", args=("sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",),
             start_s=5),
        Proc(640, 1, "agetty", args=("/sbin/agetty", "-o", "-p -- \\u", "--noclear", "tty1",
                                     "linux"), start_s=5),
        Proc(700, 1, "nginx", args=("nginx: master process /usr/sbin/nginx", "-g",
                                    "daemon on; master_process on;"), start_s=6),
        Proc(701, 700, "nginx", uid=33, gid=33, args=("nginx: worker process",), start_s=6),
        Proc(702, 700, "nginx", uid=33, gid=33, args=("nginx: worker process",), start_s=6),
        Proc(810, 1, "postgres", uid=999, gid=999,
             args=("/usr/lib/postgresql/16/bin/postgres", "-D",
                   "/var/lib/postgresql/16/main"), start_s=7),
        Proc(815, 810, "postgres", uid=999, gid=999,
             args=("postgres: 16/main: checkpointer",), start_s=7),
        Proc(816, 810, "postgres", uid=999, gid=999,
             args=("postgres: 16/main: walwriter",), start_s=7),
        Proc(1200, 602, "sshd", args=("sshd: admin [priv]",), start_s=3600),
        Proc(1205, 1200, "sshd", uid=1000, gid=1000, args=("sshd: admin@pts/0",),
             start_s=3600),
        Proc(1206, 1205, "bash", uid=1000, gid=1000, args=("-bash",), start_s=3601),
        Proc(1300, 1206, "top", uid=1000, gid=1000, args=("top",), start_s=3700),
    ]  # fmt: skip
    return Scenario("linux_benign", tuple(procs), seed=1)


def linux_orphan_and_dup() -> Scenario:
    base = linux_benign()
    extra = (
        # Its parent (a shell that ran a backup script) exited: ppid 4242 is not listed.
        Proc(4300, EXITED_PARENT, "backup.sh", uid=0,
             args=("/bin/sh", "/usr/local/bin/backup.sh", "--nightly"), start_s=7200),
        Proc(4301, 4300, "tar", uid=0, args=("tar", "-czf", "/var/backups/etc.tgz", "/etc"),
             start_s=7201),
        # A second `systemd`: the per-user manager of uid 1000.
        Proc(1190, 1, "systemd", uid=1000, gid=1000, args=("/lib/systemd/systemd", "--user"),
             start_s=3599),
    )  # fmt: skip
    return Scenario("linux_orphan_and_dup", base.procs + extra, seed=2)


WIDE_COUNT = 2000


def linux_wide() -> Scenario:
    procs = [Proc(1, 0, "systemd", args=("/sbin/init",), start_s=1),
             Proc(2, 0, "kthreadd", kthread=True)]  # fmt: skip
    # A build farm: 40 job runners, each with 49 short-lived compiler processes.
    pid = 100
    for runner in range(40):
        runner_pid = pid
        procs.append(Proc(runner_pid, 1, "runner", uid=1001, gid=1001,
                          args=("/opt/ci/runner", f"--slot={runner}"), start_s=10))  # fmt: skip
        pid += 1
        for job in range(49):
            procs.append(Proc(pid, runner_pid, "cc1", uid=1001, gid=1001,
                              args=("cc1", f"unit{runner}_{job}.c", "-O2"),
                              start_s=600 + job))  # fmt: skip
            pid += 1
    procs += [Proc(9000 + i, 2, f"kworker/u8:{i}", kthread=True)
              for i in range(WIDE_COUNT - len(procs))]  # fmt: skip
    return Scenario("linux_wide", tuple(procs[:WIDE_COUNT]), seed=3)


def symbols_missing() -> Scenario:
    base = linux_benign()
    return Scenario("symbols_missing", base.procs, banner=UNKNOWN_BANNER, seed=base.seed)


SCENARIOS: dict[str, Callable[[], Scenario]] = {
    "linux_benign": linux_benign,
    "linux_orphan_and_dup": linux_orphan_and_dup,
    "linux_wide": linux_wide,
    "symbols_missing": symbols_missing,
}


def scenario(name: str) -> Scenario:
    return SCENARIOS[name]()


__all__ = ["EXITED_PARENT", "SCENARIOS", "WIDE_COUNT", "scenario"]
