"""The decompile stage's child processes (M10 phase 2; RT4, RT15). Linux `/proc` only.

The JVM spawns Ghidra's native decompiler through `jspawnhelper` (a JVM `posix_spawn`, not a
Python audit event). After every (re)spawn and every function the probe:
- lists its children (`/proc/<pid>/stat` whose ppid is this process) and records each one's
  executable (`/proc/<pid>/exe`) under `child:<kind>` (`jspawnhelper`, `decompile`, or
  `other`); root fails the job on any `other` (this is **detection, not prevention**, RT15:
  nothing in the kernel restricts what the tool uid may `execve`; the boundary is the uid,
  seccomp and rlimits, all inherited by every exec);
- lowers a new decompiler child's `RLIMIT_AS` to `RE_DECOMPILER_AS` with `prlimit(2)` (same
  uid, lowering only: no capability needed). The child inherits the JVM's limit (heap + the
  headroom, above the 4 GiB cgroup), so a pathological function would otherwise grow it until
  the cgroup OOM killer picks the JVM and the whole stage is lost (RT4). A child that dies at
  its limit fails one function; the probe reopens the interface (at most 3 times).
"""

import os
from collections import Counter
from collections.abc import Callable
from pathlib import Path

PROC = Path("/proc")


def lower_address_space(pid: int, limit: int) -> None:
    """prlimit(2) on another process of this uid: RLIMIT_AS lowered to `limit` (never
    raised: an infinite or lower current value is kept as the bound)."""
    import resource

    infinity = resource.RLIM_INFINITY
    soft, hard = resource.prlimit(pid, resource.RLIMIT_AS)
    new_hard = limit if hard == infinity else min(hard, limit)
    new_soft = new_hard if soft == infinity else min(soft, new_hard)
    resource.prlimit(pid, resource.RLIMIT_AS, (new_soft, new_hard))


def child_pids(parent: int, proc: Path = PROC) -> list[int]:
    found = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        # pid (comm) state ppid ...: comm may hold spaces and ')' -> split after the last ')'
        fields = stat[stat.rfind(")") + 2 :].split()
        if len(fields) > 1 and fields[1] == str(parent):
            found.append(int(entry.name))
    return sorted(found)


def executable(pid: int, proc: Path = PROC) -> str | None:
    try:
        return os.readlink(proc / str(pid) / "exe")
    except OSError:
        return None


class Children:
    def __init__(
        self,
        *,
        decompiler: Path,
        spawn_helper: Path,
        as_limit: int,
        proc: Path = PROC,
        parent: int | None = None,
        lower: Callable[[int, int], None] = lower_address_space,
    ) -> None:
        self.decompiler = str(decompiler)
        self.spawn_helper = str(spawn_helper)
        self.as_limit = as_limit
        self.proc = proc
        self.parent = os.getpid() if parent is None else parent
        self.lower = lower
        self.seen: dict[int, str] = {}
        self.limited: set[int] = set()
        self.counts: Counter[str] = Counter()
        self.unexpected: list[str] = []
        self.limit_failures = 0

    def kind(self, exe: str) -> str:
        if exe == self.decompiler:
            return "decompile"
        if exe == self.spawn_helper:
            return "jspawnhelper"
        return "other"

    def scan(self) -> list[int]:
        """Record every current child; lower the limit of each new decompiler. Returns the
        live decompiler pids."""
        alive = []
        for pid in child_pids(self.parent, self.proc):
            exe = executable(pid, self.proc)
            if exe is None:
                continue
            kind = self.kind(exe)
            if self.seen.get(pid) != exe:
                self.seen[pid] = exe
                self.counts[f"child:{kind}"] += 1
                if kind == "other" and len(self.unexpected) < 32:
                    self.unexpected.append(exe[:255])
            if kind == "decompile":
                alive.append(pid)
                if pid not in self.limited:
                    self._lower(pid)
        return alive

    def _lower(self, pid: int) -> None:
        try:
            self.lower(pid, self.as_limit)
            self.limited.add(pid)
        except (OSError, ValueError):
            self.limit_failures += 1


__all__ = ["Children", "child_pids", "executable", "lower_address_space"]
