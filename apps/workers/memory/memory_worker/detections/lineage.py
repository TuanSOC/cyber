"""`heuristic:mem_process_lineage@1`: Windows core processes with an unexpected parent, and
more than one instance of a singleton core process.

A parent that is **missing** (not in the image, or its pid now belongs to a process created
later, i.e. reused) never fires: the session `smss.exe` instances that start `csrss.exe` and
`wininit.exe` exit normally (RT21). Only processes without an exit time are checked.
"""

from memory_worker.detections.base import Context, Finding, alive, joined, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

SYSTEM_PID = 4
# child (lower case) -> the parent names it may have.
EXPECTED_PARENTS: dict[str, frozenset[str]] = {
    # smss.exe: the master is a child of System; session instances are children of it.
    "smss.exe": frozenset({"system", "smss.exe"}),
    "wininit.exe": frozenset({"smss.exe"}),
    "csrss.exe": frozenset({"smss.exe"}),
    "services.exe": frozenset({"wininit.exe"}),
    "lsass.exe": frozenset({"wininit.exe"}),
    "svchost.exe": frozenset({"services.exe"}),
}
EXPECTED_TEXT: dict[str, str] = {
    "smss.exe": "System (pid 4)",
    "wininit.exe": "smss.exe",
    "csrss.exe": "smss.exe",
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
    "svchost.exe": "services.exe",
}
SINGLETONS = ("lsass.exe", "services.exe", "wininit.exe")
MAX_SINGLETON_COUNT = 1
CONFIDENCE_PARENT = 0.6
CONFIDENCE_COUNT = 0.7


def _parent_ok(child: str, parent_name: str, parent_pid: int) -> bool:
    allowed = EXPECTED_PARENTS[child]
    if child == "smss.exe" and parent_name == "system":
        return parent_pid == SYSTEM_PID
    return parent_name in allowed


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    if view.os != "windows":
        return []
    out: list[Finding] = []
    running: dict[str, list[int]] = {name: [] for name in SINGLETONS}
    for procs in ctx.by_pid.values():
        for proc in procs:
            if not alive(proc):
                continue
            name = proc.name.lower()
            if name in running:
                running[name].append(proc.pid)
            if name not in EXPECTED_PARENTS:
                continue
            parent = ctx.parent_of(proc)
            if parent is None:
                continue  # a missing parent never fires (RT21)
            if _parent_ok(name, parent.name.lower(), parent.pid):
                continue
            out.append(
                Finding(
                    type="mem_process_lineage",
                    severity="medium",
                    confidence=CONFIDENCE_PARENT,
                    values={
                        "pid": proc.pid,
                        "name": excerpt(proc.name, 64),
                        "ppid": parent.pid,
                        "parent": excerpt(parent.name, 64),
                        "expected": EXPECTED_TEXT[name],
                    },
                    key=f"{proc.pid}|{parent.pid}",
                    pid=proc.pid,
                    refs=refs([f"pid:{proc.pid}", f"pid:{parent.pid}"]),
                    attributes={"pid": proc.pid, "ppid": parent.pid, "parent": parent.name[:64]},
                )
            )
    for name, pids in running.items():
        if len(pids) <= MAX_SINGLETON_COUNT:
            continue
        pids.sort()
        out.append(
            Finding(
                type="mem_core_process_count",
                severity="medium",
                confidence=CONFIDENCE_COUNT,
                values={
                    "name": name,
                    "count": len(pids),
                    "pids": joined([str(p) for p in pids], 200),
                },
                key=name,
                refs=refs([f"pid:{p}" for p in pids]),
                attributes={"process": name, "count": len(pids)},
            )
        )
    return out
