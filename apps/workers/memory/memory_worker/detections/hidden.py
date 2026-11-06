"""`heuristic:mem_hidden_process@1`: a process the pool scan finds but the active list does not.

Only a *running* one counts: no exit time and at least `MIN_THREADS` threads. Exited
processes and pool remnants also appear in psscan only, and are not "hidden". When the
`pslist` rows were capped the detector stays silent (absence is not evidence).
"""

from cyberlab_jobs.memory import MemoryPlugin

from memory_worker.detections.base import Context, Finding, hex_addr, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

MIN_THREADS = 1
CONFIDENCE = 0.7


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    if view.os != "windows" or MemoryPlugin.WINDOWS_PSLIST.value in view.truncated:
        return []
    listed = {
        (p.pid, p.create_time)
        for procs in ctx.by_pid.values()
        for p in procs
        if "pslist" in p.sources
    }
    out: list[Finding] = []
    for procs in ctx.by_pid.values():
        for proc in procs:
            if "pslist" in proc.sources or "psscan" not in proc.sources:
                continue
            if proc.exit_time is not None or (proc.threads or 0) < MIN_THREADS:
                continue
            # The same process merged under another offset (physical vs virtual) is listed.
            if (proc.pid, proc.create_time) in listed:
                continue
            offset = hex_addr(proc.offset) if proc.offset is not None else "unknown"
            out.append(
                Finding(
                    type="mem_hidden_process",
                    severity="medium",
                    confidence=CONFIDENCE,
                    values={
                        "pid": proc.pid,
                        "name": excerpt(proc.name, 64),
                        "threads": proc.threads,
                    },
                    key=f"{proc.pid}|{offset}",
                    pid=proc.pid,
                    refs=refs([f"pid:{proc.pid}", f"offset:{offset}"]),
                    attributes={"pid": proc.pid, "threads": proc.threads or 0, "offset": offset},
                )
            )
    return out
