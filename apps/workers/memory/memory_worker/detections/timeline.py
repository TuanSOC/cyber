"""Timeline of a memory run (RT9 caps).

The image system time, process creates and exits (at most `MAX_PROCESS_EVENTS`, oldest
first), connection creation times (at most `MAX_CONNECTION_EVENTS`, oldest first) and one
event per finding; at most `limits.max_timeline` overall. When something is cut, the
`timeline` truncation flag is set. Priority when the overall cap bites: system time,
findings, processes, connections. Titles quote only names and addresses, masked anyway.
"""

from datetime import datetime
from typing import Literal

from cyberlab_jobs.memory import MemoryTimelineEvent
from cyberlab_jobs.results import FindingRecord

from memory_worker.detections.base import Context
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

MAX_PROCESS_EVENTS = 2_000
MAX_CONNECTION_EVENTS = 2_000
ProcessEvent = Literal["process_start", "process_exit"]


def _pid(finding: FindingRecord) -> int | None:
    value = finding.attributes.get("pid")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _process_events(ctx: Context) -> list[MemoryTimelineEvent]:
    raw: list[tuple[datetime, ProcessEvent, int, str]] = []
    for procs in ctx.by_pid.values():
        for proc in procs:
            name = excerpt(proc.name, 64)
            if proc.create_time is not None:
                raw.append((proc.create_time, "process_start", proc.pid, f"{name} started"))
            if proc.exit_time is not None:
                raw.append((proc.exit_time, "process_exit", proc.pid, f"{name} exited"))
    raw.sort()
    return [
        MemoryTimelineEvent(
            ts=ts, event=event, title=f"{title} (pid {pid})"[:255], pid=pid, ref=str(pid)
        )
        for ts, event, pid, title in raw
    ]


def _connection_events(view: MemoryView, ctx: Context) -> list[MemoryTimelineEvent]:
    events: list[MemoryTimelineEvent] = []
    for conn in view.connections:
        if conn.created is None:
            continue
        remote = f"{conn.remote_addr}:{conn.remote_port}" if conn.remote_addr else "no peer"
        owner = excerpt(conn.owner or ctx.name_of(conn.pid) or "unknown", 64)
        title = f"{conn.proto.upper()} connection to {remote} ({owner})"
        events.append(
            MemoryTimelineEvent(
                ts=conn.created,
                event="connection",
                title=title[:255],
                pid=conn.pid,
                remote_ip=conn.remote_addr,
                ref=f"0x{conn.offset:x}" if conn.offset is not None else None,
            )
        )
    events.sort(key=lambda e: (e.ts, e.title))
    return events


def build(
    view: MemoryView, ctx: Context, findings: list[FindingRecord], limit: int
) -> tuple[list[MemoryTimelineEvent], bool]:
    head: list[MemoryTimelineEvent] = []
    if view.image.system_time is not None:
        head.append(
            MemoryTimelineEvent(
                ts=view.image.system_time, event="system_time", title="Image system time"
            )
        )
    head += [
        MemoryTimelineEvent(
            ts=f.ts,
            event="finding",
            title=f.title,
            severity=f.severity,
            ref=str(f.finding_id),
            pid=_pid(f),
        )
        for f in findings
    ]
    processes = _process_events(ctx)
    connections = _connection_events(view, ctx)
    truncated = len(processes) > MAX_PROCESS_EVENTS or len(connections) > MAX_CONNECTION_EVENTS
    ordered = [*head, *processes[:MAX_PROCESS_EVENTS], *connections[:MAX_CONNECTION_EVENTS]]
    if len(ordered) > limit:
        truncated = True
        ordered = ordered[:limit]
    ordered.sort(key=lambda e: (e.ts, e.event, e.ref or ""))
    return ordered, truncated
