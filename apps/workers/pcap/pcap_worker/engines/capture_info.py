"""Capture metadata (capinfos) and protocol hierarchy (tshark), both run as the tool uid."""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cyberlab_jobs.results import ProtocolStat
from cyberlab_worker import sandbox
from cyberlab_worker.parsing import RECORD_ERRORS, clip, epoch, seconds

PHS_LINE = re.compile(
    r"^(?P<indent> *)(?P<proto>[A-Za-z0-9_.\-]+)\s+frames:(?P<f>\d+)\s+bytes:(?P<b>\d+)\s*$"
)
MAX_PHS_ROWS = 200


@dataclass(frozen=True)
class CaptureMeta:
    packets: int
    data_bytes: int
    first_ts: datetime | None
    last_ts: datetime | None
    duration_s: float | None
    link_type: str | None
    cut_short: bool = False


def _number(value: str | None) -> float | None:
    try:
        number = float(value) if value not in (None, "", "n/a") else None
    except RECORD_ERRORS:
        return None
    return number if number is not None and 0 <= number < 2**63 else None


def capinfos(capture: Path, dirs: sandbox.JobDirs, timeout_s: float) -> CaptureMeta:
    """Raises sandbox.ToolFailed if the capture is not readable at all.

    A capture cut short mid-packet (capture stopped abruptly) makes capinfos exit non-zero
    after printing its numbers: that is still analyzable and is reported as `cut_short`.
    """
    failure: sandbox.ToolFailed | None = None
    try:
        sandbox.run_tool(
            ["capinfos", "-T", "-M", "-S", str(capture)],
            dirs,
            timeout_s=timeout_s,
            stdout_name="capinfos.tsv",
        )
    except sandbox.ToolFailed as exc:
        failure = exc
    with sandbox.open_output(dirs, "capinfos.tsv") as f:
        lines = f.read(64 * 1024).decode("utf-8", "replace").splitlines()
    if len(lines) < 2 or (failure and "cut short" not in failure.stderr_tail):
        raise failure or sandbox.ToolFailed("capinfos", 0, "no output")
    row = dict(zip(lines[0].split("\t"), lines[1].split("\t"), strict=False))
    # Hostile/corrupt captures yield absurd values: anything out of range becomes unknown.
    duration = seconds(_number(row.get("Capture duration (seconds)")))
    return CaptureMeta(
        packets=int(_number(row.get("Number of packets")) or 0),
        data_bytes=int(_number(row.get("Data size (bytes)")) or 0),
        first_ts=epoch(_number(row.get("Start time"))),
        last_ts=epoch(_number(row.get("End time"))),
        duration_s=duration,
        link_type=clip(row.get("File encapsulation"), 128),
        cut_short=failure is not None,
    )


def protocol_hierarchy(
    capture: Path, dirs: sandbox.JobDirs, timeout_s: float
) -> list[ProtocolStat]:
    sandbox.run_tool(
        ["tshark", "-r", str(capture), "-n", "-q", "-z", "io,phs"],
        dirs,
        timeout_s=timeout_s,
        stdout_name="phs.txt",
    )
    with sandbox.open_output(dirs, "phs.txt") as f:
        text = f.read(1024 * 1024).decode("utf-8", "replace")
    stats: list[ProtocolStat] = []
    stack: list[str] = []
    for line in text.splitlines():
        match = PHS_LINE.match(line)
        if not match:
            continue
        depth = len(match["indent"]) // 2
        stack = [*stack[:depth], match["proto"]]
        try:
            frames, size = int(match["f"]), int(match["b"])
            stats.append(ProtocolStat(path=":".join(stack)[:255], frames=frames, bytes=size))
        except RECORD_ERRORS:  # absurd numbers from a hostile tool: skip the row
            continue
        if len(stats) >= MAX_PHS_ROWS:
            break
    return stats
