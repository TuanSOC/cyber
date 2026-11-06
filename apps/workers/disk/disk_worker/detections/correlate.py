"""`heuristic:disk_correlated_indicators@1` (medium): two or more *distinct* heuristics

- on the same file path (a listed file, a persistence target, a service image path), or
- within 10 minutes of each other on the image (one host), when that group is not already a
  same-path group (windows are anchored at the earliest finding and do not overlap).

One extra finding that refs the others (`finding:<id>`); it never raises their severity.
`signature:*` and `known_file:*` findings are not heuristics and do not count; a finding without
a usable time does not take part in the time windows.
"""

import uuid

from disk_worker.detections.base import (
    CORRELATION_WINDOW,
    Context,
    Finding,
    iso,
    joined,
    shared_ts,
    shown,
)

MIN_METHODS = 2
CONFIDENCE = 0.85
LABELS: dict[str, str] = {
    "heuristic:disk_exec_user_writable@1": "executable in a user-writable location",
    "heuristic:disk_double_extension@1": "deceptive file name",
    "heuristic:disk_extension_mismatch@1": "executable under a data extension",
    "heuristic:disk_ads_executable@1": "executable alternate data stream",
    "heuristic:disk_persistence@1": "autostart entry",
    "heuristic:disk_log_cleared@1": "log cleared",
    "heuristic:disk_service_installed@1": "service installed",
    "heuristic:disk_account_change@1": "account change",
    "heuristic:disk_remote_logon@1": "remote logon",
    "heuristic:disk_dual_use_execution@1": "dual-use tool or command",
}


def _counted(finding: Finding) -> bool:
    return finding.method in LABELS


def _methods(group: list[Finding]) -> list[str]:
    return sorted({LABELS[f.method] for f in group})


def _build(
    scope: str, subject: str, key: str, group: list[Finding], ids: dict[int, uuid.UUID]
) -> Finding:
    indicators = _methods(group)
    times = [t for f in group if (t := shared_ts(f.ts)) is not None]
    finding = Finding(
        type="disk_correlated_indicators",
        severity="medium",
        confidence=CONFIDENCE,
        values={
            "scope": scope,
            "subject": shown(subject),
            "count": len(indicators),
            "indicators": joined(indicators, 300),
        },
        subject=subject,
        key=key,
        ts=min(times) if times else None,
        extra_refs=[f"finding:{ids[id(f)]}" for f in group],
        attributes={"subject": shown(subject, 255), "indicators": len(indicators)},
    )
    for member in group:
        for event in member.events[:2]:
            finding.cite(event)
    return finding


def detect(findings: list[Finding], ids: dict[int, uuid.UUID], ctx: Context) -> list[Finding]:
    """`ids` maps `id(finding)` to its finding id (computed by the caller)."""
    heuristics = [f for f in findings if _counted(f)]
    by_path: dict[str, list[Finding]] = {}
    for finding in heuristics:
        for path in dict.fromkeys(finding.paths):
            if path not in by_path and not ctx.budget.take():
                break
            by_path.setdefault(path, []).append(finding)
    out: list[Finding] = []
    path_groups: list[set[int]] = []
    for path, group in sorted(by_path.items()):
        if len({f.method for f in group}) >= MIN_METHODS:
            out.append(_build("file path", path, f"path:{path}", group, ids))
            path_groups.append({id(f) for f in group})

    timed = [(t, f) for f in heuristics if (t := shared_ts(f.ts)) is not None]
    timed.sort(key=lambda item: (item[0], item[1].method, item[1].key))
    i = 0
    while i < len(timed):
        start = timed[i][0]
        j = i
        while j + 1 < len(timed) and timed[j + 1][0] - start <= CORRELATION_WINDOW:
            j += 1
        window = [f for _, f in timed[i : j + 1]]
        members = {id(f) for f in window}
        if len({f.method for f in window}) >= MIN_METHODS and not any(
            members <= group for group in path_groups
        ):
            subject = f"window:{iso(start)}"
            out.append(_build("10-minute window", subject, subject, window, ids))
        i = j + 1
    return out


__all__ = ["LABELS", "MIN_METHODS", "detect"]
