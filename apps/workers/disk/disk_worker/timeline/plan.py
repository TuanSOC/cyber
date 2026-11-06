"""The collect plan (M9 phase 3): one partition's walk listing → the files `collect` copies.

`build(files, os, profile)` (through the frozen `catalog.match`):
1. candidates: allocated regular files only (no directories, links, deleted or orphan entries,
   no named streams) whose path matches a catalog entry of the profile;
2. **never collected** (RT7): refused when **any** name of the inode (every hard-link path in
   the listing, a truncated path counting as unsafe) matches `NEVER_COLLECT_PATTERNS`, so a
   hard-linked `var/log/auth.log` whose inode is also `etc/shadow` is never copied; the
   analyzer re-checks with the job-wide name index before handing the plan to `collect`;
3. **compressed content** (RT11): a file whose magic class is `archive` or whose name says
   compressed is dropped, unless the entry expects rotated logs and the profile is `full`
   (a `.gz` / `.xz` name, <= 64 MiB): dfVFS would decompress it whatever its name;
4. per-file caps (the entry's, 512 MiB by default), then the category's file-count share
   (newest first by mtime), then the profile's total byte and file budgets in catalog
   priority order.

The target path inside the mirrored tree is decided by the collect probe from the original
path (phase 2's sanitizer, RT31); the plan carries the listed record unchanged.
"""

from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime

from cyberlab_jobs.disk import (
    PROFILE_BUDGETS,
    AnalysisProfile,
    DiskFileRecord,
    DiskLimits,
    DiskOs,
    DiskPartitionRecord,
    DiskProfile,
)

from disk_worker.normalize.records import build_index
from disk_worker.timeline.catalog import (
    ROTATED_MAX_BYTES,
    CollectPlan,
    Entry,
    classify,
    compressed_name,
    entries_for,
    rotated_name,
)

_OLDEST = datetime.min.replace(tzinfo=UTC)


def _candidate(r: DiskFileRecord) -> bool:
    return (
        r.type == "reg"
        and r.stream is None
        and r.has_flag("allocated")
        and not r.has_flag("deleted")
        and not r.has_flag("orphan")
    )


def _cap(entry: Entry, r: DiskFileRecord, profile: AnalysisProfile) -> int | str:
    """The byte cap of a matched file, or the drop reason."""
    compressed = r.magic == "archive" or compressed_name(r.name)
    if not compressed:
        return entry.max_bytes
    if profile == "full" and entry.rotated and rotated_name(r.name):
        return ROTATED_MAX_BYTES
    return "compressed"


def timeline_partitions(
    partitions: Sequence[DiskPartitionRecord], limits: DiskLimits
) -> list[DiskPartitionRecord]:
    """The OS partitions collected and run through the timeline: detected OS, opened file
    system, the largest first, at most `max_plaso_partitions` (phase 2's collect order)."""
    with_os = [p for p in partitions if p.os != "none" and p.fs_status == "ok"]
    with_os.sort(key=lambda p: -p.length_sectors)
    return with_os[: limits.max_plaso_partitions]


def build(files: Sequence[DiskFileRecord], os: DiskOs, profile: AnalysisProfile) -> CollectPlan:
    budgets = PROFILE_BUDGETS[DiskProfile(profile)]
    case_insensitive = os == "windows"
    index = build_index(files)
    plan = CollectPlan()
    dropped: Counter[str] = Counter()
    groups: dict[Entry, list[DiskFileRecord]] = {}
    seen: set[tuple[int, int]] = set()
    for r in files:
        if not _candidate(r):
            continue
        entry = classify(r.path, os, profile)
        if entry is None:
            continue
        key = (r.partition_index, r.meta_addr)
        if key in seen:
            continue  # a second matching name of the same inode: one copy is enough
        seen.add(key)
        if index.refused(r.partition_index, r.meta_addr, case_insensitive):
            plan.refused_never_collect += 1
            continue
        cap = _cap(entry, r, profile)
        if isinstance(cap, str):
            dropped[cap] += 1
            continue
        if r.size is None:
            dropped["size_unknown"] += 1
            continue
        if r.size > cap:
            dropped["too_large"] += 1
            continue
        groups.setdefault(entry, []).append(r)

    max_bytes = budgets["artifact_max_bytes"]
    max_files = budgets["artifact_max_files"]
    for entry in entries_for(os, profile):
        group = sorted(
            groups.get(entry, ()), key=lambda f: (f.mtime or _OLDEST, f.meta_addr), reverse=True
        )
        if len(group) > entry.max_files:
            dropped["category_cap"] += len(group) - entry.max_files
            group = group[: entry.max_files]
        for r in group:
            size = r.size or 0
            if len(plan.files) >= max_files:
                dropped["max_files"] += 1
            elif plan.bytes + size > max_bytes:
                dropped["budget"] += 1
            else:
                plan.files.append((entry.artifact, r))
                plan.bytes += size
    plan.dropped = dict(sorted(dropped.items()))
    return plan


__all__ = ["build", "timeline_partitions"]
