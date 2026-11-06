"""Shared helpers of the M9 phase-3 unit tests (pure: no sandbox import, so they run anywhere
the contracts import; the replay tests that need the kit skip elsewhere)."""

import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cyberlab_jobs
from cyberlab_jobs.disk import (
    DISK_LINE_ADAPTER,
    FILE_FLAG_BITS,
    DiskArtifact,
    DiskFileRecord,
    DiskLimits,
)

from disk_worker.normalize.events import Source, write_sources
from tests.unit.phase2_helpers import limits

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures"
CONTRACT_FIXTURES = FIXTURES / "disk"
PSORT_FIXTURES = FIXTURES / "psort"
PSORT_EXTRA = FIXTURES / "psort_extra"
MIRROR = "/mirror/p1"
ALLOCATED = FILE_FLAG_BITS["allocated"]
DELETED = FILE_FLAG_BITS["deleted"]
WINDOWS_FIXTURES = (
    "winevtx.jsonl",
    "winreg.jsonl",
    "amcache.jsonl",
    "prefetch.jsonl",
    "lnk.jsonl",
    "mft.jsonl",
    "chrome_history.jsonl",
)
LINUX_FIXTURES = ("syslog.jsonl", "utmp.jsonl", "bash_history.jsonl")


def contract_files(name: str) -> list[DiskFileRecord]:
    """The file records of a phase-1 `disk.v1` fixture stream."""
    out = []
    for line in (CONTRACT_FIXTURES / name).read_text(encoding="utf-8").splitlines():
        record = DISK_LINE_ADAPTER.validate_json(line)
        if isinstance(record, DiskFileRecord):
            out.append(record)
    return out


def file(
    path: str,
    meta_addr: int,
    *,
    size: int | None = 1024,
    flags: int = ALLOCATED,
    mtime: str | None = "2026-10-01T08:00:00",
    magic: str | None = "other",
    stream: str | None = None,
    partition_index: int = 1,
    type_: str = "reg",
) -> DiskFileRecord:
    name = path.rsplit("/", 1)[-1]
    return DiskFileRecord(
        partition_index=partition_index,
        meta_addr=meta_addr,
        meta_seq=1,
        stream=stream,
        path=path,
        parent_addr=5,
        name=name,
        type=type_,  # type: ignore[arg-type]
        flags=flags,
        size=size,
        mtime=datetime.fromisoformat(mtime).replace(tzinfo=UTC) if mtime else None,
        magic=magic if flags & ALLOCATED else None,  # type: ignore[arg-type]
    )


def quota_limits(quotas: dict[DiskArtifact, int], **overrides: Any) -> DiskLimits:
    """Limits with only the given categories' quotas (summing to `max_events_stored`)."""
    full = {a.value: quotas.get(a, 0) for a in DiskArtifact}
    return limits(event_quotas=full, max_events_stored=sum(quotas.values()), **overrides)


def psort_line(
    rel: str,
    ts_us: int,
    *,
    data_type: str = "syslog:line",
    parser: str = "text/syslog",
    message: str = "line",
    **attrs: Any,
) -> dict[str, Any]:
    """One psort `json_line`-shaped row (the phase-1 fixture shape)."""
    return {
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "data_type": data_type,
        "date_time": {"__class_name__": "Filetime", "__type__": "DateTimeValues"},
        "display_name": f"OS:{MIRROR}/{rel}",
        "filename": f"{MIRROR}/{rel}",
        "message": message,
        "parser": parser,
        "pathspec": {"__type__": "PathSpec", "type_indicator": "OS", "location": f"{MIRROR}/{rel}"},
        "timestamp": ts_us,
        "timestamp_desc": "Content Modification Time",
        **attrs,
    }


def write_jsonl(path: Path, rows: Iterable[dict[str, Any] | str]) -> Path:
    body = "".join(
        (r if isinstance(r, str) else json.dumps(r, separators=(",", ":"))) + "\n" for r in rows
    )
    path.write_text(body, encoding="utf-8", newline="\n")
    return path


def collect_outputs(
    root: Path, partition_index: int, entries: Sequence[tuple[str, str, DiskArtifact, int]]
) -> tuple[Path, Path]:
    """`collected.jsonl` and root's collect arguments for (target, original path, artifact,
    meta_addr) entries, as phase 2 writes them."""
    items = [
        {
            "n": n,
            "meta_addr": meta,
            "meta_seq": 1,
            "stream": None,
            "path": path,
            "artifact": artifact.value,
            "max_bytes": 1024,
        }
        for n, (_, path, artifact, meta) in enumerate(entries)
    ]
    plan = root / f"collect-p{partition_index}.json"
    plan.write_text(json.dumps({"partition_index": partition_index, "items": items}))
    rows = [
        {
            "n": n,
            "status": "ok",
            "target": target,
            "meta_addr": meta,
            "meta_seq": 1,
            "stream": None,
            "path": path,
            "artifact": artifact.value,
            "size": 10,
        }
        for n, (target, path, artifact, meta) in enumerate(entries)
    ]
    collected = write_jsonl(root / f"collected-p{partition_index}.jsonl", rows)
    return collected, plan


def manifest(root: Path, sources: Sequence[Source], name: str = "sources.json") -> Path:
    return write_sources(root / name, "plaso", sources)


def source(
    events: Path,
    *,
    os: str = "linux",
    profile: str = "triage",
    partition_index: int = 1,
    collected: Path | None = None,
    plan: Path | None = None,
    replay: bool = False,
) -> Source:
    return Source(
        partition_index=partition_index,
        events=events,
        os=os,  # type: ignore[arg-type]
        profile=profile,  # type: ignore[arg-type]
        mirror_roots=(MIRROR,),
        collected=collected,
        plan=plan,
        replay=replay,
    )


__all__ = [
    "ALLOCATED",
    "CONTRACT_FIXTURES",
    "DELETED",
    "LINUX_FIXTURES",
    "MIRROR",
    "PSORT_EXTRA",
    "PSORT_FIXTURES",
    "WINDOWS_FIXTURES",
    "collect_outputs",
    "contract_files",
    "file",
    "manifest",
    "psort_line",
    "quota_limits",
    "source",
    "write_jsonl",
]
