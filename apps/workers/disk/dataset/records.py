"""Builders of synthetic `disk.v1` records (M9 phase 6 dataset and tests).

Everything here is made up: no disk image, no real host. Hashes are derived from the path (sha256
of a label), addresses are RFC 5737 / RFC 1918 documentation ranges, and every view built here
says so in its header (`HEADER_NOTE`).
"""

import hashlib
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cyberlab_jobs.disk import (
    FILE_FLAG_BITS,
    PROFILE_BUDGETS,
    DiskEventRecord,
    DiskFileRecord,
    DiskLimits,
    DiskPartitionRecord,
    DiskProfile,
    DiskView,
    ImageInfo,
    default_stage_limits,
    split_event_quotas,
)

from disk_worker.detections import evtx_fields

HEADER_NOTE = "synthetic scenario (generated records, not a real image, not real analysis)"
ALLOCATED = FILE_FLAG_BITS["allocated"]
DELETED = FILE_FLAG_BITS["deleted"]
NTFS_PARTITION = 2
EXT_PARTITION = 1
FAT_PARTITION = 3


def ts(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


def digests(label: str) -> dict[str, str]:
    raw = label.encode("utf-8", "surrogatepass")
    return {
        "md5": hashlib.md5(raw, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def limits(**caps: int) -> DiskLimits:
    budgets = dict(PROFILE_BUDGETS[DiskProfile.TRIAGE])
    stored = 250_000
    values: dict[str, Any] = {
        "max_image_bytes": 16 * 1024**3,
        "max_media_bytes": 2 * 1024**4,
        "timeout_s": 14_400,
        "stages": default_stage_limits(
            budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"]
        ),
        **budgets,
        "max_partitions": 128,
        "max_filesystems": 32,
        "max_files": 500_000,
        "max_streams_per_file": 16,
        "max_events_stored": stored,
        "max_events_read": 20_000_000,
        "max_findings": 5_000,
        "max_iocs": 20_000,
        "max_timeline": 5_000,
        "max_result_bytes": 256 * 1024**2,
        "event_quotas": split_event_quotas(stored),
    }
    values.update(caps)
    return DiskLimits.model_validate(values)


def partition(index: int, fs_type: str, os: str, start: int = 2048) -> DiskPartitionRecord:
    return DiskPartitionRecord(
        index=index,
        start_sector=start + index * 1_000_000,
        length_sectors=900_000,
        description=f"synthetic {fs_type}",
        fs_type=fs_type,
        fs_status="ok",
        os=os,
        os_name=f"{HEADER_NOTE} ({os})" if os != "none" else None,
    )


@dataclass
class FileMaker:
    """Allocates meta addresses per partition and builds file records (ext partitions have no
    sequence numbers)."""

    ext_partitions: frozenset[int] = frozenset({EXT_PARTITION})
    next_addr: dict[int, int] = field(default_factory=dict)

    def file(
        self,
        part: int,
        path: str,
        *,
        magic: str | None = "other",
        size: int | None = 4096,
        mtime: datetime | None = None,
        crtime: datetime | None = None,
        ftype: str = "reg",
        stream: str | None = None,
        deleted: bool = False,
        known: str | None = None,
        known_set: str | None = None,
        yara: Sequence[str] = (),
        time_basis: str = "utc",
        addr: int | None = None,
        hash_label: str | None = None,
    ) -> DiskFileRecord:
        if addr is None:
            addr = self.next_addr.get(part, 64)
            self.next_addr[part] = addr + 1
        name = path.rsplit("/", 1)[-1]
        ext = name.rsplit(".", 1)[-1][:32] if "." in name.strip(".") else None
        regular = ftype == "reg"
        hashed = regular and not deleted
        data: dict[str, Any] = {
            "partition_index": part,
            "meta_addr": addr,
            "meta_seq": None if part in self.ext_partitions else 1,
            "stream": stream,
            "path": path,
            "parent_addr": 5,
            "name": name,
            "ext": ext,
            "type": ftype,
            "flags": DELETED if deleted else ALLOCATED,
            "size": size if regular else None,
            "mtime": mtime,
            "atime": mtime,
            "ctime": mtime,
            "crtime": crtime or mtime,
            "time_basis": time_basis,
            "magic": (None if deleted else magic) if regular else None,
            "hash_status": "hashed" if hashed else ("not_allocated" if deleted else "not_regular"),
            "known": known,
            "known_set": known_set,
            "yara_rules": list(yara),
        }
        if hashed:
            data.update(digests(hash_label or f"{part}:{path}:{stream or ''}"))
        return DiskFileRecord.model_validate(data)


def event(
    ordinal: int,
    when: datetime,
    artifact: str,
    data_type: str,
    path: str,
    message: str,
    attributes: dict[str, Any] | None = None,
    *,
    parser: str = "synthetic",
    part: int = NTFS_PARTITION,
    ts_desc: str = "Creation Time",
) -> DiskEventRecord:
    return DiskEventRecord.model_validate(
        {
            "ordinal": ordinal,
            "ts": when,
            "ts_desc": ts_desc,
            "artifact": artifact,
            "parser": parser,
            "data_type": data_type,
            "partition_index": part,
            "path": path,
            "message": message[:2048],
            "attributes": attributes or {},
        }
    )


CHANNEL_PATHS = {
    "Security": "Windows/System32/winevt/Logs/Security.evtx",
    "System": "Windows/System32/winevt/Logs/System.evtx",
    "Application": "Windows/System32/winevt/Logs/Application.evtx",
}


def evtx(
    ordinal: int,
    when: datetime,
    provider: str,
    event_id: int,
    strings: Sequence[str],
    channel: str = "Security",
) -> DiskEventRecord:
    attributes: dict[str, Any] = {"event_identifier": event_id, "source_name": provider}
    attributes.update(evtx_fields.flatten_strings(list(strings)))
    return event(
        ordinal,
        when,
        "evtx",
        evtx_fields.DATA_TYPE,
        CHANNEL_PATHS[channel],
        f"[{event_id} / 0x{event_id:04x}] synthetic record",
        attributes,
        parser="winevtx",
    )


def view(
    partitions: Iterable[DiskPartitionRecord],
    files: Sequence[DiskFileRecord],
    events: Sequence[DiskEventRecord],
    *,
    profile: str = "triage",
    label: str = "scenario",
) -> DiskView:
    events_tuple = tuple(events)

    def stream() -> Iterator[DiskEventRecord]:
        return iter(events_tuple)

    return DiskView(
        profile=profile,  # type: ignore[arg-type]
        image=ImageInfo(
            format="raw",
            segments=1,
            media_size=64 * 1024**3,
            sector_size=512,
            media_sha256=hashlib.sha256(label.encode()).hexdigest(),
        ),
        partitions=tuple(partitions),
        files=tuple(files),
        events=stream,
    )


def mini(
    files: Sequence[DiskFileRecord] = (),
    events: Sequence[DiskEventRecord] = (),
    *,
    label: str = "unit",
) -> DiskView:
    """A small two-system view for unit tests: NTFS partition 2 (Windows), ext4 partition 1
    (Linux)."""
    return view(
        [partition(EXT_PARTITION, "ext4", "linux"), partition(NTFS_PARTITION, "ntfs", "windows")],
        files,
        events,
        label=label,
    )


# --- EVTX record shapes (string lists in template order; see evtx_fields.LAYOUTS) -----------


def logon_strings(account: str, logon_type: int, ip: str, workstation: str = "WKS-01") -> list[str]:
    """4624 v2 (27 strings)."""
    values = ["-"] * 27
    values[0], values[1], values[2], values[3] = "S-1-5-18", "WKS-01$", "CORP", "0x3e7"
    values[4], values[5], values[6], values[7] = "S-1-5-21-1-2-3-1104", account, "CORP", "0x1a2b3c"
    values[8], values[9], values[10], values[11] = str(logon_type), "NtLmSsp", "NTLM", workstation
    values[18], values[19] = ip, "50123" if ip not in ("-", "") else "-"
    return values


def failed_logon_strings(account: str, ip: str, logon_type: int = 3) -> list[str]:
    """4625 (21 strings)."""
    values = ["-"] * 21
    values[0], values[1], values[2], values[3] = "S-1-0-0", "-", "-", "0x0"
    values[4], values[5], values[6] = "S-1-0-0", account, "CORP"
    values[7], values[8], values[9] = "0xc000006d", "%%2313", "0xc000006a"
    values[10], values[11], values[12], values[13] = str(logon_type), "NtLmSsp", "NTLM", "ATTACKBOX"
    values[19], values[20] = ip, "51515"
    return values


def process_strings(image: str, command: str) -> list[str]:
    """4688 v2 (15 strings)."""
    values = ["-"] * 15
    values[0], values[1], values[2], values[3] = "S-1-5-21-1-2-3-1104", "alice", "CORP", "0x1a2b3c"
    values[4], values[5], values[6], values[7] = "0x1f40", image, "%%1936", "0x1d4c"
    values[8] = command
    values[13], values[14] = "C:\\Windows\\explorer.exe", "S-1-16-8192"
    return values


def user_created_strings(account: str) -> list[str]:
    """4720 (26 strings)."""
    values = ["-"] * 26
    values[0], values[1], values[2] = account, "WKS-01", "S-1-5-21-1-2-3-1201"
    values[3], values[4], values[5], values[6] = "S-1-5-21-1-2-3-500", "admin", "WKS-01", "0x5f5e1"
    values[8] = account
    return values


def user_enabled_strings(account: str) -> list[str]:
    """4722 (7 strings)."""
    return [
        account,
        "WKS-01",
        "S-1-5-21-1-2-3-1201",
        "S-1-5-21-1-2-3-500",
        "admin",
        "WKS-01",
        "0x5f5e1",
    ]


def group_member_strings(member: str, group: str) -> list[str]:
    """4728 / 4732 (10 strings)."""
    return [
        member,
        "S-1-5-21-1-2-3-1201",
        group,
        "Builtin",
        "S-1-5-32-544",
        "S-1-5-21-1-2-3-500",
        "admin",
        "WKS-01",
        "0x5f5e1",
        "-",
    ]


def service_strings(name: str, image: str) -> list[str]:
    """7045 (5 strings)."""
    return [name, image, "user mode service", "auto start", "LocalSystem"]


def log_cleared_strings(account: str = "admin") -> list[str]:
    """1102 (4 strings)."""
    return ["S-1-5-21-1-2-3-500", account, "WKS-01", "0x5f5e1"]


def channel_cleared_strings(channel: str, account: str = "admin") -> list[str]:
    """104 (4 strings)."""
    return [account, "WKS-01", channel, "-"]


def minutes(start: datetime, n: int, step: int) -> list[datetime]:
    return [start + timedelta(minutes=i * step) for i in range(n)]


__all__ = [
    "ALLOCATED",
    "EXT_PARTITION",
    "FAT_PARTITION",
    "HEADER_NOTE",
    "NTFS_PARTITION",
    "FileMaker",
    "channel_cleared_strings",
    "digests",
    "event",
    "evtx",
    "failed_logon_strings",
    "group_member_strings",
    "limits",
    "log_cleared_strings",
    "logon_strings",
    "mini",
    "minutes",
    "partition",
    "process_strings",
    "service_strings",
    "ts",
    "user_created_strings",
    "user_enabled_strings",
    "view",
]
