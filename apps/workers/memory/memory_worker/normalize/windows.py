"""Windows plugin rows -> `memory.v1` records (root side).

- `windows.pslist` + `windows.psscan` -> processes, merged by (pid, offset, create time) with
  `sources`; a psscan-only entry whose (pid, create time) matches exactly one pslist entry
  under another offset is the same process and merges into it. `windows.cmdline` (`cmdline`)
  and the first `windows.dlllist` module of a pid (its main image, `image_path`) are joined
  by pid onto the active-list entries (or onto the only entry of that pid).
- `windows.dlllist` (every module after the main image) -> `module` {name, path, base, size,
  load_count, load_time}.
- `windows.netscan` -> connections. `windows.malware.malfind` -> injections (`has_pe` from
  the hex head, `private` from PrivateMemory).
- `windows.svcscan` -> `service` {name, display, state, start, type, binary, dll, order}
  (`binary` falls back to the registry value); phase 3's service-path detector reads
  name / state / binary / type.
- `windows.registry.hivelist` -> `hive` {path, offset}; `windows.registry.userassist` value
  rows -> `userassist` {hive, path, key, count, focus_count, time_focused, last_updated}.
- `windows.malware.ldrmodules` rows missing from at least one loader list -> `ldr_unlinked`
  {base, in_load, in_init, in_mem, path} (phase 3's unlinked-module detector fires when all
  three are false).
- `windows.info` -> the image's `nt_build` and `system_time`.

Address attributes are ints while they fit the bigint column, else `0x...` text.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cyberlab_jobs.memory import (
    MemoryConnectionRecord,
    MemoryInjectionRecord,
    MemoryPlugin,
    MemoryProcessRecord,
)

from memory_worker.normalize import models as m
from memory_worker.normalize.common import ATTRIBUTE_TEXT, Builder, addr
from memory_worker.normalize.values import (
    count,
    has_pe,
    hex_head,
    ip,
    iso,
    port,
    text,
    timestamp,
    u32,
    u64,
)

P = MemoryPlugin
PROTOCOLS = {"TCPV4": "tcp", "TCPV6": "tcp", "UDPV4": "udp", "UDPV6": "udp"}
BUILD = re.compile(r"^(\d{3,6})\b")
Rows = Mapping[MemoryPlugin, Iterable[Mapping[str, Any]]]


@dataclass
class _Proc:
    pid: int
    offset: int | None
    create_time: datetime | None
    fields: dict[str, Any]
    sources: list[str] = field(default_factory=list)


def _proc_fields(row: m.WinProcess) -> dict[str, Any]:
    return {
        "ppid": u32(row.ppid),
        "name": text(row.name, 64) or "",
        "exit_time": timestamp(row.exit_time),
        "threads": count(row.threads),
        "handles": count(row.handles),
        "session_id": u32(row.session_id),
        "wow64": row.wow64,
    }


def _merge_processes(pslist: list[m.WinProcess], psscan: list[m.WinProcess]) -> list[_Proc]:
    procs: dict[tuple[int, int | None, datetime | None], _Proc] = {}
    for source, rows in (("pslist", pslist), ("psscan", psscan)):
        for row in rows:
            pid = u32(row.pid)
            if pid is None:
                continue
            offset, created = u64(row.offset), timestamp(row.create_time)
            key = (pid, offset, created)
            proc = procs.get(key)
            if proc is None:
                proc = procs[key] = _Proc(pid, offset, created, _proc_fields(row))
            else:
                for name, value in _proc_fields(row).items():
                    if proc.fields.get(name) in (None, ""):
                        proc.fields[name] = value
            if source not in proc.sources:
                proc.sources.append(source)
    listed: dict[tuple[int, datetime | None], list[_Proc]] = {}
    for proc in procs.values():
        if "pslist" in proc.sources:
            listed.setdefault((proc.pid, proc.create_time), []).append(proc)
    merged: list[_Proc] = []
    for proc in procs.values():
        twins = listed.get((proc.pid, proc.create_time), [])
        if proc.sources == ["psscan"] and proc.create_time is not None and len(twins) == 1:
            twins[0].sources.append("psscan")
            continue
        merged.append(proc)
    return merged


def _by_pid(values: list[tuple[int | None, str | None]]) -> dict[int, str]:
    out: dict[int, str] = {}
    for pid, value in values:
        if pid is not None and value is not None and pid not in out:
            out[pid] = value
    return out


def _info(b: Builder, rows: list[m.WinInfo]) -> None:
    values = {r.variable: r.value for r in rows if r.variable and r.value}
    lab = values.get("NTBuildLab") or ""
    build = BUILD.match(lab)
    if build is None:
        minor = (values.get("Major/Minor") or "").partition(".")[2]
        build = BUILD.match(minor)
    b.out.info.nt_build = build.group(1) if build else None
    b.out.info.system_time = timestamp(values.get("SystemTime"))


def _processes(b: Builder, rows: Rows) -> None:
    pslist = b.parse(P.WINDOWS_PSLIST, rows.get(P.WINDOWS_PSLIST, ()), m.WinProcess)
    psscan = b.parse(P.WINDOWS_PSSCAN, rows.get(P.WINDOWS_PSSCAN, ()), m.WinProcess)
    cmd = b.parse(P.WINDOWS_CMDLINE, rows.get(P.WINDOWS_CMDLINE, ()), m.WinCmdline)
    dlls = b.parse(P.WINDOWS_DLLLIST, rows.get(P.WINDOWS_DLLLIST, ()), m.WinDll)
    cmdlines = _by_pid([(u32(r.pid), text(r.args, 4096)) for r in cmd])
    first: dict[int, m.WinDll] = {}
    for dll in dlls:
        pid = u32(dll.pid)
        if pid is not None and pid not in first:
            first[pid] = dll
    images = {pid: text(d.path, 1024) for pid, d in first.items()}
    merged = _merge_processes(pslist, psscan)
    per_pid: dict[int, int] = {}
    for proc in merged:
        per_pid[proc.pid] = per_pid.get(proc.pid, 0) + 1
    for proc in merged:
        joined = "pslist" in proc.sources or per_pid[proc.pid] == 1

        def build(proc: _Proc = proc, joined: bool = joined) -> MemoryProcessRecord:
            return MemoryProcessRecord.model_validate(
                {
                    "pid": proc.pid,
                    "offset": proc.offset,
                    "create_time": proc.create_time,
                    "sources": proc.sources,
                    "cmdline": cmdlines.get(proc.pid) if joined else None,
                    "image_path": images.get(proc.pid) if joined else None,
                    **proc.fields,
                }
            )

        b.add("processes", P.WINDOWS_PSLIST, build)
    for dll in dlls:
        dll_pid = u32(dll.pid)
        if dll_pid is not None and first.get(dll_pid) is dll:
            continue  # the main image: already the process's image_path
        b.artifact(
            P.WINDOWS_DLLLIST,
            "module",
            u32(dll.pid),
            {
                "name": text(dll.name, 255),
                "path": text(dll.path, ATTRIBUTE_TEXT),
                "base": addr(u64(dll.base)),
                "size": count(dll.size),
                "load_count": count(dll.load_count),
                "load_time": iso(timestamp(dll.load_time)),
            },
        )


def _connections(b: Builder, rows: Rows) -> None:
    for r in b.parse(P.WINDOWS_NETSCAN, rows.get(P.WINDOWS_NETSCAN, ()), m.WinNetscan):
        remote, remote_port = ip(r.foreign_addr), port(r.foreign_port)
        if remote in ("0.0.0.0", "::") and not remote_port:  # noqa: S104 - a parsed value
            remote, remote_port = None, None

        def build(
            r: m.WinNetscan = r, remote: str | None = remote, rport: int | None = remote_port
        ) -> MemoryConnectionRecord:
            return MemoryConnectionRecord.model_validate(
                {
                    "proto": PROTOCOLS.get((r.proto or "").upper(), "other"),
                    "local_addr": ip(r.local_addr),
                    "local_port": port(r.local_port),
                    "remote_addr": remote,
                    "remote_port": rport,
                    "state": text(r.state, 16),
                    "pid": u32(r.pid),
                    "owner": text(r.owner, 64),
                    "created": timestamp(r.created),
                    "offset": u64(r.offset),
                }
            )

        b.add("connections", P.WINDOWS_NETSCAN, build)


def _injections(b: Builder, rows: Rows) -> None:
    for r in b.parse(P.WINDOWS_MALFIND, rows.get(P.WINDOWS_MALFIND, ()), m.WinMalfind):
        head = hex_head(r.hexdump)

        def build(r: m.WinMalfind = r, head: str = head) -> MemoryInjectionRecord:
            return MemoryInjectionRecord.model_validate(
                {
                    "pid": u32(r.pid),
                    "process": text(r.process, 64),
                    "start": u64(r.start),
                    "end": u64(r.end),
                    "protection": text(r.protection, 64),
                    "tag": text(r.tag, 16),
                    "private": None if r.private_memory is None else r.private_memory == 1,
                    "commit_charge": count(r.commit_charge),
                    "has_pe": has_pe(head),
                    "head_hex": head,
                    "disasm": text(r.disasm, 1024),
                }
            )

        b.add("injections", P.WINDOWS_MALFIND, build)


def _artifacts(b: Builder, rows: Rows) -> None:
    for s in b.parse(P.WINDOWS_SVCSCAN, rows.get(P.WINDOWS_SVCSCAN, ()), m.WinService):
        b.artifact(
            P.WINDOWS_SVCSCAN,
            "service",
            u32(s.pid) or None,
            {
                "name": text(s.name, 255),
                "display": text(s.display, 255),
                "state": text(s.state, 64),
                "start": text(s.start, 64),
                "type": text(s.type, 128),
                "binary": text(s.binary, ATTRIBUTE_TEXT) or text(s.binary_registry, ATTRIBUTE_TEXT),
                "dll": text(s.dll, ATTRIBUTE_TEXT),
                "order": count(s.order),
            },
        )
    for h in b.parse(P.WINDOWS_HIVELIST, rows.get(P.WINDOWS_HIVELIST, ()), m.WinHive):
        b.artifact(
            P.WINDOWS_HIVELIST,
            "hive",
            None,
            {"path": text(h.path, ATTRIBUTE_TEXT), "offset": addr(u64(h.offset))},
        )
    for u in b.parse(P.WINDOWS_USERASSIST, rows.get(P.WINDOWS_USERASSIST, ()), m.WinUserAssist):
        if (u.type or "").lower() != "value" or not u.name:
            continue  # the hive / key / subkey rows of the tree
        b.artifact(
            P.WINDOWS_USERASSIST,
            "userassist",
            None,
            {
                "hive": text(u.hive_name, ATTRIBUTE_TEXT),
                "path": text(u.name, ATTRIBUTE_TEXT),
                "key": text(u.path, ATTRIBUTE_TEXT),
                "count": count(u.count),
                "focus_count": count(u.focus_count),
                "time_focused": text(u.time_focused, 64),
                "last_updated": iso(timestamp(u.last_updated)),
            },
        )
    for ldr in b.parse(P.WINDOWS_LDRMODULES, rows.get(P.WINDOWS_LDRMODULES, ()), m.WinLdrModule):
        if ldr.in_load is not False and ldr.in_init is not False and ldr.in_mem is not False:
            continue  # in every list (or unknown): not unlinked
        b.artifact(
            P.WINDOWS_LDRMODULES,
            "ldr_unlinked",
            u32(ldr.pid),
            {
                "base": addr(u64(ldr.base)),
                "in_load": ldr.in_load,
                "in_init": ldr.in_init,
                "in_mem": ldr.in_mem,
                "path": text(ldr.path, ATTRIBUTE_TEXT),
            },
        )


def normalize(b: Builder, rows: Rows) -> None:
    _info(b, b.parse(P.WINDOWS_INFO, rows.get(P.WINDOWS_INFO, ()), m.WinInfo))
    _processes(b, rows)
    _connections(b, rows)
    _injections(b, rows)
    _artifacts(b, rows)


__all__ = ["normalize"]
