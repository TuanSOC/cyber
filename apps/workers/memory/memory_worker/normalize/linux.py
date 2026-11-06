"""Linux plugin rows -> `memory.v1` records (root side).

- `linux.pslist` (threads off) -> processes (`sources` = pslist); `linux.psaux` -> `cmdline`
  joined by pid.
- `linux.bash` -> `bash` {command, time} (phase 3's shell-history detector and the IOC
  builder read `command` and `time`).
- `linux.sockstat` -> connections (AF_UNIX -> `unix`; inet by protocol; other families ->
  `other`), one per (pid, socket).
- `linux.lsof` -> `open_file` {fd, path, type, inode, mode, size, device}, one per (pid, fd).
- `linux.malware.malfind` -> injections (`private` = anonymous mapping, `has_pe` from the
  hex head).
- `linux.malware.check_syscall` -> `syscall_hook` {table, index, handler, table_address} for
  the entries whose handler resolves to no kernel symbol (`UNKNOWN`) only.
- `linux.malware.hidden_modules` -> `hidden_module` {name, offset, code_size, taints, args}.

Address attributes are ints while they fit the bigint column, else `0x...` text.
"""

from collections.abc import Iterable, Mapping
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
Rows = Mapping[MemoryPlugin, Iterable[Mapping[str, Any]]]
INET = frozenset({"AF_INET", "AF_INET6"})
TCP = frozenset({"TCP", "MPTCP"})
UDP = frozenset({"UDP", "UDPLITE"})
RAW = frozenset({"RAW", "ICMP", "ICMPV6"})
UNRESOLVED = frozenset({"UNKNOWN", ""})


def _proto(family: str | None, proto: str | None, type_: str | None) -> str:
    family, proto, type_ = (family or "").upper(), (proto or "").upper(), (type_ or "").upper()
    if family == "AF_UNIX":
        return "unix"
    if family not in INET:
        return "other"
    if proto in TCP:
        return "tcp"
    if proto in UDP:
        return "udp"
    if proto in RAW or type_ == "RAW":
        return "raw"
    return "other"


def _processes(b: Builder, rows: Rows) -> None:
    tasks = b.parse(P.LINUX_PSLIST, rows.get(P.LINUX_PSLIST, ()), m.LinuxTask)
    aux = b.parse(P.LINUX_PSAUX, rows.get(P.LINUX_PSAUX, ()), m.LinuxPsaux)
    cmdlines: dict[int, str] = {}
    for r in aux:
        pid, args = u32(r.pid), text(r.args, 4096)
        if pid is not None and args is not None:
            cmdlines.setdefault(pid, args)
    seen: set[tuple[int, int | None]] = set()
    for t in tasks:
        pid = u32(t.pid)
        if pid is None or (pid, u64(t.offset)) in seen:
            continue
        seen.add((pid, u64(t.offset)))

        def build(t: m.LinuxTask = t, pid: int = pid) -> MemoryProcessRecord:
            return MemoryProcessRecord.model_validate(
                {
                    "pid": pid,
                    "ppid": u32(t.ppid),
                    "name": text(t.comm, 64) or "",
                    "offset": u64(t.offset),
                    "create_time": timestamp(t.creation_time),
                    "sources": ["pslist"],
                    "cmdline": cmdlines.get(pid),
                }
            )

        b.add("processes", P.LINUX_PSLIST, build)


def _connections(b: Builder, rows: Rows) -> None:
    seen: set[tuple[int | None, int | None]] = set()
    for s in b.parse(P.LINUX_SOCKSTAT, rows.get(P.LINUX_SOCKSTAT, ()), m.LinuxSocket):
        key = (u32(s.pid), u64(s.sock_offset))
        if key[1] is not None and key in seen:
            continue  # the same socket seen from another thread of the process
        seen.add(key)
        proto = _proto(s.family, s.proto, s.type)
        inet = proto in ("tcp", "udp", "raw") or (s.family or "").upper() in INET

        def build(s: m.LinuxSocket = s, proto: str = proto, inet: bool = inet) -> Any:
            return MemoryConnectionRecord.model_validate(
                {
                    "proto": proto,
                    "local_addr": ip(s.source_addr) if inet else None,
                    "local_port": port(s.source_port) if inet else None,
                    "remote_addr": ip(s.destination_addr) if inet else None,
                    "remote_port": port(s.destination_port) if inet else None,
                    "state": text(s.state, 16),
                    "pid": u32(s.pid),
                    "owner": text(s.process, 64),
                    "offset": u64(s.sock_offset),
                }
            )

        b.add("connections", P.LINUX_SOCKSTAT, build)


def _injections(b: Builder, rows: Rows) -> None:
    for r in b.parse(P.LINUX_MALFIND, rows.get(P.LINUX_MALFIND, ()), m.LinuxMalfind):
        head = hex_head(r.hexdump)
        path = text(r.path, 1024)
        anonymous = path is None or path.startswith("[") or path == "Anonymous Mapping"

        def build(r: m.LinuxMalfind = r, head: str = head, anon: bool = anonymous) -> Any:
            return MemoryInjectionRecord.model_validate(
                {
                    "pid": u32(r.pid),
                    "process": text(r.process, 64),
                    "start": u64(r.start),
                    "end": u64(r.end),
                    "protection": text(r.protection, 64),
                    "private": anon,
                    "has_pe": has_pe(head),
                    "head_hex": head,
                    "disasm": text(r.disasm, 1024),
                }
            )

        b.add("injections", P.LINUX_MALFIND, build)


def _artifacts(b: Builder, rows: Rows) -> None:
    for h in b.parse(P.LINUX_BASH, rows.get(P.LINUX_BASH, ()), m.LinuxBash):
        b.artifact(
            P.LINUX_BASH,
            "bash",
            u32(h.pid),
            {
                "command": text(h.command, ATTRIBUTE_TEXT),
                "time": iso(timestamp(h.command_time)),
            },
        )
    seen: set[tuple[int | None, int | None]] = set()
    for f in b.parse(P.LINUX_LSOF, rows.get(P.LINUX_LSOF, ()), m.LinuxOpenFile):
        key = (u32(f.pid), count(f.fd))
        if key in seen:
            continue  # threads share the descriptor table
        seen.add(key)
        b.artifact(
            P.LINUX_LSOF,
            "open_file",
            key[0],
            {
                "fd": key[1],
                "path": text(f.path, ATTRIBUTE_TEXT),
                "type": text(f.type, 64),
                "inode": count(f.inode),
                "mode": text(f.mode, 64),
                "size": count(f.size),
                "device": text(f.device, 64),
            },
        )
    for c in b.parse(P.LINUX_CHECK_SYSCALL, rows.get(P.LINUX_CHECK_SYSCALL, ()), m.LinuxSyscall):
        if (c.handler_symbol or "").strip().upper() not in UNRESOLVED:
            continue  # resolves to a kernel symbol: not a hook candidate
        b.artifact(
            P.LINUX_CHECK_SYSCALL,
            "syscall_hook",
            None,
            {
                "table": text(c.table_name, 64),
                "index": count(c.index),
                "handler": addr(u64(c.handler_address)),
                "table_address": addr(u64(c.table_address)),
            },
        )
    for h in b.parse(
        P.LINUX_HIDDEN_MODULES, rows.get(P.LINUX_HIDDEN_MODULES, ()), m.LinuxHiddenModule
    ):
        b.artifact(
            P.LINUX_HIDDEN_MODULES,
            "hidden_module",
            None,
            {
                "name": text(h.module_name, 255),
                "offset": addr(u64(h.offset)),
                "code_size": count(h.code_size),
                "taints": text(h.taints, 255),
                "args": text(h.load_arguments, ATTRIBUTE_TEXT),
            },
        )


def normalize(b: Builder, rows: Rows) -> None:
    _processes(b, rows)
    _connections(b, rows)
    _injections(b, rows)
    _artifacts(b, rows)


__all__ = ["normalize"]
