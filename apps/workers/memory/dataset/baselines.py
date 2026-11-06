# ruff: noqa: E501 - hand-written synthetic records, one per line
"""Benign baselines of the scenario set (M8 phase 3): synthetic, hand-written, in the exact
phase-1 `memory.v1` record shapes. Nothing here comes from a real memory image (requirement
§16); addresses of "external" peers are RFC 5737 documentation addresses.

- `windows_workstation`: Windows 10 workstation, profile `full` (~120 processes: browser,
  Office, a .NET JIT host with RWX regions, Defender under `\\ProgramData\\...\\Platform\\`,
  Credential Guard `LsaIso.exe`, `sihost.exe`, exited `userinit.exe` remnant, `.mui` data
  files unlinked from the loader lists, session `smss.exe` gone).
- `windows_server`: Windows Server domain controller, profile `triage` (many services and
  drivers, `w3wp.exe` JIT host, `lsass.exe` talking to internal clients, the session
  `smss.exe` present as an exited remnant).
- `linux_server`: Debian web / database server, profile `triage` (benign shell history,
  including near-misses such as `curl` without a pipe and `nc -zv`).

Each builder returns a fresh `Draft` (plain dicts) that scenarios mutate before `view()`
validates every record through the contract models.
"""

from dataclasses import dataclass, field
from typing import Any

from cyberlab_jobs.memory import (
    MemoryArtifactRecord,
    MemoryConnectionRecord,
    MemoryImageRecord,
    MemoryInjectionRecord,
    MemoryOs,
    MemoryProcessRecord,
    MemoryProfile,
)

from memory_worker.view import MemoryView

Record = dict[str, Any]
WIN = "C:\\Windows\\System32\\"
PF = "C:\\Program Files\\"
PF86 = "C:\\Program Files (x86)\\"
DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\"
EDGE = PF86 + "Microsoft\\Edge\\Application\\msedge.exe"
OFFICE = PF + "Microsoft Office\\root\\Office16\\"
PS = WIN + "WindowsPowerShell\\v1.0\\powershell.exe"
SYSTEM_TIME = "2026-11-01T10:30:00Z"


def ts(minute: int, second: int = 0) -> str:
    """2026-11-01 08:00 + `minute` min + `second` s (synthetic clock of every scenario)."""
    total = minute * 60 + second
    hours, rest = divmod(total, 3600)
    return f"2026-11-01T{8 + hours:02d}:{rest // 60:02d}:{rest % 60:02d}Z"


@dataclass
class Draft:
    os: MemoryOs
    profile: MemoryProfile
    image: Record
    processes: list[Record] = field(default_factory=list)
    connections: list[Record] = field(default_factory=list)
    injections: list[Record] = field(default_factory=list)
    artifacts: list[Record] = field(default_factory=list)
    truncated: set[str] = field(default_factory=set)

    def proc(self, pid: int) -> Record:
        return next(p for p in self.processes if p["pid"] == pid)

    def add_process(
        self,
        pid: int,
        ppid: int | None,
        name: str,
        path: str | None,
        minute: int,
        *,
        cmdline: str | None = None,
        sources: tuple[str, ...] = ("pslist", "psscan"),
        exit_minute: int | None = None,
        threads: int | None = None,
        session: int | None = None,
    ) -> Record:
        # Creation order follows insertion order within a minute, so a parent added before
        # its child is also created before it (`Context.parent_of` checks that).
        order = len(self.processes)
        record: Record = {
            "kind": "process",
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "offset": 0xFFFF_C000_0000_0000 + pid * 0x80,
            "create_time": ts(minute, order),
            "exit_time": ts(exit_minute, order + 30) if exit_minute is not None else None,
            "threads": threads
            if threads is not None
            else (0 if exit_minute is not None else 4 + pid % 17),
            "handles": 80 + pid % 400,
            "session_id": session if session is not None else (0 if minute < 5 else 1),
            "wow64": False,
            "sources": list(sources),
            "cmdline": cmdline if cmdline is not None else path,
            "image_path": path,
        }
        self.processes.append(record)
        return record

    def view(self) -> MemoryView:
        return MemoryView(
            os=self.os,
            profile=self.profile,
            image=MemoryImageRecord.model_validate(self.image),
            processes=tuple(MemoryProcessRecord.model_validate(p) for p in self.processes),
            connections=tuple(MemoryConnectionRecord.model_validate(c) for c in self.connections),
            injections=tuple(MemoryInjectionRecord.model_validate(i) for i in self.injections),
            artifacts=tuple(MemoryArtifactRecord.model_validate(a) for a in self.artifacts),
            truncated=frozenset(self.truncated),
        )


def tcp(
    pid: int,
    owner: str,
    local: str,
    lport: int,
    remote: str | None = None,
    rport: int | None = None,
    state: str = "ESTABLISHED",
    minute: int | None = None,
) -> Record:
    return {
        "kind": "connection",
        "proto": "tcp",
        "local_addr": local,
        "local_port": lport,
        "remote_addr": remote,
        "remote_port": rport,
        "state": state,
        "pid": pid,
        "owner": owner,
        "created": ts(minute) if minute is not None else None,
        "offset": 0xFFFF_D000_0000_0000 + (pid * 0x1000 + lport) * 0x10,
    }


def udp(pid: int, owner: str, local: str, lport: int) -> Record:
    return {
        "kind": "connection",
        "proto": "udp",
        "local_addr": local,
        "local_port": lport,
        "pid": pid,
        "owner": owner,
        "offset": 0xFFFF_D100_0000_0000 + (pid * 0x1000 + lport) * 0x10,
    }


def region(
    pid: int,
    process: str,
    start: int,
    size: int,
    protection: str,
    head: str,
    *,
    has_pe: bool = False,
    private: bool = True,
) -> Record:
    return {
        "kind": "injection",
        "pid": pid,
        "process": process,
        "start": start,
        "end": start + size - 1,
        "protection": protection,
        "tag": "VadS" if private else "Vad ",
        "private": private,
        "commit_charge": size // 4096,
        "has_pe": has_pe,
        "head_hex": head,
    }


def service(
    name: str,
    binary: str,
    *,
    pid: int | None = None,
    state: str = "SERVICE_RUNNING",
    kind: str = "SERVICE_WIN32_OWN_PROCESS",
    start: str = "SERVICE_AUTO_START",
) -> Record:
    return {
        "kind": "artifact",
        "type": "service",
        "pid": pid,
        "attributes": {
            "name": name,
            "state": state,
            "start": start,
            "binary": binary,
            "type": kind,
        },
    }


def driver(name: str, binary: str) -> Record:
    return service(name, binary, kind="SERVICE_KERNEL_DRIVER", start="SERVICE_SYSTEM_START")


def ldr(pid: int, path: str, base: int, load: bool, init: bool, mem: bool) -> Record:
    return {
        "kind": "artifact",
        "type": "ldr_unlinked",
        "pid": pid,
        "attributes": {"base": base, "in_load": load, "in_init": init, "in_mem": mem, "path": path},
    }


def module(pid: int, path: str, base: int, size: int) -> Record:
    return {
        "kind": "artifact",
        "type": "module",
        "pid": pid,
        "attributes": {"path": path, "base": base, "size": size},
    }


def bash(pid: int, command: str, minute: int) -> Record:
    return {
        "kind": "artifact",
        "type": "bash",
        "pid": pid,
        "attributes": {"command": command, "time": ts(minute)},
    }


# --- Windows 10 workstation --------------------------------------------------------------

# Bytes of benign regions: JIT stubs and trampolines (no PE header).
JIT_HEAD = "4883ec28e8000000004883c428c3cccc49bb0000000000000000"
STUB_HEAD = "48b8000000000000000050c3cccccccc"
SVCHOST_GROUPS = [
    "DcomLaunch -p",
    "RPCSS -p",
    "LocalServiceNetworkRestricted -p",
    "netsvcs -p",
    "LocalService -p",
    "LocalSystemNetworkRestricted -p",
    "NetworkService -p",
    "LocalServiceNoNetwork -p",
    "appmodel -p",
    "UnistackSvcGroup",
    "wsappx -p",
    "utcsvc -p",
    "LocalServiceAndNoImpersonation -p",
]
WORKSTATION_SERVICES = [
    "BFE",
    "BrokerInfrastructure",
    "CDPSvc",
    "CoreMessagingRegistrar",
    "CryptSvc",
    "DcomLaunch",
    "Dhcp",
    "DiagTrack",
    "DispBrokerDesktopSvc",
    "Dnscache",
    "DPS",
    "DusmSvc",
    "EventLog",
    "EventSystem",
    "FontCache",
    "gpsvc",
    "iphlpsvc",
    "LanmanServer",
    "LanmanWorkstation",
    "lmhosts",
    "LSM",
    "mpssvc",
    "NcbService",
    "netprofm",
    "NlaSvc",
    "nsi",
    "PcaSvc",
    "Power",
    "ProfSvc",
    "RpcEptMapper",
    "RpcSs",
    "Schedule",
    "SENS",
    "ShellHWDetection",
    "StateRepository",
    "SysMain",
    "SystemEventsBroker",
    "Themes",
    "TimeBrokerSvc",
    "TokenBroker",
    "UserManager",
    "UsoSvc",
    "W32Time",
    "Wcmsvc",
    "WinHttpAutoProxySvc",
    "Winmgmt",
    "WpnService",
    "wscsvc",
    "WSearch",
]


def windows_workstation() -> Draft:
    d = Draft(
        os="windows",
        profile=MemoryProfile.FULL,
        image={
            "kind": "image",
            "size_bytes": 8_589_934_592,
            "sha256": "1" * 64,
            "layer": "WindowsCrashDump64Layer>WindowsIntel32e",
            "arch": "x64",
            "nt_build": "19045",
            "pdb": {"name": "ntkrnlmp.pdb", "guid": "1A2B3C4D5E6F708192A3B4C5D6E7F801", "age": 1},
            "system_time": SYSTEM_TIME,
        },
    )
    p = d.add_process
    p(4, 0, "System", None, 0, cmdline="")
    p(92, 4, "Registry", None, 0, cmdline="")
    p(356, 4, "smss.exe", "\\SystemRoot\\System32\\smss.exe", 0)
    # Session smss.exe instances (pids 460, 536) exited and are gone: their children's
    # parent is missing, which never fires (RT21).
    p(
        468,
        460,
        "csrss.exe",
        WIN + "csrss.exe",
        0,
        cmdline="%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
    )
    p(544, 460, "wininit.exe", WIN + "wininit.exe", 0)
    p(552, 536, "csrss.exe", WIN + "csrss.exe", 0)
    p(640, 536, "winlogon.exe", WIN + "winlogon.exe", 0)
    p(676, 544, "services.exe", WIN + "services.exe", 0)
    p(696, 544, "lsass.exe", WIN + "lsass.exe", 0)
    p(704, 544, "LsaIso.exe", WIN + "LsaIso.exe", 0)
    p(828, 544, "fontdrvhost.exe", WIN + "fontdrvhost.exe", 0)
    p(836, 640, "fontdrvhost.exe", WIN + "fontdrvhost.exe", 0)
    p(980, 640, "dwm.exe", WIN + "dwm.exe", 1)
    p(1880, 4, "MemCompression", None, 1, cmdline="")
    pid = 900
    for i in range(46):
        group = SVCHOST_GROUPS[i % len(SVCHOST_GROUPS)]
        svc = WORKSTATION_SERVICES[i % len(WORKSTATION_SERVICES)]
        p(
            pid,
            676,
            "svchost.exe",
            WIN + "svchost.exe",
            1 + i // 12,
            cmdline=f"C:\\Windows\\system32\\svchost.exe -k {group} -s {svc}",
        )
        pid += 24
    p(2104, 676, "spoolsv.exe", WIN + "spoolsv.exe", 2)
    p(2188, 676, "MsMpEng.exe", DEFENDER + "MsMpEng.exe", 2)
    p(2212, 676, "NisSrv.exe", DEFENDER + "NisSrv.exe", 2)
    p(2236, 676, "SecurityHealthService.exe", WIN + "SecurityHealthService.exe", 2)
    p(
        2260,
        676,
        "VGAuthService.exe",
        PF + "VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe",
        2,
    )
    p(2284, 676, "vmtoolsd.exe", PF + "VMware\\VMware Tools\\vmtoolsd.exe", 2)
    p(
        2308,
        676,
        "SearchIndexer.exe",
        WIN + "SearchIndexer.exe",
        3,
        cmdline="C:\\Windows\\system32\\SearchIndexer.exe /Embedding",
    )
    p(2332, 676, "SgrmBroker.exe", WIN + "SgrmBroker.exe", 3)
    p(
        2356,
        676,
        "MicrosoftEdgeUpdate.exe",
        PF86 + "Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        3,
        cmdline=f'"{PF86}Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /svc',
    )
    p(
        2380,
        900,
        "WmiPrvSE.exe",
        WIN + "wbem\\WmiPrvSE.exe",
        3,
        cmdline="C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
    )
    p(
        2404,
        900,
        "dllhost.exe",
        WIN + "dllhost.exe",
        3,
        cmdline="C:\\Windows\\system32\\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
    )
    # userinit.exe started explorer.exe and exited: a psscan-only remnant with an exit time.
    p(2900, 640, "userinit.exe", WIN + "userinit.exe", 5, sources=("psscan",), exit_minute=5)
    p(2920, 1020, "sihost.exe", WIN + "sihost.exe", 5)
    p(
        2944,
        1020,
        "taskhostw.exe",
        WIN + "taskhostw.exe",
        5,
        cmdline="taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}",
    )
    p(
        3040,
        2900,
        "explorer.exe",
        "C:\\Windows\\explorer.exe",
        5,
        cmdline="C:\\Windows\\Explorer.EXE",
    )
    p(
        3064,
        900,
        "StartMenuExperienceHost.exe",
        "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe",
        5,
    )
    p(
        3088,
        900,
        "RuntimeBroker.exe",
        WIN + "RuntimeBroker.exe",
        5,
        cmdline="C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
    )
    p(
        3112,
        900,
        "SearchApp.exe",
        "C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe",
        5,
    )
    p(
        3136,
        900,
        "RuntimeBroker.exe",
        WIN + "RuntimeBroker.exe",
        5,
        cmdline="C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
    )
    p(
        3160,
        900,
        "ShellExperienceHost.exe",
        "C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe",
        5,
    )
    p(3184, 1020, "ctfmon.exe", WIN + "ctfmon.exe", 5)
    p(
        3208,
        900,
        "TextInputHost.exe",
        "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe",
        6,
    )
    p(3232, 3040, "SecurityHealthSystray.exe", WIN + "SecurityHealthSystray.exe", 6)
    p(
        3256,
        3040,
        "vmtoolsd.exe",
        PF + "VMware\\VMware Tools\\vmtoolsd.exe",
        6,
        cmdline=f'"{PF}VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr',
    )
    p(
        3280,
        3040,
        "OneDrive.exe",
        "C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
        6,
        cmdline='"C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
    )
    p(
        3304,
        900,
        "smartscreen.exe",
        WIN + "smartscreen.exe",
        6,
        cmdline="C:\\Windows\\System32\\smartscreen.exe -Embedding",
    )
    p(
        3328,
        900,
        "ApplicationFrameHost.exe",
        WIN + "ApplicationFrameHost.exe",
        7,
        cmdline="C:\\Windows\\system32\\ApplicationFrameHost.exe -Embedding",
    )
    p(
        3352,
        900,
        "SystemSettings.exe",
        "C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
        7,
        cmdline='"C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe" -ServerName:microsoft.windows.immersivecontrolpanel',
    )
    p(
        3376,
        1044,
        "audiodg.exe",
        WIN + "audiodg.exe",
        7,
        cmdline="C:\\Windows\\system32\\AUDIODG.EXE 0x4f0",
    )
    edge_args = [
        "--type=crashpad-handler --user-data-dir=C:\\Users\\alice\\AppData\\Local\\Microsoft\\Edge\\User Data --database=C:\\Users\\alice\\AppData\\Local\\Microsoft\\Edge\\User Data\\Crashpad --annotation=IsOfficialBuild=1",
        "--type=gpu-process --gpu-preferences=UAAAAAAAAADgAAAEAAAAAAAAAAAAAAAAAABgAAAAAAAwAAAAAAAAAAAAAAAAAAAA --mojo-platform-channel-handle=1976 --field-trial-handle=1780,i,4825739011729480317,10373516233911512042,262144 /prefetch:2",
        "--type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --mojo-platform-channel-handle=2216 --field-trial-handle=1780,i,4825739011729480317,10373516233911512042,262144 /prefetch:3",
        "--type=utility --utility-sub-type=storage.mojom.StorageService --lang=en-US --service-sandbox-type=service --mojo-platform-channel-handle=2468 /prefetch:8",
        "--type=renderer --instant-process --lang=en-US --js-flags=--ms-user-locale= --device-scale-factor=1 --num-raster-threads=2 --renderer-client-id=6 --mojo-platform-channel-handle=3304 /prefetch:1",
        "--type=renderer --lang=en-US --js-flags=--ms-user-locale= --device-scale-factor=1 --num-raster-threads=2 --renderer-client-id=9 --mojo-platform-channel-handle=4120 /prefetch:1",
        "--type=renderer --extension-process --lang=en-US --renderer-client-id=12 --mojo-platform-channel-handle=4480 /prefetch:1",
    ]
    p(4400, 3040, "msedge.exe", EDGE, 8, cmdline=f'"{EDGE}" --profile-directory=Default')
    for i, args in enumerate(edge_args):
        p(4424 + i * 24, 4400, "msedge.exe", EDGE, 8, cmdline=f'"{EDGE}" {args}')
    p(
        4800,
        3040,
        "WINWORD.EXE",
        OFFICE + "WINWORD.EXE",
        12,
        cmdline=f'"{OFFICE}WINWORD.EXE" /n "C:\\Users\\alice\\Documents\\Quarterly report.docx"',
    )
    p(
        4824,
        3040,
        "EXCEL.EXE",
        OFFICE + "EXCEL.EXE",
        13,
        cmdline=f'"{OFFICE}EXCEL.EXE" "C:\\Users\\alice\\Documents\\budget-2026.xlsx"',
    )
    p(
        4848,
        3040,
        "OUTLOOK.EXE",
        OFFICE + "OUTLOOK.EXE",
        13,
        cmdline=f'"{OFFICE}OUTLOOK.EXE" /recycle',
    )
    p(
        4872,
        900,
        "backgroundTaskHost.exe",
        WIN + "backgroundTaskHost.exe",
        14,
        cmdline='"C:\\Windows\\system32\\backgroundTaskHost.exe" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca',
    )
    p(5100, 3040, "cmd.exe", WIN + "cmd.exe", 20, cmdline='"C:\\Windows\\system32\\cmd.exe"')
    p(
        5124,
        5100,
        "conhost.exe",
        WIN + "conhost.exe",
        20,
        cmdline="\\??\\C:\\Windows\\system32\\conhost.exe 0x4",
    )
    p(5148, 5100, "PING.EXE", WIN + "PING.EXE", 21, cmdline="ping -n 4 10.0.0.1", exit_minute=21)
    # The .NET JIT host (RWX regions without a PE header are expected, skipped).
    p(
        5200,
        3040,
        "powershell.exe",
        PS,
        25,
        cmdline=f'"{PS}" -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1',
    )
    p(
        5224,
        5200,
        "conhost.exe",
        WIN + "conhost.exe",
        25,
        cmdline="\\??\\C:\\Windows\\system32\\conhost.exe 0x4",
    )
    p(
        5300,
        3040,
        "notepad.exe",
        WIN + "notepad.exe",
        30,
        cmdline='"C:\\Windows\\system32\\notepad.exe" C:\\Users\\alice\\Desktop\\todo.txt',
    )
    p(
        5324,
        3040,
        "Teams.exe",
        "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
        31,
        cmdline='"C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe" --process-start-args "--system-initiated"',
    )
    p(
        5348,
        3040,
        "mstsc.exe",
        WIN + "mstsc.exe",
        40,
        cmdline='"C:\\Windows\\system32\\mstsc.exe" /v:fileserver01.corp.example',
    )
    p(
        5372,
        900,
        "WUDFHost.exe",
        WIN + "WUDFHost.exe",
        41,
        cmdline='"C:\\Windows\\System32\\WUDFHost.exe" -HostGUID:{193a1820-d9ac-4997-8c55-be817523f6aa} -IoEventPortName:\\UMDFCommunicationPorts\\WUDF\\HostProcess-8c6d0b14',
    )
    # Exited processes still found by the pool scan (not "hidden": exit time, no threads).
    p(
        5600,
        3040,
        "setup.exe",
        "C:\\Users\\alice\\Downloads\\setup.exe",
        50,
        sources=("psscan",),
        exit_minute=52,
    )
    p(
        5624,
        900,
        "TiWorker.exe",
        "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.4585_none_7d93a0b6d5e2c84f\\TiWorker.exe",
        55,
        sources=("psscan",),
        exit_minute=58,
    )
    p(
        5648,
        900,
        "MpCmdRun.exe",
        DEFENDER + "MpCmdRun.exe",
        60,
        sources=("psscan",),
        exit_minute=61,
        threads=2,
    )  # exit time set: not hidden either

    d.connections += [
        tcp(4, "System", "0.0.0.0", 445, state="LISTENING"),
        tcp(4, "System", "10.0.0.15", 139, state="LISTENING"),
        tcp(696, "lsass.exe", "0.0.0.0", 49664, state="LISTENING"),
        tcp(544, "wininit.exe", "0.0.0.0", 49665, state="LISTENING"),
        tcp(676, "services.exe", "0.0.0.0", 49669, state="LISTENING"),
        tcp(924, "svchost.exe", "0.0.0.0", 135, state="LISTENING"),
        tcp(948, "svchost.exe", "10.0.0.15", 49702, "192.0.2.10", 443, minute=4),
        tcp(4448, "msedge.exe", "10.0.0.15", 49810, "192.0.2.44", 443, minute=9),
        tcp(4448, "msedge.exe", "10.0.0.15", 49811, "198.51.100.200", 443, minute=10),
        tcp(3280, "OneDrive.exe", "10.0.0.15", 49755, "192.0.2.20", 443, minute=7),
        tcp(4848, "OUTLOOK.EXE", "10.0.0.15", 49890, "192.0.2.30", 443, minute=14),
        tcp(5324, "Teams.exe", "10.0.0.15", 49912, "192.0.2.31", 443, minute=32),
        tcp(5348, "mstsc.exe", "10.0.0.15", 49950, "10.0.0.40", 3389, minute=40),
        # lsass to the domain controller (internal: never "external").
        tcp(696, "lsass.exe", "10.0.0.15", 49720, "10.0.0.2", 389, minute=5),
        tcp(5200, "powershell.exe", "10.0.0.15", 49960, "10.0.0.8", 5985, minute=26),
        udp(948, "svchost.exe", "0.0.0.0", 5353),
        udp(948, "svchost.exe", "::", 5355),
        udp(4448, "msedge.exe", "0.0.0.0", 5353),
    ]
    d.injections += [
        region(4448, "msedge.exe", 0x2A4_0000_0000, 0x10000, "PAGE_EXECUTE_READWRITE", JIT_HEAD),
        region(4520, "msedge.exe", 0x3B8_0000_0000, 0x40000, "PAGE_EXECUTE_READWRITE", JIT_HEAD),
        region(
            5200, "powershell.exe", 0x7FF8_1000_0000, 0x20000, "PAGE_EXECUTE_READWRITE", JIT_HEAD
        ),
        region(
            5200, "powershell.exe", 0x7FF8_1004_0000, 0x10000, "PAGE_EXECUTE_READWRITE", STUB_HEAD
        ),
        region(5324, "Teams.exe", 0x1C0_0000_0000, 0x80000, "PAGE_EXECUTE_READWRITE", JIT_HEAD),
        # Executable but not writable: outside the rule.
        region(3112, "SearchApp.exe", 0x1F0_0000_0000, 0x1000, "PAGE_EXECUTE_READ", STUB_HEAD),
        # Writable and executable but image-backed (not private): outside the rule.
        region(
            3040,
            "explorer.exe",
            0x7FF7_2000_0000,
            0x1000,
            "PAGE_EXECUTE_WRITECOPY",
            STUB_HEAD,
            private=False,
        ),
    ]
    d.artifacts += [
        module(3040, WIN + dll, 0x7FFB_0000_0000 + i * 0x100_0000, 0x1A0000)
        for i, dll in enumerate(
            ("ntdll.dll", "kernel32.dll", "KERNELBASE.dll", "user32.dll", "shell32.dll")
        )
    ]
    d.artifacts += [
        ldr(3040, WIN + "ntdll.dll", 0x7FFB_0000_0000, True, True, True),
        ldr(3040, "C:\\Windows\\explorer.exe", 0x7FF7_1000_0000, True, False, True),
        # Mapped data files the loader never lists (not modules).
        ldr(3040, WIN + "en-US\\explorer.exe.mui", 0x1E0_0000_0000, False, False, False),
        ldr(3040, WIN + "locale.nls", 0x1E1_0000_0000, False, False, False),
        ldr(4800, OFFICE + "1033\\wwintl.dll.mui", 0x1E2_0000_0000, False, False, False),
        # The process's own image missing from the lists is excluded (spec).
        ldr(5300, WIN + "notepad.exe", 0x7FF6_0000_0000, False, False, False),
        ldr(4800, OFFICE + "wwlib.dll", 0x7FFA_0000_0000, True, True, True),
    ]
    svc_pid = 900
    for i, name in enumerate(WORKSTATION_SERVICES):
        group = SVCHOST_GROUPS[i % len(SVCHOST_GROUPS)]
        d.artifacts.append(
            service(
                name,
                f"C:\\Windows\\system32\\svchost.exe -k {group}",
                pid=svc_pid + 24 * (i % 46),
                kind="SERVICE_WIN32_SHARE_PROCESS",
            )
        )
    d.artifacts += [
        service("Spooler", WIN + "spoolsv.exe", pid=2104),
        service("WinDefend", f'"{DEFENDER}MsMpEng.exe"', pid=2188),
        service("WdNisSvc", f'"{DEFENDER}NisSrv.exe"', pid=2212),
        service("SecurityHealthService", WIN + "SecurityHealthService.exe", pid=2236),
        service(
            "VGAuthService",
            f'"{PF}VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe"',
            pid=2260,
        ),
        service("VMTools", f'"{PF}VMware\\VMware Tools\\vmtoolsd.exe"', pid=2284),
        service(
            "edgeupdate",
            f'"{PF86}Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /svc',
            pid=2356,
            start="SERVICE_DEMAND_START",
        ),
        service("SgrmBroker", WIN + "SgrmBroker.exe", pid=2332),
        service(
            "OneSyncSvc_4a3c1",
            "C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup",
            kind="SERVICE_USER_OWN_PROCESS",
            state="SERVICE_STOPPED",
        ),
        service(
            "MozillaMaintenance",
            f'"{PF86}Mozilla Maintenance Service\\maintenanceservice.exe"',
            state="SERVICE_STOPPED",
            start="SERVICE_DEMAND_START",
        ),
        driver("Tcpip", "\\Driver\\Tcpip"),
        driver("Ntfs", "\\FileSystem\\Ntfs"),
        driver("tcpip", "\\SystemRoot\\System32\\drivers\\tcpip.sys"),
        driver("WdFilter", "\\SystemRoot\\system32\\drivers\\wd\\WdFilter.sys"),
        driver("vmci", "System32\\drivers\\vmci.sys"),
        driver(
            "e1iexpress",
            "\\SystemRoot\\System32\\DriverStore\\FileRepository\\e1i63x64.inf_amd64_fd4b3c3e8c7b1e0a\\e1i63x64.sys",
        ),
        driver("disk", "\\SystemRoot\\System32\\drivers\\disk.sys"),
        {
            "kind": "artifact",
            "type": "hive",
            "attributes": {"path": "\\REGISTRY\\MACHINE\\SYSTEM", "offset": 0xF8A0_0002_4000},
        },
        {
            "kind": "artifact",
            "type": "hive",
            "attributes": {
                "path": "\\??\\C:\\Users\\alice\\ntuser.dat",
                "offset": 0xF8A0_0102_4000,
            },
        },
        {
            "kind": "artifact",
            "type": "userassist",
            "attributes": {
                "hive": "\\??\\C:\\Users\\alice\\ntuser.dat",
                "path": "Microsoft.Office.WINWORD.EXE.15",
                "count": 41,
                "last_updated": "2026-11-01T08:12:00Z",
            },
        },
    ]
    return d


# --- Windows Server domain controller -----------------------------------------------------

SERVER_SERVICES = [
    "ADWS",
    "AppHostSvc",
    "BFE",
    "CertPropSvc",
    "CryptSvc",
    "DcomLaunch",
    "Dfs",
    "DFSR",
    "Dhcp",
    "DNS",
    "Dnscache",
    "DPS",
    "EventLog",
    "EventSystem",
    "gpsvc",
    "IAS",
    "IISADMIN",
    "IsmServ",
    "Kdc",
    "KeyIso",
    "LanmanServer",
    "LanmanWorkstation",
    "lmhosts",
    "LSM",
    "mpssvc",
    "MSDTC",
    "Netlogon",
    "netprofm",
    "NlaSvc",
    "nsi",
    "NTDS",
    "PlugPlay",
    "PolicyAgent",
    "Power",
    "ProfSvc",
    "RpcEptMapper",
    "RpcSs",
    "SamSs",
    "Schedule",
    "SENS",
    "ServerManager",
    "ShellHWDetection",
    "SstpSvc",
    "TermService",
    "UmRdpService",
    "UserManager",
    "VSS",
    "W32Time",
    "W3SVC",
    "WAS",
    "WinRM",
    "Winmgmt",
    "wuauserv",
]


def windows_server() -> Draft:
    d = Draft(
        os="windows",
        profile=MemoryProfile.TRIAGE,
        image={
            "kind": "image",
            "size_bytes": 17_179_869_184 // 2,
            "sha256": "2" * 64,
            "layer": "WindowsCrashDump64Layer>WindowsIntel32e",
            "arch": "x64",
            "nt_build": "20348",
            "pdb": {"name": "ntkrnlmp.pdb", "guid": "2B3C4D5E6F708192A3B4C5D6E7F80912", "age": 1},
            "system_time": SYSTEM_TIME,
        },
    )
    p = d.add_process
    p(4, 0, "System", None, 0, cmdline="")
    p(88, 4, "Registry", None, 0, cmdline="")
    p(312, 4, "smss.exe", "\\SystemRoot\\System32\\smss.exe", 0)
    # The session smss.exe instance exited but is still found by the pool scan.
    p(
        404,
        312,
        "smss.exe",
        "\\SystemRoot\\System32\\smss.exe",
        0,
        sources=("psscan",),
        exit_minute=0,
    )
    p(412, 404, "csrss.exe", WIN + "csrss.exe", 0)
    p(488, 404, "wininit.exe", WIN + "wininit.exe", 0)
    p(624, 488, "services.exe", WIN + "services.exe", 0)
    p(640, 488, "lsass.exe", WIN + "lsass.exe", 0)
    p(812, 488, "fontdrvhost.exe", WIN + "fontdrvhost.exe", 0)
    p(1100, 1096, "csrss.exe", WIN + "csrss.exe", 30)  # RDP session: parent gone
    p(1120, 1096, "winlogon.exe", WIN + "winlogon.exe", 30)
    p(1164, 1120, "dwm.exe", WIN + "dwm.exe", 30)
    pid = 700
    for i in range(40):
        group = SVCHOST_GROUPS[i % len(SVCHOST_GROUPS)]
        p(
            pid,
            624,
            "svchost.exe",
            WIN + "svchost.exe",
            1 + i // 10,
            cmdline=f"C:\\Windows\\system32\\svchost.exe -k {group} -s {SERVER_SERVICES[i]}",
        )
        pid += 8
    for spid, name, path, minute in (
        (2000, "dns.exe", WIN + "dns.exe", 2),
        (2008, "ismserv.exe", WIN + "ismserv.exe", 2),
        (2016, "dfsrs.exe", WIN + "dfsrs.exe", 2),
        (
            2024,
            "Microsoft.ActiveDirectory.WebServices.exe",
            "C:\\Windows\\ADWS\\Microsoft.ActiveDirectory.WebServices.exe",
            2,
        ),
        (2032, "dfssvc.exe", WIN + "dfssvc.exe", 2),
        (2040, "MsMpEng.exe", DEFENDER + "MsMpEng.exe", 2),
        (2048, "vmtoolsd.exe", PF + "VMware\\VMware Tools\\vmtoolsd.exe", 2),
        (
            2056,
            "VGAuthService.exe",
            PF + "VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe",
            2,
        ),
        (
            2064,
            "sqlservr.exe",
            PF + "Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
            3,
        ),
        (2072, "sqlwriter.exe", PF + "Microsoft SQL Server\\90\\Shared\\sqlwriter.exe", 3),
        (2080, "spoolsv.exe", WIN + "spoolsv.exe", 3),
        (2088, "wsmprovhost.exe", WIN + "wsmprovhost.exe", 40),
    ):
        p(spid, 624, name, path, minute)
    p(
        2200,
        700,
        "WmiPrvSE.exe",
        WIN + "wbem\\WmiPrvSE.exe",
        4,
        cmdline="C:\\Windows\\system32\\wbem\\wmiprvse.exe -Embedding",
    )
    p(
        2300,
        860,
        "w3wp.exe",
        "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        5,
        cmdline='c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "DefaultAppPool" -v "v4.0" -l "webengine4.dll" -a \\\\.\\pipe\\iisipm5f0c -h "C:\\inetpub\\temp\\apppools\\DefaultAppPool\\DefaultAppPool.config" -w "" -m 0',
    )
    p(
        2308,
        860,
        "w3wp.exe",
        "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        5,
        cmdline='c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "Intranet" -v "v4.0" -l "webengine4.dll" -h "C:\\inetpub\\temp\\apppools\\Intranet\\Intranet.config" -w "" -m 0',
    )
    p(2400, 1120, "userinit.exe", WIN + "userinit.exe", 31, sources=("psscan",), exit_minute=31)
    p(
        2420,
        2400,
        "explorer.exe",
        "C:\\Windows\\explorer.exe",
        31,
        cmdline="C:\\Windows\\Explorer.EXE",
    )
    p(
        2440,
        700,
        "ServerManager.exe",
        WIN + "ServerManager.exe",
        31,
        cmdline='"C:\\Windows\\system32\\ServerManager.exe"',
    )
    p(2460, 2420, "rdpclip.exe", WIN + "rdpclip.exe", 31)
    p(2480, 716, "taskhostw.exe", WIN + "taskhostw.exe", 31, cmdline="taskhostw.exe USER")
    p(2500, 716, "sihost.exe", WIN + "sihost.exe", 31)
    p(
        2520,
        2420,
        "mmc.exe",
        WIN + "mmc.exe",
        45,
        cmdline='"C:\\Windows\\system32\\mmc.exe" "C:\\Windows\\system32\\dsa.msc"',
    )
    p(
        2540,
        2420,
        "powershell.exe",
        PS,
        50,
        cmdline=f'"{PS}" -NoProfile -Command "Get-ADUser -Filter * -SearchBase \'OU=Staff,DC=corp,DC=example\' | Measure-Object"',
    )
    p(
        2560,
        2540,
        "conhost.exe",
        WIN + "conhost.exe",
        50,
        cmdline="\\??\\C:\\Windows\\system32\\conhost.exe 0x4",
    )

    d.connections += [
        tcp(640, "lsass.exe", "0.0.0.0", 88, state="LISTENING"),
        tcp(640, "lsass.exe", "0.0.0.0", 389, state="LISTENING"),
        tcp(640, "lsass.exe", "0.0.0.0", 636, state="LISTENING"),
        tcp(640, "lsass.exe", "10.0.0.2", 389, "10.0.0.15", 49720, minute=5),
        tcp(640, "lsass.exe", "10.0.0.2", 88, "10.0.0.16", 50112, minute=7),
        tcp(640, "lsass.exe", "10.0.0.2", 49668, "10.0.0.3", 51022, minute=9),
        tcp(2000, "dns.exe", "10.0.0.2", 53, state="LISTENING"),
        tcp(2064, "sqlservr.exe", "0.0.0.0", 1433, state="LISTENING"),
        tcp(2064, "sqlservr.exe", "10.0.0.2", 1433, "10.0.0.50", 52200, minute=12),
        tcp(4, "System", "0.0.0.0", 80, state="LISTENING"),
        tcp(4, "System", "0.0.0.0", 445, state="LISTENING"),
        tcp(4, "System", "10.0.0.2", 445, "10.0.0.15", 49800, minute=6),
        tcp(716, "svchost.exe", "0.0.0.0", 3389, state="LISTENING"),
        tcp(716, "svchost.exe", "10.0.0.2", 3389, "10.0.0.15", 49900, minute=30),
        tcp(748, "svchost.exe", "10.0.0.2", 50001, "192.0.2.90", 443, minute=20),
        tcp(2040, "MsMpEng.exe", "10.0.0.2", 50010, "192.0.2.91", 443, minute=21),
        udp(2000, "dns.exe", "10.0.0.2", 53),
        udp(640, "lsass.exe", "0.0.0.0", 389),
        udp(4, "System", "10.0.0.2", 137),
    ]
    d.injections += [
        region(2300, "w3wp.exe", 0x7FF8_2000_0000, 0x10000, "PAGE_EXECUTE_READWRITE", JIT_HEAD),
        region(2308, "w3wp.exe", 0x7FF8_3000_0000, 0x10000, "PAGE_EXECUTE_READWRITE", JIT_HEAD),
        region(
            2540, "powershell.exe", 0x7FF8_4000_0000, 0x20000, "PAGE_EXECUTE_READWRITE", JIT_HEAD
        ),
    ]
    for i, name in enumerate(SERVER_SERVICES):
        d.artifacts.append(
            service(
                name,
                f"C:\\Windows\\system32\\svchost.exe -k {SVCHOST_GROUPS[i % len(SVCHOST_GROUPS)]}",
                pid=700 + 8 * (i % 40),
                kind="SERVICE_WIN32_SHARE_PROCESS",
            )
        )
    d.artifacts += [
        service("NTDS", WIN + "lsass.exe", pid=640),
        service("DNS", WIN + "dns.exe", pid=2000),
        service("IsmServ", WIN + "ismserv.exe", pid=2008),
        service("DFSR", WIN + "dfsrs.exe", pid=2016),
        service("ADWS", "C:\\Windows\\ADWS\\Microsoft.ActiveDirectory.WebServices.exe", pid=2024),
        service("WinDefend", f'"{DEFENDER}MsMpEng.exe"', pid=2040),
        service(
            "MSSQLSERVER",
            f'"{PF}Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe" -sMSSQLSERVER',
            pid=2064,
        ),
        service("SQLWriter", f'"{PF}Microsoft SQL Server\\90\\Shared\\sqlwriter.exe"', pid=2072),
        service("VMTools", f'"{PF}VMware\\VMware Tools\\vmtoolsd.exe"', pid=2048),
        driver("Tcpip", "\\Driver\\Tcpip"),
        driver("NetBT", "\\Driver\\NetBT"),
        driver("Ntfs", "\\FileSystem\\Ntfs"),
        driver("HTTP", "\\SystemRoot\\system32\\drivers\\HTTP.sys"),
        driver(
            "vmxnet3",
            "\\SystemRoot\\System32\\DriverStore\\FileRepository\\vmxnet3.inf_amd64_8e1c4b7cf0e0d3a5\\vmxnet3.sys",
        ),
        driver("WdBoot", "\\SystemRoot\\system32\\drivers\\wd\\WdBoot.sys"),
        {
            "kind": "artifact",
            "type": "hive",
            "attributes": {"path": "\\REGISTRY\\MACHINE\\SAM", "offset": 0xF8A0_0003_4000},
        },
    ]
    return d


# --- Linux server -------------------------------------------------------------------------

LINUX_HISTORY = [
    "sudo apt update && sudo apt upgrade -y",
    "systemctl status nginx",
    "tail -n 200 /var/log/nginx/error.log",
    "curl -s https://api.example.com/health",
    "wget https://downloads.example.org/releases/app-2.4.1.tar.gz",
    "tar xzf app-2.4.1.tar.gz && cd app-2.4.1",
    "nc -zv 10.0.0.31 5432",
    "python3 -c \"import json,sys; print(json.load(sys.stdin)['version'])\" < package.json",
    "mysql -u root -pHunter2pass appdb",
    "ssh -p 2222 deploy@10.0.0.40",
    "git pull --ff-only",
    "docker compose ps",
    "chmod +x deploy.sh && ./deploy.sh staging",
    "export PGPASSWORD_FILE=/etc/app/pgpass && psql -h 10.0.0.31 -U app appdb",
    "ls -la /etc/nginx/sites-enabled",
]
LINUX_SECRETS = ["Hunter2pass"]


def linux_server() -> Draft:
    banner = "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
    d = Draft(
        os="linux",
        profile=MemoryProfile.TRIAGE,
        image={
            "kind": "image",
            "size_bytes": 4_294_967_296,
            "sha256": "3" * 64,
            "layer": "LimeLayer>Intel32e",
            "arch": "x64",
            "kernel_banner": banner,
            "system_time": SYSTEM_TIME,
        },
    )
    p = d.add_process

    def lp(pid: int, ppid: int, name: str, cmd: str | None, minute: int) -> None:
        p(pid, ppid, name, None, minute, cmdline=cmd, sources=("pslist",), threads=1, session=0)

    lp(1, 0, "systemd", "/sbin/init", 0)
    lp(2, 0, "kthreadd", None, 0)
    for i in range(8):
        lp(10 + i, 2, f"kworker/{i}:1", None, 0)
    for pid, name, cmd in (
        (301, "systemd-journal", "/lib/systemd/systemd-journald"),
        (330, "systemd-udevd", "/lib/systemd/systemd-udevd"),
        (402, "systemd-network", "/lib/systemd/systemd-networkd"),
        (410, "systemd-resolve", "/lib/systemd/systemd-resolved"),
        (
            430,
            "dbus-daemon",
            "/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only",
        ),
        (441, "rsyslogd", "/usr/sbin/rsyslogd -n -iNONE"),
        (450, "cron", "/usr/sbin/cron -f"),
        (460, "chronyd", "/usr/sbin/chronyd -F 1"),
        (480, "containerd", "/usr/bin/containerd"),
        (520, "dockerd", "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"),
        (600, "sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
        (610, "agetty", "/sbin/agetty -o -p -- \\u --noclear - linux"),
        (700, "nginx", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
        (
            800,
            "postgres",
            "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main -c config_file=/etc/postgresql/15/main/postgresql.conf",
        ),
        (
            900,
            "gunicorn",
            "/srv/app/venv/bin/python3 /srv/app/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 app.wsgi:application",
        ),
        (950, "node", "node /srv/metrics/server.js --port 9100"),
    ):
        lp(pid, 1, name, cmd, 1)
    for i in range(4):
        lp(701 + i, 700, "nginx", "nginx: worker process", 1)
    for i, role in enumerate(
        (
            "checkpointer",
            "background writer",
            "walwriter",
            "autovacuum launcher",
            "logical replication launcher",
        )
    ):
        lp(801 + i, 800, "postgres", f"postgres: 15/main: {role}", 1)
    lp(820, 800, "postgres", "postgres: 15/main: app appdb 10.0.0.12(51234) idle", 20)
    for i in range(3):
        lp(
            901 + i,
            900,
            "gunicorn",
            "/srv/app/venv/bin/python3 /srv/app/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 app.wsgi:application",
            1,
        )
    lp(1022, 600, "sshd", "sshd: deploy [priv]", 30)
    lp(1029, 1022, "sshd", "sshd: deploy@pts/0", 30)
    lp(1030, 1029, "bash", "-bash", 30)
    lp(1090, 1030, "sudo", "sudo -i", 60)
    lp(1091, 1090, "bash", "-bash", 60)
    lp(1095, 1091, "top", "top", 80)

    d.connections += [
        tcp(600, "sshd", "0.0.0.0", 22, state="LISTEN"),
        tcp(700, "nginx", "0.0.0.0", 80, state="LISTEN"),
        tcp(700, "nginx", "0.0.0.0", 443, state="LISTEN"),
        tcp(800, "postgres", "127.0.0.1", 5432, state="LISTEN"),
        tcp(900, "gunicorn", "127.0.0.1", 8000, state="LISTEN"),
        tcp(950, "node", "0.0.0.0", 9100, state="LISTEN"),
        tcp(1029, "sshd", "10.0.0.20", 22, "10.0.0.5", 50522, minute=30),
        tcp(701, "nginx", "10.0.0.20", 443, "192.0.2.150", 61000, minute=88),
        tcp(820, "postgres", "10.0.0.20", 5432, "10.0.0.12", 51234, minute=20),
        {"kind": "connection", "proto": "unix", "pid": 301, "owner": "systemd-journal"},
        {"kind": "connection", "proto": "unix", "pid": 430, "owner": "dbus-daemon"},
    ]
    d.artifacts += [bash(1030, cmd, 31 + i) for i, cmd in enumerate(LINUX_HISTORY)]
    return d


BASELINES = {
    "windows_workstation": windows_workstation,
    "windows_server": windows_server,
    "linux_server": linux_server,
}
