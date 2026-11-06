# ruff: noqa: E501 - hand-written synthetic paths, one per line
"""Benign baselines of the disk scenario set (M9 phase 6): a Windows 10-shaped and a Windows
11-shaped workstation (NTFS system volume, FAT32 EFI partition; the Windows 11 one also has a
FAT32 USB stick with local, 2-second file times) and a Debian-shaped server (ext4), each with a
file tree of a few thousand paths at realistic install locations and the events of a quiet week
(2026-10-01 .. 2026-10-08 UTC).

Seeded and deterministic (`random.Random(SEED + n)`); built in memory, never committed as
output. Hard negatives live here on purpose: Windows Defender platform and definition updates,
OneDrive / Teams per-user installs, package caches, Recent-items shortcuts named `x.pdf.lnk`,
`Zone.Identifier` streams, legitimate service installs from installer paths, `sudo` usage,
package-created system accounts, loopback logons, failed logons below the burst threshold and
near-miss command lines. Every view says it is synthetic (`records.HEADER_NOTE`).
"""

import random
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import cache
from typing import Any

from cyberlab_jobs.disk import DiskEventRecord, DiskFileRecord, DiskPartitionRecord, DiskView

from dataset import records as r

SEED = 9061
WEEK_START = r.ts("2026-10-01T00:00:00")
INSTALL = r.ts("2026-03-10T09:00:00")
OLD = r.ts("2026-05-02T10:00:00")
SECURITY = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"
SCM = "Service Control Manager"
DEFENDER_PLATFORM = "ProgramData/Microsoft/Windows Defender/Platform/4.18.24090.11-0"
DEFENDER_DEFS = "ProgramData/Microsoft/Windows Defender/Definition Updates/{6E1D2C4A-58B1-4E5B-9D44-3E7F0A1B2C3D}"

_SYLLABLES = "ad ap bc cf cl cm cr ds dx fs gd hl hv ip ks lm mf ms nc nt ol pc pr rp sc sh sr ss sv tc tp ui ux vb wd wl wm ws xp".split()


def _names(rng: random.Random, n: int, ext: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    while len(out) < n:
        name = "".join(rng.choice(_SYLLABLES) for _ in range(rng.randint(2, 4))) + f".{ext}"
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


@dataclass
class Draft:
    """A baseline (or a scenario under construction): records plus the makers that continue
    their numbering."""

    name: str
    profile: str
    partitions: list[DiskPartitionRecord]
    files: list[DiskFileRecord] = field(default_factory=list)
    events: list[DiskEventRecord] = field(default_factory=list)
    maker: r.FileMaker = field(default_factory=r.FileMaker)

    # files
    def add_file(self, part: int, path: str, **kw: Any) -> DiskFileRecord:
        record = self.maker.file(part, path, **kw)
        self.files.append(record)
        return record

    # events
    @property
    def next_ordinal(self) -> int:
        return len(self.events)

    def add_event(
        self,
        when: datetime,
        artifact: str,
        data_type: str,
        path: str,
        message: str,
        attributes: dict[str, Any] | None = None,
        **kw: Any,
    ) -> DiskEventRecord:
        record = r.event(
            self.next_ordinal, when, artifact, data_type, path, message, attributes, **kw
        )
        self.events.append(record)
        return record

    def add_evtx(
        self,
        when: datetime,
        provider: str,
        event_id: int,
        strings: list[str],
        channel: str = "Security",
    ) -> DiskEventRecord:
        record = r.evtx(self.next_ordinal, when, provider, event_id, strings, channel)
        self.events.append(record)
        return record

    def add_syslog(
        self,
        when: datetime,
        reporter: str,
        body: str,
        *,
        path: str = "var/log/auth.log",
        artifact: str = "auth_log",
        pid: int = 1000,
    ) -> DiskEventRecord:
        return self.add_event(
            when,
            artifact,
            "syslog:line",
            path,
            f"[{reporter}, pid: {pid}] {body}",
            {"reporter": reporter, "body": body, "pid": pid, "hostname": "srv-01"},
            part=r.EXT_PARTITION,
            parser="syslog",
            ts_desc="Content Modification Time",
        )

    def add_bash(self, when: datetime, command: str, user: str = "alice") -> DiskEventRecord:
        home = "root" if user == "root" else f"home/{user}"
        return self.add_event(
            when,
            "shell_history",
            "bash:history:command",
            f"{home}/.bash_history",
            f"Command executed: {command}",
            {"command": command},
            part=r.EXT_PARTITION,
            parser="bash_history",
            ts_desc="Last Time Executed",
        )

    def add_registry(
        self,
        when: datetime,
        artifact: str,
        data_type: str,
        hive: str,
        key: str,
        message_tail: str,
        attributes: dict[str, Any],
    ) -> DiskEventRecord:
        return self.add_event(
            when,
            artifact,
            data_type,
            hive,
            f"[{key}] {message_tail}",
            {"key_path": key, **attributes},
            parser="winreg",
            ts_desc="Last Written Time",
        )

    def add_run_key(
        self, when: datetime, key: str, entries: list[str], hive: str = "Users/alice/NTUSER.DAT"
    ) -> DiskEventRecord:
        attrs: dict[str, Any] = {"entries_count": len(entries)}
        attrs.update({f"entries.{i}": e for i, e in enumerate(entries)})
        artifact = "registry_user" if hive.casefold().endswith("ntuser.dat") else "registry_system"
        return self.add_registry(
            when, artifact, "windows:registry:run", hive, key, " ".join(entries), attrs
        )

    def add_service_key(
        self, when: datetime, name: str, image: str, start_type: int = 2
    ) -> DiskEventRecord:
        key = f"HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\{name}"
        return self.add_registry(
            when,
            "registry_system",
            "windows:registry:service",
            "Windows/System32/config/SYSTEM",
            key,
            f"ImagePath: {image} Start: {start_type}",
            {"image_path": image, "start_type": start_type, "service_type": 16},
        )

    def add_prefetch(self, when: datetime, exe: str, hint: str) -> DiskEventRecord:
        path = f"Windows/Prefetch/{exe}-1A2B3C4D.pf"
        return self.add_event(
            when,
            "prefetch",
            "windows:prefetch:execution",
            path,
            f"Prefetch [{exe}] was executed - run count 1 path hints: {hint}",
            {"executable": exe, "run_count": 1, "path_hints.0": hint, "path_hints_count": 1},
            parser="prefetch",
            ts_desc="Last Time Executed",
        )

    def view(self) -> DiskView:
        return r.view(
            self.partitions, self.files, self.events, profile=self.profile, label=self.name
        )

    def copy(self, name: str) -> "Draft":
        maker = r.FileMaker(self.maker.ext_partitions, dict(self.maker.next_addr))
        return Draft(
            name, self.profile, list(self.partitions), list(self.files), list(self.events), maker
        )


def _bind(method: Callable[..., object], *args: Any) -> Callable[[Draft, datetime], object]:
    """`method(draft, when, *args)` with `args` bound now (not at call time)."""
    return lambda d, w: method(d, w, *args)


def _sorted_events(
    d: Draft, raw: list[tuple[datetime, Callable[[Draft, datetime], object]]]
) -> None:
    for when, add in sorted(raw, key=lambda item: item[0]):
        add(d, when)


# --- Windows ------------------------------------------------------------------------------------


def _windows_tree(d: Draft, rng: random.Random, version: str) -> None:
    P = r.NTFS_PARTITION
    add = d.add_file
    add(1, "EFI/Microsoft/Boot/bootmgfw.efi", magic="pe", mtime=INSTALL)
    add(1, "EFI/Boot/bootx64.efi", magic="pe", mtime=INSTALL)
    add(1, "EFI/Microsoft/Boot/BCD", mtime=INSTALL)
    for directory in (
        "Windows",
        "Windows/System32",
        "Windows/SysWOW64",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "Users",
        "Users/alice",
        "Users/bob",
        "Users/Public",
    ):
        add(P, directory, ftype="dir", mtime=INSTALL)
    for name in _names(rng, 900, "dll"):
        add(
            P,
            f"Windows/System32/{name}",
            magic="pe",
            size=rng.randint(20_000, 2_000_000),
            mtime=INSTALL,
            known="good",
            known_set="nsrl-minimal",
        )
    for name in _names(rng, 150, "exe"):
        add(
            P,
            f"Windows/System32/{name}",
            magic="pe",
            size=rng.randint(20_000, 900_000),
            mtime=INSTALL,
        )
    for name in (
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "cmd.exe",
        "wevtutil.exe",
        "vssadmin.exe",
        "certutil.exe",
        "SecurityHealthSystray.exe",
    ):
        add(
            P,
            f"Windows/System32/{name}",
            magic="pe",
            mtime=INSTALL,
            known="good",
            known_set="nsrl-minimal",
        )
    add(P, "Windows/System32/WindowsPowerShell/v1.0/powershell.exe", magic="pe", mtime=INSTALL)
    for name in _names(rng, 60, "dll.mui"):
        add(P, f"Windows/System32/en-US/{name}", magic="pe", mtime=INSTALL)
    for name in _names(rng, 160, "sys"):
        add(P, f"Windows/System32/drivers/{name}", magic="pe", mtime=INSTALL)
    for name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"):
        add(
            P,
            f"Windows/System32/config/{name}",
            size=8_388_608,
            mtime=WEEK_START + timedelta(days=6),
        )
    for channel in (
        "Security",
        "System",
        "Application",
        "Setup",
        "Microsoft-Windows-PowerShell%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-Windows Defender%4Operational",
    ):
        add(
            P,
            f"Windows/System32/winevt/Logs/{channel}.evtx",
            size=20_975_616,
            mtime=WEEK_START + timedelta(days=7),
        )
    for task in (
        "Microsoft/Windows/UpdateOrchestrator/Schedule Scan",
        "Microsoft/Windows/Defrag/ScheduledDefrag",
        "Microsoft/Windows/Windows Defender/Windows Defender Scheduled Scan",
        "Microsoft/Windows/WindowsUpdate/Scheduled Start",
        "MicrosoftEdgeUpdateTaskMachineCore",
        "OneDrive Reporting Task-S-1-5-21-1-2-3-1104",
    ):
        add(P, f"Windows/System32/Tasks/{task}", size=3_400, mtime=OLD)
    for name in _names(rng, 300, "dll"):
        add(P, f"Windows/SysWOW64/{name}", magic="pe", mtime=INSTALL)
    for i, name in enumerate(_names(rng, 200, "dll")):
        add(
            P,
            f"Windows/WinSxS/amd64_microsoft-windows-{i:04d}_31bf3856ad364e35_10.0.19041.{i}_none/{name}",
            magic="pe",
            mtime=INSTALL,
        )
    add(
        P,
        "Windows/Installer/{4A03706F-666A-4037-7777-5F2748764D10}/ARPPRODUCTICON.exe",
        magic="pe",
        mtime=OLD,
    )
    add(P, "Windows/Installer/1a2b3c.msi", magic="other", mtime=OLD)
    add(P, "Windows/Temp/MpCmdRun.log", magic="other", mtime=WEEK_START + timedelta(days=5))
    add(P, "Windows/Temp/vminst.log", magic="other", mtime=OLD)
    for exe in (
        "CHROME.EXE",
        "EXPLORER.EXE",
        "NOTEPAD.EXE",
        "MSEDGE.EXE",
        "ONEDRIVE.EXE",
        "TEAMS.EXE",
        "WINWORD.EXE",
        "CMD.EXE",
        "POWERSHELL.EXE",
        "SVCHOST.EXE",
        "WEVTUTIL.EXE",
        "CERTUTIL.EXE",
    ):
        add(
            P,
            f"Windows/Prefetch/{exe}-1A2B3C4D.pf",
            mtime=WEEK_START + timedelta(days=rng.randint(0, 6)),
        )
    add(
        P,
        "Windows/AppCompat/Programs/Amcache.hve",
        size=1_048_576,
        mtime=WEEK_START + timedelta(days=6),
    )
    # Program Files
    apps = {
        "Google/Chrome/Application": 40,
        "Mozilla Firefox": 30,
        "7-Zip": 6,
        "Notepad++": 12,
        "Microsoft Office/root/Office16": 80,
        "Acme/Backup Agent": 10,
        "WindowsApps/Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe": 8,
    }
    for app, n in apps.items():
        for name in _names(rng, n, "dll"):
            add(P, f"Program Files/{app}/{name}", magic="pe", mtime=INSTALL)
        add(P, f"Program Files/{app}/setup.x64.exe", magic="pe", mtime=INSTALL)
    add(P, "Program Files/Acme/Backup Agent/acmesvc.exe", magic="pe", mtime=INSTALL)
    add(P, "Program Files/Mozilla Firefox/browser/jquery.min.js", magic="script", mtime=INSTALL)
    add(P, "Program Files/Notepad++/readme.txt", magic="other", mtime=INSTALL)
    for name in _names(rng, 60, "dll"):
        add(
            P,
            f"Program Files (x86)/Microsoft/EdgeUpdate/1.3.195.1/{name}",
            magic="pe",
            mtime=INSTALL,
        )
    add(
        P,
        "Program Files (x86)/Microsoft/EdgeUpdate/MicrosoftEdgeUpdate.exe",
        magic="pe",
        mtime=INSTALL,
    )
    # ProgramData: Defender platform and definitions (hard negatives), package caches
    for name in (
        "MsMpEng.exe",
        "MpCmdRun.exe",
        "NisSrv.exe",
        "MpDefenderCoreService.exe",
        "mpclient.dll",
        "mpsvc.dll",
        "MpOav.dll",
    ):
        add(P, f"{DEFENDER_PLATFORM}/{name}", magic="pe", mtime=INSTALL + timedelta(days=150))
    for name in ("mpengine.dll", "MpKslDrv.sys", "mpasbase.vdm", "mpavbase.vdm"):
        magic = "pe" if name.endswith((".dll", ".sys")) else "other"
        add(
            P, f"{DEFENDER_DEFS}/{name}", magic=magic, mtime=WEEK_START + timedelta(days=5, hours=3)
        )
    add(
        P,
        "ProgramData/Package Cache/{8A4C1B5E-3F2D-4C6B-9E1A-7D5F3B2C1A09}/VC_redist.x64.exe",
        magic="pe",
        mtime=OLD,
    )
    add(
        P,
        "ProgramData/Microsoft/Windows/Start Menu/Programs/Accessories/Notepad.lnk",
        mtime=INSTALL,
    )
    add(P, "ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_x/Report.wer", mtime=OLD)
    add(P, "ProgramData/Microsoft/Network/Downloader/qmgr.db", mtime=OLD)
    # Users
    for user in ("alice", "bob"):
        base = f"Users/{user}"
        add(P, f"{base}/NTUSER.DAT", size=2_097_152, mtime=WEEK_START + timedelta(days=6))
        add(
            P,
            f"{base}/AppData/Local/Microsoft/Windows/UsrClass.dat",
            size=1_048_576,
            mtime=WEEK_START + timedelta(days=6),
        )
        add(
            P,
            f"{base}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/desktop.ini",
            magic="other",
            size=174,
            mtime=INSTALL,
        )
        add(P, f"{base}/AppData/Local/Microsoft/OneDrive/OneDrive.exe", magic="pe", mtime=OLD)
        for name in _names(rng, 15, "dll"):
            add(
                P,
                f"{base}/AppData/Local/Microsoft/OneDrive/24.180.0905.0002/{name}",
                magic="pe",
                mtime=OLD,
            )
        add(P, f"{base}/AppData/Local/Microsoft/Teams/current/Teams.exe", magic="pe", mtime=OLD)
        add(P, f"{base}/AppData/Local/Microsoft/Teams/Update.exe", magic="pe", mtime=OLD)
        for _ in range(25):
            add(
                P,
                f"{base}/AppData/Local/Temp/{rng.randrange(16**8):08x}.tmp",
                magic="other",
                mtime=WEEK_START + timedelta(days=rng.randint(0, 6)),
            )
        add(
            P,
            f"{base}/AppData/Local/Temp/wct{user}.log",
            magic="other",
            mtime=WEEK_START + timedelta(days=2),
        )
        for i, doc in enumerate(
            (
                "invoice_2026-09.pdf",
                "quarterly report.docx",
                "budget.xlsx",
                "slides.pptx",
                "photo.jpg",
                "archive.tar.gz",
                "backup.2024.zip",
                "report.final.pdf",
            )
        ):
            downloaded = add(
                P,
                f"{base}/Downloads/{doc}",
                magic="document"
                if not doc.endswith((".zip", ".gz", ".jpg"))
                else "archive"
                if not doc.endswith(".jpg")
                else "other",
                mtime=WEEK_START + timedelta(days=i % 7, hours=9),
            )
            add(
                P,
                downloaded.path,
                magic="other",
                size=26,
                mtime=downloaded.mtime,
                stream="Zone.Identifier",
                addr=downloaded.meta_addr,
            )
            add(
                P,
                f"{base}/AppData/Roaming/Microsoft/Windows/Recent/{doc}.lnk",
                magic="other",
                mtime=downloaded.mtime,
            )
        add(P, f"{base}/Documents/notes.txt", magic="other", mtime=WEEK_START + timedelta(days=3))
        notes = d.files[-1]
        add(
            P,
            notes.path,
            magic="other",
            size=90,
            stream="SmartScreen",
            mtime=notes.mtime,
            addr=notes.meta_addr,
        )
        for name in _names(rng, 120, "docx"):
            add(P, f"{base}/Documents/{name}", magic="document", mtime=OLD, known=None)
        for name in _names(rng, 40, "jpg"):
            add(P, f"{base}/Pictures/{name}", magic="other", mtime=OLD)
    add(P, "Users/Public/Desktop/desktop.ini", magic="other", mtime=INSTALL)
    add(P, "Users/Public/Documents/desktop.ini", magic="other", mtime=INSTALL)
    add(P, "$Recycle.Bin/S-1-5-21-1-2-3-1104/desktop.ini", magic="other", mtime=INSTALL)
    add(
        P,
        "$Recycle.Bin/S-1-5-21-1-2-3-1104/$IAB12CD.docx",
        magic="other",
        size=544,
        mtime=WEEK_START + timedelta(days=4),
    )
    add(
        P,
        "$Recycle.Bin/S-1-5-21-1-2-3-1104/$RAB12CD.docx",
        magic="document",
        mtime=WEEK_START + timedelta(days=4),
    )
    add(P, "pagefile.sys", magic="other", size=4 * 1024**3, mtime=WEEK_START + timedelta(days=7))
    add(P, "Users/alice/Documents/old_draft.docx", deleted=True, mtime=OLD)
    del version


def _windows_events(d: Draft, rng: random.Random, version: str) -> None:
    raw: list[tuple[datetime, Callable[[Draft, datetime], object]]] = []

    def at(when: datetime, add: Callable[[Draft, datetime], object]) -> None:
        raw.append((when, add))

    for day in range(7):
        morning = WEEK_START + timedelta(days=day, hours=8, minutes=rng.randint(0, 40))
        at(
            morning,
            lambda d, w: d.add_evtx(w, SECURITY, 4624, r.logon_strings("alice", 2, "127.0.0.1")),
        )
        at(
            morning + timedelta(hours=4),
            lambda d, w: d.add_evtx(w, SECURITY, 4624, r.logon_strings("alice", 7, "-")),
        )
        at(
            morning + timedelta(hours=9),
            lambda d, w: d.add_evtx(
                w, SECURITY, 4634, ["S-1-5-21-1-2-3-1104", "alice", "CORP", "0x1a2b3c", "2"]
            ),
        )
        for k in range(12):
            when = WEEK_START + timedelta(days=day, hours=2 * k, minutes=rng.randint(0, 59))
            at(when, lambda d, w: d.add_evtx(w, SECURITY, 4624, r.logon_strings("SYSTEM", 5, "-")))
            at(
                when + timedelta(seconds=1),
                lambda d, w: d.add_evtx(
                    w,
                    SECURITY,
                    4672,
                    [
                        "S-1-5-18",
                        "SYSTEM",
                        "NT AUTHORITY",
                        "0x3e7",
                        "SeAssignPrimaryTokenPrivilege",
                    ],
                ),
            )
            at(
                when + timedelta(minutes=3),
                lambda d, w: d.add_evtx(w, SCM, 7036, ["Windows Update", "running"], "System"),
            )
        # network logons from the loopback / no address (hard negatives)
        at(
            morning + timedelta(minutes=5),
            lambda d, w: d.add_evtx(w, SECURITY, 4624, r.logon_strings("alice", 3, "::1")),
        )
        at(
            morning + timedelta(minutes=6),
            lambda d, w: d.add_evtx(w, SECURITY, 4624, r.logon_strings("WKS-01$", 3, "-")),
        )
        at(
            morning + timedelta(hours=2),
            lambda d, w: d.add_evtx(w, SECURITY, 4624, r.logon_strings("alice", 11, "-")),
        )
    # a few failed logons (a mistyped password), far below the burst threshold
    for k in range(5):
        at(
            WEEK_START + timedelta(days=2, hours=8, minutes=k),
            lambda d, w: d.add_evtx(
                w, SECURITY, 4625, r.failed_logon_strings("alice", "10.0.0.23", 2)
            ),
        )
    # service installs from standard locations (hard negatives)
    at(
        WEEK_START + timedelta(days=5, hours=3, minutes=1),
        lambda d, w: d.add_evtx(
            w,
            SCM,
            7045,
            r.service_strings(
                "MpKslDrv", f"C:\\{DEFENDER_DEFS.replace('/', chr(92))}\\MpKslDrv.sys"
            ),
            "System",
        ),
    )
    at(
        WEEK_START + timedelta(days=3, hours=11),
        lambda d, w: d.add_evtx(
            w,
            SCM,
            7045,
            r.service_strings(
                "AcmeBackup", '"C:\\Program Files\\Acme\\Backup Agent\\acmesvc.exe" -service'
            ),
            "System",
        ),
    )
    at(
        WEEK_START + timedelta(days=3, hours=11, minutes=1),
        lambda d, w: d.add_evtx(
            w,
            SCM,
            7045,
            r.service_strings("vmci", "\\SystemRoot\\System32\\drivers\\vmci.sys"),
            "System",
        ),
    )
    # a record of another provider with id 104 (not a log clearing)
    at(
        WEEK_START + timedelta(days=4, hours=2),
        lambda d, w: d.add_evtx(w, "VSS", 104, ["0x80042306"], "Application"),
    )
    # registry: autostart values and services of a clean system
    hkcu_run = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    hklm_run = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    at(
        WEEK_START + timedelta(days=6, hours=8),
        lambda d, w: d.add_run_key(
            w,
            hkcu_run,
            [
                'OneDrive: "C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
                'com.squirrel.Teams.Teams: C:\\Users\\alice\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart "Teams.exe" --process-start-args "--system-initiated"',
            ],
        ),
    )
    at(
        WEEK_START + timedelta(days=6, hours=8, minutes=1),
        lambda d, w: d.add_run_key(
            w,
            hklm_run,
            [
                "SecurityHealth: %windir%\\system32\\SecurityHealthSystray.exe",
                'RtkAudUService: "C:\\Windows\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_1a2b\\RtkAudUService64.exe" -background',
            ],
            "Windows/System32/config/SOFTWARE",
        ),
    )
    services = [
        ("WinDefend", f'"C:\\{DEFENDER_PLATFORM.replace("/", chr(92))}\\MsMpEng.exe"'),
        ("WdNisSvc", f'"C:\\{DEFENDER_PLATFORM.replace("/", chr(92))}\\NisSrv.exe"'),
        (
            "edgeupdate",
            '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /svc',
        ),
        ("AcmeBackup", '"C:\\Program Files\\Acme\\Backup Agent\\acmesvc.exe" -service'),
        ("vmci", "\\SystemRoot\\System32\\drivers\\vmci.sys"),
        ("disk", "System32\\drivers\\disk.sys"),
    ] + [(f"svc{i:02d}", "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p") for i in range(50)]
    for i, (name, image) in enumerate(services):
        at(
            INSTALL + timedelta(minutes=i),
            _bind(Draft.add_service_key, name, image),
        )
    # execution artifacts of ordinary programs
    for day in range(7):
        for exe, hint in (
            ("CHROME.EXE", "\\PROGRAM FILES\\GOOGLE\\CHROME\\APPLICATION\\CHROME.EXE"),
            ("WINWORD.EXE", "\\PROGRAM FILES\\MICROSOFT OFFICE\\ROOT\\OFFICE16\\WINWORD.EXE"),
            ("NOTEPAD.EXE", "\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"),
        ):
            at(
                WEEK_START + timedelta(days=day, hours=9, minutes=rng.randint(0, 50)),
                _bind(Draft.add_prefetch, exe, hint),
            )
    at(
        WEEK_START + timedelta(days=2, hours=10),
        lambda d, w: d.add_event(
            w,
            "registry_user",
            "windows:registry:userassist",
            "Users/alice/NTUSER.DAT",
            "[HKEY_CURRENT_USER\\...\\UserAssist] Value name: {6D809377-6AF0-444B-8957-A3773F02200E}\\Notepad++\\notepad++.exe Count: 4",
            {
                "value_name": "{6D809377-6AF0-444B-8957-A3773F02200E}\\Notepad++\\notepad++.exe",
                "number_of_executions": 4,
            },
        ),
    )
    at(
        WEEK_START + timedelta(days=2, hours=10, minutes=5),
        lambda d, w: d.add_event(
            w,
            "registry_system",
            "windows:registry:bam",
            "Windows/System32/config/SYSTEM",
            "\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            {
                "binary_path": "\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
            },
        ),
    )
    at(
        WEEK_START + timedelta(days=1, hours=14),
        lambda d, w: d.add_event(
            w,
            "amcache",
            "windows:registry:amcache",
            "Windows/AppCompat/Programs/Amcache.hve",
            "path: c:\\program files\\7-zip\\7zfm.exe",
            {"full_path": "c:\\program files\\7-zip\\7zfm.exe"},
        ),
    )
    if version == "11":
        # process auditing on: near-miss command lines (hard negatives)
        for k, command in enumerate(
            (
                "wevtutil qe Security /c:5 /f:text",
                "vssadmin list shadows",
                "certutil -hashfile C:\\Users\\alice\\Downloads\\invoice_2026-09.pdf SHA256",
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1",
                "cmd.exe /c dir C:\\Users\\alice\\Documents",
                "curl.exe -O https://downloads.example.org/tool.zip",
            )
        ):
            image = command.split(" ", 1)[0]
            at(
                WEEK_START + timedelta(days=3, hours=14, minutes=10 * k),
                _bind(
                    Draft.add_evtx,
                    SECURITY,
                    4688,
                    r.process_strings(f"C:\\Windows\\System32\\{image}", command),
                ),
            )
    _sorted_events(d, raw)


def _windows(version: str) -> Draft:
    rng = random.Random(SEED + (10 if version == "10" else 11))
    partitions = [r.partition(1, "fat32", "none"), r.partition(r.NTFS_PARTITION, "ntfs", "windows")]
    if version == "11":
        partitions.append(r.partition(r.FAT_PARTITION, "fat32", "none"))
    d = Draft(f"windows{version}_workstation", "triage", partitions)
    _windows_tree(d, rng, version)
    if version == "11":
        # A USB stick (FAT32): local times of unknown zone with 2-second resolution.
        for i, name in enumerate(
            ("Setup.exe", "manual.pdf", "photos/IMG_0001.JPG", "photos/IMG_0002.JPG", "notes.txt")
        ):
            when = WEEK_START + timedelta(days=4, hours=10, minutes=i, seconds=2 * i)
            d.add_file(
                r.FAT_PARTITION,
                name.upper() if i == 0 else name,
                magic="pe" if name.endswith(".exe") else "other",
                mtime=when,
                time_basis="local_unknown",
            )
    _windows_events(d, rng, version)
    return d


# --- Debian -------------------------------------------------------------------------------------


def _linux_tree(d: Draft, rng: random.Random) -> None:
    P = r.EXT_PARTITION
    add = d.add_file
    for directory in ("bin", "etc", "home", "home/alice", "root", "tmp", "usr", "var", "var/log"):
        add(P, directory, ftype="dir", mtime=INSTALL)
    for name in _names(rng, 500, "x"):
        add(
            P,
            f"usr/bin/{name[:-2]}",
            magic="elf",
            mtime=INSTALL,
            known="good",
            known_set="nsrl-minimal",
        )
    for name in ("bash", "sh", "curl", "wget", "nc", "python3", "sudo", "ssh", "rclone"):
        add(P, f"usr/bin/{name}", magic="elf", mtime=INSTALL)
    for name in _names(rng, 150, "x"):
        add(P, f"usr/sbin/{name[:-2]}", magic="elf", mtime=INSTALL)
    for name in _names(rng, 700, "so.1"):
        add(P, f"usr/lib/x86_64-linux-gnu/lib{name}", magic="elf", mtime=INSTALL)
    for name in _names(rng, 120, "service"):
        add(P, f"lib/systemd/system/{name}", magic="other", mtime=OLD)
    for name in _names(rng, 250, "conf"):
        add(P, f"etc/{name}", magic="other", mtime=INSTALL)
    for name in (
        "crontab",
        "cron.d/e2scrub_all",
        "cron.d/php",
        "cron.d/.placeholder",
        "cron.daily/apt-compat",
        "cron.daily/dpkg",
        "cron.daily/logrotate",
        "cron.daily/man-db",
        "cron.weekly/man-db",
    ):
        add(
            P,
            f"etc/{name}",
            magic="script" if "daily" in name or "weekly" in name else "other",
            mtime=OLD,
        )
    for name in (
        "ssh.service",
        "multi-user.target.wants/cron.service",
        "multi-user.target.wants/ssh.service",
        "timers.target.wants/apt-daily.timer",
    ):
        add(P, f"etc/systemd/system/{name}", ftype="lnk", mtime=OLD)
    add(P, "etc/ld.so.conf", mtime=INSTALL)
    add(P, "etc/hostname", mtime=INSTALL)
    add(P, "var/spool/cron/crontabs", ftype="dir", mtime=INSTALL)
    for home in ("home/alice", "root"):
        add(P, f"{home}/.bashrc", mtime=INSTALL)
        add(P, f"{home}/.profile", mtime=INSTALL)
        add(P, f"{home}/.bash_history", mtime=WEEK_START + timedelta(days=6))
        add(P, f"{home}/.ssh/authorized_keys", size=742, mtime=OLD)
        add(P, f"{home}/.ssh/known_hosts", size=1_420, mtime=OLD)
    # developer caches in hidden home directories (clean-system exclusions)
    for name in _names(rng, 20, "so"):
        add(P, f"home/alice/.cache/pip/wheels/ab/cd/{name}", magic="elf", mtime=OLD)
        add(
            P,
            f"home/alice/.local/lib/python3.11/site-packages/numpy/core/{name}",
            magic="elf",
            mtime=OLD,
        )
    add(
        P,
        "home/alice/.vscode-server/bin/f1e16e1e6214d7c44d078b1f0607b2388f29d729/node",
        magic="elf",
        mtime=OLD,
    )
    add(P, "home/alice/.cargo/bin/rustc", magic="elf", mtime=OLD)
    add(P, "home/alice/.config/htop/htoprc", mtime=OLD)
    for name in ("systemd-private-6f1e-systemd-logind.service-AbCdEf", ".X11-unix", ".ICE-unix"):
        add(P, f"tmp/{name}", ftype="dir", mtime=WEEK_START + timedelta(days=6))
    add(P, "tmp/sess_2c1f9e0b", mtime=WEEK_START + timedelta(days=5))
    add(
        P,
        "tmp/apt-dpkg-install-Xy12/00-libfoo.deb",
        magic="archive",
        mtime=WEEK_START + timedelta(days=2),
    )
    logs = {
        "auth.log": 48_213,
        "auth.log.1": 120_554,
        "auth.log.2.gz": 9_812,
        "syslog": 300_112,
        "syslog.1": 512_002,
        "wtmp": 384 * 52,
        "wtmp.1": 384 * 410,
        "btmp": 0,
        "lastlog": 292_292,
        "dpkg.log": 40_120,
        "kern.log": 77_310,
    }
    for name, size in logs.items():
        add(
            P,
            f"var/log/{name}",
            size=size,
            magic="empty" if size == 0 else "other",
            mtime=WEEK_START + timedelta(days=7)
            if "." not in name or name.endswith(".log")
            else OLD,
        )


def _linux_events(d: Draft, rng: random.Random) -> None:
    raw: list[tuple[datetime, Callable[[Draft, datetime], object]]] = []

    def at(when: datetime, add: Callable[[Draft, datetime], object]) -> None:
        raw.append((when, add))

    for hour in range(7 * 24):
        when = WEEK_START + timedelta(hours=hour, minutes=17)
        at(
            when,
            lambda d, w: d.add_syslog(
                w,
                "CRON",
                "(root) CMD (cd / && run-parts --report /etc/cron.hourly)",
                path="var/log/syslog",
                artifact="syslog",
            ),
        )
        if hour % 2 == 0:
            at(
                when + timedelta(minutes=22),
                lambda d, w: d.add_syslog(
                    w,
                    "CRON",
                    "(root) CMD ([ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi)",
                    path="var/log/syslog",
                    artifact="syslog",
                ),
            )
        if hour % 6 == 0:
            at(
                when + timedelta(minutes=30),
                lambda d, w: d.add_syslog(
                    w,
                    "CRON",
                    "(root) CMD (find /tmp -type f -atime +10 -delete)",
                    path="var/log/syslog",
                    artifact="syslog",
                ),
            )
        # an Internet scanner: about 6 failures an hour from one source (below the burst rate)
        for k in range(6):
            at(
                WEEK_START + timedelta(hours=hour, minutes=10 * k + 3),
                lambda d, w: d.add_syslog(
                    w,
                    "sshd",
                    "Failed password for invalid user admin from 192.0.2.200 port 40112 ssh2",
                ),
            )
    for day in range(7):
        start = WEEK_START + timedelta(days=day, hours=9, minutes=rng.randint(0, 30))
        at(
            start,
            lambda d, w: d.add_syslog(
                w,
                "sshd",
                "Accepted publickey for alice from 127.0.0.1 port 51022 ssh2: ED25519 SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            ),
        )
        at(
            start + timedelta(minutes=2),
            lambda d, w: d.add_syslog(
                w,
                "sudo",
                "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt upgrade -y",
            ),
        )
        at(
            start + timedelta(minutes=2, seconds=1),
            lambda d, w: d.add_syslog(
                w,
                "sudo",
                "pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
            ),
        )
    at(
        WEEK_START + timedelta(days=2, hours=9, minutes=40),
        lambda d, w: d.add_syslog(
            w,
            "useradd",
            "new user: name=systemd-coredump, UID=998, GID=998, home=/, shell=/usr/sbin/nologin, from=none",
        ),
    )
    at(
        WEEK_START + timedelta(days=2, hours=9, minutes=41),
        lambda d, w: d.add_syslog(w, "usermod", "add 'alice' to group 'audio'"),
    )
    for k, command in enumerate(
        (
            "ls -la",
            "sudo apt update",
            "curl -O https://deb.example.org/pool/main/t/tool/tool_1.2_amd64.deb",
            "wget https://downloads.example.org/release/tool-1.2.tar.gz",
            "nc -zv 10.0.0.5 22",
            "python3 -c 'print(42)'",
            "git clone https://git.example.org/team/infra.git",
            "ssh admin@10.0.0.7",
            "chmod +x ./deploy.sh",
            "tail -f /var/log/syslog",
        )
    ):
        at(
            WEEK_START + timedelta(days=k % 7, hours=10, minutes=5 * k),
            _bind(Draft.add_bash, command),
        )
    _sorted_events(d, raw)


def _linux() -> Draft:
    rng = random.Random(SEED + 20)
    d = Draft("debian_server", "triage", [r.partition(r.EXT_PARTITION, "ext4", "linux")])
    _linux_tree(d, rng)
    _linux_events(d, rng)
    return d


@cache
def _baseline(name: str) -> Draft:
    if name == "windows10_workstation":
        return _windows("10")
    if name == "windows11_workstation":
        return _windows("11")
    if name == "debian_server":
        return _linux()
    raise KeyError(name)


BASELINES: tuple[str, ...] = ("windows10_workstation", "windows11_workstation", "debian_server")


def baseline(name: str) -> Draft:
    """A fresh copy of the (cached) baseline: scenarios append to it."""
    return _baseline(name).copy(name)


__all__ = [
    "BASELINES",
    "DEFENDER_DEFS",
    "DEFENDER_PLATFORM",
    "EVENTLOG",
    "SCM",
    "SECURITY",
    "WEEK_START",
    "Draft",
    "baseline",
]
