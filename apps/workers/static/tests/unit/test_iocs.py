"""IOC extraction from attacker-controlled strings: what counts, what is noise."""

import time

import pytest

from static_worker.detections.iocs import IocCollector, has_run_key


def iocs(*texts: str) -> set[tuple[str, str]]:
    collector = IocCollector(limit=1000)
    for text in texts:
        collector.observe(text, "strings")
    return set(collector.entries)


def test_urls_domains_ips_emails() -> None:
    found = iocs(
        "GET http://downloads.example.net/update/payload.bin HTTP/1.1",
        "ehttps://cdn.example.org/files/setup.msi",  # UTF-16 artefact glued in front
        "contact: Support@Example.org",
        "c2=198.51.100.23:8443",
        "fallback 2001:db8:85a3::8a2e:370:7334",
        "plain host update.example.com here",
    )
    assert found >= {
        ("url", "http://downloads.example.net/update/payload.bin"),
        ("url", "https://cdn.example.org/files/setup.msi"),
        ("domain", "downloads.example.net"),
        ("domain", "cdn.example.org"),
        ("email", "support@example.org"),
        ("ip", "198.51.100.23"),
        ("ip", "2001:db8:85a3::8a2e:370:7334"),
        ("domain", "update.example.com"),
    }


@pytest.mark.parametrize(
    "noise",
    [
        "kernel32.dll",
        "System.Net.Http",
        "System.Net",
        "settings.ini",
        '<assemblyIdentity version="6.0.0.0" name="x"/>',
        "FileVersion 10.0.19041.1",
        "1.2.0.0",
        "127.0.0.1",
        "0.0.0.0",  # noqa: S104 - a string under test, not a bind address
        "std::vector<int>",
        "d::",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "Hello, world",
    ],
)
def test_common_noise_is_not_an_ioc(noise: str) -> None:
    assert iocs(noise) == set()


def test_registry_and_paths() -> None:
    found = iocs(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CyberLabSvc",
        "C:\\ProgramData\\CyberLabTest\\updater.exe",
        "%APPDATA%\\cyberlab\\cfg.dat",
        "/etc/cron.d/cyberlab",
        "/tmp/.cyberlab",
    )
    assert found == {
        ("registry_key", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("registry_key", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CyberLabSvc"),
        ("file_path", "C:\\ProgramData\\CyberLabTest\\updater.exe"),
        ("file_path", "%APPDATA%\\cyberlab\\cfg.dat"),
        ("file_path", "/etc/cron.d/cyberlab"),
        ("file_path", "/tmp/.cyberlab"),
    }
    assert has_run_key("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    assert not has_run_key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")


def test_cap_and_counts() -> None:
    collector = IocCollector(limit=2)
    for i in range(5):
        collector.observe(f"http://h{i}.example.com/", "strings")
    collector.observe("http://h0.example.com/", "floss")
    assert len(collector.entries) == 2 and collector.capped
    assert collector.entries[("url", "http://h0.example.com/")].count == 2
    assert collector.entries[("url", "http://h0.example.com/")].source == "strings"


def test_hostile_strings_are_linear_time() -> None:
    hostile = [
        "a" * 512, "." * 512, ":" * 512, "\\" * 512, "1." * 256, "a@" * 256, "http://" + "a" * 505,
        "C:\\" + "x\\" * 254, "/" * 512, "a-" * 256 + ".com",
    ]  # fmt: skip
    started = time.monotonic()
    for _ in range(50):
        iocs(*hostile)
    assert time.monotonic() - started < 5
