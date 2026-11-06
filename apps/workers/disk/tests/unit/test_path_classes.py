# ruff: noqa: E501 - test data tables (long literal paths)
"""`detections.paths`: normalisation, the user-writable classes, the clean-system exclusions,
variable expansion from the fixed table and command targets."""

import pytest

from disk_worker.detections import paths


@pytest.mark.parametrize(
    ("raw", "ci", "expected"),
    [
        (
            "C:\\Users\\Alice\\AppData\\Local\\Temp\\X.EXE",
            True,
            "users/alice/appdata/local/temp/x.exe",
        ),
        ("\\??\\C:\\Windows\\Temp\\a.exe", True, "windows/temp/a.exe"),
        ("\\\\?\\C:\\ProgramData\\x.exe", True, "programdata/x.exe"),
        ("Users//alice/./Downloads/", True, "users/alice/downloads"),
        (
            "Users/alice/Downloads/evil.exe. ",
            True,
            "users/alice/downloads/evil.exe",
        ),  # Win32 trailing dot / space
        ("/tmp/.X/Miner", False, "tmp/.X/Miner"),  # ext is case-sensitive
    ],
)
def test_normalize(raw: str, ci: bool, expected: str) -> None:
    assert paths.normalize(raw, ci) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%SystemRoot%\\system32\\svchost.exe", "windows/system32/svchost.exe"),
        ("%windir%\\Temp\\x.exe", "windows/temp/x.exe"),
        ("%ProgramData%\\x.exe", "programdata/x.exe"),
        ("%PUBLIC%\\x.exe", "users/public/x.exe"),
        ("%TEMP%\\x.exe", "users/%user%/appdata/local/temp/x.exe"),
        ("%LOCALAPPDATA%\\Temp\\x.exe", "users/%user%/appdata/local/temp/x.exe"),
        ("\\SystemRoot\\System32\\drivers\\x.sys", "windows/system32/drivers/x.sys"),
        ("System32\\drivers\\x.sys", "windows/system32/drivers/x.sys"),
        ("%ATTACKER_VAR%\\x.exe", "%attacker_var%/x.exe"),  # never expanded: not in the table
    ],
)
def test_expansion_uses_the_fixed_table_only(raw: str, expected: str) -> None:
    assert paths.windows_path(raw) == expected


WINDOWS_WRITABLE = [
    ("users/alice/appdata/local/temp/a.exe", "user temp directory"),
    ("users/%user%/appdata/local/temp/a.exe", "user temp directory"),
    ("users/bob/downloads/sub/a.exe", "Downloads folder"),
    ("users/public/libraries/a.dll", "public user profile"),
    ("programdata/a.exe", "ProgramData"),
    ("programdata/vendor/a.exe", "ProgramData"),
    ("windows/temp/a.exe", "Windows temp directory"),
    ("$recycle.bin/s-1-5-21-1/$r1.exe", "Recycle Bin"),
]
WINDOWS_NOT_WRITABLE = [
    "windows/system32/a.exe",
    "program files/vendor/a.exe",
    "users/alice/appdata/roaming/vendor/a.exe",
    "users/alice/documents/a.exe",
    "users/alice/downloads",  # the folder itself
    "programdata",
    # clean-system exclusions (M8 RT21 lesson)
    "programdata/microsoft/windows defender/platform/4.18.24090.11-0/msmpeng.exe",
    "programdata/microsoft/windows defender/definition updates/{x}/mpengine.dll",
    "programdata/microsoft/windows defender advanced threat protection/platform/1/mssense.exe",
    "programdata/package cache/{x}/vc_redist.x64.exe",
    "programdata/microsoft/clicktorun/officeclicktorun.exe",
    "windows/installer/{x}/icon.exe",
]


@pytest.mark.parametrize(("path", "cls"), WINDOWS_WRITABLE)
def test_windows_user_writable(path: str, cls: str) -> None:
    assert paths.user_writable_class(path, "windows") == cls


@pytest.mark.parametrize("path", WINDOWS_NOT_WRITABLE)
def test_windows_not_user_writable(path: str) -> None:
    assert paths.user_writable_class(path, "windows") is None


@pytest.mark.parametrize(
    ("path", "cls"),
    [
        ("tmp/x", "/tmp"),
        ("tmp/.x/miner", "/tmp"),
        ("var/tmp/k", "/var/tmp"),
        ("dev/shm/.s", "/dev/shm"),
        ("home/alice/.local/bin/agent", "hidden directory in a home directory"),
        ("home/alice/.x", "hidden directory in a home directory"),
    ],
)
def test_linux_user_writable(path: str, cls: str) -> None:
    assert paths.user_writable_class(path, "linux") == cls


@pytest.mark.parametrize(
    "path",
    [
        "tmp",
        "usr/bin/curl",
        "home/alice/bin/tool",
        "home/alice/..",
        "TMP/x",  # case-sensitive
        "home/alice/.cache/pip/wheels/a.so",
        "home/alice/.vscode-server/bin/abc/node",
        "home/alice/.local/lib/python3.11/site-packages/x.so",
        "home/alice/.cargo/bin/rustc",
        "home/alice/.mozilla/firefox/x/gmp-widevinecdm/libwidevinecdm.so",
    ],
)
def test_linux_not_user_writable(path: str) -> None:
    assert paths.user_writable_class(path, "linux") is None


def test_exclusions_are_lowercase_for_windows_and_every_class_is_reachable() -> None:
    assert all(p == p.lower() for p in paths.WINDOWS_EXCLUSIONS)
    assert {cls for _, cls in WINDOWS_WRITABLE} == set(paths.WINDOWS_CLASSES)


@pytest.mark.parametrize(
    ("command", "named", "expected"),
    [
        (
            '"C:\\Program Files\\Vendor\\app.exe" /background',
            False,
            ["C:\\Program Files\\Vendor\\app.exe"],
        ),
        (
            "sync: C:\\Users\\a\\AppData\\Local\\Temp\\u.exe",
            True,
            ["C:\\Users\\a\\AppData\\Local\\Temp\\u.exe"],
        ),
        ("rundll32.exe C:\\ProgramData\\h.dll,Start", False, ["C:\\ProgramData\\h.dll"]),
        (
            '"C:\\Python\\python.exe" C:\\Users\\Public\\x.py',
            False,
            ["C:\\Python\\python.exe", "C:\\Users\\Public\\x.py"],
        ),
        ("cmd.exe /c echo a > \\\\.\\pipe\\a", False, ["cmd.exe"]),
        (
            "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
            False,
            ["%SystemRoot%\\system32\\svchost.exe"],
        ),
    ],
)
def test_windows_targets(command: str, named: bool, expected: list[str]) -> None:
    assert paths.windows_targets(command, named=named) == expected


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/tmp/.x/miner -B", "/tmp/.x/miner"),
        ('/bin/sh -c "/dev/shm/run.sh"', "/dev/shm/run.sh"),
        ("nohup /var/tmp/k &", "/var/tmp/k"),
        ("cd / && run-parts --report /etc/cron.hourly", None),
        ("[ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean", None),
        ("find /tmp -type f -delete", None),
    ],
)
def test_linux_target(command: str, expected: str | None) -> None:
    assert paths.linux_target(command) == expected


def test_startup_task_and_standard_locations() -> None:
    assert paths.is_startup(
        "users/a/appdata/roaming/microsoft/windows/start menu/programs/startup/x.lnk"
    )
    assert paths.is_startup("programdata/microsoft/windows/start menu/programs/startup/x.bat")
    assert not paths.is_startup(
        "users/a/appdata/roaming/microsoft/windows/start menu/programs/x.lnk"
    )
    assert paths.is_task("windows/system32/tasks/microsoft/windows/x")
    assert paths.is_standard_program("program files (x86)/x/y.exe")
    assert paths.is_standard_program(
        "programdata/microsoft/windows defender/definition updates/{x}/mpksldrv.sys"
    )
    assert not paths.is_standard_program("windows/psexesvc.exe")


def test_hostile_paths_stay_bounded() -> None:
    """Long and odd input never makes the matchers slow or raise."""
    long_path = "a/" * 2000 + "b.exe"
    assert paths.user_writable_class(paths.normalize(long_path, True), "windows") is None
    text = "C:\\" + "x" * 5000 + " " * 3000
    assert len(paths.windows_targets(text)) <= paths.MAX_TARGETS
