"""The artifact catalog (M9 phase 3; pure): patterns per (OS, profile), case rules, the parser
lists, and that no pattern can ever select a never-collected file under any of its names (RT7)."""

import re

import pytest
from cyberlab_jobs.disk import (
    ARTIFACTS_BY_PROFILE,
    NEVER_COLLECT_PATTERNS,
    DiskArtifact,
    DiskProfile,
    never_collect,
)

from disk_worker.timeline import catalog, plan
from tests.unit.timeline_helpers import file

PROFILES = ("triage", "full")
OSES = ("windows", "linux")


def _instance(pattern: str, fill: str) -> str:
    """A concrete path a glob matches (`**/` one directory, `/**` one file, `*` the fill)."""
    out = pattern.replace("**/", "d/").replace("/**", "/f")
    return out.replace("*", fill)


def _catalog_paths() -> list[tuple[str, str]]:
    return [
        (os_name, _instance(p, "alice"))
        for os_name, entries in catalog.ENTRIES.items()
        for entry in entries
        for p in entry.patterns
    ]


def _never_paths() -> list[str]:
    return [_instance(p, "x") for ps in NEVER_COLLECT_PATTERNS.values() for p in ps]


def test_every_category_of_a_profile_has_an_entry_and_nothing_else() -> None:
    for os_name in OSES:
        for profile in PROFILES:
            wanted = set(ARTIFACTS_BY_PROFILE[(os_name, DiskProfile(profile))])
            entries = catalog.entries_for(os_name, profile)  # type: ignore[arg-type]
            got = {e.artifact for e in entries}
            assert got == wanted, (os_name, profile)


def test_double_star_only_under_the_journal() -> None:
    for entries in catalog.ENTRIES.values():
        for entry in entries:
            for pattern in entry.patterns:
                if "**" in pattern:
                    assert entry.artifact == DiskArtifact.SYSTEMD_JOURNAL
                    assert pattern.startswith("var/log/journal/**/")


def test_every_pattern_matches_its_own_instance() -> None:
    for os_name, path in _catalog_paths():
        assert catalog.classify(path, os_name, "full") is not None, path  # type: ignore[arg-type]


def test_windows_matching_ignores_case_and_linux_does_not() -> None:
    hit = catalog.classify("windows/system32/WINEVT/logs/SECURITY.EVTX", "windows", "triage")
    assert hit is not None and hit.artifact == DiskArtifact.EVTX
    assert catalog.classify("Var/Log/Syslog", "linux", "triage") is None
    hit = catalog.classify("var/log/syslog", "linux", "triage")
    assert hit is not None and hit.artifact == DiskArtifact.SYSLOG


@pytest.mark.parametrize(
    ("path", "os_name", "profile", "artifact"),
    [
        ("Windows/System32/winevt/Logs/Security.evtx", "windows", "triage", "evtx"),
        (
            "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
            "windows",
            "triage",
            "evtx",
        ),
        ("Windows/System32/config/SYSTEM", "windows", "triage", "registry_system"),
        ("Users/bob/NTUSER.DAT", "windows", "triage", "registry_user"),
        (
            "Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat",
            "windows",
            "triage",
            "registry_user",
        ),
        ("Windows/AppCompat/Programs/Amcache.hve", "windows", "triage", "amcache"),
        ("Windows/Prefetch/CMD.EXE-0BD30981.pf", "windows", "triage", "prefetch"),
        (
            "Users/bob/AppData/Roaming/Microsoft/Windows/Recent/a.docx.lnk",
            "windows",
            "triage",
            "lnk",
        ),
        ("$MFT", "windows", "full", "mft"),
        ("$Recycle.Bin/S-1-5-21-1-1001/$IABC.txt", "windows", "full", "recycle_bin"),
        (
            "Users/bob/AppData/Local/Google/Chrome/User Data/Default/History",
            "windows",
            "full",
            "browser",
        ),
        ("etc/timezone", "linux", "triage", "preprocess"),
        ("var/log/auth.log.1", "linux", "triage", "auth_log"),
        ("var/log/secure-20261001", "linux", "triage", "auth_log"),
        ("var/log/wtmp", "linux", "triage", "utmp"),
        ("home/bob/.bash_history", "linux", "triage", "shell_history"),
        ("root/.zsh_history", "linux", "triage", "shell_history"),
        ("var/log/dpkg.log", "linux", "triage", "packages"),
        ("var/log/journal/0123abcd/system.journal", "linux", "full", "systemd_journal"),
        ("home/bob/.mozilla/firefox/x.default/places.sqlite", "linux", "full", "browser"),
    ],
)
def test_catalog_paths(path: str, os_name: str, profile: str, artifact: str) -> None:
    hit = catalog.classify(path, os_name, profile)  # type: ignore[arg-type]
    assert hit is not None and hit.artifact == artifact


@pytest.mark.parametrize(
    ("path", "os_name", "profile"),
    [
        ("$MFT", "windows", "triage"),  # `full` only
        ("Users/bob/AppData/Local/Google/Chrome/User Data/Default/History", "windows", "triage"),
        ("var/log/journal/0123abcd/system.journal", "linux", "triage"),
        ("Windows/System32/winevt/Logs/Channel00.evtx", "windows", "full"),  # not a listed channel
        ("Windows/System32/Tasks/Updater", "windows", "full"),  # task XML is never collected
        ("Windows/System32/config/SAM", "windows", "full"),
        ("Users/bob/NTUSER.DAT/extra", "windows", "full"),  # `*` stays in one component
        ("etc/shadow", "linux", "full"),
    ],
)
def test_not_in_the_catalog(path: str, os_name: str, profile: str) -> None:
    assert catalog.classify(path, os_name, profile) is None  # type: ignore[arg-type]


def test_no_pattern_selects_a_never_collected_name() -> None:
    """Every catalog pattern instance hard-linked to every never-collected class (one inode, two
    names), plus catalog-shaped names that are themselves secrets: the plan selects none."""
    never = _never_paths()
    assert all(never_collect([p], fs_case_insensitive=True) for p in never)
    for os_name in OSES:
        records = []
        meta = 1000
        for listed_os, path in _catalog_paths():
            if listed_os != os_name:
                continue
            for secret in never:
                meta += 1
                records += [file(path, meta), file(secret, meta)]
        for shaped in ("var/log/syslog.key", "var/log/auth.log.pem", "var/log/messages.dmp"):
            meta += 1
            records.append(file(shaped, meta))
        for profile in PROFILES:
            selected = plan.build(records, os_name, profile)  # type: ignore[arg-type]
            assert selected.files == [], (os_name, profile)
            assert selected.refused_never_collect > 0


def test_the_auth_log_hard_linked_to_shadow_is_refused() -> None:
    listing = [file("var/log/auth.log", 19), file("etc/shadow", 19), file("var/log/syslog", 18)]
    selected = plan.build(listing, "linux", "triage")
    assert [r.path for _, r in selected.files] == ["var/log/syslog"]
    assert selected.refused_never_collect == 1


def test_parser_lists_are_fixed_and_exclude_filestat() -> None:
    for os_name in OSES:
        for profile in PROFILES:
            expression = catalog.parser_expression(os_name, profile)  # type: ignore[arg-type]
            assert expression.endswith(",!filestat")
            names = expression.split(",")
            assert len(names) == len(set(names))
            assert all(re.fullmatch(r"!?[a-z0-9_/]+", n) for n in names)
    assert "mft" in catalog.parser_expression("windows", "full")
    assert "mft" not in catalog.parser_expression("windows", "triage")
    assert "systemd_journal" in catalog.parser_expression("linux", "full")
