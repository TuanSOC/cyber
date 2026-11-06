"""The collect plan (M9 phase 3; pure): phase 1's listings, candidates only, compressed content
(RT11), per-file caps, the category share (newest first), the byte and file budgets, and the
partitions a timeline runs on."""

from cyberlab_jobs.disk import (
    PROFILE_BUDGETS,
    DiskArtifact,
    DiskPartitionRecord,
    DiskProfile,
    never_collect,
)

from disk_worker.timeline import catalog, plan
from tests.unit.phase2_helpers import limits
from tests.unit.timeline_helpers import ALLOCATED, DELETED, contract_files, file

MIB = 1024**2


def test_windows_fixture_plan() -> None:
    selected = catalog.match(contract_files("windows_triage.ndjson"), "windows", "triage")
    paths = {r.path: a for a, r in selected.files}
    assert paths["Windows/System32/config/SYSTEM"] == DiskArtifact.REGISTRY_SYSTEM
    assert paths["Windows/System32/config/SOFTWARE"] == DiskArtifact.REGISTRY_SYSTEM
    assert paths["Windows/AppCompat/Programs/Amcache.hve"] == DiskArtifact.AMCACHE
    assert paths["Users/alice/NTUSER.DAT"] == DiskArtifact.REGISTRY_USER
    assert sum(a == DiskArtifact.PREFETCH for a in paths.values()) == 40
    assert sum(a == DiskArtifact.LNK for a in paths.values()) > 0
    # Not a listed channel, never collected, not an artifact:
    assert not any("Channel" in p or p.endswith("/SAM") or p.endswith(".dll") for p in paths)
    assert all(not never_collect([p], True) for p in paths)
    assert selected.bytes == sum(r.size or 0 for _, r in selected.files)
    order = [a for a, _ in selected.files]
    assert order.index(DiskArtifact.REGISTRY_SYSTEM) < order.index(DiskArtifact.PREFETCH)


def test_linux_fixture_plan() -> None:
    selected = catalog.match(contract_files("linux_triage.ndjson"), "linux", "triage")
    assert {r.path: a.value for a, r in selected.files} == {
        "etc/hostname": "preprocess",
        "etc/passwd": "preprocess",
        "var/log/auth.log": "auth_log",
        "var/log/wtmp": "utmp",
        "root/.bash_history": "shell_history",
        "var/log/syslog": "syslog",
    }


def test_only_allocated_regular_files_without_streams() -> None:
    listing = [
        file("var/log/syslog", 1, flags=DELETED),
        file("var/log/syslog.1", 2, flags=ALLOCATED | 4),  # orphan
        file("var/log/messages", 3, type_="lnk"),
        file("var/log/kern.log", 4, stream="ads"),
        file("var/log/auth.log", 5),
    ]
    selected = plan.build(listing, "linux", "triage")
    assert [r.path for _, r in selected.files] == ["var/log/auth.log"]


def test_compressed_content_is_dropped_unless_a_full_rotated_log() -> None:
    listing = [
        file("var/log/auth.log", 1, magic="archive"),  # a gzip named auth.log
        file("var/log/auth.log.2.gz", 2, magic="archive"),
        file("var/log/syslog.3.bz2", 3, magic="archive"),
        file("var/log/syslog.4.xz", 4, magic="archive", size=65 * MIB),  # > 64 MiB compressed
        file("Windows/Prefetch/X.EXE-1.pf", 5, magic="archive"),
    ]
    triage = plan.build(listing, "linux", "triage")
    assert triage.files == []
    assert triage.dropped["compressed"] == 4
    full = plan.build(listing, "linux", "full")
    assert [r.path for _, r in full.files] == ["var/log/auth.log.2.gz"]
    assert full.dropped == {"compressed": 2, "too_large": 1}
    # Windows has no rotated entry: a compressed prefetch file (MAM) is never collected here.
    assert plan.build(listing, "windows", "full").dropped == {"compressed": 1}


def test_per_file_caps() -> None:
    listing = [
        file("var/log/syslog", 1, size=512 * MIB + 1),
        file("etc/hostname", 2, size=2 * MIB),  # preprocess files are small
        file("var/log/auth.log", 3, size=None),
        file("var/log/wtmp", 4, size=512 * MIB),
    ]
    selected = plan.build(listing, "linux", "full")
    assert [r.path for _, r in selected.files] == ["var/log/wtmp"]
    assert selected.dropped == {"size_unknown": 1, "too_large": 2}
    mft = plan.build([file("$MFT", 9, size=900 * MIB)], "windows", "full")
    assert [r.path for _, r in mft.files] == ["$MFT"]


def test_the_category_share_keeps_the_newest() -> None:
    listing = [
        file(f"var/log/syslog.{i}", 10 + i, mtime=f"2026-10-{1 + i:02d}T08:00:00")
        for i in range(28)
    ] + [file(f"var/log/messages-{i}", 100 + i, mtime=None) for i in range(40)]
    selected = plan.build(listing, "linux", "triage")
    kept = [r.path for a, r in selected.files if a == DiskArtifact.SYSLOG]
    assert len(kept) == 64
    assert kept[0] == "var/log/syslog.27"  # newest first; files without a time come last
    assert selected.dropped["category_cap"] == 28 + 40 - 64


def test_the_byte_and_file_budgets() -> None:
    budget = PROFILE_BUDGETS[DiskProfile.TRIAGE]["artifact_max_bytes"]
    big = 400 * MIB
    listing = [file(f"var/log/syslog.{i}", i + 1, size=big) for i in range(8)]
    selected = plan.build(listing, "linux", "triage")
    assert selected.bytes <= budget
    assert len(selected.files) == budget // big
    assert selected.dropped["budget"] == 8 - budget // big


def test_a_second_name_of_the_same_inode_is_copied_once() -> None:
    listing = [file("var/log/syslog", 7), file("var/log/syslog.1", 7)]
    assert len(plan.build(listing, "linux", "triage").files) == 1


def _partition(index: int, os: str, length: int, status: str = "ok") -> DiskPartitionRecord:
    return DiskPartitionRecord(
        index=index,
        start_sector=2048 + index * 10_000_000,
        length_sectors=length,
        fs_type="ntfs" if status == "ok" else None,
        fs_status=status,  # type: ignore[arg-type]
        os=os,  # type: ignore[arg-type]
    )


def test_timeline_partitions_are_the_largest_os_partitions() -> None:
    parts = [
        _partition(0, "none", 9_000_000),
        _partition(1, "windows", 1_000_000),
        _partition(2, "windows", 5_000_000),
        _partition(3, "linux", 3_000_000),
        _partition(4, "linux", 8_000_000, status="encrypted"),
    ]
    triage = plan.timeline_partitions(parts, limits())
    assert [p.index for p in triage] == [2, 3]
    full = plan.timeline_partitions(parts, limits(max_plaso_partitions=4))
    assert [p.index for p in full] == [2, 3, 1]
