"""M9 phase 5: YARA candidate selection (PE only, budgets, order, hard links, known-good files
skipped unless they sit in a user-writable path class; RT8, RT18)."""

from typing import Any

import pytest
from cyberlab_jobs.disk import (
    FILE_FLAG_BITS,
    PROFILE_BUDGETS,
    DiskFileRecord,
    DiskLimits,
    DiskProfile,
    default_stage_limits,
    split_event_quotas,
)

from disk_worker import scan
from disk_worker.scan import build_candidates, select_candidates

MIB = 1024**2
ALLOCATED = FILE_FLAG_BITS["allocated"]


def limits(profile: DiskProfile = DiskProfile.TRIAGE, **override: int) -> DiskLimits:
    budgets = {**PROFILE_BUDGETS[profile], **override}
    return DiskLimits.model_validate(
        {
            "max_image_bytes": 16 * 1024**3,
            "max_media_bytes": 2 * 1024**4,
            "timeout_s": 14_400,
            "stages": {
                k: v.model_dump()
                for k, v in default_stage_limits(
                    budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"]
                ).items()
            },
            **budgets,
            "max_partitions": 128,
            "max_filesystems": 32,
            "max_files": 500_000,
            "max_streams_per_file": 16,
            "max_events_stored": 250_000,
            "max_events_read": 20_000_000,
            "max_findings": 5_000,
            "max_iocs": 20_000,
            "max_timeline": 5_000,
            "max_result_bytes": 256 * MIB,
            "event_quotas": {k.value: v for k, v in split_event_quotas(250_000).items()},
        }
    )


_addr = iter(range(100, 10**9))


def record(path: str, size: int = 1000, **kw: Any) -> DiskFileRecord:
    fields: dict[str, Any] = {
        "partition_index": 0,
        "meta_addr": next(_addr),
        "path": path,
        "name": path.rsplit("/", 1)[-1],
        "type": "reg",
        "flags": ALLOCATED,
        "size": size,
        "magic": "pe",
        "hash_status": "hashed",
        "sha256": "a" * 64,
    }
    fields.update(kw)
    if fields["hash_status"] != "hashed":
        fields.pop("sha256", None)
    return DiskFileRecord.model_validate(fields)


def writable(r: DiskFileRecord) -> bool:
    return "/Users/" in r.path or r.path.startswith("/tmp/")


def test_only_allocated_hashed_pe_files_and_streams() -> None:
    keep = [
        record("/Windows/a.exe"),
        record("/Users/bob/doc.txt", stream="payload"),  # an ADS with PE magic
    ]
    drop = [
        record("/bin/ls", magic="elf"),
        record("/x.sh", magic="script"),
        record("/y.zip", magic="archive"),
        record("/z.exe", magic=None),
        record("/big.exe", hash_status="too_large"),
        record("/del.exe", flags=FILE_FLAG_BITS["deleted"], hash_status="not_allocated"),
        record("/orphan.exe", flags=FILE_FLAG_BITS["orphan"]),
        record("/dir.exe", type="dir"),
        record("/empty.exe", size=0),
    ]
    got = select_candidates([*drop, *keep], "triage", limits(), user_writable=writable)
    assert {c.meta_addr for c in got.candidates} == {r.meta_addr for r in keep}
    assert got.eligible == 2
    assert [c.stream for c in got.candidates if c.stream] == ["payload"]


def test_known_good_is_skipped_unless_user_writable() -> None:
    system = record("/Windows/System32/psexec.exe", known="good", known_set="nsrl")
    temp = record("/Users/bob/AppData/Local/Temp/psexec.exe", known="good", known_set="nsrl")
    bad = record("/Windows/evil.exe", known="bad", known_set="lab")
    got = select_candidates([system, temp, bad], "full", limits(DiskProfile.FULL),
                            user_writable=writable)
    assert {c.meta_addr for c in got.candidates} == {temp.meta_addr, bad.meta_addr}
    assert got.skipped_known_good == 1


def test_order_user_writable_first_then_size_then_path() -> None:
    files = [
        record("/Windows/b.exe", 300),
        record("/Windows/a.exe", 300),
        record("/Windows/c.exe", 100),
        record("/Users/bob/z.exe", 900),
        record("/tmp/y.exe", 50),
    ]
    got = build_candidates(files, "triage", limits())  # the frozen signature
    assert len(got) == 5
    got = select_candidates(files, "triage", limits(), user_writable=writable).candidates
    by_addr = {r.meta_addr: r.path for r in files}
    assert [by_addr[c.meta_addr] for c in got] == [
        "/tmp/y.exe", "/Users/bob/z.exe", "/Windows/c.exe", "/Windows/a.exe", "/Windows/b.exe"
    ]


@pytest.mark.parametrize(
    ("override", "expected", "field"),
    [
        ({"yara_max_file_bytes": 500}, 5, "skipped_too_large"),
        ({"yara_max_files": 3}, 3, "skipped_budget"),
        ({"yara_max_bytes": 1000}, 4, "skipped_budget"),  # 4 × 200 + skips 400 / 600
    ],
)
def test_budgets(override: dict[str, int], expected: int, field: str) -> None:
    sizes = [200, 200, 200, 200, 400, 600]
    files = [record(f"/Windows/f{i}.exe", s) for i, s in enumerate(sizes)]
    got = select_candidates(files, "triage", limits(**override), user_writable=writable)
    assert len(got.candidates) == expected
    assert getattr(got, field) > 0 and got.truncated
    assert got.bytes == sum(c.size for c in got.candidates)


def test_budgets_never_exceed_the_profile_ceiling() -> None:
    # A job whose limits claim the full profile's 64 MiB per file under `triage` is held to
    # triage's 32 MiB.
    files = [record("/Windows/big.exe", 40 * MIB)]
    lim = limits(yara_max_file_bytes=64 * MIB)
    assert select_candidates(files, "triage", lim, user_writable=writable).candidates == []
    full = limits(DiskProfile.FULL)
    assert len(select_candidates(files, "full", full, user_writable=writable).candidates) == 1


def test_profile_budgets_are_the_plan_table() -> None:
    assert scan._budgets("triage", limits()) == (32 * MIB, 20_000, 4 * 1024**3)
    assert scan._budgets("full", limits(DiskProfile.FULL)) == (64 * MIB, 100_000, 16 * 1024**3)


def test_hard_links_are_scanned_once() -> None:
    a = record("/Windows/a.exe", meta_addr=7, flags=ALLOCATED | FILE_FLAG_BITS["hard_linked"])
    b = record("/Users/bob/b.exe", meta_addr=7, flags=ALLOCATED | FILE_FLAG_BITS["hard_linked"])
    got = select_candidates([a, b], "triage", limits(), user_writable=writable)
    assert len(got.candidates) == 1


def test_default_classifier_never_skips_known_good_without_path_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scan, "_phase6_user_writable", lambda: None)
    files = [record("/Windows/System32/x.exe", known="good", known_set="nsrl")]
    assert len(build_candidates(files, "triage", limits())) == 1


def test_candidates_round_trip(tmp_path: Any) -> None:
    files = [record("/Windows/a.exe", 10), record("/Users/x/b.exe", 20, stream="s", meta_seq=3)]
    got = build_candidates(files, "triage", limits())
    path = tmp_path / "candidates.jsonl"
    assert scan.write_candidates(path, got) == 2
    assert list(scan.read_candidates(path, 10)) == got
    assert list(scan.read_candidates(path, 1)) == got[:1]
    with open(path, "a") as f:
        f.write('{"partition_index": -1}\n')
    assert list(scan.read_candidates(path, 10)) == got


def test_phase6_path_classes_decide_known_good_skips() -> None:
    classify = scan._phase6_user_writable()
    if classify is None:
        pytest.skip("phase 6's path classes are not present")
    temp = record("Users/bob/AppData/Local/Temp/psexec.exe", known="good", known_set="nsrl")
    tmp = record("tmp/x/tool", known="good", known_set="nsrl")
    system = record("Windows/System32/psexec.exe", known="good", known_set="nsrl")
    got = build_candidates([temp, tmp, system], "triage", limits())
    assert {c.meta_addr for c in got} == {temp.meta_addr, tmp.meta_addr}
