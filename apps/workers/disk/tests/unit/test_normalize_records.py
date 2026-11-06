"""Probe rows -> `disk.v1` records (M9 phase 2): re-validation, clamping, the deferred hashes,
the per-inode name index (RT7) and hard-link flags. Pure: runs anywhere."""

import hashlib
import io
from datetime import UTC, datetime
from typing import Any

import pytest
from cyberlab_jobs.disk import FILE_FLAG_BITS
from pydantic import ValidationError

from disk_worker.normalize.models import FileRow, HashRow, PartitionRow, StageStatusDoc
from disk_worker.normalize.reader import ReadStats, read_jsonl, read_status
from disk_worker.normalize.records import (
    build_index,
    file_record,
    partition_record,
    to_time,
    with_hard_links,
)

SHA = hashlib.sha256(b"x").hexdigest()


def row(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "n": 0,
        "meta_addr": 50,
        "meta_seq": 1,
        "stream": None,
        "path": "/etc/passwd",
        "path_truncated": False,
        "parent_addr": 10,
        "name": "passwd",
        "name_lossy": False,
        "ext": None,
        "type": "reg",
        "allocated": True,
        "deleted": False,
        "orphan": False,
        "reallocated": False,
        "hard_linked": False,
        "size": 1,
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "times": {"mtime": [1_700_000_000, 123_456_789], "crtime": None},
        "time_basis": "utc",
        "magic": "other",
        "hash_status": "pending",
        "md5": None,
        "sha1": None,
        "sha256": None,
    }
    base.update(kw)
    return base


def test_a_file_row_becomes_a_record_with_its_deferred_hashes() -> None:
    deferred = HashRow(n=0, hash_status="hashed", md5="a" * 32, sha1="b" * 40, sha256=SHA)
    rec = file_record(FileRow.model_validate(row()), 1, deferred)
    assert rec.hash_status == "hashed" and rec.sha256 == SHA
    assert rec.mtime == datetime(2023, 11, 14, 22, 13, 20, 123_456, tzinfo=UTC)
    assert rec.flags == FILE_FLAG_BITS["allocated"]


def test_a_pending_hash_without_a_deferred_row_is_budget() -> None:
    rec = file_record(FileRow.model_validate(row()), 1, None)
    assert rec.hash_status == "budget" and rec.sha256 is None


def test_deleted_entries_never_carry_hashes_or_magic() -> None:
    data = row(
        allocated=False, deleted=True, hash_status="hashed", md5="a" * 32, sha1="b" * 40, sha256=SHA
    )
    rec = file_record(FileRow.model_validate(data), 1, None)
    assert rec.has_flag("deleted") and not rec.has_flag("allocated")
    assert rec.hash_status == "error" and rec.sha256 is None and rec.magic is None


def test_hostile_integers_cost_the_field_not_the_row() -> None:
    data = row(
        mode=2**40,
        uid=-1,
        gid=2**33,
        meta_seq=2**40,
        size=-5,
        times={"mtime": [-(2**62), 0], "atime": [10**12, 0]},
    )
    rec = file_record(FileRow.model_validate(data), 1, None)
    assert (rec.mode, rec.uid, rec.gid, rec.meta_seq, rec.size) == (None,) * 5
    assert rec.mtime is None and rec.atime is None


def test_unknown_fields_and_wrong_types_are_bad_rows() -> None:
    with pytest.raises(ValidationError):
        FileRow.model_validate(row(extra="x"))
    with pytest.raises(ValidationError):
        FileRow.model_validate(row(meta_addr="50"))
    with pytest.raises(ValidationError):
        FileRow.model_validate(row(allocated=1))


def test_control_characters_in_a_path_are_refused_by_the_contract() -> None:
    with pytest.raises(ValueError):
        file_record(FileRow.model_validate(row(path="/a\nb")), 1, None)


def test_times_outside_1601_2200_are_null() -> None:
    assert to_time([-11_644_473_600, 0]) == datetime(1601, 1, 1, tzinfo=UTC)
    assert to_time([-11_644_473_601, 0]) is None
    assert to_time([7_258_118_400, 0]) is None  # 2200-01-01
    assert to_time(None) is None


def test_every_name_of_an_inode_is_checked_for_never_collect() -> None:
    shadow = file_record(FileRow.model_validate(row(path="/etc/shadow", name="shadow")), 1, None)
    alias = file_record(
        FileRow.model_validate(row(n=1, path="/var/log/auth.log", name="auth.log", parent_addr=11)),
        1,
        None,
    )
    other = file_record(FileRow.model_validate(row(n=2, meta_addr=51)), 1, None)
    index = build_index([shadow, alias, other])
    assert index.refused(1, 50, case_insensitive=False)  # auth.log shares the shadow inode
    assert not index.refused(1, 51, case_insensitive=False)
    assert index.names_of(1, 50) == {"/etc/shadow", "/var/log/auth.log"}
    linked = with_hard_links([shadow, alias, other], index)
    assert [r.has_flag("hard_linked") for r in linked] == [True, True, False]


def test_a_named_stream_inherits_its_files_refusal() -> None:
    sam = file_record(
        FileRow.model_validate(row(path="/Windows/System32/config/SAM", name="SAM")), 1, None
    )
    ads = file_record(
        FileRow.model_validate(
            row(n=1, path="/Windows/System32/config/SAM", name="SAM", stream="x")
        ),
        1,
        None,
    )
    index = build_index([sam, ads])
    assert index.refused(1, 50, case_insensitive=True)
    assert not with_hard_links([sam, ads], index)[0].has_flag("hard_linked")


def test_a_truncated_path_is_refused_for_collection() -> None:
    rec = file_record(FileRow.model_validate(row(path_truncated=True)), 1, None)
    assert rec.has_flag("path_truncated")
    assert build_index([rec]).refused(1, 50, case_insensitive=False)


def test_partition_rows() -> None:
    data = {
        "index": 0,
        "start_sector": 2048,
        "length_sectors": 1000,
        "sector_size": 512,
        "volume_system": "gpt",
        "description": "Basic data",
        "fs_type": "ntfs",
        "fs_status": "ok",
        "reason": None,
        "block_size": 4096,
        "os": "windows",
        "os_name": None,
        "counts": {"blocks": 10, "inodes": 5},
    }
    rec = partition_record(PartitionRow.model_validate(data))
    assert rec.fs_status == "ok" and rec.fs_type == "ntfs" and rec.os == "windows"
    failed = partition_record(PartitionRow.model_validate(data), walk_error="walk_memory")
    assert failed.fs_status == "error" and failed.error_code == "walk_memory"
    assert failed.os == "none"
    encrypted = partition_record(
        PartitionRow.model_validate(
            {**data, "fs_status": "encrypted", "fs_type": None, "reason": "bitlocker", "os": "none"}
        )
    )
    assert encrypted.fs_status == "encrypted" and encrypted.fs_type is None


def test_the_reader_bounds_lines_and_counts_bad_ones() -> None:
    data = b'{"a":1}\nnot json\n[1]\n{"b":NaN}\n' + b'{"c":"' + b"x" * 200 + b'"}\n{"d":2}\n'
    stats = ReadStats()
    rows = list(
        read_jsonl(io.BytesIO(data), stats, max_rows=10, max_bytes=10**6, max_line_bytes=64)
    )
    assert rows == [{"a": 1}, {"d": 2}]
    assert stats.bad == 4 and stats.lines == 6
    assert stats.bad_ratio() > 0.01


def test_the_reader_stops_at_its_own_caps() -> None:
    data = b'{"a":1}\n' * 100
    stats = ReadStats()
    assert len(list(read_jsonl(io.BytesIO(data), stats, max_rows=5, max_bytes=10**6))) == 5
    assert stats.truncated
    stats = ReadStats()
    assert len(list(read_jsonl(io.BytesIO(data), stats, max_rows=100, max_bytes=40))) == 5


def test_status_documents() -> None:
    raw = read_status(io.BytesIO(b'{"status":"ok","rows":3,"audit":{"socket":0},"x":1}'))
    assert raw is not None
    doc = StageStatusDoc.model_validate(raw)
    assert doc.status == "ok" and doc.rows == 3 and doc.audit == {"socket": 0}
    assert read_status(io.BytesIO(b"[]")) is None
    assert read_status(io.BytesIO(b"{" * 10)) is None
