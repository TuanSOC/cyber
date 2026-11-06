"""M9 phase 7: validation of `disk.v1` result streams (pass 1) and the ref resolution of the
write pass (pass 2), without a database.

Every hostile phase-1 fixture is refused; a full fixture validates with its counts; refs that
resolve are kept, the rest counted; the two passes agree on what is dropped.
"""

import dataclasses
import gzip
import hashlib
import json
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import cyberlab_jobs
import pytest

from app.modules.analysis.result_stream import InvalidResult
from app.modules.disk_forensics import ingest, stream

FIXTURES = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures" / "disk"

WINDOWS_JOB = uuid.UUID("7b2e1d2f-9e7c-4d66-8eaf-1e2c7a6b2001")
CAPS = stream.Caps(
    max_decompressed_bytes=1024**3,
    per_kind={
        "partition": 128,
        "file": 500_000,
        "event": 250_000,
        "finding": 5_000,
        "ioc": 20_000,
        "timeline": 5_000,
    },
    max_lines=780_131,
    max_media_bytes=2 * 1024**4,
)
DIAGNOSTIC_CAPS = stream.Caps(
    max_decompressed_bytes=130 * 1024**2,
    per_kind={"partition": 128},
    max_lines=130,
    max_media_bytes=2 * 1024**4,
)


def _objs(name: str) -> list[dict[str, Any]]:
    objs = [json.loads(line) for line in (FIXTURES / name).read_bytes().splitlines()]
    assert objs[-1]["kind"] == "trailer"
    return objs[:-1]


def _write(tmp_path: Path, objs: list[dict[str, Any]]) -> Path:
    """Gzip NDJSON with the hashed trailer (the shared framing)."""
    body = b"".join(json.dumps(o).encode() + b"\n" for o in objs)
    digest = hashlib.sha256(body).hexdigest()
    trailer = {"kind": "trailer", "line_count": len(objs), "sha256": digest}
    path = tmp_path / "result.ndjson.gz"
    path.write_bytes(gzip.compress(body + json.dumps(trailer).encode() + b"\n"))
    return path


def _facts(objs: list[dict[str, Any]], **over: Any) -> stream.JobFacts:
    header = objs[0]
    values = {
        "job_id": uuid.UUID(header["job_id"]),
        "profile": header["profile"],
        "segments": header["image"]["segments"],
        **over,
    }
    return stream.JobFacts(**values)


def _validate(tmp_path: Path, objs: list[dict[str, Any]], **caps: Any) -> stream.Validated:
    use = dataclasses.replace(CAPS, **caps)
    return stream.validate(_write(tmp_path, objs), _facts(objs), use)


def _refused(tmp_path: Path, objs: list[dict[str, Any]], **caps: Any) -> str:
    with pytest.raises(InvalidResult) as caught:
        _validate(tmp_path, objs, **caps)
    return caught.value.reason


def test_the_windows_fixture_validates(tmp_path: Path) -> None:
    result = _validate(tmp_path, _objs("windows_triage.ndjson"))
    assert dict(result.counts) == {
        "partition": 2,
        "file": 306,
        "event": 8,
        "finding": 3,
        "ioc": 3,
        "timeline": 4,
    }
    # The fixture's findings cite files by path (not the worker's ref form) and one event names
    # a file that is not listed: counted, never refused.
    assert result.unresolved == Counter({"finding_ref": 2, "event_file": 1})
    assert result.cited_events == {0, 1, 2}
    assert result.hashed_files > 0


@pytest.mark.parametrize("name", ["linux_triage.ndjson", "ewf_mismatch.ndjson"])
def test_the_other_fixtures_validate(tmp_path: Path, name: str) -> None:
    assert _validate(tmp_path, _objs(name)).counts["partition"] >= 1


@pytest.mark.parametrize(
    "path", sorted((FIXTURES / "hostile").glob("*.ndjson")), ids=lambda p: p.name
)
def test_every_hostile_fixture_is_refused(tmp_path: Path, path: Path) -> None:
    facts = stream.JobFacts(job_id=WINDOWS_JOB, profile="triage", segments=1)
    target = tmp_path / "hostile.gz"
    target.write_bytes(gzip.compress(path.read_bytes()))
    with pytest.raises(InvalidResult):
        if path.name.startswith("diagnostic"):
            stream.validate_diagnostic(target, facts, DIAGNOSTIC_CAPS)
        else:
            stream.validate(target, facts, CAPS)


@pytest.mark.parametrize(
    ("facts", "reason"),
    [
        ({"job_id": uuid.uuid4()}, "header_job_mismatch"),
        ({"profile": "full"}, "header_profile_mismatch"),
        ({"segments": 2}, "header_segments_mismatch"),
    ],
)
def test_the_header_must_name_this_job(
    tmp_path: Path, facts: dict[str, Any], reason: str
) -> None:
    objs = _objs("windows_triage.ndjson")
    with pytest.raises(InvalidResult) as caught:
        stream.validate(_write(tmp_path, objs), _facts(objs, **facts), CAPS)
    assert caught.value.reason == reason


def test_media_and_header_blocks_are_bounded(tmp_path: Path) -> None:
    objs = _objs("windows_triage.ndjson")
    assert _refused(tmp_path, objs, max_media_bytes=1024) == "media_too_large"
    objs[0]["tool_versions"] = {f"tool{i}": "v" * 60 for i in range(40)}
    assert _refused(tmp_path, objs) in {"header_too_large", "invalid_header"}


def _first(objs: list[dict[str, Any]], kind: str) -> int:
    return next(i for i, o in enumerate(objs) if o["kind"] == kind)


def test_duplicates_are_refused(tmp_path: Path) -> None:
    for kind, reason in (
        ("partition", "duplicate_partition"),
        ("file", "duplicate_file"),
        ("event", "duplicate_event"),
        ("finding", "duplicate_finding"),
        ("ioc", "duplicate_ioc"),
    ):
        objs = _objs("windows_triage.ndjson")
        i = _first(objs, kind)
        objs.insert(i + 1, dict(objs[i]))
        assert _refused(tmp_path, objs) == reason, kind


def test_a_hard_linked_name_is_not_a_duplicate(tmp_path: Path) -> None:
    objs = _objs("windows_triage.ndjson")
    i = _first(objs, "file")
    twin = {**objs[i], "name": "second-name", "path": objs[i]["path"] + "-2"}
    objs.insert(i + 1, twin)
    assert _validate(tmp_path, objs).counts["file"] == 307


def test_records_need_a_listed_partition_and_the_line_order(tmp_path: Path) -> None:
    objs = _objs("windows_triage.ndjson")
    objs[_first(objs, "file")]["partition_index"] = 77
    assert _refused(tmp_path, objs) == "unknown_partition"
    objs = _objs("windows_triage.ndjson")
    objs.append(dict(objs[_first(objs, "file")]) | {"name": "late", "meta_addr": 424242})
    assert _refused(tmp_path, objs) == "out_of_order"


def test_caps_are_the_job_caps(tmp_path: Path) -> None:
    objs = _objs("windows_triage.ndjson")
    caps = {**CAPS.per_kind, "file": 300}
    assert _refused(tmp_path, objs, per_kind=caps) == "too_many_file"
    assert _refused(tmp_path, objs, max_lines=50) == "too_many_lines"
    assert _refused(tmp_path, objs, max_decompressed_bytes=4096) == "decompressed_too_large"


def test_a_diagnostic_stream_is_header_partitions_trailer(tmp_path: Path) -> None:
    objs = _objs("no_supported_filesystem.ndjson")
    result = stream.validate_diagnostic(_write(tmp_path, objs), _facts(objs), DIAGNOSTIC_CAPS)
    assert dict(result.counts) == {"partition": 2}
    with_file = [*objs, _objs("windows_triage.ndjson")[3]]
    with pytest.raises(InvalidResult) as caught:
        stream.validate_diagnostic(
            _write(tmp_path, with_file), _facts(with_file), DIAGNOSTIC_CAPS
        )
    assert caught.value.reason == "diagnostic_with_records"


def test_file_refs_are_the_worker_form() -> None:
    assert stream.file_ref(1, 65, 1, None) == "file:1:65:1"
    assert stream.file_ref(0, 5, None, None) == "file:0:5:"
    assert stream.file_ref(2, 9, 3, "Zone.Identifier") == "file:2:9:3:Zone.Identifier"
    long = stream.file_ref(2, 9, 3, "s" * 80)
    assert long.startswith("file:2:9:3:#") and len(long) == len("file:2:9:3:#") + 16
    assert stream.event_ordinal("event:12") == 12
    assert stream.event_ordinal("event:012") is None
    finding = uuid.uuid4()
    assert stream.finding_id(f"finding:{finding}") == finding
    assert stream.finding_id(str(finding)) is None
    assert stream.finding_id(str(finding), bare=True) == finding


# --- refs: pass 1 cites, pass 2 maps to row ids ------------------------------------------------


def _ref_stream() -> list[dict[str, Any]]:
    """The Windows header and partitions, two listed files (one with a long stream name), two
    events (one naming a listed file, one an unlisted one), findings citing every ref kind."""
    objs = _objs("windows_triage.ndjson")
    header, partitions = objs[0], [o for o in objs if o["kind"] == "partition"]
    base_file = next(o for o in objs if o["kind"] == "file")
    exe = {**base_file, "meta_addr": 900, "meta_seq": 2, "name": "a.exe", "path": "a.exe"}
    ads = {**exe, "stream": "x" * 80, "name": "a.exe:long", "path": "a.exe:long"}
    event = next(o for o in objs if o["kind"] == "event")
    key = {"partition_index": 1, "meta_addr": 900, "meta_seq": 2}
    linked = {**event, "ordinal": 10, "file": key}
    unlinked = {**event, "ordinal": 11, "file": {"partition_index": 1, "meta_addr": 1}}
    finding = next(o for o in objs if o["kind"] == "finding")
    first_id, second_id = str(uuid.uuid4()), str(uuid.uuid4())
    first = {
        **finding,
        "finding_id": first_id,
        "evidence_refs": [
            "file:1:900:2",
            stream.file_ref(1, 900, 2, "x" * 80),
            "event:11",
            f"finding:{second_id}",  # cites a later finding: still resolves
            "file:1:31337:",  # not listed
            "event:99",  # not exported
            "registry:HKLM",  # unknown kind
        ],
    }
    second = {**finding, "finding_id": second_id, "evidence_refs": [f"finding:{uuid.uuid4()}"]}
    timeline = next(o for o in objs if o["kind"] == "timeline")
    timelines = [
        {**timeline, "ref": "event:10"},
        {**timeline, "ref": first_id},
        {**timeline, "ref": "event:404"},
    ]
    return [header, *partitions, exe, ads, linked, unlinked, first, second, *timelines]


def test_refs_resolve_or_are_counted(tmp_path: Path) -> None:
    result = _validate(tmp_path, _ref_stream())
    assert result.cited_files == {
        "file:1:900:2",
        stream.file_ref(1, 900, 2, "x" * 80),
    }
    assert result.cited_events == {10, 11}
    assert result.unresolved == Counter(
        {"event_file": 1, "finding_ref": 4, "timeline_ref": 1}
    )


def test_the_write_pass_maps_cited_refs_to_row_ids(tmp_path: Path) -> None:
    objs = _ref_stream()
    path = _write(tmp_path, objs)
    result = stream.validate(path, _facts(objs), CAPS)
    resolver = ingest.Resolver(result)
    rows: dict[str, list[dict[str, Any]]] = {}
    for record, _ in stream.records(path, CAPS):
        table, row = resolver.to_row(record)
        rows.setdefault(table.name, []).append(row)

    exe, ads = rows["disk_files"]
    assert resolver.files["file:1:900:2"] == exe["id"]
    linked, unlinked = rows["disk_events"]
    assert linked["file_id"] == exe["id"] and unlinked["file_id"] is None
    first, second = rows["analysis_findings"]
    assert first["evidence_refs"] == [
        f"file:{exe['id']}",
        f"file:{ads['id']}",
        f"event:{unlinked['id']}",
        f"finding:{second['finding_id']}",
    ]
    assert second["evidence_refs"] == []
    # Both passes drop exactly the same refs (the ingest checks it).
    assert resolver.dropped["finding_ref"] == result.unresolved["finding_ref"]
    refs = [t["ref"] for t in rows["analysis_timeline"]]
    assert refs == [f"event:{linked['id']}", str(first["finding_id"]), None]
    # Addresses go in as NUMERIC, never as a float.
    assert str(exe["meta_addr"]) == "900"


def test_extensions_are_normalized() -> None:
    objs = _objs("windows_triage.ndjson")
    base = next(o for o in objs if o["kind"] == "file" and o["type"] == "reg")
    from cyberlab_jobs.disk import DiskFileRecord

    def ext(**over: Any) -> str | None:
        return ingest.normalized_ext(DiskFileRecord.model_validate({**base, **over}))

    assert ext(ext="EXE") == "exe"
    assert ext(ext=None, name="Report.PDF") == "pdf"
    assert ext(ext=None, name=".bashrc") is None
    assert ext(ext=None, name="noext") is None


def test_the_summary_fits_and_names_the_trusted_segments(tmp_path: Path) -> None:
    from app.modules.disk_forensics.segments import Segment

    result = _validate(tmp_path, _objs("windows_triage.ndjson"))
    segments = [
        Segment(0, uuid.uuid4(), "b", "k", "v", "a" * 64, 4096),
    ]
    summary = ingest.build_summary(result, segments)
    assert summary["image"]["size_bytes"] == 4096 and summary["image"]["segments"] == 1
    assert summary["counts"]["files"] == 306
    assert summary["counts"]["unresolved_finding_refs"] == 2
    assert len(json.dumps(summary)) <= ingest.SUMMARY_MAX_BYTES
    image = ingest.image_row(result)
    assert image["media_hash_status"] is None and image["format"] == "raw"
