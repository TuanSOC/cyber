"""The disk timeline export's CSV / JSONL (M9 phase 8): Timesketch's required columns first
(`message`, `datetime` ISO 8601 UTC, `timestamp_desc`), formula-safe cells (the M6 rule), no
BOM unless `excel=1`, FAT local times labelled; the k-way merge of the index-ordered streams;
the md5 list and the label in the file name."""

import asyncio
import csv
import io
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.modules.disk_forensics import exports_interop as ex
from app.modules.disk_forensics import repository as repo

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)


def _file(stream: str, ts: datetime, path: str = "Windows/x.exe", **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        ts=ts,
        stream=stream,
        id=kw.get("id", uuid.uuid4()),
        path=path,
        partition=1,
        time_basis=kw.get("time_basis", "utc"),
        artifact=None,
        message=None,
        ts_desc=None,
        file_id=None,
    )


def _event(ts: datetime, message: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        ts=ts,
        stream="event",
        id=kw.get("id", uuid.uuid4()),
        path="Windows/System32/winevt/Logs/Security.evtx",
        partition=1,
        time_basis="utc",
        artifact="evtx",
        message=message,
        ts_desc="Creation Time",
        file_id=None,
    )


async def _collect(chunks: AsyncIterator[bytes]) -> bytes:
    return b"".join([c async for c in chunks])


def _csv(rows: list[SimpleNamespace], *, excel: bool, monkeypatch: pytest.MonkeyPatch) -> bytes:
    async def fake_rows(session: Any, org_id: Any, job_id: Any) -> AsyncIterator[Any]:
        for row in rows:
            yield row

    monkeypatch.setattr(ex, "_timeline_rows", fake_rows)
    session: Any = None  # the rows are faked: no database
    return asyncio.run(_collect(ex._timeline_csv(session, uuid.uuid4(), uuid.uuid4(), excel=excel)))


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r", "＝"])
def test_formula_cells_are_neutralized(lead: str, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [_file("mtime", T0, path=f"{lead}cmd|' /C calc'!A0"), _event(T0, f"{lead}SUM(A1)")]
    body = _csv(rows, excel=False, monkeypatch=monkeypatch).decode("utf-8")
    records = list(csv.reader(io.StringIO(body)))
    assert tuple(records[0]) == ex.TIMELINE_COLUMNS
    file_row, event_row = records[1:]
    assert file_row[0].startswith("'") and file_row[6].startswith("'")  # message, path
    assert event_row[0].startswith("'")


def test_header_first_and_bom_only_for_excel(monkeypatch: pytest.MonkeyPatch) -> None:
    plain = _csv([_file("mtime", T0)], excel=False, monkeypatch=monkeypatch)
    assert plain.startswith(b"message,datetime,timestamp_desc,source,artifact,partition,path,")
    assert not plain.startswith(b"\xef\xbb\xbf")
    assert b"#" not in plain.split(b"\r\n")[0]  # no comment line (it breaks both importers)
    excel = _csv([_file("mtime", T0)], excel=True, monkeypatch=monkeypatch)
    assert excel == b"\xef\xbb\xbf" + plain


def test_records_for_files_and_events() -> None:
    file_record = ex.timeline_record(_file("crtime", T0))
    assert file_record == {
        "message": "Windows/x.exe",
        "datetime": "2026-10-01T08:00:00+00:00",
        "timestamp_desc": "Creation Time",
        "source": "file",
        "artifact": None,
        "partition": 1,
        "path": "Windows/x.exe",
        "time_basis": "utc",
    }
    local = ex.timeline_record(_file("mtime", T0, time_basis="local_unknown"))
    assert local["timestamp_desc"] == "Content Modification Time (local time, zone unknown)"
    event = ex.timeline_record(_event(T0, "[4624] Logon"))
    assert (event["message"], event["timestamp_desc"], event["artifact"]) == (
        "[4624] Logon",
        "Creation Time",
        "evtx",
    )
    line = ex.timeline_jsonl_line(event)
    assert line.endswith("\n") and line.count("\n") == 1
    assert list(json.loads(line)) == list(ex.TIMELINE_COLUMNS)


def test_iso_utc_converts_offsets() -> None:
    plus2 = datetime(2026, 10, 1, 10, 0, tzinfo=timezone(timedelta(hours=2)))
    assert ex.iso_utc(plus2) == "2026-10-01T08:00:00+00:00"
    assert ex.iso_utc(datetime(2026, 10, 1, 8, 0)) == "2026-10-01T08:00:00+00:00"


def test_merge_of_index_ordered_streams_is_total() -> None:
    ids = sorted(uuid.uuid4() for _ in range(4))
    streams_in = {
        "atime": [_file("atime", T0, id=ids[1]), _file("atime", T0 + timedelta(seconds=2))],
        "event": [_event(T0, "e0", id=ids[0]), _event(T0 + timedelta(seconds=1), "e1")],
        "mtime": [_file("mtime", T0, id=ids[0]), _file("mtime", T0, id=ids[3])],
        "crtime": [],
    }

    async def gen(rows: list[SimpleNamespace]) -> AsyncIterator[SimpleNamespace]:
        for row in rows:
            yield row

    async def run() -> list[SimpleNamespace]:
        merged = ex.merge_streams([gen(rows) for rows in streams_in.values()])
        return [row async for row in merged]

    out = asyncio.run(run())
    keys = [(r.ts, r.stream, r.id) for r in out]
    assert keys == sorted(keys) and len(keys) == 6
    assert [r.stream for r in out[:4]] == ["atime", "event", "mtime", "mtime"]


def test_streams_selected_by_the_filters() -> None:
    assert repo.timeline_streams(None, None, None) == ("mtime", "atime", "ctime", "crtime", "event")
    assert repo.timeline_streams("file", None, None) == ("mtime", "atime", "ctime", "crtime")
    assert repo.timeline_streams("event", "mtime", None) == ("event",)
    assert repo.timeline_streams(None, "ctime", None) == ("ctime", "event")
    assert repo.timeline_streams(None, None, "evtx") == ("event",)
    assert repo.timeline_streams("file", None, "evtx") == ()


def test_finding_refs_name_listed_files() -> None:
    row_id = uuid.uuid4()
    ids, paths = repo.parse_file_refs(
        [f"file:{row_id}", "file:1:Users/a:b/c.exe", "event:3", "file:x:y", "file:", "pid:4"]
    )
    assert ids == {row_id}
    assert paths == {(1, "Users/a:b/c.exe")}


@pytest.mark.parametrize(
    ("label", "name", "expected"),
    [
        (
            "restricted",
            "notable-hashes.txt",
            "CASE-00007-disk-12345678-notable-hashes-TLP-RED.txt",
        ),
        ("TLP:AMBER", "bodyfile", "CASE-00007-disk-12345678-bodyfile-TLP-AMBER.body"),
        (
            "TLP:AMBER+STRICT",
            "timeline.csv",
            "CASE-00007-disk-12345678-timeline-TLP-AMBER-STRICT.csv",
        ),
        ("TLP:CLEAR", "timeline.jsonl", "CASE-00007-disk-12345678-timeline-TLP-CLEAR.jsonl"),
    ],
)
def test_export_file_names_carry_the_label(label: str, name: Any, expected: str) -> None:
    job = uuid.UUID("12345678-0000-4000-8000-000000000000")
    assert ex.export_filename("CASE-00007", job, name, label) == expected
