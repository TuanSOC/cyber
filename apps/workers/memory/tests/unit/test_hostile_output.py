"""Hostile probe output (a compromised or confused probe) ends as a skipped row, a plugin
engine error or no output, never a crash of the root process (pure Python; the symlink /
FIFO cases need the kit's `open_output` and run in the memory-worker image).

Also root's compressed / archive refusal before any probe runs (RT19)."""

import io
import json
import os
from pathlib import Path

import pytest
from cyberlab_jobs.memory import MemoryPlugin

from memory_worker.engines.magic import compressed_format, image_format
from memory_worker.normalize.reader import (
    MAX_LINE_BYTES,
    MAX_STATUS_BYTES,
    RowSource,
    RowStats,
    read_rows,
    read_status,
)
from tests.replay_helpers import kinds, run_scenario

P = MemoryPlugin


def _short(value: object) -> str:
    return repr(value)[:40]


def _read(data: bytes, max_rows: int = 100) -> tuple[list[dict[str, object]], RowStats]:
    stats = RowStats()
    return list(read_rows(io.BytesIO(data), max_rows, stats)), stats


def test_giant_lines_are_skipped_in_bounded_chunks() -> None:
    data = b'{"PID": 1}\n' + b'{"x": "' + b"A" * (5 * MAX_LINE_BYTES) + b'"}\n' + b'{"PID": 2}\n'
    rows, stats = _read(data)
    assert rows == [{"PID": 1}, {"PID": 2}] and stats.skipped == 1


@pytest.mark.parametrize(
    "line",
    [
        b"not json",
        b'{"PID": NaN}',
        b'{"PID": Infinity}',
        b'{"PID": -Infinity}',
        b"[1, 2, 3]",
        b'"a string"',
        b"[" * 100_000 + b"]" * 100_000,
        b'{"PID": 1',
        b"\xff\xfe\x00",
    ],
    ids=_short,
)
def test_unusable_lines_are_skipped(line: bytes) -> None:
    rows, stats = _read(b'{"PID": 1}\n' + line + b'\n{"PID": 2}\n')
    assert rows == [{"PID": 1}, {"PID": 2}] and stats.skipped == 1


def test_root_caps_rows_whatever_the_probe_claims() -> None:
    data = b"".join(b'{"PID": %d}\n' % i for i in range(50))
    rows, stats = _read(data, max_rows=10)
    assert len(rows) == 10 and stats.truncated


def test_nothing_after_the_truncation_marker_counts() -> None:
    real = b'{"PID": 1}\n{"_truncated": true}\n'
    forged = b'{"PID": 666}\n{"_truncated": false}\n'
    rows, stats = _read(real + forged)
    assert rows == [{"PID": 1}] and stats.truncated
    # A false marker also ends the rows (and changes nothing).
    rows, stats = _read(b'{"PID": 1}\n{"_truncated": false}\n{"PID": 2}\n')
    assert rows == [{"PID": 1}] and not stats.truncated


def test_a_missing_rows_file_yields_nothing() -> None:
    seen: list[RowStats] = []

    def missing() -> io.BytesIO:
        raise FileNotFoundError("rows.jsonl")

    assert list(RowSource(missing, 10, seen.append)) == []
    assert seen and seen[0].rows == 0


@pytest.mark.parametrize(
    "status",
    [
        b"",
        b"null",
        b"[]",
        b'{"status": "pwned"}',
        b'{"status": "ok", "rows": -1}',
        b'{"status": "ok", "rows": "12"}',
        b'{"status": "ok", "error": "Error: <image bytes here>"}',
        b'{"status": "ok", "audit": {"socket": 1.5}}',
        b'{"status": "ok", "layers": ["Bad Layer!"]}',
        b'{"status": "ok", "isf": ' + json.dumps(["x"] * 9).encode() + b"}",
        b'{"status": "ok", "truncated": NaN}',
        b'{"status": "ok", "x": "' + b"A" * MAX_STATUS_BYTES + b'"}',
    ],
    ids=_short,
)
def test_invalid_status_files_are_none(status: bytes) -> None:
    assert read_status(io.BytesIO(status)) is None


def test_a_valid_status_is_read_and_its_offline_facts_checked() -> None:
    status = read_status(
        io.BytesIO(
            json.dumps(
                {
                    "status": "ok",
                    "rows": 3,
                    "audit": {"socket": 0},
                    "offline": True,
                    "remote_isf_url": None,
                    "symbol_paths": [
                        "/symbols",
                        "/opt/venv/lib/python3.12/site-packages/volatility3/symbols",
                        "/opt/venv/lib/python3.12/site-packages/volatility3/framework/symbols",
                    ],
                    "unknown_key": {"ignored": True},
                }
            ).encode()
        )
    )
    assert status is not None and status.rows == 3
    assert status.offline_verified("/symbols")
    assert not status.offline_verified("/symbols-test")
    online = status.model_copy(update={"offline": False})
    remote = status.model_copy(update={"remote_isf_url": "http://example.com/banners.json"})
    cache = status.model_copy(update={"symbol_paths": [*status.symbol_paths, "/x/.cache/symbols"]})
    assert not any(s.offline_verified("/symbols") for s in (online, remote, cache))


def test_garbage_rows_never_break_the_stream(tmp_path: Path) -> None:
    def garbage(plugin: MemoryPlugin, data: bytes) -> bytes:
        if plugin is P.WINDOWS_PSSCAN:
            return data + b'{"PID": {"a": 1}}\n{"PID": 9999999999}\nNaN\n' + b"x" * 200_000 + b"\n"
        if plugin is P.WINDOWS_NETSCAN:
            return b'{"Proto": "TCPv4", "LocalAddr": "1.2.3.4%x", "LocalPort": 70000}\n' + data
        if plugin is P.WINDOWS_SVCSCAN:
            return b'{"Name": "\\u0000evil\\ud800", "Binary": "C:\\\\x\\u0000.exe"}\n' + data
        return data

    lines = run_scenario("windows", "triage", tmp_path / "r.gz", mutate=garbage)
    header = lines[0]
    assert kinds(lines)["process"] == 40
    assert "windows_psscan_rows_skipped" in header.engine_errors
    evil = [
        line for line in lines if line.kind == "artifact" and line.attributes.get("name") == "evilu"
    ]
    assert evil == [] or all("\x00" not in str(e.attributes) for e in evil)


# --- RT19: compressed / archived uploads are refused before any probe -------------------------


@pytest.mark.parametrize(
    ("head", "name"),
    [
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"BZh91AY&SY", "bzip2"),
        (b"\xfd7zXZ\x00\x00", "xz"),
        (b"\x28\xb5\x2f\xfd\x00", "zstd"),
        (b"PK\x03\x04\x14\x00", "zip"),
        (b"PK\x05\x06" + bytes(18), "zip"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
    ],
)
def test_compressed_and_archive_magic_is_refused(head: bytes, name: str, tmp_path: Path) -> None:
    assert compressed_format(head) == name
    path = tmp_path / "image"
    path.write_bytes(head + os.urandom(64))
    assert image_format(path) == name


@pytest.mark.parametrize(
    "head",
    [
        bytes(16),  # raw: a zero page
        b"EMiL\x01\x00\x00\x00" + bytes(8),  # LiME
        b"\x7fELF\x02\x01\x01\x00" + bytes(8),  # ELF core
        b"PAGEDU64" + bytes(8),  # Windows crash dump
        b"BZh0" + bytes(12),  # not a bzip2 block size
        b"CYBERLAB-REPLAY windows\n",
        b"",
    ],
)
def test_memory_formats_pass(head: bytes) -> None:
    assert compressed_format(head) is None
