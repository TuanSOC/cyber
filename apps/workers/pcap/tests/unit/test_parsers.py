"""Hostile tool output: a compromised engine controls these files; the root reader must not
crash, hang or blow up memory, and must report what it skipped or capped."""

import json
import os
from pathlib import Path

from pcap_worker import sandbox
from pcap_worker.engines import zeek
from pcap_worker.engines.common import MAX_LINE_BYTES, JsonLines, clip, epoch, ip, iso

GOOD = {
    "ts": 1767225600.5,
    "uid": "C1",
    "id.orig_h": "10.0.0.1",
    "id.orig_p": 40000,
    "id.resp_h": "203.0.113.9",
    "id.resp_p": 443,
    "proto": "tcp",
}


def _plant(dirs: sandbox.JobDirs, name: str, data: bytes) -> None:
    (dirs.out / name).write_bytes(data)


def _line(item: object) -> bytes:
    return json.dumps(item).encode() + b"\n"


def test_giant_lines_are_skipped_without_loading_them(dirs: sandbox.JobDirs) -> None:
    giant = b'{"ts": "' + b"A" * (3 * MAX_LINE_BYTES) + b'"}\n'
    _plant(dirs, "conn.log", giant + _line(GOOD) + b"x" * (2 * MAX_LINE_BYTES))
    source = JsonLines(dirs, "conn.log", max_lines=100)
    assert [f.flow_ref for f in zeek.flows(source)] == ["C1"]
    assert source.skipped == 2  # the giant line and the unterminated tail


def test_line_cap_is_reported(dirs: sandbox.JobDirs) -> None:
    _plant(dirs, "conn.log", _line(GOOD) * 10)
    source = JsonLines(dirs, "conn.log", max_lines=3)
    assert len(list(zeek.flows(source))) == 3 and source.capped


def test_malformed_and_hostile_values_skip_single_records(dirs: sandbox.JobDirs) -> None:
    hostile = [
        b"[" * 100_000 + b"\n",  # recursion bomb
        b"not json\n",
        _line([1, 2, 3]),  # not an object
        _line({**GOOD, "ts": 10**400}),  # overflowing number
        _line({**GOOD, "ts": "yesterday"}),
        _line({**GOOD, "ts": -5}),
        _line({**GOOD, "orig_bytes": 2**70}),
        _line({**GOOD, "duration": "inf"}),
        _line({**GOOD, "id.orig_h": "fe80::1%" + "x" * 10_000}),
        _line({**GOOD, "service": "ok" + chr(0) + "\ud800tail"}),
        _line({**GOOD, "id.orig_p": 99999, "uid": 7}),
    ]
    _plant(dirs, "conn.log", b"".join(hostile) + _line(GOOD))
    source = JsonLines(dirs, "conn.log", max_lines=100)
    flows = list(zeek.flows(source))
    assert flows[-1].flow_ref == "C1"
    for flow in flows:
        assert flow.orig_bytes < 2**63
        assert flow.service is None or chr(0) not in flow.service
        flow.model_dump_json()  # always serializable
    assert source.skipped >= 5


def test_special_files_and_symlinks_read_as_empty(dirs: sandbox.JobDirs) -> None:
    os.mkfifo(dirs.out / "dns.log")
    (dirs.out / "http.log").symlink_to("/etc/passwd")
    assert list(JsonLines(dirs, "dns.log", max_lines=10)) == []
    assert list(JsonLines(dirs, "http.log", max_lines=10)) == []
    assert list(JsonLines(dirs, "missing.log", max_lines=10)) == []


def test_value_helpers_reject_hostile_input() -> None:
    assert ip("fe80::1%eth0") is None and ip("10.0.0.1") == "10.0.0.1" and ip(42) is None
    assert clip("a" + chr(0) + "\ud800b", 10) == "a?b"
    assert epoch(-1) is None and epoch(1e20) is None and epoch(float("nan")) is None
    assert iso("0001-01-01T00:00:00+14:00") is None and iso("2026-01-01T00:00:00+0000")


def test_tls_records_survive_missing_certificates(dirs: sandbox.JobDirs) -> None:
    _plant(dirs, "ssl.log", _line({**GOOD, "cert_chain_fps": ["nope"], "version": "TLSv12"}))
    [record] = zeek.tls(JsonLines(dirs, "ssl.log", max_lines=10), {}, lambda cid, ts: (None, None))
    assert record.cert_subject is None and record.version == "TLSv12"


def test_planted_paths_cannot_escape(dirs: sandbox.JobDirs, tmp_path: Path) -> None:
    secret = tmp_path / "secret.log"
    secret.write_bytes(_line(GOOD))
    (dirs.out / "x509.log").symlink_to(secret)
    assert zeek.certificates(JsonLines(dirs, "x509.log", max_lines=10)) == {}
