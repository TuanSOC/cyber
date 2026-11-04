"""Hostile engine output: a compromised probe / engine controls these files. The root reader
must not crash, hang or blow up memory, must only accept contract-valid records of the kinds
that engine may produce, and must report what it skipped or capped."""

import json
import os
import shutil
from pathlib import Path

import pytest
from cyberlab_worker import sandbox
from cyberlab_worker.parsing import MAX_LINE_BYTES

from static_worker.engines import capa, clamav, floss
from static_worker.engines.probes import OUTPUT, ProbeRun, archive_result, facts
from static_worker.engines.workspace import Workspace
from static_worker.probe import reduce
from tests.conftest import in_container
from tests.helpers import FAST, place

pytestmark = in_container

GOOD_STRING = {"kind": "string", "value": "hello world", "encoding": "ascii", "offset": 4}


def _line(item: object) -> bytes:
    return json.dumps(item).encode() + b"\n"


def _plant(dirs: sandbox.JobDirs, name: str, data: bytes) -> None:
    (dirs.out / name).write_bytes(data)


def _run(dirs: sandbox.JobDirs, mode: str, max_lines: int = 100) -> ProbeRun:
    return ProbeRun(mode, dirs, max_lines, errors=[], truncated={})


def test_probe_may_only_emit_its_own_record_kinds(dirs: sandbox.JobDirs) -> None:
    forged = [
        {"kind": "finding", "finding_id": "00000000-0000-0000-0000-000000000000"},
        {"kind": "signature_match", "engine": "clamav", "name": "Forged"},
        {"kind": "header", "schema_version": "static.v1"},
        {"kind": "sample", "size": 1},
        GOOD_STRING,
    ]
    _plant(dirs, OUTPUT, b"".join(_line(i) for i in forged))
    run = _run(dirs, "strings")
    assert [r.kind for r in run.records()] == ["string"]
    assert run.skipped == 4
    # yara may emit signature matches, but only as engine "yara": the forged ClamAV match
    # (and every other kind) in the same output is rejected.
    assert list(_run(dirs, "yara").records()) == []


def test_invalid_values_skip_single_records(dirs: sandbox.JobDirs) -> None:
    hostile = [
        b"[" * 100_000 + b"\n",  # recursion bomb
        b"not json\n",
        _line([1, 2, 3]),
        b'{"kind": "section", "index": 0, "name": "x", "virtual_address": 0, "virtual_size": 0,'
        b' "raw_size": 0, "entropy": NaN}\n',
        _line({**GOOD_STRING, "value": "x" * 600}),  # over Text512
        _line({**GOOD_STRING, "value": "a\x00b"}),  # NUL
        _line({**GOOD_STRING, "value": "\ud800"}),  # lone surrogate (not serializable)
        _line({**GOOD_STRING, "offset": -1}),
        _line({**GOOD_STRING, "offset": 2**70}),
        _line({**GOOD_STRING, "encoding": "rot13"}),
        _line({**GOOD_STRING, "extra": 1}),  # extra=forbid
        _line({"kind": "import", "library": "k32", "function": "f" * 300}),
        _line(GOOD_STRING),
    ]
    _plant(dirs, OUTPUT, b"".join(hostile))
    run = _run(dirs, "strings")
    records = list(run.records())
    assert [r.model_dump(exclude={"kind"}) for r in records] == [
        {"value": "hello world", "encoding": "ascii", "offset": 4}
    ]
    assert run.skipped >= 11


def test_giant_lines_and_line_cap(dirs: sandbox.JobDirs) -> None:
    giant = b'{"kind": "string", "value": "' + b"A" * (3 * MAX_LINE_BYTES) + b'"}\n'
    _plant(dirs, OUTPUT, giant + _line(GOOD_STRING) * 10)
    run = _run(dirs, "strings", max_lines=4)
    assert len(list(run.records())) == 4
    assert run.truncated == {"strings_output": True} and run.skipped == 1


def test_error_codes_and_flags_come_from_allowlists(dirs: sandbox.JobDirs) -> None:
    lines = [
        {"kind": "error", "code": "pe_partial"},
        {"kind": "error", "code": "pe_partial"},
        {"kind": "error", "code": "anything_the_probe_likes"},
        {"kind": "error", "code": ["pe_partial"]},
        {"kind": "summary", "truncated": {"imports": True, "made_up": True, "sections": "yes"}},
        {"kind": "summary", "truncated": ["imports"]},
    ]
    _plant(dirs, OUTPUT, b"".join(_line(i) for i in lines))
    run = _run(dirs, "pe")
    assert list(run.records()) == []
    assert run.errors == ["pe_partial"] and run.truncated == {"imports": True}


def test_facts_are_checked_field_by_field(dirs: sandbox.JobDirs) -> None:
    lines = [
        {"kind": "facts", "size": -5, "md5": "XYZ", "sha1": "0" * 40, "sha256": "0" * 63,
         "entropy": 99, "file_type": 7, "mime": "text/plain"},
        {"kind": "ssdeep", "value": "3:a\x00b" + "x" * 500},
        {"kind": "finding", "severity": "high"},
        {"kind": "archive", "format": "zip", "unchecked": False},  # not a facts record
    ]  # fmt: skip
    _plant(dirs, OUTPUT, b"".join(_line(i) for i in lines))
    run = _run(dirs, "facts")
    got = facts(run)
    assert got.size == 0 and got.md5 is None and got.sha1 == "0" * 40 and got.sha256 is None
    assert got.entropy is None and got.file_type is None and got.mime == "text/plain"
    assert got.ssdeep is not None and len(got.ssdeep) == 128 and "\x00" not in got.ssdeep
    assert run.skipped == 2


GOOD_ARCHIVE = {"kind": "archive", "sha256": "a" * 64, "format": "zip", "members": 1,
                "declared_bytes": 5, "largest_member": 5, "depth": 1, "encrypted": False,
                "unchecked": False}  # fmt: skip


@pytest.mark.parametrize(
    "record",
    [
        {"format": "tar"},
        {"members": "many"},
        {"largest_member": 2**80},
        {"format": "zip", "members": True},
        {"format": "zip", "depth": -1},
        {"format": "zip", "encrypted": 0},
        {"unchecked": None},
        {"unchecked": "false"},
    ],
)
def test_archive_record_fails_closed(dirs: sandbox.JobDirs, record: dict[str, object]) -> None:
    """A malformed pre-check record counts as "could not check" (unchecked)."""
    _plant(dirs, OUTPUT, _line(GOOD_ARCHIVE))
    got = archive_result(_run(dirs, "archive"))
    assert got.record is not None and not clamav.exceeds_limits(got.record)
    assert got.sha256 == "a" * 64
    (dirs.out / OUTPUT).unlink()
    _plant(dirs, OUTPUT, _line(GOOD_ARCHIVE | record))
    got = archive_result(_run(dirs, "archive"))
    assert got.record is not None and clamav.exceeds_limits(got.record)


def test_archive_line_rules(dirs: sandbox.JobDirs) -> None:
    _plant(dirs, OUTPUT, _line({"kind": "facts", "size": 1}))
    assert archive_result(_run(dirs, "archive")).record is None  # missing: None
    (dirs.out / OUTPUT).unlink()
    forged_sha = GOOD_ARCHIVE | {"sha256": "nope"}
    _plant(dirs, OUTPUT, _line(forged_sha) + _line(GOOD_ARCHIVE))
    got = archive_result(_run(dirs, "archive"))  # only the first line counts
    assert got.record is not None and got.sha256 is None


def _tool_output(
    dirs: sandbox.JobDirs, name: str = "", data: bytes | None = None
) -> tuple[Workspace, sandbox.JobDirs]:
    """A job with a sample and a fresh tool out dir holding `name` (a tool's JSON document)."""
    if not (dirs.input / "sample").exists():
        place(dirs, b"x")
    ws = Workspace(dirs)
    source = ws.engine(f"tool-{os.urandom(4).hex()}")
    if data is not None:
        (source.out / name).write_bytes(data)
    return ws, source


def test_special_files_and_symlinks_read_as_empty(dirs: sandbox.JobDirs, tmp_path: Path) -> None:
    secret = tmp_path / "secret.jsonl"
    secret.write_bytes(_line(GOOD_STRING))
    (dirs.out / OUTPUT).symlink_to(secret)
    assert list(_run(dirs, "strings").records()) == []
    (dirs.out / OUTPUT).unlink()
    os.mkfifo(dirs.out / OUTPUT)
    assert list(_run(dirs, "strings").records()) == []
    ws, source = _tool_output(dirs)
    (source.out / capa.OUTPUT).symlink_to(secret)
    errors: list[str] = []
    assert capa.parse(ws, FAST, source, limit=10, errors=errors, truncated={}) == []
    assert errors == ["capa_failed"]


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"[]",
        b'{"rules": []}',
        b"{" * 50_000,
        json.dumps({"rules": {"x": {"meta": "nope"}, "y": 5}}).encode(),
    ],
)
def test_capa_garbage_is_a_failure_not_a_crash(dirs: sandbox.JobDirs, document: bytes) -> None:
    """Parsed by the tool-uid reducer probe; root only sees its validated lines."""
    ws, source = _tool_output(dirs, capa.OUTPUT, document)
    errors: list[str] = []
    result = capa.parse(ws, FAST, source, limit=10, errors=errors, truncated={})
    assert result == [] and errors in ([], ["capa_failed"])


def test_capa_fields_are_validated(dirs: sandbox.JobDirs) -> None:
    rules = {
        "inject thread": {
            "meta": {"namespace": "host-interaction/process/inject",
                     "attack": [{"id": "T1055.003"}, {"id": "T99"}, {"id": None}, "T1620"],
                     "mbc": [{"id": "C0007"}, {"id": "lowercase1"}]},
            "matches": [[1, 2]] * 3,
        },
        "library helper": {"meta": {"lib": True, "namespace": "internal"}, "matches": []},
        "n" * 400: {"meta": {"namespace": "x" + "\x00" * 3}, "matches": {}},
    }  # fmt: skip
    document = json.dumps({"rules": rules}).encode()
    ws, source = _tool_output(dirs, capa.OUTPUT, document)
    truncated: dict[str, bool] = {}
    result = capa.parse(ws, FAST, source, limit=1, errors=[], truncated=truncated)
    assert len(result) == 1 and truncated == {"capabilities": True}
    shutil.rmtree(dirs.root / "probe-capa-out")  # an engine dir is used once per job
    full = capa.parse(ws, FAST, source, limit=10, errors=[], truncated={})
    inject = next(c for c in full if c.name == "inject thread")
    assert inject.attack == ["T1055.003"] and inject.mbc == ["C0007"] and inject.matches == 3
    assert all(c.name != "library helper" for c in full)
    assert any(len(c.name) == 255 and c.namespace == "x" for c in full)


def test_floss_output_is_validated(dirs: sandbox.JobDirs) -> None:
    document = {
        "strings": {
            "stack_strings": [{"string": "stack-string-one"}, {"string": "abc"}, "nope",
                              {"string": "stack-string-one"}, {"string": "z" * 2000}],
            "decoded_strings": {"not": "a list"},
            "tight_strings": [{"string": "tight\x00string"}],
        }
    }  # fmt: skip
    ws, source = _tool_output(dirs, floss.OUTPUT, json.dumps(document).encode())
    records = floss.parse(ws, FAST, source, limit=10, errors=[], truncated={})
    assert [(r.encoding, r.value[:16]) for r in records] == [
        ("floss_stack", "stack-string-one"),
        ("floss_stack", "z" * 16),
        ("floss_tight", "tightstring"),
    ]
    assert len(records[1].value) == 512


def test_clamav_output_only_trusts_lines_for_the_sample(dirs: sandbox.JobDirs) -> None:
    sample = dirs.input / "sample"
    lines = [
        f"{sample}: Win.Test.EICAR_HDB-1 FOUND",
        f"{sample}: Win.Test.EICAR_HDB-1 FOUND",  # --allmatch duplicates
        "/etc/passwd: Forged.Elsewhere FOUND",
        f"{sample}: Heuristics.Limits.Exceeded.MaxScanSize FOUND",
        f"{sample}: OK",
        "LibClamAV Warning: noise",
        f"{sample}: " + "N" * 400 + " FOUND",
    ]
    _plant(dirs, clamav.OUTPUT, "\n".join(lines).encode())
    errors: list[str] = []
    truncated: dict[str, bool] = {}
    matches = clamav.parse(dirs, sample, errors=errors, truncated=truncated)
    assert [m.name[:20] for m in matches] == ["Win.Test.EICAR_HDB-1", "N" * 20]
    assert errors == ["av_not_fully_scanned"] and truncated == {"clamav_limits": True}


def test_huge_clamav_output_counts_as_not_fully_scanned(dirs: sandbox.JobDirs) -> None:
    _plant(dirs, clamav.OUTPUT, b"x" * (clamav.MAX_OUTPUT + 10))
    errors: list[str] = []
    assert clamav.parse(dirs, dirs.input / "sample", errors=errors, truncated={}) == []
    assert errors == ["av_not_fully_scanned"]


def test_zip_precheck_limits() -> None:
    assert not clamav.exceeds_limits({})
    ok = {"members": 3, "declared_bytes": 1000, "largest_member": 900, "depth": 2,
          "encrypted": False, "unchecked": False}  # fmt: skip
    assert not clamav.exceeds_limits(ok)
    assert clamav.exceeds_limits(ok | {"largest_member": clamav.MAX_FILESIZE + 1})
    assert clamav.exceeds_limits(ok | {"declared_bytes": clamav.MAX_SCANSIZE + 1})
    assert clamav.exceeds_limits(ok | {"depth": clamav.MAX_RECURSION + 1})
    assert clamav.exceeds_limits(ok | {"encrypted": True})
    assert clamav.exceeds_limits(ok | {"unchecked": True})


@pytest.mark.parametrize(
    ("returncode", "hits", "expected"),
    [
        (1, True, []),
        (0, False, []),
        (2, True, ["av_not_fully_scanned"]),  # error after printing a match: keep it
        (2, False, ["av_unavailable"]),  # e.g. DB load failure: no verdict at all
        (-9, True, ["av_not_fully_scanned"]),  # killed (RLIMIT_AS, OOM)
        (None, True, ["av_timeout", "av_not_fully_scanned"]),
        (None, False, ["av_timeout"]),
    ],
)
def test_clamav_exit_codes_keep_printed_hits(
    dirs: sandbox.JobDirs, returncode: int | None, hits: bool, expected: list[str]
) -> None:
    sample = dirs.input / "sample"
    output = f"{sample}: Win.Test.EICAR_HDB-1 FOUND\n" if hits else "LibClamAV Error: boom\n"
    _plant(dirs, clamav.OUTPUT, output.encode())
    errors: list[str] = []
    matches = clamav.outcome(dirs, sample, returncode, errors=errors, truncated={})
    assert [m.name for m in matches] == (["Win.Test.EICAR_HDB-1"] if hits else [])
    assert errors == expected


def test_scantime_leaves_headroom_for_the_db_load() -> None:
    argv = clamav.argv(FAST, Path("/s"), Path("/o"), 300, 10)
    assert "--max-scantime=270000" in argv
    assert "--max-scantime=1000" in clamav.argv(FAST, Path("/s"), Path("/o"), 20, 10)


@pytest.mark.parametrize("tool", ["capa", "floss"])
def test_oversized_tool_json_never_reaches_root(dirs: sandbox.JobDirs, tool: str) -> None:
    """The reducer refuses a document above its cap; root reads only its error line."""
    module = capa if tool == "capa" else floss
    cap = reduce.CAPA_MAX_BYTES if tool == "capa" else reduce.FLOSS_MAX_BYTES
    ws, source = _tool_output(dirs, module.OUTPUT, b" " * (cap + 1))
    errors: list[str] = []
    truncated: dict[str, bool] = {}
    assert module.parse(ws, FAST, source, limit=10, errors=errors, truncated=truncated) == []
    assert errors == [f"{tool}_output_too_large"] and truncated == {f"{tool}_output": True}
