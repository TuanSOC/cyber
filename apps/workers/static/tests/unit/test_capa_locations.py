"""M10 phase 6: capa match locations and the capa base address (static worker side).

The reducer (tool uid) keeps only `absolute` match addresses (deduplicated, sorted, at most
32 per rule) and reports `meta.analysis.base_address` in one `capa_meta` line; root validates
that line and puts the base into `StaticResultHeader.capa_base_address` (else the PE
ImageBase; nothing when capa did not run). The documents are hand-written fragments in the
shape of capa 10.x's JSON result document (`rules.*.matches[*] = [Address, Match]`,
`Address = {type, value}`).

The reducer and header tests are pure Python; the probe round trip needs the worker image
(`dirs`, root + the tool uid).
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.static import CapabilityRecord, PeInfo, StaticResultHeader
from cyberlab_worker import sandbox

from static_worker import analyzer
from static_worker.engines import capa
from static_worker.engines.workspace import Workspace
from static_worker.probe import reduce
from tests.conftest import in_container
from tests.helpers import FAST, place

BASE = 0x140000000


def _abs(value: Any) -> dict[str, Any]:
    return {"type": "absolute", "value": value}


def _match(address: dict[str, Any]) -> list[Any]:
    return [address, {"success": True, "node": {"type": "statement"}, "children": []}]


def _document(**rules: list[Any]) -> dict[str, Any]:
    return {
        "meta": {"analysis": {"format": "pe", "arch": "amd64", "base_address": _abs(BASE)}},
        "rules": {
            name: {"meta": {"name": name, "namespace": "host-interaction/test"}, "matches": m}
            for name, m in rules.items()
        },
    }


# --- reducer (tool uid side, pure) ---------------------------------------------------------


def test_only_absolute_addresses_are_kept_sorted_and_unique() -> None:
    stats = reduce.LocationStats()
    matches = [
        _match(_abs(BASE + 0x1300)),
        _match(_abs(BASE + 0x1280)),
        _match(_abs(BASE + 0x1300)),  # duplicate
        _match({"type": "relative", "value": 0x1000}),
        _match({"type": "file", "value": 0x400}),
        _match({"type": "no address"}),
        _match({"type": "dn token", "value": 0x06000001}),
        _match({"type": "process", "value": [1, 2]}),
        _match({"type": "call", "value": [1, 2, 3]}),
        _match(_abs(-1)),
        _match(_abs(2**64)),
        _match(_abs(True)),
        _match(_abs("0x140001000")),
        [],
        "garbage",
        [42, {}],  # a bare integer is not a capa Address
    ]
    assert reduce.capa_locations(matches, stats) == [BASE + 0x1280, BASE + 0x1300]
    assert stats.dropped == 13 and stats.truncated is False


def test_more_than_32_locations_keep_the_lowest_and_flag_truncation() -> None:
    stats = reduce.LocationStats()
    matches = [_match(_abs(BASE + 0x10 * i)) for i in reversed(range(40))]
    kept = reduce.capa_locations(matches, stats)
    assert kept == [BASE + 0x10 * i for i in range(32)]
    assert stats.truncated is True and stats.dropped == 0


@pytest.mark.parametrize("matches", [None, {}, {"0x1000": []}, "x", 7])
def test_non_list_matches_have_no_locations(matches: object) -> None:
    stats = reduce.LocationStats()
    assert reduce.capa_locations(matches, stats) == []
    assert stats.dropped == 0


@pytest.mark.parametrize(
    ("analysis", "expected"),
    [
        ({"base_address": _abs(BASE)}, BASE),
        ({"base_address": _abs(0)}, 0),
        ({"base_address": {"type": "relative", "value": BASE}}, None),
        ({"base_address": {"type": "no address"}}, None),
        ({"base_address": BASE}, None),  # pre-10 integer form: not accepted
        ({"base_address": _abs(2**64)}, None),
        ({"base_address": _abs(True)}, None),
        ({}, None),
        ("nope", None),
    ],
)
def test_the_base_address_is_absolute_only(analysis: object, expected: int | None) -> None:
    assert reduce.capa_base({"meta": {"analysis": analysis}}) == expected
    assert reduce.capa_base({"rules": {}}) is None
    assert reduce.capa_base([]) is None


def test_capability_lines_carry_their_locations_and_validate() -> None:
    document = _document(
        **{
            "inject thread": [_match(_abs(BASE + 0x12A0)), _match(_abs(BASE + 0x1280))],
            "check for debugger": [_match({"type": "no address"})],
        }
    )
    document["rules"]["library helper"] = {"meta": {"lib": True}, "matches": [_match(_abs(1))]}
    stats = reduce.LocationStats()
    lines = list(reduce.capa_records(document, stats))
    records = {r["name"]: CapabilityRecord.model_validate(r) for r in lines}
    assert set(records) == {"inject thread", "check for debugger"}
    assert records["inject thread"].locations == [BASE + 0x1280, BASE + 0x12A0]
    assert records["inject thread"].matches == 2
    assert records["check for debugger"].locations == []
    assert stats.dropped == 1


def _reduce(
    tmp_path: Path, document: object, capsys: pytest.CaptureFixture[str], max_records: int = 100
) -> list[Any]:
    source = tmp_path / "capa.json"
    source.write_text(json.dumps(document))
    capsys.readouterr()
    reduce.run("capa", source, max_records=max_records)
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_the_reducer_reports_the_base_and_the_dropped_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    many = [_match(_abs(BASE + i)) for i in range(33)]
    document = _document(
        a=[_match(_abs(BASE + 0x2000)), _match({"type": "file", "value": 0})], b=many
    )
    out = _reduce(tmp_path, document, capsys)
    [meta] = [line for line in out if line["kind"] == reduce.CAPA_META]
    assert meta == {"kind": "capa_meta", "base_address": BASE, "dropped_locations": 1}
    assert {"kind": "summary", "truncated": {"capability_locations": True}} in out
    caps = {line["name"]: line for line in out if line["kind"] == "capability"}
    assert caps["a"]["locations"] == [BASE + 0x2000] and len(caps["b"]["locations"]) == 32


def test_the_meta_line_survives_the_record_cap(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    document = _document(a=[_match(_abs(BASE))], b=[], c=[])
    out = _reduce(tmp_path, document, capsys, max_records=1)
    assert [line["kind"] for line in out] == ["capability", "summary", "capa_meta"]
    assert out[1] == {"kind": "summary", "truncated": {"capabilities": True}}


def test_a_document_without_a_base_reports_none(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    document = {"rules": {"x": {"meta": {"namespace": "n"}, "matches": []}}}
    out = _reduce(tmp_path, document, capsys)
    assert out[-1] == {"kind": "capa_meta", "base_address": None, "dropped_locations": 0}


# --- root side (pure) ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "base", "dropped"),
    [
        ({"base_address": BASE, "dropped_locations": 3}, BASE, 3),
        ({"base_address": 2**64 - 1, "dropped_locations": -1}, 2**64 - 1, 0),
        ({"base_address": 2**64, "dropped_locations": "3"}, None, 0),
        ({"base_address": -5}, None, 0),
        ({"base_address": True}, None, 0),
        ({"base_address": "0x140000000"}, None, 0),
        ({"base_address": None}, None, 0),
    ],
)
def test_root_validates_the_meta_line(
    line: dict[str, object], base: int | None, dropped: int
) -> None:
    meta = capa.CapaMeta()
    capa.read_meta({"kind": "capa_meta", **line}, meta)
    assert (meta.base_address, meta.dropped_locations) == (base, dropped)


def _pe(image_base: int) -> PeInfo:
    return PeInfo(machine="amd64", bits=64, is_dll=False, entry_point=0x1000, image_base=image_base)


def test_the_header_base_is_capas_else_the_pe_image_base() -> None:
    got = analyzer.Collected(info=_pe(0x400000))
    assert analyzer.capa_base_address(got) is None  # capa did not run
    got.capa_meta = capa.CapaMeta()
    assert analyzer.capa_base_address(got) == 0x400000  # fallback: vivisect loads a PE there
    got.capa_meta.base_address = BASE
    assert analyzer.capa_base_address(got) == BASE
    assert analyzer.capa_base_address(analyzer.Collected(capa_meta=capa.CapaMeta())) is None


def test_the_header_field_is_additive() -> None:
    """Old streams have no base; a new one validates with it (static.v1, RT18)."""
    common = {"job_id": "6a1f0c1e-8d6b-4c55-9d9e-0d1b6f5a1001", "profile": "full",
              "file_format": "pe", "tool_versions": {"capa": "10.0.0"}}  # fmt: skip
    assert StaticResultHeader.model_validate(common).capa_base_address is None
    header = StaticResultHeader.model_validate({**common, "capa_base_address": BASE})
    assert header.capa_base_address == BASE


# --- probe round trip (worker image) -------------------------------------------------------


@in_container
def test_the_probe_hands_locations_and_base_to_root(dirs: sandbox.JobDirs) -> None:
    place(dirs, b"x")
    ws = Workspace(dirs)
    source = ws.engine(f"tool-{os.urandom(4).hex()}")
    document = _document(
        **{
            "inject thread": [_match(_abs(BASE + 0x12A0)), _match(_abs(BASE + 0x1280))],
            "parse PE header": [_match({"type": "no address"})],
        }
    )
    (source.out / capa.OUTPUT).write_text(json.dumps(document))
    meta = capa.CapaMeta()
    truncated: dict[str, bool] = {}
    records = capa.parse(ws, FAST, source, limit=10, errors=[], truncated=truncated, meta=meta)
    by_name = {r.name: r for r in records}
    assert by_name["inject thread"].locations == [BASE + 0x1280, BASE + 0x12A0]
    assert by_name["parse PE header"].locations == []
    assert (meta.base_address, meta.dropped_locations) == (BASE, 1)
    assert truncated == {}


@in_container
def test_a_forged_meta_line_cannot_inject_records(dirs: sandbox.JobDirs) -> None:
    """The meta line only sets the two validated fields; it is never a contract record."""
    place(dirs, b"x")
    ws = Workspace(dirs)
    source = ws.engine(f"tool-{os.urandom(4).hex()}")
    (source.out / capa.OUTPUT).write_text(json.dumps({"rules": {}}))
    meta = capa.CapaMeta()
    assert capa.parse(ws, FAST, source, limit=10, errors=[], truncated={}, meta=meta) == []
    assert meta.base_address is None
