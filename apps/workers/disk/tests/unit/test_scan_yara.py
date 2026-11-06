"""M9 phase 5: the in-probe YARA scan, root's rule check, the bounded output parser and the
severity mapping through the lifted M3 allow-list (RT8). The probe flow runs against a stub
`yara` module on any host and against real yara-python (with the M3 baseline and test marker
rules) where it is installed (the disk worker image)."""

import io
import json
import shutil
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cyberlab_worker.yara_rules import BASELINE_SHA256, TEST_RULES_SHA256

from disk_worker import scan
from disk_worker.probe import scan_yara
from disk_worker.scan import (
    Candidate,
    RulesTampered,
    YaraHit,
    check_rules,
    parse_scan_report,
    resolve_hits,
    rules_by_file,
)

MARKER = b"CYBERLAB-STATIC-TEST-MARKER-7f3a"
CLAMP = b"CYBERLAB-SEVERITY-CLAMP-TEST"
_STATIC = Path(__file__).resolve().parents[3] / "static"


def _source(repo: Path, image: Path) -> Path | None:
    for p in (repo, image):
        if p.is_file():
            return p
    return None


BASELINE = _source(_STATIC / "rules/yara/cyberlab_baseline.yar",
                   Path("/opt/rules/image/cyberlab_baseline.yar"))
TEST_RULES = _source(_STATIC / "tests/rules/yara/cyberlab_test.yar",
                     Path("/srv/rules-test/cyberlab_test.yar"))


@pytest.fixture
def rules(tmp_path: Path) -> tuple[Path, Path]:
    if BASELINE is None or TEST_RULES is None:
        pytest.skip("the M3 rule sources are not available here")
    image, test = tmp_path / "image", tmp_path / "test"
    image.mkdir()
    test.mkdir()
    shutil.copyfile(BASELINE, image / "cyberlab_baseline.yar")
    shutil.copyfile(TEST_RULES, test / "cyberlab_test.yar")
    return image, test


# --- root: the rule check --------------------------------------------------------------------


def test_check_rules_hashes_without_parsing(rules: tuple[Path, Path]) -> None:
    image, test = rules
    assert check_rules(image, None, {"rules_sha256": BASELINE_SHA256}) == {
        "image.cyberlab_baseline": BASELINE_SHA256
    }
    assert check_rules(image, test, None) == {
        "image.cyberlab_baseline": BASELINE_SHA256,
        "test.cyberlab_test": TEST_RULES_SHA256,
    }


def test_a_tampered_or_missing_baseline_is_refused(rules: tuple[Path, Path]) -> None:
    image, _ = rules
    with pytest.raises(RulesTampered):
        check_rules(image, None, {"rules_sha256": "0" * 64})
    with open(image / "cyberlab_baseline.yar", "a") as f:
        f.write("\n// edited\n")
    with pytest.raises(RulesTampered):
        check_rules(image, None, {"rules_sha256": BASELINE_SHA256})
    (image / "cyberlab_baseline.yar").unlink()
    with pytest.raises(RulesTampered):
        check_rules(image, None, None)


# --- root: output parsing and severities -----------------------------------------------------


def _hit(**kw: Any) -> dict[str, Any]:
    line = {
        "kind": "hit",
        "partition_index": 0,
        "meta_addr": 42,
        "meta_seq": 1,
        "stream": None,
        "namespace": "test.cyberlab_test",
        "rule": "CyberLab_Test_Marker",
        "tags": ["test"],
        "strings_count": 2,
        "severity": "medium",
        "description": "CyberLab synthetic test marker string",
    }
    line.update(kw)
    return line


def _write(path: Path, lines: list[Any]) -> Path:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write((line if isinstance(line, str) else json.dumps(line)) + "\n")
    return path


def test_parse_validates_and_bounds(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "scan.jsonl",
        [
            {"kind": "rule_error", "namespace": "image.broken"},
            _hit(),
            _hit(rule="bad name!"),  # invalid rule name
            _hit(strings_count=5000),  # over the bound
            _hit(tags=["t"] * 9),
            _hit(matched_data="4d5a"),  # an unknown field: matched bytes are never accepted
            "not json",
            "x" * 20_000,
            _hit(meta_addr=43, rule="Other"),
            {"kind": "summary", "counts": {"scanned": 2, "hits": 2}, "truncated": False},
        ],
    )
    report = parse_scan_report(path)
    assert [(h.meta_addr, h.rule) for h in report.hits] == [
        (42, "CyberLab_Test_Marker"), (43, "Other")
    ]
    assert report.rule_errors == ["image.broken"]
    assert report.invalid_lines == 6
    assert report.summary["scanned"] == 2
    assert scan.parse_scan_output(path) == report.hits  # the frozen signature


def test_parse_caps_hits_per_file_and_total(tmp_path: Path) -> None:
    lines = [_hit(rule=f"R{i}") for i in range(20)] + [_hit(meta_addr=99, rule="X")]
    report = parse_scan_report(_write(tmp_path / "s.jsonl", lines))
    assert len(report.hits) == 17 and report.truncated
    report = parse_scan_report(_write(tmp_path / "t.jsonl", lines), max_hits=5)
    assert len(report.hits) == 5 and report.truncated


def test_parse_refuses_a_symlink_or_oversized_output(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.jsonl", [_hit()])
    try:
        (tmp_path / "link.jsonl").symlink_to(target)
    except OSError:
        pytest.skip("symlinks are not available on this host")
    with pytest.raises(OSError):
        parse_scan_report(tmp_path / "link.jsonl")


def test_severities_through_the_allow_list() -> None:
    hashes = {"image.cyberlab_baseline": BASELINE_SHA256, "test.cyberlab_test": TEST_RULES_SHA256}

    def h(ns: str, rule: str, sev: str | None) -> YaraHit:
        return YaraHit(0, 1, None, ns, rule, sev)

    hits = [
        h("image.cyberlab_baseline", "CyberLab_Embedded_PE_In_Overlay", "high"),  # → medium
        h("image.cyberlab_baseline", "CyberLab_UPX_Section_Names", "medium"),  # unlisted → low
        h("test.cyberlab_test", "CyberLab_Test_Marker", "medium"),  # test profile → medium
        h("test.cyberlab_test", "CyberLab_Test_Unlisted_High", "high"),  # → low
        h("image.cyberlab_baseline", "CyberLab_Embedded_PE_In_Resource", "bogus"),  # → low
        h("image.planted", "CyberLab_Embedded_PE_In_Overlay", "high"),  # never hashed: dropped
    ]
    scored, dropped = resolve_hits(hits, hashes, test_rules=True)
    assert [s.severity for s in scored] == ["medium", "low", "medium", "low", "low"]
    assert dropped == 1
    # Outside the test profile the test namespace is dropped and never allow-listed.
    scored, dropped = resolve_hits(hits, hashes, test_rules=False)
    assert [s.hit.namespace for s in scored] == ["image.cyberlab_baseline"] * 3
    assert dropped == 3
    # A copied rule name under another file's hash inherits nothing.
    fake = {"image.cyberlab_baseline": "f" * 64}
    scored, _ = resolve_hits(hits[:1], fake, test_rules=False)
    assert scored[0].severity == "low"


def test_rules_by_file() -> None:
    hits = [
        YaraHit(0, 1, None, "image.x", f"R{i:02}", None, meta_seq=2) for i in range(20)
    ] + [YaraHit(0, 1, None, "image.x", "R00", None, meta_seq=2)]
    scored, _ = resolve_hits(hits, {"image.x": "a" * 64}, test_rules=False)
    by_file = rules_by_file(scored)
    assert by_file == {(0, 1, 2, None): [f"R{i:02}" for i in range(16)]}


# --- probe: stub yara ------------------------------------------------------------------------


class _StubError(Exception):
    pass


class _StubTimeout(_StubError):
    pass


class _StubString:
    def __init__(self, n: int) -> None:
        self.instances = [object()] * n


class _StubMatch:
    def __init__(self, namespace: str, rule: str, n: int) -> None:
        self.namespace = namespace
        self.rule = rule
        self.tags = [f"t{i}" for i in range(12)]
        self.meta = {"severity": "medium", "description": "stub\nrule"}
        self.strings = [_StubString(n)]


class _StubRules:
    def __init__(self, namespaces: list[str]) -> None:
        self.namespaces = namespaces
        self.calls: list[dict[str, Any]] = []

    def match(self, *, data: bytes, timeout: int, fast: bool) -> list[_StubMatch]:
        self.calls.append({"len": len(data), "timeout": timeout, "fast": fast})
        if b"SLOW" in data:
            raise _StubTimeout()
        if b"FAIL" in data:
            raise _StubError()
        n = data.count(MARKER)
        return [_StubMatch(ns, "Marker", n) for ns in self.namespaces] if n else []


def _stub_yara() -> types.ModuleType:
    mod = types.ModuleType("yara")

    def compile(*, filepaths: dict[str, str] | None = None, filepath: str | None = None,
                includes: bool = True) -> _StubRules:
        assert includes is False
        paths = filepaths or {"default": filepath or ""}
        for p in paths.values():
            if b"SYNTAX_ERROR" in Path(p).read_bytes():
                raise _StubError("syntax")
        return _StubRules(sorted(paths))

    mod.compile = compile  # type: ignore[attr-defined]
    mod.Error = _StubError  # type: ignore[attr-defined]
    mod.TimeoutError = _StubTimeout  # type: ignore[attr-defined]
    return mod


@pytest.fixture
def stub_yara(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setitem(sys.modules, "yara", _stub_yara())
    yield


def _cands(*sizes: int) -> list[Candidate]:
    return [Candidate(0, 100 + i, 1, None, s) for i, s in enumerate(sizes)]


def test_probe_compiles_sources_and_drops_broken_files(stub_yara: None, tmp_path: Path) -> None:
    image, test = tmp_path / "image", tmp_path / "test"
    image.mkdir()
    test.mkdir()
    (image / "good.yar").write_text("rule a { condition: true }")
    (image / "broken.yar").write_text("SYNTAX_ERROR")
    (test / "t.yara").write_text("rule b { condition: true }")
    (image / "compiled.yarc").write_bytes(b"\x00")  # never loaded
    compiled, errors = scan_yara.compile_rules([image, test])
    assert errors == ["image.broken"]
    assert compiled.namespaces == ["image.good", "test.t"]
    assert scan_yara.compile_rules([tmp_path / "none"]) == (None, [])


def test_probe_scan_emits_bounded_lines_without_matched_bytes(
    stub_yara: None, tmp_path: Path
) -> None:
    contents = {
        100: b"MZ" + MARKER * 3,
        101: b"MZ SLOW",
        102: b"MZ FAIL",
        103: b"MZ clean",
        104: b"MZ" + MARKER * 2000,
    }
    cands = _cands(*(len(contents[100 + i]) for i in range(5))) + [Candidate(0, 105, 1, None, 9)]

    def read(c: Candidate) -> bytes | None:
        if c.meta_addr == 105:
            raise OSError("unreadable")
        return contents[c.meta_addr]

    rules = _StubRules(["image.cyberlab_baseline", "test.cyberlab_test"])
    out = io.StringIO()
    summary = scan_yara.run(cands, read, rules, ["image.broken"], out,
                            max_file_bytes=10**6, max_files=100, max_bytes=10**9)
    assert (summary.scanned, summary.timeouts, summary.errors, summary.hits) == (5, 1, 2, 4)
    assert all(c == {"len": c["len"], "timeout": 10, "fast": False} for c in rules.calls)
    text = out.getvalue()
    assert MARKER.decode() not in text
    path = tmp_path / "scan.jsonl"
    path.write_text(text, encoding="utf-8")
    report = parse_scan_report(path)
    assert report.invalid_lines == 0
    assert report.rule_errors == ["image.broken"]
    assert {(h.meta_addr, h.strings_count) for h in report.hits} == {(100, 3), (104, 1000)}
    assert all(len(h.tags) == 8 and h.description == "stub?rule" for h in report.hits)
    assert report.summary["hits"] == 4


def test_probe_rechecks_budgets(stub_yara: None) -> None:
    rules = _StubRules(["image.x"])
    data = b"MZ" + MARKER

    def read(c: Candidate) -> bytes:
        return data

    out = io.StringIO()
    s = scan_yara.run(_cands(10, 10, 10, 10**7), read, rules, [], out,
                      max_file_bytes=10**6, max_files=2, max_bytes=10**9)
    assert (s.scanned, s.skipped, s.truncated) == (2, 2, True)
    s = scan_yara.run(_cands(len(data)) * 3, read, rules, [], io.StringIO(),
                      max_file_bytes=10**6, max_files=10, max_bytes=2 * len(data))
    assert (s.scanned, s.skipped) == (2, 1)
    s = scan_yara.run(_cands(10), lambda c: b"x" * 100, rules, [], io.StringIO(),
                      max_file_bytes=50, max_files=10, max_bytes=10**9)
    assert (s.scanned, s.errors) == (0, 1)  # the reader returned more than the per-file cap
    s = scan_yara.run(_cands(10), read, None, [], io.StringIO(),
                      max_file_bytes=50, max_files=10, max_bytes=10**9)
    assert (s.candidates, s.scanned) == (1, 0)


# --- probe: real yara-python (the disk worker image) -----------------------------------------


def test_real_yara_marker_and_clamp(rules: tuple[Path, Path], tmp_path: Path) -> None:
    pytest.importorskip("yara")
    image, test = rules
    compiled, errors = scan_yara.compile_rules([image, test])
    assert errors == [] and compiled is not None
    contents = {100: b"MZ" + b"\x00" * 64 + MARKER, 101: b"MZ" + CLAMP, 102: b"MZ" + b"\x00" * 64}
    out = io.StringIO()
    scan_yara.run(_cands(*(len(contents[100 + i]) for i in range(3))),
                  lambda c: contents[c.meta_addr], compiled, errors, out,
                  max_file_bytes=10**6, max_files=10, max_bytes=10**9)
    path = tmp_path / "scan.jsonl"
    path.write_text(out.getvalue(), encoding="utf-8")
    hashes = check_rules(image, test, {"rules_sha256": BASELINE_SHA256})
    scored, dropped = resolve_hits(parse_scan_report(path).hits, hashes, test_rules=True)
    assert dropped == 0
    got = {(s.hit.meta_addr, s.hit.rule, s.severity) for s in scored}
    assert got == {
        (100, "CyberLab_Test_Marker", "medium"),
        (101, "CyberLab_Test_Unlisted_High", "low"),
    }
    assert MARKER.decode() not in out.getvalue()


def test_stage_shell_interface(stub_yara: None, tmp_path: Path) -> None:
    """`scan(rule_dirs, items, emit, deadline)`: phase 2's `probe/scan_stage.py` calls it with
    `ScanItem`s; `emit` returning False (the stage's line cap) stops emitting."""
    import time
    from dataclasses import dataclass as dc

    @dc(frozen=True)
    class Item:
        partition_index: int
        meta_addr: int
        meta_seq: int | None
        stream: str | None
        size: int
        data: bytes | None

        def read(self) -> bytes | None:
            return self.data

    image = tmp_path / "image"
    image.mkdir()
    (image / "cyberlab_baseline.yar").write_text("rule a { condition: true }")
    items = [Item(0, 1 + i, None, None, 10, b"MZ" + MARKER if i != 2 else None) for i in range(5)]
    lines: list[dict[str, Any]] = []

    def emit(line: dict[str, Any]) -> bool:
        lines.append(line)
        return len(lines) < 3

    counts = scan_yara.scan([image], iter(items), emit, time.monotonic() + 60)
    assert counts["hits"] == 2 and counts["truncated"] == 1 and counts["errors"] == 1
    assert all(isinstance(v, int) for v in counts.values())
    assert [line["meta_addr"] for line in lines] == [1, 2, 4]
    counts = scan_yara.scan([image], iter(items), lambda _l: True, time.monotonic() - 1)
    assert counts["scanned"] == 0 and counts["skipped"] == 5
    counts = scan_yara.scan([tmp_path / "none"], iter(items), lambda _l: True, 0.0)
    assert counts["no_rules"] == 1 and counts["scanned"] == 0
