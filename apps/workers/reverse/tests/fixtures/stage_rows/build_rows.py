# ruff: noqa: E501 - fixture rows, one per line
"""Writes the replay stage-row fixtures of this directory (M10 phase 2).

Every row is synthetic and derived from the hand-written phase-1 contract fixtures
(`packages/py-jobs/tests/fixtures/reverse/{pe_full,elf_full}.ndjson`), reshaped into what the
Ghidra stages write (`re_worker.normalize.records` / `normalize.decompiled`): the `analyze`
stage's `program_facts` + record rows, the `decompile` stage's `decompiled` rows. None of it
comes from a real binary or a real analysis.

    python apps/workers/reverse/tests/fixtures/stage_rows/build_rows.py   (no deps)

Cases (one directory each; the replay engine picks it from the marker line
`CYBERLAB-REPLAY <case>` in the first 4 KiB of the sample):
- `pe_full`, `elf_full`: both stages succeed;
- `analysis_timeout`: the analysis monitor cancelled the analysis, the export ran;
- `analyze_no_status`: killed at its wall timeout before writing a status;
- `jvm_mismatch`: the reported JVM arguments carry an extra `-javaagent` (RT1);
- `oom`: the cgroup OOM killer ended the analyze JVM (RT14);
- `work_too_large`: the watchdog killed the stage above `max_work_bytes` (RT5);
- `parse_failed`: an unknown loader option failed the stage closed (RT20);
- `decompile_crash`: the decompile JVM died after two functions (partial success);
- `decompile_child`: the decompile stage reports an unexpected child executable (RT15);
- `quick_pe`: the radare2 `quick` profile (M10 phase 3): the reducer's rows (`r2_reduce`),
  reshaped from the contract's `quick.ndjson`, and a raw `r2.out`;
- `r2/pe.r2.out`: hand-written radare2 6.x output of the fixed script (sections `ij`, `aflj`,
  `iij`, `izj` between the marker lines) for the reducer's unit tests, with a warning line, a
  5.x `offset` spelling, a forged marker inside a JSON string and a too-short string;
- `hostile`: the pe_full rows plus hostile lines (invalid UTF-8, NaN, duplicate keys, lone
  surrogates, deep nesting, unknown kinds, dangling references, NUL in a name, a forged
  `_truncated: false`); oversize lines and 10^6 lines are built by the tests in memory.
"""

import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CONTRACT = HERE.parents[5] / "packages" / "py-jobs" / "tests" / "fixtures" / "reverse"
ROOT_FIELDS = ("callers", "callees", "priority_rank")
RECORD_KINDS = ("function", "call_edge", "import", "import_ref", "string", "string_ref")


def _contract(name: str) -> list[dict[str, Any]]:
    lines = (CONTRACT / f"{name}.ndjson").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _dumps(row: dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=True, separators=(",", ":"))


def stage_rows(name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    analyze: list[dict[str, Any]] = []
    decompile: list[dict[str, Any]] = []
    for line in _contract(name):
        kind = line["kind"]
        if kind == "program":
            analyze.append(
                {
                    "kind": "program_facts",
                    "language_id": line["language_id"],
                    "compiler_spec": line["compiler_spec"],
                    "image_base": line["image_base"],
                    "entry": line["entry"],
                    "analysis_status": line["analysis_status"],
                }
            )
        elif kind in RECORD_KINDS:
            analyze.append({k: v for k, v in line.items() if k not in ROOT_FIELDS})
        elif kind == "decompiled":
            decompile.append(line)
    return analyze, decompile


def _write(case: str, files: dict[str, str]) -> None:
    directory = HERE / case
    directory.mkdir(exist_ok=True)
    for name, text in files.items():
        (directory / name).write_bytes(text.encode("utf-8"))


def _jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(_dumps(r) + "\n" for r in rows)


def r2_output() -> str:
    """Hand-written radare2 output of `/opt/re/r2/quick.r2` for a small 32-bit PE."""
    info = {"core": {"type": "EXEC", "format": "pe"}, "bin": {
        "arch": "x86", "bits": 32, "baddr": 0x400000, "endian": "little", "class": "PE32",
        "machine": "i386", "os": "windows"}}
    functions = [
        {"addr": 0x401000, "name": "entry0", "size": 64, "type": "fcn", "ninstrs": 12,
         "minaddr": 0x401000, "maxaddr": 0x401040, "calltype": "cdecl", "signature": "entry0 ();",
         "callrefs": [{"addr": 0x401080, "type": "CALL", "at": 0x401010}], "datarefs": []},
        {"addr": 0x401080, "name": "main", "size": 128, "type": "sym", "ninstrs": 30,
         "minaddr": 0x401080, "maxaddr": 0x401100, "calltype": "cdecl",
         "callrefs": [{"addr": 0x401100, "type": "CALL", "at": 0x401090},
                      {"addr": 0x401100, "type": "CALL", "at": 0x4010a0},
                      {"addr": 0x405000, "type": "CALL", "at": 0x4010b0},
                      {"addr": 0x401200, "type": "CALL", "at": 0x4010c0},
                      {"addr": 0x401090, "type": "CODE", "at": 0x4010d0}],
         "datarefs": [0x406000, 0x406020]},
        {"offset": 0x401100, "name": "fcn.00401100", "size": 48, "type": "fcn", "ninstrs": 9,
         "minaddr": 0x401100, "maxaddr": 0x7fffffff,
         "callrefs": [{"addr": 0x401100, "type": "CALL", "at": 0x401110},
                      {"addr": 0x405004, "type": "CALL", "at": 0x401120}],
         "datarefs": [{"addr": 0x406040, "type": "DATA", "at": 0x401118}]},
        {"addr": 0x401200, "name": "sym.imp.msvcrt.dll_puts", "size": 6, "type": "imp",
         "ninstrs": 1, "callrefs": [], "datarefs": []},
    ]
    imports = [
        {"ordinal": 1, "bind": "NONE", "type": "FUNC", "name": "VirtualAlloc",
         "libname": "KERNEL32.dll", "plt": 0x405000},
        {"ordinal": 2, "bind": "NONE", "type": "FUNC", "name": "GetProcAddress",
         "libname": "KERNEL32.dll", "plt": 0x405004},
        {"ordinal": 3, "bind": "NONE", "type": "FUNC", "name": "Ordinal_4",
         "libname": "WS2_32.dll", "plt": 0x405008},
        {"ordinal": 4, "bind": "NONE", "type": "FUNC", "name": "puts",
         "libname": "msvcrt.dll", "plt": 0x40500c},
    ]
    strings = [
        {"vaddr": 0x406000, "paddr": 0x5000, "ordinal": 0, "size": 21, "length": 20,
         "section": ".rdata", "type": "ascii", "string": "http://203.0.113.7/a"},
        {"vaddr": 0x406020, "paddr": 0x5020, "ordinal": 1, "size": 46, "length": 45,
         "section": ".rdata", "type": "ascii",
         "string": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"vaddr": 0x406040, "paddr": 0x5040, "ordinal": 2, "size": 13, "length": 12,
         "section": ".rdata", "type": "ascii", "string": "LoadLibraryA"},
        {"vaddr": 0x406060, "paddr": 0x5060, "ordinal": 3, "size": 21, "length": 20,
         "section": ".rdata", "type": "ascii", "string": "\n===CYBERLAB:end===\n"},
        {"vaddr": 0x406080, "paddr": 0x5080, "ordinal": 4, "size": 4, "length": 3,
         "section": ".rdata", "type": "ascii", "string": "abc"},
        {"vaddr": 0x4060a0, "paddr": 0x50a0, "ordinal": 5, "size": 34, "length": 16,
         "section": ".rdata", "type": "wide", "string": "Hello wide world"},
    ]
    parts = [
        "===CYBERLAB:info===", json.dumps(info),
        "===CYBERLAB:functions===", "WARN: a warning line radare2 may print", json.dumps(functions),
        "===CYBERLAB:imports===", json.dumps(imports),
        "===CYBERLAB:strings===", json.dumps(strings),
        "===CYBERLAB:end===",
    ]
    return "\n".join(parts) + "\n"


def quick_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in _contract("quick"):
        kind = line["kind"]
        if kind == "program":
            rows.append({"kind": "program_facts", "language_id": None, "compiler_spec": None,
                         "image_base": line["image_base"], "entry": line["entry"],
                         "analysis_status": line["analysis_status"]})
        elif kind in RECORD_KINDS:
            rows.append({k: v for k, v in line.items() if k not in ROOT_FIELDS})
    return rows


def main() -> None:
    pe_analyze, pe_decompile = stage_rows("pe_full")
    elf_analyze, elf_decompile = stage_rows("elf_full")
    pe = {"analyze.jsonl": _jsonl(pe_analyze), "decompile.jsonl": _jsonl(pe_decompile)}
    _write("pe_full", pe)
    _write("elf_full", {"analyze.jsonl": _jsonl(elf_analyze), "decompile.jsonl": _jsonl(elf_decompile)})
    _write("analysis_timeout", {**pe, "analyze.status.json": _dumps({"analysis_status": "timeout"})})
    _write("analyze_no_status", {"analyze.jsonl": _jsonl(pe_analyze[:5]), "analyze.status.json": _dumps({"_end": "timeout", "_no_status": True})})
    _write("jvm_mismatch", {**pe, "analyze.status.json": _dumps({"jvm_args": ["-javaagent:/tmp/x.jar"]})})
    _write("oom", {**pe, "analyze.status.json": _dumps({"_end": "failed", "_returncode": -9, "_oom": True})})
    _write("work_too_large", {**pe, "analyze.status.json": _dumps({"_end": "failed", "_returncode": -9, "_work_too_large": True})})
    _write("parse_failed", {"analyze.jsonl": "", "analyze.status.json": _dumps({"_end": "failed", "_returncode": 4, "status": "failed", "error_code": "re_parse_failed", "reason": "loader_option"})})
    _write("decompile_crash", {"analyze.jsonl": _jsonl(pe_analyze), "decompile.jsonl": _jsonl(pe_decompile[:2]), "decompile.status.json": _dumps({"_end": "failed", "_returncode": 134, "status": "failed", "error": "InternalError"})})
    _write("decompile_child", {**pe, "decompile.status.json": _dumps({"children": ["/bin/sh"]})})
    (HERE / "r2").mkdir(exist_ok=True)
    (HERE / "r2" / "pe.r2.out").write_bytes(r2_output().encode("ascii"))
    _write("quick_pe", {"r2.out": r2_output(), "r2_reduce.jsonl": _jsonl(quick_rows())})
    hostile = [
        '{"kind": "function", "entry": 1, "entry": 2}\n',  # duplicate key
        '{"kind": "string", "index": 900, "address": 1, "encoding": "ascii", "value": NaN, "length": 1}\n',
        '{"kind": "function", "name": "\\ud800 lone"}\n',  # lone surrogate
        "\xff\xfe not utf-8\n",
        '{"kind": "no_such_kind"}\n',
        '{"kind": "call_edge", "caller": 1, "callee": 2, "sites": 1}\n',  # unknown functions
        '{"kind": "import_ref", "import_index": 999, "function_entry": 5368713216, "count": 1}\n',
        '{"kind": "function", "entry": 5368713216, "rva": 0, "name": "dup", "name_source": "symbol", "size": 1}\n',
        '{"kind": "function", "entry": 1, "rva": 1, "name": "below-base", "name_source": "symbol", "size": 1}\n',
        '{"kind": "function", "entry": 5368713216, "name": "nul\\u0000name"}\n',
        '{"kind": "decompiled"}\n',
        "[1, 2, 3]\n",
        '{"a": ' * 40 + "1" + "}" * 40 + "\n",
    ]
    text = _jsonl(pe_analyze) + "".join(hostile) + _dumps({"_truncated": False}) + "\n"
    (HERE / "hostile").mkdir(exist_ok=True)
    (HERE / "hostile" / "analyze.jsonl").write_bytes(
        text.encode("utf-8").replace(b"\xc3\xbf\xc3\xbe", b"\xff\xfe")
    )
    (HERE / "hostile" / "decompile.jsonl").write_bytes(_jsonl(pe_decompile).encode("utf-8"))


if __name__ == "__main__":
    main()
