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
