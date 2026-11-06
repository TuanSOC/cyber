"""In-probe YARA scan (M9 phase 5; the M3 `probe/yarascan.py` pattern, RT8).

Imported by phase 2's sandboxed `scan` stage shell (`probe/scan_stage.py`), which reads each
candidate's bytes through the image openers and hands them over one item at a time:

    counts = scan(rule_dirs, items, emit, deadline)   # the stage shell's interface
    summary = run(candidates, read, rules, errors, out, max_file_bytes=..., ...)  # budgets

- The rule **sources** are compiled here (`yara.compile(filepaths=...)`, namespaces
  `image.<stem>` / `test.<stem>` from `cyberlab_worker.yara_rules.rule_files`, `include`
  directives refused); never a `.yarc`, because root keys the severity allow-list on each
  source file's sha256. A file that does not compile is dropped and reported; the others run.
- `rules.match(data=<bytes>, timeout=10, fast=False)` per candidate; a timeout or a YARA error
  is counted and the scan goes on.
- Output (JSONL): `hit` lines (the file's natural key, rule, namespace, ≤ 8 tags, the matched
  string instance count ≤ 1 000, and the rule's own `severity` / `description` meta),
  `rule_error` lines and one `summary`. The matched string data is **never** emitted: file
  contents stay in the image.
"""

import json
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, TextIO

from cyberlab_worker.yara_rules import rule_files

from disk_worker.scan import MAX_HITS, MAX_RULES_PER_FILE, MAX_STRINGS_COUNT, MAX_TAGS, Candidate

MATCH_TIMEOUT_S = 10


@dataclass
class ScanSummary:
    candidates: int = 0
    scanned: int = 0
    bytes: int = 0
    skipped: int = 0  # over a budget
    errors: int = 0  # unreadable candidate or YARA error
    timeouts: int = 0
    hits: int = 0
    rule_errors: int = 0
    truncated: bool = False


def _text(value: object, limit: int) -> str:
    """Printable ASCII, at most `limit` characters (rule-supplied strings)."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = "".join(ch if 0x20 <= ord(ch) < 0x7F else "?" for ch in str(value))
    return text[:limit]


def compile_rules(directories: Sequence[Path]) -> tuple[Any | None, list[str]]:
    """(compiled rules or None, namespaces whose file did not compile)."""
    import yara

    files = {ns: str(path) for ns, path in rule_files(list(directories)).items()}
    if not files:
        return None, []
    try:
        return yara.compile(filepaths=files, includes=False), []
    except yara.Error:
        good: dict[str, str] = {}
        failed: list[str] = []
        for namespace, path in files.items():
            try:
                yara.compile(filepath=path, includes=False)
            except yara.Error:
                failed.append(namespace)
                continue
            good[namespace] = path
        return (yara.compile(filepaths=good, includes=False) if good else None), failed


def _strings_count(match: Any) -> int:
    total = 0
    for s in getattr(match, "strings", None) or ():
        instances = getattr(s, "instances", None)  # yara-python >= 4.3: StringMatch
        total += len(instances) if instances is not None else 1  # older: (offset, id, data)
        if total >= MAX_STRINGS_COUNT:
            return MAX_STRINGS_COUNT
    return total


def _hit(candidate: "_Item | Candidate", match: Any) -> dict[str, Any]:
    meta = getattr(match, "meta", None) or {}
    severity = meta.get("severity")
    description = meta.get("description")
    return {
        "kind": "hit",
        "partition_index": candidate.partition_index,
        "meta_addr": candidate.meta_addr,
        "meta_seq": candidate.meta_seq,
        "stream": candidate.stream,
        "namespace": _text(match.namespace, 128),
        "rule": _text(match.rule, 128),
        "tags": [_text(t, 64) for t in list(getattr(match, "tags", None) or ())[:MAX_TAGS]],
        "strings_count": _strings_count(match),
        "severity": _text(severity, 16) if severity is not None else None,
        "description": _text(description, 255) if description is not None else None,
    }


class _Item(Protocol):
    """What the scanner reads of a candidate (phase 2's `probe.scan_stage.ScanItem`)."""

    @property
    def partition_index(self) -> int: ...

    @property
    def meta_addr(self) -> int: ...

    @property
    def meta_seq(self) -> int | None: ...

    @property
    def stream(self) -> str | None: ...

    @property
    def size(self) -> int: ...

    def read(self) -> bytes | None: ...


class _Bound:
    """A `Candidate` with its reader (the `run` entry point)."""

    def __init__(self, candidate: Candidate, reader: Callable[[Candidate], bytes | None]):
        self.candidate = candidate
        self.reader = reader
        self.partition_index = candidate.partition_index
        self.meta_addr = candidate.meta_addr
        self.meta_seq = candidate.meta_seq
        self.stream = candidate.stream
        self.size = candidate.size

    def read(self) -> bytes | None:
        return self.reader(self.candidate)


def _scan_items(
    items: Iterable[_Item],
    rules: Any | None,
    rule_errors: Sequence[str],
    emit: Callable[[dict[str, Any]], bool],
    *,
    max_file_bytes: int | None = None,
    max_files: int | None = None,
    max_bytes: int | None = None,
    max_hits: int = MAX_HITS,
    deadline: float | None = None,
    timeout: int = MATCH_TIMEOUT_S,
) -> ScanSummary:
    import yara

    summary = ScanSummary(rule_errors=len(rule_errors))
    for namespace in rule_errors:
        emit({"kind": "rule_error", "namespace": _text(namespace, 128)})
    stopped = False
    for item in items:
        summary.candidates += 1
        if rules is None:
            continue
        if (
            stopped
            or (deadline is not None and time.monotonic() > deadline)
            or (max_file_bytes is not None and item.size > max_file_bytes)
            or (max_files is not None and summary.scanned >= max_files)
            or (max_bytes is not None and summary.bytes + item.size > max_bytes)
        ):
            summary.skipped += 1
            summary.truncated = True
            continue
        try:
            data = item.read()
        except Exception:  # noqa: BLE001 - one unreadable file never ends the scan
            data = None
        if data is None or (max_file_bytes is not None and len(data) > max_file_bytes):
            summary.errors += 1
            continue
        summary.scanned += 1
        summary.bytes += len(data)
        try:
            matches = rules.match(data=data, timeout=max(1, timeout), fast=False)
        except yara.TimeoutError:
            summary.timeouts += 1
            continue
        except yara.Error:
            summary.errors += 1
            continue
        finally:
            del data
        for match in list(matches)[:MAX_RULES_PER_FILE]:
            if summary.hits >= max_hits or not emit(_hit(item, match)):
                summary.truncated = True
                stopped = True
                break
            summary.hits += 1
        if len(matches) > MAX_RULES_PER_FILE:
            summary.truncated = True
    return summary


def scan(
    rule_dirs: list[Path],
    items: Iterator[_Item],
    emit: Callable[[dict[str, Any]], bool],
    deadline: float,
) -> dict[str, int]:
    """Phase 2's `scan` stage entry point: compile the rule sources, scan every item until
    `deadline` (`time.monotonic()`), write `hit` / `rule_error` lines through `emit` (False
    once the stage's line cap is hit) and return the counts for `status.json`."""
    rules, errors = compile_rules(rule_dirs)
    summary = _scan_items(items, rules, errors, emit, deadline=deadline)
    counts = {k: int(v) for k, v in asdict(summary).items()}
    counts["no_rules"] = int(rules is None)
    return counts


def run(
    candidates: Iterable[Candidate],
    read: Callable[[Candidate], bytes | None],
    rules: Any | None,
    rule_errors: Sequence[str],
    out: TextIO,
    *,
    max_file_bytes: int,
    max_files: int,
    max_bytes: int,
    max_hits: int = MAX_HITS,
    timeout: int = MATCH_TIMEOUT_S,
) -> ScanSummary:
    """Scan candidates within the budgets (re-checked here), JSONL to `out` with a summary."""

    def emit(line: dict[str, Any]) -> bool:
        out.write(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        return True

    summary = _scan_items(
        (_Bound(c, read) for c in candidates),
        rules,
        rule_errors,
        emit,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_bytes=max_bytes,
        max_hits=max_hits,
        timeout=timeout,
    )
    counts = {k: v for k, v in asdict(summary).items() if k != "truncated"}
    emit({"kind": "summary", "counts": counts, "truncated": summary.truncated})
    out.flush()
    return summary
