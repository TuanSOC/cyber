"""YARA candidates, the rule check and the scan stage output (M9 phase 5; RT8, RT18).

Root side of the YARA file scan. The probe side (`probe/scan_yara.py`) runs inside phase 2's
sandboxed `scan` stage, compiles the rule sources and emits bounded JSONL; root never parses a
rule file, it only hashes them (`cyberlab_worker.yara_rules.rule_hashes`).

- `build_candidates(files, profile, limits)`: allocated regular files and named streams with
  `hash_status = hashed` and a magic class in `YARA_MAGIC_CLASSES` (`{pe}`: every M3 baseline
  rule is `pe` / `MZ` anchored, RT8), within the per-file / count / byte budgets (the job's
  `DiskLimits`, never above `PROFILE_BUDGETS[profile]`). Order: user-writable path classes
  first, then size ascending, then path. A `known = good` file is skipped (counted) unless it
  sits in a user-writable path class (RT18: NSRL lists dual-use tools too). One candidate per
  inode stream: hard-linked names share the content and the hit.
- `check_rules(rules_dir, test_rules_dir, versions)`: root hashes the rule files and refuses
  when the baked baseline does not hash to the image's `versions.json` `rules_sha256` (and to
  `BASELINE_SHA256`).
- `parse_scan_output(path)` / `parse_scan_report(path)`: the probe's JSONL, re-validated by
  root with fixed bounds; `resolve_hits(hits, rule_hashes, test_rules=...)` keeps the hits
  whose namespace root hashed and maps severities through the lifted M3 allow-list
  (`yara_ceilings` / `yara_severity`; unknown → `low`); `rules_by_file` gives each file's
  `disk_files.yara_rules`.
"""

import importlib
import json
import os
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from cyberlab_jobs.base import Strict
from cyberlab_jobs.disk import (
    PROFILE_BUDGETS,
    YARA_MAGIC_CLASSES,
    AnalysisProfile,
    DiskFileRecord,
    DiskLimits,
    DiskProfile,
)
from cyberlab_worker.yara_rules import (
    BASELINE_SHA256,
    Severity,
    rule_hashes,
    yara_ceilings,
    yara_severity,
)
from pydantic import Field, TypeAdapter, ValidationError

BASELINE_NAMESPACE = "image.cyberlab_baseline"
MAX_HITS = 100_000
MAX_RULES_PER_FILE = 16  # DiskFileRecord.yara_rules
MAX_TAGS = 8
MAX_STRINGS_COUNT = 1_000
MAX_RULE_ERRORS = 64
MAX_LINE_BYTES = 8 * 1024
MAX_OUTPUT_BYTES = 256 * 1024**2  # the `scan` stage's RLIMIT_FSIZE
MAX_CANDIDATE_LINE_BYTES = 8 * 1024
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)

FileKey = tuple[int, int, int | None, str | None]  # partition, meta_addr, meta_seq, stream
UserWritable = Callable[[DiskFileRecord], bool]


class RulesTampered(RuntimeError):
    """The baked rule source does not hash to the image's recorded sha256 (RT8)."""


@dataclass(frozen=True)
class Candidate:
    partition_index: int
    meta_addr: int
    meta_seq: int | None
    stream: str | None
    size: int

    @property
    def key(self) -> FileKey:
        return (self.partition_index, self.meta_addr, self.meta_seq, self.stream)


@dataclass(frozen=True)
class YaraHit:
    partition_index: int
    meta_addr: int
    stream: str | None
    namespace: str
    rule: str
    severity_meta: str | None  # the rule's own `severity` meta (a claim; see resolve_hits)
    meta_seq: int | None = None
    tags: tuple[str, ...] = ()
    strings_count: int = 0
    description: str | None = None

    @property
    def key(self) -> FileKey:
        return (self.partition_index, self.meta_addr, self.meta_seq, self.stream)

    # `cyberlab_worker.yara_rules.YaraMatch`
    @property
    def name(self) -> str:
        return self.rule

    @property
    def meta(self) -> dict[str, str]:
        return {"severity": self.severity_meta} if self.severity_meta is not None else {}


@dataclass(frozen=True)
class ScoredHit:
    hit: YaraHit
    severity: Severity
    rule_sha256: str


@dataclass
class CandidateSet:
    candidates: list[Candidate] = field(default_factory=list)
    bytes: int = 0
    eligible: int = 0
    skipped_known_good: int = 0
    skipped_too_large: int = 0
    skipped_budget: int = 0

    @property
    def truncated(self) -> bool:
        return bool(self.skipped_too_large or self.skipped_budget)


@dataclass
class ScanReport:
    hits: list[YaraHit] = field(default_factory=list)
    rule_errors: list[str] = field(default_factory=list)  # namespaces whose file did not compile
    summary: dict[str, int | bool] = field(default_factory=dict)
    invalid_lines: int = 0
    truncated: bool = False


# --- candidates ------------------------------------------------------------------------------


def _phase6_user_writable() -> UserWritable | None:
    """Phase 6's path classes (`disk_worker.detections.paths`). The record does not carry its
    file system type, so a path counts as user-writable when it is in a class of either family
    (Windows, case-folded; Linux, case-sensitive): a false positive only means a known-good file
    is scanned, the RT18-safe direction."""
    try:
        paths = importlib.import_module("disk_worker.detections.paths")
    except ImportError:
        return None
    classify = getattr(paths, "user_writable_class", None)
    normalize = getattr(paths, "normalize", None)
    if not callable(classify) or not callable(normalize):
        return None

    def writable(record: DiskFileRecord) -> bool:
        return any(
            classify(normalize(record.path, ci), family) is not None
            for family, ci in (("windows", True), ("linux", False))
        )

    return writable


def _always(record: DiskFileRecord) -> bool:
    return True


def default_user_writable() -> UserWritable:
    """Phase 6's classifier, or (without it) one that calls every file user-writable: known-good
    files are then scanned rather than skipped, the RT18-safe direction."""
    return _phase6_user_writable() or _always


def _budgets(profile: AnalysisProfile, limits: DiskLimits) -> tuple[int, int, int]:
    ceiling = PROFILE_BUDGETS[DiskProfile(profile)]
    return (
        min(limits.yara_max_file_bytes, ceiling["yara_max_file_bytes"]),
        min(limits.yara_max_files, ceiling["yara_max_files"]),
        min(limits.yara_max_bytes, ceiling["yara_max_bytes"]),
    )


def eligible(record: DiskFileRecord) -> bool:
    return (
        record.has_flag("allocated")
        and not record.has_flag("deleted")
        and record.type == "reg"
        and record.hash_status == "hashed"
        and record.magic in YARA_MAGIC_CLASSES
        and record.size is not None
        and record.size > 0
    )


def select_candidates(
    files: Iterable[DiskFileRecord],
    profile: AnalysisProfile,
    limits: DiskLimits,
    *,
    user_writable: UserWritable | None = None,
) -> CandidateSet:
    max_file, max_files, max_bytes = _budgets(profile, limits)
    is_user_writable = user_writable or default_user_writable()
    out = CandidateSet()
    ranked: dict[FileKey, tuple[bool, int, str, Candidate]] = {}
    for record in files:
        if not eligible(record):
            continue
        out.eligible += 1
        writable = is_user_writable(record)
        if record.known == "good" and not writable:
            out.skipped_known_good += 1
            continue
        size = record.size or 0
        if size > max_file:
            out.skipped_too_large += 1
            continue
        candidate = Candidate(
            partition_index=record.partition_index,
            meta_addr=record.meta_addr,
            meta_seq=record.meta_seq,
            stream=record.stream,
            size=size,
        )
        entry = (not writable, size, record.path, candidate)
        previous = ranked.get(candidate.key)
        # A hard-linked inode is scanned once, at its best rank.
        if previous is None or entry[:3] < previous[:3]:
            ranked[candidate.key] = entry
    ordered = sorted(
        ranked.values(),
        key=lambda e: (e[0], e[1], e[2], e[3].partition_index, e[3].meta_addr, e[3].stream or ""),
    )
    for _, size, _, candidate in ordered:
        if len(out.candidates) >= max_files or out.bytes + size > max_bytes:
            out.skipped_budget += 1
            continue
        out.candidates.append(candidate)
        out.bytes += size
    return out


def build_candidates(
    files: Sequence[DiskFileRecord], profile: AnalysisProfile, limits: DiskLimits
) -> list[Candidate]:
    return select_candidates(files, profile, limits).candidates


def write_candidates(path: Path, candidates: Iterable[Candidate]) -> int:
    """The probe's input (JSONL, one candidate per line); root writes it."""
    count = 0
    with open(path, "x", encoding="utf-8") as f:
        for c in candidates:
            f.write(
                json.dumps(
                    {
                        "partition_index": c.partition_index,
                        "meta_addr": c.meta_addr,
                        "meta_seq": c.meta_seq,
                        "stream": c.stream,
                        "size": c.size,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            count += 1
    return count


class _CandidateLine(Strict):
    partition_index: Annotated[int, Field(ge=0, lt=128)]
    meta_addr: Annotated[int, Field(ge=0, le=2**64 - 1)]
    meta_seq: Annotated[int, Field(ge=0, le=2**32 - 1)] | None = None
    stream: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    size: Annotated[int, Field(ge=1)]


def read_candidates(path: Path, max_count: int) -> Iterator[Candidate]:
    """The probe reads root's candidate list back (bounded; a malformed line ends the list)."""
    with open(path, "rb") as f:
        for _ in range(max_count):
            line = f.readline(MAX_CANDIDATE_LINE_BYTES + 1)
            if not line:
                return
            try:
                c = _CandidateLine.model_validate_json(line)
            except ValidationError:
                return
            yield Candidate(c.partition_index, c.meta_addr, c.meta_seq, c.stream, c.size)


# --- rules (root) ----------------------------------------------------------------------------


def rule_dirs(rules_dir: Path, test_rules_dir: Path | None) -> list[Path]:
    """`[image, test]` in `yara_rules.SOURCES` order (the test dir only when configured)."""
    return [rules_dir, test_rules_dir] if test_rules_dir is not None else [rules_dir]


def check_rules(
    rules_dir: Path, test_rules_dir: Path | None, versions: Mapping[str, str] | None
) -> dict[str, str]:
    """namespace -> sha256 of every rule file the probe will compile. Raises `RulesTampered`
    when the baked baseline is missing or does not hash to `versions.json`'s `rules_sha256`
    (the image build pins it to `BASELINE_SHA256`)."""
    hashes = rule_hashes(rule_dirs(rules_dir, test_rules_dir))
    expected = (versions or {}).get("rules_sha256") or BASELINE_SHA256
    actual = hashes.get(BASELINE_NAMESPACE)
    if actual is None:
        raise RulesTampered(f"{BASELINE_NAMESPACE} is missing")
    if actual != expected or actual != BASELINE_SHA256:
        raise RulesTampered(f"{BASELINE_NAMESPACE} hashes to {actual}, not {expected}")
    return hashes


# --- probe output (root) ---------------------------------------------------------------------

_Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]{1,128}$")]
_Printable = Annotated[str, Field(pattern=r"^[\x20-\x7e]*$")]


class _HitLine(Strict):
    kind: Literal["hit"]
    partition_index: Annotated[int, Field(ge=0, lt=128)]
    meta_addr: Annotated[int, Field(ge=0, le=2**64 - 1)]
    meta_seq: Annotated[int, Field(ge=0, le=2**32 - 1)] | None = None
    stream: Annotated[str, Field(min_length=1, max_length=255)] | None = None
    namespace: Annotated[_Printable, Field(min_length=1, max_length=128)]
    rule: _Name
    tags: Annotated[list[Annotated[_Printable, Field(max_length=64)]], Field(max_length=MAX_TAGS)]
    strings_count: Annotated[int, Field(ge=0, le=MAX_STRINGS_COUNT)]
    severity: Annotated[_Printable, Field(max_length=16)] | None = None
    description: Annotated[str, Field(max_length=255, pattern=r"^[^\x00]*$")] | None = None


class _RuleErrorLine(Strict):
    kind: Literal["rule_error"]
    namespace: Annotated[_Printable, Field(max_length=128)]


class _SummaryLine(Strict):
    kind: Literal["summary"]
    counts: Annotated[
        dict[Annotated[str, Field(max_length=32)], Annotated[int, Field(ge=0)]],
        Field(max_length=16),
    ]
    truncated: bool = False


_LINE: TypeAdapter[_HitLine | _RuleErrorLine | _SummaryLine] = TypeAdapter(
    Annotated[_HitLine | _RuleErrorLine | _SummaryLine, Field(discriminator="kind")]
)


def _lines(path: Path) -> Iterator[bytes | None]:
    """Lines of a regular, non-symlink file of at most MAX_OUTPUT_BYTES; None for a line
    longer than MAX_LINE_BYTES (skipped to its end)."""
    fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_OUTPUT_BYTES:
            raise ValueError("the scan output is not a bounded regular file")
        while line := f.readline(MAX_LINE_BYTES + 1):
            if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
                while (rest := f.readline(MAX_LINE_BYTES)) and not rest.endswith(b"\n"):
                    pass
                yield None
                continue
            yield line


def parse_scan_report(path: Path, max_hits: int = MAX_HITS) -> ScanReport:
    report = ScanReport()
    per_file: dict[FileKey, int] = {}
    for raw in _lines(path):
        if raw is None or not raw.strip():
            report.invalid_lines += raw is None
            continue
        try:
            line = _LINE.validate_json(raw)
        except ValidationError:
            report.invalid_lines += 1
            continue
        if isinstance(line, _SummaryLine):
            report.summary = {**line.counts, "truncated": line.truncated}
            report.truncated |= line.truncated
        elif isinstance(line, _RuleErrorLine):
            if len(report.rule_errors) < MAX_RULE_ERRORS:
                report.rule_errors.append(line.namespace)
        else:
            hit = YaraHit(
                partition_index=line.partition_index,
                meta_addr=line.meta_addr,
                meta_seq=line.meta_seq,
                stream=line.stream,
                namespace=line.namespace,
                rule=line.rule,
                severity_meta=line.severity,
                tags=tuple(line.tags),
                strings_count=line.strings_count,
                description=line.description,
            )
            seen = per_file.get(hit.key, 0)
            if len(report.hits) >= max_hits or seen >= MAX_RULES_PER_FILE:
                report.truncated = True
                continue
            per_file[hit.key] = seen + 1
            report.hits.append(hit)
    return report


def parse_scan_output(path: Path) -> list[YaraHit]:
    return parse_scan_report(path).hits


def resolve_hits(
    hits: Iterable[YaraHit], hashes: Mapping[str, str], *, test_rules: bool
) -> tuple[list[ScoredHit], int]:
    """(hits whose namespace root hashed, with the allow-listed severity; dropped count). A
    namespace the probe names but root never hashed (or a `test.*` one outside the test
    profile) is dropped: the allow-list is keyed on root's hashes only."""
    ceilings = yara_ceilings(dict(hashes), test_rules=test_rules)
    out: list[ScoredHit] = []
    dropped = 0
    for hit in hits:
        sha256 = hashes.get(hit.namespace)
        if sha256 is None or (hit.namespace.startswith("test.") and not test_rules):
            dropped += 1
            continue
        out.append(ScoredHit(hit=hit, severity=yara_severity(hit, ceilings), rule_sha256=sha256))
    return out, dropped


def rules_by_file(hits: Iterable[ScoredHit]) -> dict[FileKey, list[str]]:
    """`disk_files.yara_rules` per file key: sorted unique rule names, at most 16."""
    rules: dict[FileKey, set[str]] = {}
    for scored in hits:
        rules.setdefault(scored.hit.key, set()).add(scored.hit.rule)
    return {k: sorted(v)[:MAX_RULES_PER_FILE] for k, v in rules.items()}


def apply_rules(record: DiskFileRecord, by_file: Mapping[FileKey, list[str]]) -> DiskFileRecord:
    key = (record.partition_index, record.meta_addr, record.meta_seq, record.stream)
    rules = by_file.get(key)
    return record.model_copy(update={"yara_rules": rules}) if rules else record
