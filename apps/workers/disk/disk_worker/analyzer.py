"""The disk analysis of one job (M9 phase 2; `analyze(job, dirs, config) -> Path` is frozen).

Root never parses image bytes beyond the magic check (`formats`):
1. free-space check (image + 3 × artifact budget + the floor + 2 GiB) → `insufficient_disk`;
2. every segment downloaded through the kit (sha256 + size verified, root-owned 0444; the
   kit's `integrity_mismatch`, RT22), no image cache (RT1);
3. the magic check of segment 0 (and a VHD footer at the end of the last segment) →
   `unsupported_disk_format` before any probe runs; the segments renamed to the fixed names
   the probes open; the concatenated media sha256 for split raw (root, streaming);
4. stages through `stage.run_stage` (fresh out dir, deadline budget, watchdog, kill + seal):
   `layout` (also the media size, and the EWF stored hashes) → `verify` (EWF only; budgeted by
   the media size, so it runs after `layout`; a timeout is `not_verified`, RT6) → `walk` per
   opened file system (OS partitions first, RT5) → `collect` per OS partition (phase 3's
   catalog plan after `never_collect()` over every name of each inode, RT7) → `scan` (phase 5)
   → the timeline (phase 3);
5. hash-set matching (phase 5), detections over every event (phase 6; pass 1), the stored
   events (phase 3; pass 2: the quotas plus every cited event, RT10), assembly → `disk.v1`.

Job success: the downloads, `layout`, `verify` (when EWF; a timeout or skip leaves
`not_verified`) and at least one `walk`. No file system opened, or none walked: the diagnostic
stream (header + partitions) and `no_supported_filesystem` (`DiagnosticResult`). The format
refused by a probe (libewf, the media-size cap): `unsupported_disk_format` with a diagnostic
stream. The floor of the write watchdog hit before any walk succeeded: `insufficient_disk`.
Every later stage is best effort and reported in the header.

Phases 3 / 5 / 6 plug in through their frozen entry points; a stub that still raises
`NotImplementedError` reports its stage `skipped` (`not_available`).
"""

import hashlib
import json
import os
import re
import shutil
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from cyberlab_jobs.disk import (
    CASE_INSENSITIVE_FS,
    DIAGNOSTIC_ERROR_CODES,
    ArtifactStat,
    DetectionOutput,
    DiskArtifact,
    DiskEventRecord,
    DiskFileRecord,
    DiskJobV1,
    DiskLimits,
    DiskPartitionRecord,
    DiskStage,
    DiskView,
    EwfInfo,
    FsType,
    ImageFormat,
    MediaHashStatus,
    StageLimitKey,
    StageStatus,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.transfer import download
from pydantic import ValidationError

from disk_worker import detections, formats, scan, stage, timeline
from disk_worker.budget import Budget
from disk_worker.config import Config, ConfigError, tool_versions
from disk_worker.hashsets.store import HashSetStore
from disk_worker.normalize import BAD_ROW_RATIO
from disk_worker.normalize.events import EventSource
from disk_worker.normalize.models import CollectedRow, FileRow, HashRow, PartitionRow
from disk_worker.normalize.reader import ReadStats, read_jsonl
from disk_worker.normalize.records import (
    NameIndex,
    build_index,
    file_record,
    partition_record,
    with_hard_links,
)
from disk_worker.probe.names import is_safe_relative
from disk_worker.result import RunFacts, ewf_mismatch_finding, write_diagnostic, write_result
from disk_worker.timeline import catalog
from disk_worker.timeline.replay import ReplayRefused

GIB = 1024**3
MIB = 1024**2
HEADROOM = 2 * GIB
TEST_HEADROOM = 16 * MIB
RESULT = "result.ndjson.gz"
DIAGNOSTIC = "diagnostic.ndjson.gz"
PROBE_MODULE = "disk_worker.probe"
MAX_DIR_ENTRIES = 200_000
# Files the root reads from a stage's out dir (bounded on top of RLIMIT_FSIZE).
MAX_STAGE_FILE = 2 * GIB
FAMILY = {
    FsType.NTFS: "ntfs",
    FsType.FAT12: "fat",
    FsType.FAT16: "fat",
    FsType.FAT32: "fat",
    FsType.EXFAT: "fat",
    FsType.EXT2: "ext",
    FsType.EXT3: "ext",
    FsType.EXT4: "ext",
}
YARA_STORED = re.compile(r"^[A-Za-z0-9_.]{1,128}$")  # `DiskFileRecord.yara_rules`


class DiagnosticResult(JobFailed):
    """No file system could be opened (or the format was refused after the layout): `path` is
    the diagnostic stream (header, at most the partitions, trailer) to upload, then report
    failed / `code` with its version id."""

    def __init__(self, code: str, path: Path) -> None:
        if code not in DIAGNOSTIC_ERROR_CODES:
            raise ValueError(f"{code} is not a diagnostic error code")
        super().__init__(code)
        self.path = path


def _test_profile() -> bool:
    return os.environ.get("TEST_PROFILE") == "1"


def required_free(job: DiskJobV1, config: Config) -> int:
    total = sum(s.size_bytes for s in job.segments)
    headroom = TEST_HEADROOM if _test_profile() else HEADROOM
    return total + 3 * job.limits.artifact_max_bytes + config.min_free_bytes + headroom


@dataclass
class Partition:
    row: PartitionRow
    walk_error: str | None = None

    @property
    def index(self) -> int:
        return self.row.index

    @property
    def offset(self) -> int:
        return self.row.start_sector * self.row.sector_size

    @property
    def family(self) -> str | None:
        return FAMILY.get(self.row.fs_type) if self.row.fs_type is not None else None

    def record(self) -> DiskPartitionRecord:
        return partition_record(self.row, self.walk_error)


@dataclass
class Job:
    """Everything one analysis holds between stages."""

    job: DiskJobV1
    dirs: sandbox.JobDirs
    config: Config
    budget: Budget
    facts: RunFacts
    paths: list[Path] = field(default_factory=list)
    partitions: list[Partition] = field(default_factory=list)
    files: list[DiskFileRecord] = field(default_factory=list)
    index: NameIndex = field(default_factory=NameIndex)
    walked: bool = False
    python: str = sys.executable

    @property
    def limits(self) -> DiskLimits:
        return self.job.limits

    def image_spec(self) -> dict[str, Any]:
        return {
            "format": self.facts.format.value,
            "paths": [str(p) for p in self.paths],
            "max_media": self.limits.max_media_bytes,
        }

    def write_args(self, name: str, args: dict[str, Any]) -> Path:
        """Root writes the stage's arguments into the read-only input dir (0444)."""
        path = self.dirs.input / f"{name}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            json.dump(args, f, ensure_ascii=True, allow_nan=False)
        return path

    def run(
        self, probe_stage: str, key: StageLimitKey, name: str, args: dict[str, Any]
    ) -> stage.StageResult:
        timeout = self.budget.timeout(key)
        if timeout <= 0:
            return stage.StageResult(
                stage=key,
                status=StageStatus.SKIPPED,
                out_dir=self.dirs.root / f"{name}-out",
                reason="deadline",
            )
        sd = stage.fresh(self.dirs, name)
        # The probe stops itself before the hard timeout so its status is always written.
        soft = max(5.0, timeout - min(60.0, timeout * 0.1))
        args = {**args, "out": str(sd.out), "image": self.image_spec(), "deadline_s": soft}
        argv = [
            self.python,
            "-I",
            "-s",
            "-B",
            "-m",
            PROBE_MODULE,
            probe_stage,
            str(self.write_args(name, args)),
        ]
        result = stage.run_stage(argv, sd, key, self.limits, self.budget)
        if result.error_code == "insufficient_disk" and not self.walked:
            raise JobFailed("insufficient_disk", f"the work volume floor was hit in {name}")
        return result


# --- download and format ----------------------------------------------------------------------


def _download(j: Job) -> None:
    job = j.job
    started = Budget.monotonic()
    raw_paths = []
    for seg in job.segments:
        dest = j.dirs.input / f"segment-{seg.ordinal:03d}"
        download(
            str(seg.url),
            dest,
            expected_sha256=seg.expected_sha256,
            size_bytes=seg.size_bytes,
            max_bytes=job.limits.max_image_bytes,
            too_large_code="disk_image_too_large",
        )
        raw_paths.append(dest)
    head, footer = formats.read_magic(raw_paths)
    try:
        fmt = formats.detect(head, footer, len(raw_paths))
    except formats.UnsupportedFormat as exc:
        j.facts.report(DiskStage.DOWNLOAD, status="unsupported", reason=exc.reason)
        raise JobFailed("unsupported_disk_format", exc.reason) from exc
    j.facts.format = fmt
    for ordinal, src in enumerate(raw_paths):
        dst = j.dirs.input / formats.segment_name(fmt, ordinal, len(raw_paths))
        os.rename(src, dst)
        j.paths.append(dst)
    if fmt == ImageFormat.RAW:
        j.facts.media_sha256 = job.segments[0].expected_sha256
        j.facts.media_size = job.segments[0].size_bytes
    elif fmt == ImageFormat.SPLIT_RAW:
        j.facts.media_sha256 = _concat_sha256(j.paths)
        j.facts.media_size = sum(s.size_bytes for s in job.segments)
    duration = int((Budget.monotonic() - started) * 1000)
    j.facts.report(DiskStage.DOWNLOAD, status="ok", duration_ms=duration, rows=len(job.segments))


def _concat_sha256(paths: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        with open(path, "rb") as f:
            while chunk := f.read(4 * MIB):
                digest.update(chunk)
    return digest.hexdigest()


# --- reading stage output ---------------------------------------------------------------------


def _rows(
    result: stage.StageResult, name: str, stats: ReadStats, max_rows: int
) -> Iterator[dict[str, Any]]:
    dirs = sandbox.JobDirs(root=result.out_dir.parent, input=result.out_dir, out=result.out_dir)
    try:
        with sandbox.open_output(dirs, name) as f:
            yield from read_jsonl(f, stats, max_rows=max_rows, max_bytes=MAX_STAGE_FILE)
    except (OSError, ValueError):
        return


def _too_bad(stats: ReadStats) -> bool:
    return stats.bad_ratio() > BAD_ROW_RATIO


# --- layout and verify ------------------------------------------------------------------------


def _diagnostic(j: Job, code: str) -> DiagnosticResult:
    path = j.dirs.root / DIAGNOSTIC
    records = [p.record() for p in j.partitions]
    return DiagnosticResult(code, write_diagnostic(path, j.facts, records))


def _layout(j: Job) -> None:
    res = j.run(
        "layout",
        "layout",
        "layout",
        {
            "max_partitions": j.limits.max_partitions,
            "max_filesystems": j.limits.max_filesystems,
        },
    )
    j.facts.report(DiskStage.LAYOUT, res)
    if res.status == StageStatus.UNSUPPORTED:
        raise _diagnostic(j, "unsupported_disk_format")
    if res.status in (StageStatus.SKIPPED, StageStatus.TIMEOUT):
        raise JobFailed("stage_timeout", "layout")
    if not res.usable:
        raise JobFailed(res.error_code or "disk_parse_failed", "layout")
    facts = res.facts
    media, sector = facts.get("media_size"), facts.get("sector_size")
    if isinstance(media, int) and media >= 0:
        j.facts.media_size = media
    if isinstance(sector, int) and 0 < sector <= 65_536:
        j.facts.sector_size = sector
    j.budget.set_media_size(j.facts.media_size)
    if j.facts.format == ImageFormat.EWF:
        j.facts.ewf = _ewf_info(facts, None)
    stats = ReadStats()
    seen: set[int] = set()
    for raw in _rows(res, "partitions.jsonl", stats, j.limits.max_partitions):
        try:
            row = PartitionRow.model_validate(raw)
        except ValidationError:
            stats.bad += 1
            continue
        if row.index in seen:
            stats.bad += 1
            continue
        seen.add(row.index)
        j.partitions.append(Partition(row))
    if stats.truncated:
        j.facts.truncate("partitions")
    if stats.bad:
        j.facts.error("layout_bad_rows")
    if _too_bad(stats):
        raise JobFailed("disk_parse_failed", "layout rows")


def _ewf_info(facts: dict[str, Any], verified: dict[str, Any] | None) -> EwfInfo:
    source = verified or facts
    md5 = source.get("stored_md5") if isinstance(source.get("stored_md5"), str) else None
    sha1 = source.get("stored_sha1") if isinstance(source.get("stored_sha1"), str) else None
    meta_raw = source.get("ewf_meta")
    meta = (
        {str(k)[:64]: str(v)[:256] for k, v in list(meta_raw.items())[:8]}
        if isinstance(meta_raw, dict)
        else {}
    )
    stored = md5 is not None or sha1 is not None
    status: MediaHashStatus = "absent" if not stored else "not_verified"
    if verified is not None and stored:
        candidate = verified.get("media_hash_status")
        if candidate in ("matched", "mismatch", "not_verified"):
            status = cast(MediaHashStatus, candidate)
    try:
        return EwfInfo(stored_md5=md5, stored_sha1=sha1, media_hash_status=status, meta=meta)
    except ValidationError:
        return EwfInfo(stored_md5=md5, stored_sha1=sha1, media_hash_status=status)


def _verify(j: Job) -> None:
    res = j.run("verify", "verify", "verify", {})
    j.facts.report(DiskStage.VERIFY, res)
    if res.status == StageStatus.UNSUPPORTED:
        raise _diagnostic(j, "unsupported_disk_format")
    if res.status in (StageStatus.SKIPPED, StageStatus.TIMEOUT):
        return  # `not_verified` (from the layout's stored values), never a failure (RT6)
    if not res.usable:
        raise JobFailed(res.error_code or "disk_parse_failed", "verify")
    j.facts.ewf = _ewf_info(res.facts, res.facts)
    sha256 = res.facts.get("media_sha256")
    if isinstance(sha256, str) and len(sha256) == 64:
        j.facts.media_sha256 = sha256
    if j.facts.ewf.media_hash_status == "mismatch":
        j.facts.findings.append(ewf_mismatch_finding())


# --- walk -------------------------------------------------------------------------------------


def _walk_order(partitions: Sequence[Partition]) -> list[Partition]:
    ok = [p for p in partitions if p.row.fs_status == "ok" and p.family is not None]
    return sorted(ok, key=lambda p: (p.row.os == "none", p.index))


def _walk(j: Job) -> None:
    files_left = j.limits.max_files
    hash_left = j.limits.hash_budget_bytes
    walk_limits = j.limits.stages["walk"]
    for p in _walk_order(j.partitions):
        if files_left <= 0:
            p.walk_error = None
            j.facts.report(
                DiskStage.WALK, partition_index=p.index, status="skipped", reason="max_files"
            )
            j.facts.truncate("files")
            continue
        res = j.run(
            "walk",
            "walk",
            f"walk-p{p.index}",
            {
                "offset": p.offset,
                "family": p.family,
                "max_rows": files_left,
                "max_bytes": max(MIB, walk_limits.rlimit_fsize - 16 * MIB),
                "max_dir_entries": MAX_DIR_ENTRIES,
                "max_streams": j.limits.max_streams_per_file,
                "hash_max_file_bytes": j.limits.hash_max_file_bytes,
                "hash_budget_bytes": hash_left,
            },
        )
        if not res.usable:
            timed_out = res.status in (StageStatus.SKIPPED, StageStatus.TIMEOUT)
            p.walk_error = "stage_timeout" if timed_out else res.error_code or "disk_parse_failed"
            j.facts.report(DiskStage.WALK, res, partition_index=p.index)
            continue
        records, stats = _read_walk(j, p, res, files_left)
        if _too_bad(stats):
            p.walk_error = "disk_parse_failed"
            j.facts.report(
                DiskStage.WALK,
                res,
                partition_index=p.index,
                status="failed",
                reason="bad_rows",
                rows=len(records),
                error_code="disk_parse_failed",
            )
            j.facts.error("walk_bad_rows")
            continue
        if stats.bad:
            j.facts.error("walk_bad_rows")
        truncated = res.truncated or stats.truncated
        if truncated:
            j.facts.truncate("files")
        j.facts.report(
            DiskStage.WALK,
            res,
            partition_index=p.index,
            rows=len(records),
            status="truncated" if truncated else None,
        )
        j.files.extend(records)
        files_left -= len(records)
        hash_left = max(
            0, hash_left - sum(r.size or 0 for r in records if r.hash_status == "hashed")
        )
        j.walked = True


def _read_walk(
    j: Job, p: Partition, res: stage.StageResult, max_rows: int
) -> tuple[list[DiskFileRecord], ReadStats]:
    hashes: dict[int, HashRow] = {}
    hstats = ReadStats()
    for raw in _rows(res, "hashes.jsonl", hstats, max_rows):
        try:
            h = HashRow.model_validate(raw)
        except ValidationError:
            continue
        hashes.setdefault(h.n, h)
    stats = ReadStats()
    out: list[DiskFileRecord] = []
    streams = 0
    for raw in _rows(res, "files.jsonl", stats, max_rows):
        try:
            row = FileRow.model_validate(raw)
            record = file_record(row, p.index, hashes.get(row.n))
        except (ValidationError, ValueError):
            stats.bad += 1
            continue
        if record.stream is None:
            streams = 0
        else:
            streams += 1
            if streams > j.limits.max_streams_per_file:
                j.facts.truncate("streams")
                continue
        out.append(record)
    return out, stats


# --- hash sets --------------------------------------------------------------------------------


def _hashsets(j: Job) -> None:
    """Phase 5's read-only store: `known` / `known_set` on every hashed file. An invalid store
    disables matching and is reported as `hashsets_invalid` (never a job failure)."""
    try:
        store = HashSetStore(j.config.hashsets_dir)
    except Exception:  # noqa: BLE001 - the store's own loader already maps its errors
        j.facts.error("hashsets_invalid")
        return
    try:
        if store.status == "invalid":
            j.facts.error("hashsets_invalid")
            return
        j.facts.hashsets = store.refs()[:32]
        if store.status != "ok":
            return
        j.files = [store.annotate(r) for r in j.files]
    except Exception:  # noqa: BLE001
        j.facts.error("hashsets_match_failed")
    finally:
        store.close()


# --- collect ----------------------------------------------------------------------------------


def _collect(j: Job) -> dict[DiskArtifact, ArtifactStat]:
    stats: dict[DiskArtifact, ArtifactStat] = {}
    os_parts = [
        p
        for p in j.partitions
        if p.walk_error is None and p.row.os != "none" and p.row.fs_status == "ok"
    ]
    os_parts.sort(key=lambda p: -p.row.length_sectors)  # the largest first (phase 3's order)
    files_left, bytes_left = j.limits.artifact_max_files, j.limits.artifact_max_bytes
    for p in os_parts[: j.limits.max_plaso_partitions]:
        listed = [r for r in j.files if r.partition_index == p.index]
        try:
            plan = catalog.match(listed, p.row.os, j.job.profile)  # type: ignore[arg-type]
        except NotImplementedError:
            j.facts.report(
                DiskStage.COLLECT, partition_index=p.index, status="skipped", reason="not_available"
            )
            continue
        if any(plan.dropped.get(k) for k in ("budget", "max_files", "category_cap")):
            j.facts.truncate("collect")  # a catalog budget cut matched files (phase 3)
        case_insensitive = p.row.fs_type in CASE_INSENSITIVE_FS
        items: list[dict[str, Any]] = []
        refused = plan.refused_never_collect
        for artifact, r in plan.files:
            if j.index.refused(p.index, r.meta_addr, case_insensitive):
                refused += 1  # RT7: any name of the inode is on the list
                continue
            if not r.has_flag("allocated") or r.type != "reg":
                continue
            if len(items) >= files_left:
                j.facts.truncate("collect")
                break
            items.append(
                {
                    "n": len(items),
                    "meta_addr": r.meta_addr,
                    "meta_seq": r.meta_seq,
                    "stream": r.stream,
                    "path": r.path,
                    "artifact": artifact.value,
                    "max_bytes": j.limits.artifact_max_file_bytes,
                }
            )
        if not items:
            j.facts.report(
                DiskStage.COLLECT,
                partition_index=p.index,
                status="skipped",
                reason="nothing_to_collect",
                rows=0,
            )
            continue
        res = j.run(
            "collect",
            "collect",
            stage.collect_name(p.index),
            {
                "partition_index": p.index,
                "offset": p.offset,
                "family": p.family,
                "case_insensitive": case_insensitive,
                "items": items,
                "max_total_bytes": bytes_left,
                "max_files": files_left,
            },
        )
        collected = _read_collected(j, res, items, stats) if res.usable else 0
        j.facts.report(
            DiskStage.COLLECT,
            res,
            partition_index=p.index,
            rows=collected,
            reason=(f"refused_never_collect_{refused}" if refused else None),
        )
        files_left -= collected
        bytes_left = max(0, bytes_left - sum(s.bytes for s in stats.values()))
    return stats


def _read_collected(
    j: Job,
    res: stage.StageResult,
    items: list[dict[str, Any]],
    stats: dict[DiskArtifact, ArtifactStat],
) -> int:
    read = ReadStats()
    ok = 0
    for raw in _rows(res, "collected.jsonl", read, len(items) + 1):
        try:
            row = CollectedRow.model_validate(raw)
        except ValidationError:
            read.bad += 1
            continue
        if row.status != "ok" or row.target is None or not is_safe_relative(row.target):
            continue
        if row.artifact is None or not 0 <= row.n < len(items):
            read.bad += 1
            continue
        if row.artifact != items[row.n]["artifact"]:
            read.bad += 1
            continue
        artifact = DiskArtifact(row.artifact)
        stat_ = stats.setdefault(artifact, ArtifactStat(artifact=artifact))
        stats[artifact] = stat_.model_copy(
            update={"files": stat_.files + 1, "bytes": stat_.bytes + (row.size or 0)}
        )
        ok += 1
    if read.bad:
        j.facts.error("collect_bad_rows")
    return ok


# --- scan -------------------------------------------------------------------------------------


def _stored_rule(hit: scan.YaraHit) -> str:
    """`<namespace>.<rule>` as `DiskFileRecord.yara_rules` keeps it (phase 6 splits it back);
    the rule alone when the pair does not fit the contract's rule-name pattern."""
    stored = f"{hit.namespace}.{hit.rule}"
    return stored if YARA_STORED.fullmatch(stored) else hit.rule


def _scan(j: Job) -> dict[str, str]:
    """Phase 5's YARA scan in the sandboxed `scan` stage; returns rule → severity for the
    detections (`signature:yara@1`)."""
    try:
        selected = scan.select_candidates(j.files, j.job.profile, j.limits)
    except NotImplementedError:
        j.facts.report(DiskStage.SCAN, status="skipped", reason="not_available")
        return {}
    if selected.truncated:
        j.facts.truncate("scan")
    if not selected.candidates:
        j.facts.report(DiskStage.SCAN, status="skipped", reason="no_candidates")
        return {}
    try:
        # Root hashes the rule sources it hands the probe (never parsing them) and refuses a
        # baked baseline that does not match `versions.json` (RT8).
        hashes = scan.check_rules(j.config.rules_dir, j.config.test_rules_dir, tool_versions())
    except scan.RulesTampered:
        j.facts.error("rules_tampered")
        j.facts.report(DiskStage.SCAN, status="failed", reason="rules_tampered")
        return {}
    rule_dirs = scan.rule_dirs(j.config.rules_dir, j.config.test_rules_dir)
    parts = {
        str(p.index): {"offset": p.offset, "family": p.family}
        for p in j.partitions
        if p.family is not None and p.walk_error is None
    }
    res = j.run(
        "scan",
        "scan",
        "scan",
        {
            "partitions": parts,
            "candidates": [
                {
                    "partition_index": c.partition_index,
                    "meta_addr": c.meta_addr,
                    "meta_seq": c.meta_seq,
                    "stream": c.stream,
                    "size": c.size,
                }
                for c in selected.candidates
            ],
            "rule_dirs": [str(d) for d in rule_dirs],
            "max_file_bytes": j.limits.yara_max_file_bytes,
            "max_rows": scan.MAX_HITS + scan.MAX_RULE_ERRORS + 2,
        },
    )
    j.facts.report(DiskStage.SCAN, res)
    if not res.usable:
        return {}
    try:
        report = scan.parse_scan_report(res.out_dir / "hits.jsonl")
    except Exception:  # noqa: BLE001 - a bad scan output never fails the job
        j.facts.error("scan_output_invalid")
        return {}
    if report.invalid_lines:
        j.facts.error("scan_output_invalid")
    if report.rule_errors:
        j.facts.error("yara_rule_error")
    if report.truncated:
        j.facts.truncate("scan")
    scored, dropped = scan.resolve_hits(
        report.hits, hashes, test_rules=j.config.test_rules_dir is not None
    )
    if dropped:
        j.facts.error("scan_hits_dropped")
    by_file: dict[scan.FileKey, list[str]] = {}
    severity: dict[str, str] = {}
    for s in scored:
        stored = _stored_rule(s.hit)
        rules = by_file.setdefault(s.hit.key, [])
        if stored not in rules and len(rules) < scan.MAX_RULES_PER_FILE:
            rules.append(stored)
        severity[stored] = s.severity
    if by_file:
        j.files = [
            r.model_copy(update={"yara_rules": sorted(by_file[k])})
            if (k := (r.partition_index, r.meta_addr, r.meta_seq, r.stream)) in by_file
            else r
            for r in j.files
        ]
    return severity


# --- timeline and events (phase 3) ------------------------------------------------------------


def _no_events() -> Iterator[DiskEventRecord]:
    return iter(())


@dataclass
class Events:
    """The two event passes (RT10) through phase 3's normalizer (`normalize.events`):
    `pass1()` streams every event to the detections; `EventSource.select(cited)` then fixes the
    stored subset and the per-category counts before the stream is written (`_stored`).
    Without a timeline: no events."""

    source: EventSource | None = None

    def pass1(self) -> Iterator[DiskEventRecord]:
        return self.source.events() if self.source is not None else _no_events()


def _merge_artifacts(j: Job, counts: dict[DiskArtifact, tuple[int, int]]) -> None:
    """Per-category `events_read` / `events_stored` into the collect statistics."""
    merged = {a.artifact: a for a in j.facts.artifacts}
    for artifact, (read, stored) in counts.items():
        base = merged.get(artifact) or ArtifactStat(artifact=artifact)
        merged[artifact] = base.model_copy(update={"events_read": read, "events_stored": stored})
    j.facts.artifacts = list(merged.values())


def _timeline(j: Job) -> Events:
    if j.config.timeline_engine == "none":
        j.facts.report(DiskStage.TIMELINE, status="skipped", reason="disabled")
        return Events()
    partitions = [p.record() for p in j.partitions]
    try:
        out = timeline.run_timeline(j.dirs, partitions, j.job.profile, j.limits, j.budget)
    except NotImplementedError:
        j.facts.report(DiskStage.TIMELINE, status="skipped", reason="not_available")
        return Events()
    except (ConfigError, ReplayRefused):
        j.facts.report(DiskStage.TIMELINE, status="skipped", reason="refused")
        return Events()
    j.facts.timeline_engine = out.engine
    for i, res in enumerate(out.stages):
        index = out.stage_partitions[i] if i < len(out.stage_partitions) else None
        j.facts.report(DiskStage.TIMELINE, res, partition_index=index)
    _merge_artifacts(j, {a.artifact: (a.events_read, a.events_stored) for a in out.artifacts})
    if out.events_path is None:
        return Events()
    try:
        return Events(EventSource(out.events_path, j.limits))
    except (OSError, ValueError, KeyError, TypeError):
        j.facts.error("events_unavailable")
        return Events()


def _stored(j: Job, events: Events, cited: set[int]) -> Callable[[], Iterator[DiskEventRecord]]:
    """Pass 2's stored events (quotas + every cited ordinal); the header counts first."""
    if events.source is None:
        return _no_events
    try:
        selection = events.source.select(cited)
    except (OSError, ValueError):
        j.facts.error("events_unavailable")
        return _no_events
    categories = set(selection.read) | set(selection.stored)
    _merge_artifacts(
        j,
        {a: (selection.read.get(a, 0), selection.stored.get(a, 0)) for a in categories},
    )
    if selection.counts.dropped or selection.counts.bad_lines:
        j.facts.error("timeline_events_dropped")
    if selection.counts.truncated:
        j.facts.truncate("events")
    return selection.records


# --- assembly ---------------------------------------------------------------------------------


def _detect(j: Job, events: Events, yara_severity: dict[str, str]) -> DetectionOutput:
    view = DiskView(
        profile=j.job.profile,
        image=j.facts.image(),
        partitions=tuple(p.record() for p in j.partitions),
        files=j.files,
        events=events.pass1,
        hashsets=tuple(j.facts.hashsets),
        truncated=dict(j.facts.truncated),
    )
    try:
        # Phase 6's keyword (rule as stored in `yara_rules` -> allow-listed severity).
        extra: dict[str, Any] = {"yara_severity": yara_severity} if yara_severity else {}
        found = detections.run(view, j.limits, **extra)
    except Exception:  # noqa: BLE001 - a detector bug costs the findings, never the job
        j.facts.error("detections_failed")
        found = DetectionOutput()
    limits = j.limits
    findings = [*j.facts.findings, *found.findings]
    if len(findings) > limits.max_findings:
        j.facts.truncate("findings")
    if len(found.iocs) > limits.max_iocs:
        j.facts.truncate("iocs")
    if len(found.timeline) > limits.max_timeline:
        j.facts.truncate("timeline")
    if found.truncated:
        j.facts.truncate("detections")
    return DetectionOutput(
        findings=findings[: limits.max_findings],
        iocs=found.iocs[: limits.max_iocs],
        timeline=found.timeline[: limits.max_timeline],
        cited_events=found.cited_events,
        truncated=found.truncated,
    )


def analyze(job: DiskJobV1, dirs: sandbox.JobDirs, config: Config) -> Path:
    budget = Budget(job.deadline_at, job.limits)
    if shutil.disk_usage(config.work_dir).free < required_free(job, config):
        raise JobFailed("insufficient_disk")
    facts = RunFacts(
        job_id=job.job_id,
        profile=job.profile,
        tool_versions=tool_versions(),
        format=ImageFormat.RAW,
        segments=len(job.segments),
    )
    j = Job(job=job, dirs=dirs, config=config, budget=budget, facts=facts)
    _download(j)
    _layout(j)
    if facts.format == ImageFormat.EWF:
        _verify(j)
    if not _walk_order(j.partitions):
        raise _diagnostic(j, "no_supported_filesystem")
    _walk(j)
    if not j.walked:
        raise _diagnostic(j, "no_supported_filesystem")
    j.index = build_index(j.files)
    j.files = with_hard_links(j.files, j.index)
    _hashsets(j)
    facts.artifacts = list(_collect(j).values())
    yara_severity = _scan(j)
    events = _timeline(j)
    found = _detect(j, events, yara_severity)
    stored = _stored(j, events, set(found.cited_events))
    return write_result(
        dirs.root / RESULT,
        facts,
        [p.record() for p in j.partitions],
        j.files,
        stored,
        found,
        job.limits.max_result_bytes,
    )


__all__ = ["DiagnosticResult", "analyze", "required_free"]
