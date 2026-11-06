"""The in-container side of `pnpm disk:metrics` (M9 phase 13; `scripts/disk_metrics.py` drives
it on the host). Runs inside `disk-worker-test` as root (the sandbox needs it), never in the
gate. Each sub-command prints one JSON document between `BEGIN` / `END` markers:

    python -m dataset.metrics scenarios
        precision / recall of `dataset.evaluate` over the labelled scenario set (pure Python);
    python -m dataset.metrics images --images DIR [--generate] [--only IDS] [--rounds 3]
        the real analyzer (TSK, libewf, Plaso, YARA, hash sets: the image's engines, through the
        real stage sandbox) on every generated image with a `ground_truth.json`, `--rounds`
        times each: per-stage and per-job latency, parse success, the findings against each
        image's `expected_findings`, and one run of the Windows image with the test-only replay
        timeline engine (labelled `replay`);
    python -m dataset.metrics hostile --count N --seed S
        phase 4's hostile mutations, built and analysed one at a time (the 1 GiB tmpfs): the
        outcome of each (result, diagnostic, known job failure, crash), tool survivors and
        audit-hook counts;
    python -m dataset.metrics sparse --gib 4 --files 20000 --file-kib 12
        a `full` run on a sparse ext4 image of that apparent size (holes cost no disk) holding
        generated files: walk and hashing throughput, extrapolated.

How one analysis runs (`one`, always in a fresh child process so the children's peak RSS is
this job's): `analyzer.analyze` unchanged, with the kit's `download` replaced by a local
hard link (or a sparse copy across file systems), mode 0444 as the kit leaves it. Nothing is
uploaded and nothing reaches a broker. Deviations from a dispatched job, recorded in the
report: the artifact budget is lowered to `ARTIFACT_MAX_BYTES` (the free-space check wants 3x
it on the test tmpfs), and the `sparse` run counts the segments' allocated bytes, not their
apparent size, in that check.

Peak RSS: `getrusage(RUSAGE_CHILDREN).ru_maxrss` after each stage (the high-water mark of every
stage process waited for so far in this job): a stage's own peak is exact only when it raised
the mark (`raised`).

Synthetic data only: generated images (our own content) and replayed Windows rows; these numbers
show the analyzer behaves as specified on them, not real-world quality or capacity.
"""

import argparse
import gzip
import hashlib
import json
import os
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BEGIN = "=== DISK METRIC BEGIN ==="
END = "=== DISK METRIC END ==="
CAVEAT = "generated images and replayed Windows rows only"
MIB = 1024**2
GIB = 1024**3
# The artifact budget of a metric run (the free-space check wants image + 3x it + the floor on
# the 1 GiB test tmpfs; a dispatched triage job has 2 GiB).
ARTIFACT_MAX_BYTES = 96 * MIB
ARTIFACT_MAX_FILE_BYTES = 32 * MIB
JOB_TIMEOUT_S = 3600
CHILD_MARGIN_S = 300
WORK = Path(os.environ.get("DISK_METRIC_WORK", "/work"))
JOBS_DIR = WORK / "metric-jobs"  # the analyzer's WORK_DIR: `sandbox.prepare` empties it per job
SRC_DIR = WORK / "metric-src"  # generated inputs (outside JOBS_DIR, so never wiped by a job)
LOCAL = "http://metrics.local"
KNOWN_FAILURE = "job_failure_known"
CRASH = "crash"


# --- small helpers ------------------------------------------------------------------------------


def emit(doc: dict[str, Any]) -> None:
    print(BEGIN)
    print(json.dumps(doc, sort_keys=True, default=str))
    print(END, flush=True)


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile (`None` for no values)."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))
    return ordered[int(rank) - 1]


def p50_p95(values: list[float]) -> dict[str, float | int | None]:
    return {"n": len(values), "p50": percentile(values, 50), "p95": percentile(values, 95)}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4 * MIB):
            digest.update(chunk)
    return digest.hexdigest()


def sparse_copy(src: Path, dst: Path) -> None:
    """Copy keeping holes: all-zero chunks are skipped (seek), then the size is fixed."""
    size = src.stat().st_size
    zero = bytes(MIB)
    with open(src, "rb") as fin, open(dst, "xb") as fout:
        while chunk := fin.read(MIB):
            if chunk == zero[: len(chunk)]:
                fout.seek(len(chunk), os.SEEK_CUR)
            else:
                fout.write(chunk)
        fout.truncate(size)


def allocated(path: Path) -> int:
    return path.stat().st_blocks * 512


def tool_survivors() -> int:
    """Live processes of the tool uid (the sandbox kills them after every stage; RT3)."""
    from cyberlab_worker import sandbox

    count = 0
    for status in Path("/proc").glob("[0-9]*/status"):
        try:
            fields = dict(
                line.split(":", 1) for line in status.read_text().splitlines() if ":" in line
            )
        except OSError:
            continue
        uids = {int(u) for u in fields.get("Uid", "").split()}
        state = fields.get("State", "").strip()[:1]
        if sandbox.TOOL_UID in uids and state not in {"Z", "X"}:
            count += 1
    return count


def segment_paths(case: Path, fmt: str, names: Iterable[str] | None = None) -> list[Path]:
    if names:
        return [case / n for n in names]
    pattern = {"raw": "image.raw", "split_raw": "image.[0-9][0-9][0-9]", "ewf": "image.E[0-9][0-9]"}
    return sorted(case.glob(pattern.get(fmt, "image.*")))


# --- one analysis (child process) ---------------------------------------------------------------


def limits_dict(profile: str) -> dict[str, Any]:
    from cyberlab_jobs.disk import (
        PROFILE_BUDGETS,
        DiskProfile,
        default_stage_limits,
        split_event_quotas,
    )

    budgets = dict(PROFILE_BUDGETS[DiskProfile(profile)])
    budgets["artifact_max_bytes"] = min(budgets["artifact_max_bytes"], ARTIFACT_MAX_BYTES)
    budgets["artifact_max_file_bytes"] = min(
        budgets["artifact_max_file_bytes"], ARTIFACT_MAX_FILE_BYTES
    )
    budgets["hash_budget_bytes"] = min(budgets["hash_budget_bytes"], 16 * GIB)
    stages = default_stage_limits(budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"])
    return {
        "max_image_bytes": 16 * GIB,
        "max_media_bytes": 2 * 1024**4,
        "timeout_s": 14_400,
        "stages": {k: v.model_dump() for k, v in stages.items()},
        **budgets,
        "max_partitions": 128,
        "max_filesystems": 32,
        "max_files": 500_000,
        "max_streams_per_file": 16,
        "max_events_stored": 250_000,
        "max_events_read": 20_000_000,
        "max_findings": 5_000,
        "max_iocs": 20_000,
        "max_timeline": 5_000,
        "max_result_bytes": 256 * MIB,
        "event_quotas": {k.value: v for k, v in split_event_quotas(250_000).items()},
    }


def _read_stream(path: Path) -> dict[str, Any]:
    """The facts of a `disk.v1` stream (header, partitions, counts, findings, hashed bytes)."""
    out: dict[str, Any] = {
        "header": None,
        "partitions": [],
        "kinds": {},
        "findings": [],
        "hashed_files": 0,
        "hashed_bytes": 0,
    }
    kinds: dict[str, int] = out["kinds"]
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            doc = json.loads(line)
            kind = str(doc.get("kind"))
            kinds[kind] = kinds.get(kind, 0) + 1
            if kind == "header":
                out["header"] = doc
            elif kind == "partition":
                out["partitions"].append(
                    {
                        k: doc.get(k)
                        for k in ("index", "fs_type", "fs_status", "os", "counts", "error_code")
                    }
                )
            elif kind == "file" and doc.get("hash_status") == "hashed":
                out["hashed_files"] += 1
                out["hashed_bytes"] += int(doc.get("size") or 0)
            elif kind == "finding":
                attrs = doc.get("attributes") or {}
                out["findings"].append(
                    {
                        "method": doc.get("detection_method"),
                        "type": doc.get("type"),
                        "severity": doc.get("severity"),
                        "subject": attrs.get("subject"),
                        "attributes": attrs,
                    }
                )
    return out


def run_one(spec: dict[str, Any]) -> dict[str, Any]:
    """One analysis in this process (the `one` sub-command's child)."""
    os.environ["DISK_TIMELINE_ENGINE"] = spec["engine"]
    from cyberlab_jobs.disk import DISK_ERROR_CODES, DiskJobV1
    from cyberlab_worker import sandbox
    from cyberlab_worker.errors import JobFailed

    from disk_worker import analyzer, stage
    from disk_worker.config import load

    sources = {f"{LOCAL}/segment/{i}": Path(p) for i, p in enumerate(spec["segments"])}

    def local_download(url: str, dest: Path, **_: Any) -> None:
        src = sources[url]
        try:
            os.link(src, dest)
        except OSError:
            sparse_copy(src, dest)
        os.chmod(dest, 0o444)

    stage_rss: list[dict[str, Any]] = []
    original_run_stage = stage.run_stage

    def measured_run_stage(*args: Any, **kwargs: Any) -> Any:
        before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        result = original_run_stage(*args, **kwargs)
        after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        stage_rss.append(
            {
                "stage": str(result.stage),
                "status": str(result.status),
                "rows": result.rows,
                "duration_ms": result.duration_ms,
                "peak_kib": after,
                "raised": after > before,
            }
        )
        return result

    analyzer.download = local_download  # type: ignore[assignment]
    stage.run_stage = measured_run_stage  # type: ignore[assignment]
    if spec.get("count_allocated"):
        original_required = analyzer.required_free

        def required_allocated(job: Any, config: Any) -> int:
            apparent = sum(s.size_bytes for s in job.segments)
            real = sum(allocated(p) for p in sources.values())
            return int(original_required(job, config)) - apparent + real

        analyzer.required_free = required_allocated  # type: ignore[assignment]

    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "WORK_DIR": str(JOBS_DIR), "DISK_TIMELINE_ENGINE": spec["engine"]}
    config = load(env)
    msg = DiskJobV1.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "segments": [
                {
                    "ordinal": i,
                    "evidence_id": str(uuid.uuid4()),
                    "expected_sha256": spec["sha256"][i],
                    "size_bytes": Path(p).stat().st_size,
                    "url": f"{LOCAL}/segment/{i}",
                }
                for i, p in enumerate(spec["segments"])
            ],
            "profile": spec["profile"],
            "os_hint": "auto",
            "result_post": {"url": f"{LOCAL}/results", "fields": {"key": "metric"}},
            "ingest_token": "m" * 43,
            "limits": limits_dict(spec["profile"]),
            "deadline_at": (datetime.now(UTC) + timedelta(seconds=JOB_TIMEOUT_S)).isoformat(),
        }
    )
    record: dict[str, Any] = {
        "outcome": None,
        "error_code": None,
        "engine": spec["engine"],
        "profile": spec["profile"],
    }
    dirs = None
    started = time.monotonic()
    try:
        dirs = sandbox.prepare(config.work_dir, str(msg.job_id))
        try:
            path = analyzer.analyze(msg, dirs, config)
            record["outcome"] = "result"
        except analyzer.DiagnosticResult as diag:
            path = diag.path
            record["outcome"] = "diagnostic"
            record["error_code"] = diag.code
        record["stream"] = _read_stream(path)
    except JobFailed as exc:
        known = exc.code in DISK_ERROR_CODES and exc.code not in {"analyzer_error", "timed_out"}
        record["outcome"] = KNOWN_FAILURE if known else CRASH
        record["error_code"] = exc.code
    except Exception as exc:  # the worker would report `analyzer_error`
        record["outcome"] = CRASH
        record["error_code"] = "analyzer_error"
        record["exception"] = f"{type(exc).__name__}: {exc}"[:500]
        record["traceback"] = traceback.format_exc()[-2000:]
    finally:
        record["job_s"] = round(time.monotonic() - started, 3)
        sandbox.cleanup(dirs)
    record["stage_rss"] = stage_rss
    record["peak_children_kib"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return record


def analyse(
    segments: list[Path],
    sha256: list[str],
    *,
    profile: str = "triage",
    engine: str = "plaso",
    count_allocated: bool = False,
) -> dict[str, Any]:
    """`run_one` in a fresh child process (its own RUSAGE_CHILDREN), with a hard timeout."""
    spec = {
        "segments": [str(p) for p in segments],
        "sha256": sha256,
        "profile": profile,
        "engine": engine,
        "count_allocated": count_allocated,
    }
    tmp = "/tmp"  # noqa: S108 - the container's private tmpfs (mode 1700, root)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, dir=tmp) as f:
        json.dump(spec, f)
        spec_path = f.name
    started = time.monotonic()
    try:
        done = subprocess.run(  # noqa: S603 - this interpreter, this module, a spec file we wrote
            [sys.executable, "-m", "dataset.metrics", "one", spec_path],
            capture_output=True,
            text=True,
            timeout=JOB_TIMEOUT_S + CHILD_MARGIN_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"outcome": CRASH, "error_code": "harness_timeout", "job_s": JOB_TIMEOUT_S}
    finally:
        os.unlink(spec_path)
    out = done.stdout
    if done.returncode != 0 or BEGIN not in out:
        return {
            "outcome": CRASH,
            "error_code": f"child_exit_{done.returncode}",
            "job_s": round(time.monotonic() - started, 3),
            "stderr": done.stderr[-2000:],
        }
    record: dict[str, Any] = json.loads(out[out.index(BEGIN) + len(BEGIN) : out.index(END)])
    record["survivors"] = tool_survivors()
    return record


# --- summaries ----------------------------------------------------------------------------------


def stage_reports(record: dict[str, Any]) -> list[dict[str, Any]]:
    header = (record.get("stream") or {}).get("header") or {}
    return list(header.get("stages") or [])


def audit_events(record: dict[str, Any]) -> int:
    return sum(sum((s.get("audit_counts") or {}).values()) for s in stage_reports(record))


def stage_latency(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    per: dict[str, list[float]] = {}
    for record in records:
        for s in stage_reports(record):
            if s.get("status") in ("skipped",):
                continue
            per.setdefault(str(s.get("stage")), []).append(float(s.get("duration_ms") or 0))
    return {name: p50_p95(values) for name, values in sorted(per.items())}


def _norm(value: object) -> str:
    return str(value or "").strip().strip("'\"").lower()


def matches(finding: dict[str, Any], label: dict[str, Any]) -> bool:
    if finding.get("method") != label.get("method") or finding.get("type") != label.get("type"):
        return False
    path = _norm(label.get("path"))
    if not path:
        return True
    texts = [_norm(finding.get("subject"))]
    texts += [_norm(v) for v in (finding.get("attributes") or {}).values() if isinstance(v, str)]
    return any(t == path or t.endswith(path) or path in t for t in texts if t)


def applicable(label: dict[str, Any], truth: dict[str, Any], record: dict[str, Any]) -> str | None:
    """`None` when the label applies to this run, else why not (`requires` of phase 4)."""
    header = (record.get("stream") or {}).get("header") or {}
    for need in label.get("requires") or []:
        if need == "plaso" and header.get("timeline_engine") != "plaso":
            return "requires plaso"
        if need == "hivex":
            hive = Path(str(label.get("path", ""))).name.upper()
            outcome = (truth.get("hive_outcome") or {}).get(hive)
            if outcome != "merged":
                return f"requires a hivex-merged {hive} hive ({outcome})"
    if label.get("method", "").endswith("ads_executable@1") and truth.get("ntfs_route") not in (
        None,
        "libntfs",
    ):
        return "requires the libntfs NTFS route"
    return None


def score(
    truth: dict[str, Any], record: dict[str, Any], counts: dict[str, dict[str, int]]
) -> dict[str, list[str]]:
    """Add one run's TP / FP / FN per method to `counts`; the labels missed / extra / n/a."""
    found = [
        f for f in (record.get("stream") or {}).get("findings", []) if f.get("severity") != "info"
    ]
    missed: list[str] = []
    skipped: list[str] = []
    for label in truth.get("expected_findings") or []:
        why = applicable(label, truth, record)
        if why is not None:
            skipped.append(f"{label['type']} {label.get('path')}: {why}")
            continue
        c = counts.setdefault(label["method"], {"tp": 0, "fp": 0, "fn": 0})
        hit = next((f for f in found if matches(f, label)), None)
        if hit is None:
            c["fn"] += 1
            missed.append(f"{label['type']} {label.get('path')}")
        else:
            c["tp"] += 1
            found.remove(hit)
    extra = []
    for f in found:
        counts.setdefault(str(f.get("method")), {"tp": 0, "fp": 0, "fn": 0})["fp"] += 1
        extra.append(f"{f.get('type')} {f.get('subject')!r} ({f.get('severity')})")
    return {"missed": missed, "extra": extra, "not_applicable": skipped}


def parse_ok(truth: dict[str, Any], record: dict[str, Any]) -> tuple[bool, str]:
    """A generated image parses when the job succeeds, every partition the ground truth lists
    has its file-system status, and an EWF set reports the expected media-hash status."""
    if record.get("outcome") != "result":
        return False, f"{record.get('outcome')} {record.get('error_code')}"
    got = {p.get("index"): p for p in (record.get("stream") or {}).get("partitions", [])}
    for want in truth.get("partitions") or []:
        have = got.get(want.get("index"))
        if have is None or have.get("fs_status") != want.get("fs_status"):
            return False, f"partition {want.get('index')}: {have and have.get('fs_status')}"
    status = truth.get("media_hash_status")
    if status:
        header = (record.get("stream") or {}).get("header") or {}
        ewf = (header.get("image") or {}).get("ewf") or {}
        if ewf.get("media_hash_status") != status:
            return False, f"media hash {ewf.get('media_hash_status')} (expected {status})"
    return True, "ok"


def _entries(counts: dict[str, Any]) -> int | None:
    """The claimed inode / MFT entry count of a partition record's `counts`."""
    keys = [k for k in counts if any(w in k for w in ("inode", "mft", "entries"))]
    return max((int(counts[k]) for k in keys), default=None)


def rss_rows(name: str, record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Walk RSS against the claimed inode / MFT entry count (RT30). The measured walk stages
    pair, in order, with the header's walk reports that actually ran (their partition)."""
    walks = [s for s in record.get("stage_rss") or [] if s.get("stage") == "walk"]
    reports = [
        s
        for s in stage_reports(record)
        if s.get("stage") == "walk" and not (s.get("status") == "skipped")
    ]
    parts = {p.get("index"): p for p in (record.get("stream") or {}).get("partitions", [])}
    for i, w in enumerate(walks):
        index = reports[i].get("partition_index") if i < len(reports) else None
        part = parts.get(index) or {}
        yield {
            "image": name,
            "partition": index,
            "fs_type": part.get("fs_type"),
            "entries_claimed": _entries(part.get("counts") or {}),
            "walk_rows": w.get("rows"),
            "walk_status": w.get("status"),
            "peak_kib": w.get("peak_kib"),
            "raised": w.get("raised"),
        }


def slim(record: dict[str, Any]) -> dict[str, Any]:
    """A run without its findings / traceback bulk (kept in the JSON sidecar)."""
    stream = record.get("stream") or {}
    header = stream.get("header") or {}
    return {
        "outcome": record.get("outcome"),
        "error_code": record.get("error_code"),
        "engine": record.get("engine"),
        "profile": record.get("profile"),
        "job_s": record.get("job_s"),
        "survivors": record.get("survivors"),
        "audit_events": audit_events(record),
        "timeline_engine": header.get("timeline_engine"),
        "engine_errors": header.get("engine_errors"),
        "truncated": header.get("truncated"),
        "stages": [
            {k: s.get(k) for k in ("stage", "partition_index", "status", "reason", "duration_ms")}
            for s in stage_reports(record)
        ],
        "kinds": stream.get("kinds"),
        "peak_children_kib": record.get("peak_children_kib"),
        "exception": record.get("exception"),
    }


# --- sub-commands -------------------------------------------------------------------------------


def cmd_scenarios(_: argparse.Namespace) -> dict[str, Any]:
    from dataset.evaluate import evaluate, table

    report = evaluate()
    return {
        "per_method": {
            m: {"tp": c.tp, "fp": c.fp, "fn": c.fn} for m, c in sorted(report.per_method.items())
        },
        "ioc_found": report.ioc_found,
        "ioc_expected": report.ioc_expected,
        "false_positives": report.false_positives,
        "false_negatives": report.false_negatives,
        "table": table(report),
    }


def _cases(root: Path, only: list[str]) -> list[Path]:
    cases = sorted(p for p in root.iterdir() if (p / "ground_truth.json").is_file())
    return [c for c in cases if not only or c.name in only]


def _generate(out: Path, only: list[str]) -> None:
    argv = [sys.executable, "-m", "samples.diskgen", "--out", str(out), "--skip-missing"]
    if only:
        argv += ["--only", ",".join(only)]
    subprocess.run(argv, check=True)  # noqa: S603 - this interpreter, fixed module


def cmd_images(args: argparse.Namespace) -> dict[str, Any]:
    only = [i for i in args.only.split(",") if i]
    root = Path(args.images)
    if args.generate or not root.is_dir() or not _cases(root, only):
        root = SRC_DIR / "diskgen"
        shutil.rmtree(root, ignore_errors=True)
        _generate(root, only)
    cases = _cases(root, only)
    images: dict[str, Any] = {}
    all_runs: list[dict[str, Any]] = []
    counts: dict[str, dict[str, int]] = {}
    rss: list[dict[str, Any]] = []
    for case in cases:
        truth = json.loads((case / "ground_truth.json").read_text(encoding="utf-8"))
        segments = segment_paths(case, truth.get("format", "raw"), truth.get("segments"))
        sha = [sha256_file(p) for p in segments]
        runs = []
        for _ in range(args.rounds):
            record = analyse(segments, sha, profile=args.profile)
            runs.append(record)
            print(f"{case.name}: {record.get('outcome')} {record.get('job_s')} s", file=sys.stderr)
        all_runs += runs
        first = runs[0]
        scored = score(truth, first, counts)
        oks = [parse_ok(truth, r) for r in runs]
        rss.extend(rss_rows(case.name, first))
        images[case.name] = {
            "format": truth.get("format"),
            "segments": len(segments),
            "bytes": sum(p.stat().st_size for p in segments),
            "parse_ok": sum(ok for ok, _ in oks),
            "parse_problems": sorted({why for ok, why in oks if not ok}),
            "job_s": p50_p95([float(r.get("job_s") or 0) for r in runs]),
            "stages": stage_latency(runs),
            "scored": scored,
            "ntfs_route": truth.get("ntfs_route"),
            "hive_outcome": truth.get("hive_outcome"),
            "runs": [slim(r) for r in runs],
        }
    replay: dict[str, Any] = {}
    windows = [c for c in cases if c.name == "ntfs_windows"]
    if args.replay and windows:
        case = windows[0]
        truth = json.loads((case / "ground_truth.json").read_text(encoding="utf-8"))
        segments = segment_paths(case, truth.get("format", "raw"), truth.get("segments"))
        record = analyse(segments, [sha256_file(p) for p in segments], engine="replay")
        by_method: dict[str, int] = {}
        for f in (record.get("stream") or {}).get("findings", []):
            by_method[str(f.get("method"))] = by_method.get(str(f.get("method")), 0) + 1
        replay = {"image": case.name, "run": slim(record), "findings_by_method": by_method}
        all_runs.append(record)
    return {
        "source": str(root),
        "rounds": args.rounds,
        "profile": args.profile,
        "images": images,
        "detectors": counts,
        "stages": stage_latency(all_runs),
        "job_s": p50_p95([float(r.get("job_s") or 0) for r in all_runs]),
        "rss": rss,
        "replay": replay,
        "failures": _failures(all_runs),
    }


def _failures(runs: list[dict[str, Any]]) -> dict[str, Any]:
    crashed = [r for r in runs if r.get("outcome") == CRASH]
    return {
        "runs": len(runs),
        "crashed": len(crashed),
        "codes": sorted({str(r.get("error_code")) for r in crashed}),
        "survivors": sum(int(r.get("survivors") or 0) for r in runs),
        "audit_events": sum(audit_events(r) for r in runs),
    }


def cmd_hostile(args: argparse.Namespace) -> dict[str, Any]:
    from samples.diskgen import images as gen_images
    from samples.diskgen import mutate, tools

    root = SRC_DIR / "hostile"
    shutil.rmtree(root, ignore_errors=True)
    gen = gen_images.Generator(root / "bases")
    names = list(mutate.CATALOG)
    cases: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    rss: list[dict[str, Any]] = []
    for i in range(args.count):
        name = names[i % len(names)]
        directory = root / f"{i:03d}_{name}"
        try:
            case = mutate.run_one(gen, name, args.seed + i, directory)
        except tools.ToolMissing as exc:
            cases.append({"case": directory.name, "outcome": "skipped", "reason": str(exc)})
            continue
        except Exception as exc:  # a generator failure is not an analyzer outcome
            reason = f"{type(exc).__name__}: {exc}"[:300]
            cases.append({"case": directory.name, "outcome": "not_generated", "reason": reason})
            shutil.rmtree(directory, ignore_errors=True)
            continue
        fmt = json.loads((directory / "mutation.json").read_text(encoding="utf-8"))["format"]
        segments = case.segments or segment_paths(directory, fmt)
        record = analyse(segments, [sha256_file(p) for p in segments])
        runs.append(record)
        rss.extend(rss_rows(directory.name, record))
        outcome = f"{record.get('outcome')} {record.get('error_code')}"
        print(f"{directory.name}: {outcome}", file=sys.stderr)
        cases.append(
            {
                "case": directory.name,
                "mutation": name,
                "expect": case.expect,
                **slim(record),
            }
        )
        shutil.rmtree(directory, ignore_errors=True)
    outcomes: dict[str, int] = {}
    for c in cases:
        outcomes[str(c["outcome"])] = outcomes.get(str(c["outcome"]), 0) + 1
    return {
        "count": args.count,
        "seed": args.seed,
        "outcomes": outcomes,
        "cases": cases,
        "stages": stage_latency(runs),
        "rss": rss,
        "failures": _failures(runs),
    }


def _sparse_image(path: Path, gib: int, files: int, file_kib: int, seed: int) -> dict[str, Any]:
    """An ext4 file system of `gib` GiB apparent size (sparse) holding `files` generated files
    of `file_kib` KiB (seeded pseudo-random content, so hashing does real work)."""
    staging = SRC_DIR / "sparse-tree"
    shutil.rmtree(staging, ignore_errors=True)
    rng = random.Random(seed)
    per_dir = 1000
    for n in range(files):
        d = staging / f"data/d{n // per_dir:04d}"
        if n % per_dir == 0:
            d.mkdir(parents=True, exist_ok=True)
        (d / f"f{n:07d}.bin").write_bytes(rng.randbytes(file_kib * 1024))
    path.unlink(missing_ok=True)
    with open(path, "wb") as f:
        f.truncate(gib * GIB)
    subprocess.run(  # noqa: S603 - fixed argv, our own paths
        [
            "mke2fs",
            "-q",
            "-F",
            "-t",
            "ext4",
            "-E",
            "lazy_itable_init=1,lazy_journal_init=1,nodiscard",
            "-d",
            str(staging),
            str(path),
        ],
        check=True,
    )
    shutil.rmtree(staging, ignore_errors=True)
    return {
        "apparent_bytes": path.stat().st_size,
        "allocated_bytes": allocated(path),
        "files": files,
        "file_bytes": files * file_kib * 1024,
    }


def cmd_sparse(args: argparse.Namespace) -> dict[str, Any]:
    if shutil.which("mke2fs") is None:
        return {"skipped": "mke2fs is not installed (the disk worker dev image has it)"}
    SRC_DIR.mkdir(parents=True, exist_ok=True)
    image = SRC_DIR / "sparse.raw"
    shape = _sparse_image(image, args.gib, args.files, args.file_kib, args.seed)
    record = analyse([image], [sha256_file(image)], profile="full", count_allocated=True)
    image.unlink(missing_ok=True)
    walks = [s for s in stage_reports(record) if s.get("stage") == "walk"]
    walk_ms = sum(int(s.get("duration_ms") or 0) for s in walks)
    stream = record.get("stream") or {}
    rows = sum(int(s.get("rows") or 0) for s in walks)
    hashed = int(stream.get("hashed_bytes") or 0)
    seconds = walk_ms / 1000 if walk_ms else None
    files_per_s = rows / seconds if seconds else None
    mib_per_s = hashed / MIB / seconds if seconds else None
    return {
        "shape": shape,
        "run": slim(record),
        "walk_ms": walk_ms,
        "walk_rows": rows,
        "hashed_files": stream.get("hashed_files"),
        "hashed_bytes": hashed,
        "files_per_s": files_per_s,
        "hash_mib_per_s": mib_per_s,
        # Linear extrapolations of the walk stage (rows and hashing share it).
        "extrapolated_s": {
            "500k_files": 500_000 / files_per_s if files_per_s else None,
            "16_gib_hashed": 16 * 1024 / mib_per_s if mib_per_s else None,
        },
        "rss": list(rss_rows("sparse_full", record)),
    }


def cmd_one(args: argparse.Namespace) -> dict[str, Any]:
    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    return run_one(spec)


COMMANDS: dict[str, Callable[[argparse.Namespace], dict[str, Any]]] = {
    "scenarios": cmd_scenarios,
    "images": cmd_images,
    "hostile": cmd_hostile,
    "sparse": cmd_sparse,
    "one": cmd_one,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dataset.metrics")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scenarios")
    images = sub.add_parser("images")
    images.add_argument("--images", default="/samples/disk")
    images.add_argument("--generate", action="store_true", help="generate into /work instead")
    images.add_argument("--only", default="")
    images.add_argument("--rounds", type=int, default=3)
    images.add_argument("--profile", choices=("triage", "full"), default="triage")
    images.add_argument("--no-replay", dest="replay", action="store_false")
    hostile = sub.add_parser("hostile")
    hostile.add_argument("--count", type=int, default=15)
    hostile.add_argument("--seed", type=int, default=0)
    sparse = sub.add_parser("sparse")
    sparse.add_argument("--gib", type=int, default=4)
    sparse.add_argument("--files", type=int, default=20_000)
    sparse.add_argument("--file-kib", type=int, default=12)
    sparse.add_argument("--seed", type=int, default=9064)
    one = sub.add_parser("one")
    one.add_argument("spec")
    args = parser.parse_args(argv)
    if args.command != "one" and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        print("dataset.metrics: run as root inside disk-worker-test", file=sys.stderr)
        return 2
    started = time.monotonic()
    doc = COMMANDS[args.command](args)
    if args.command != "one":
        doc = {"command": args.command, "caveat": CAVEAT, **doc}
        doc["seconds"] = round(time.monotonic() - started, 1)
    emit(doc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
