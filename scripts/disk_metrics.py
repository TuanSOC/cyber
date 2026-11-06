#!/usr/bin/env python3
"""`pnpm disk:metrics` (M9 phase 13): the §14 numbers of the disk analyzer, written to
plans/reports/disk-metric-YYMMDD.md (+ a .json sidecar). Standard library only.

A HEAVY step: the parent runs it alone, on the host, with only the infra (postgres, redis,
redis-broker, minio) and the disk worker up (`--manage-workers` stops every other worker for the
run and starts them again afterwards). Never part of the gate. Nothing is downloaded: the images
are phase 4's generated set (`pnpm disk:gen`, the `cyberlab_e2e_samples` volume under `disk/`),
else generated afresh inside the container.

  python scripts/disk_metrics.py --manage-workers           # everything (about an hour)
  python scripts/disk_metrics.py --skip sparse --skip ingest --rounds 1   # a quick pass
  python scripts/disk_metrics.py --dry-run                  # print the steps, run nothing

Steps (each a one-off container; `--skip NAME` leaves one out):
1. `scenarios`: precision / recall of phase 6's `dataset.evaluate` (the labelled scenario set).
2. `images`: the real analyzer (TSK, libewf, Plaso, YARA, the test hash-set store) through the
   real stage sandbox in `disk-worker-test`, `--rounds` times on every generated image: latency
   per stage and per job (p50 / p95), parse success, precision / recall against each image's
   `expected_findings`, walk RSS against the claimed inode / MFT count (RT30), and one run of
   `ntfs_windows` with the test-only replay timeline engine (labelled `replay`).
3. `hostile`: `--hostile N` of phase 4's mutations (seed `--seed`), built and analysed one at a
   time: counts by outcome, tool survivors, audit-hook events, crashes.
4. `sparse`: a `full` run on a sparse ext4 image of `--sparse-gib` GiB apparent size holding
   generated files (holes cost no disk): walk and hashing throughput, extrapolated.
5. `ingest`: phase 7's capped stream (`tests/integration/test_disk_ingest_caps.py`,
   DISK_INGEST_CAPS=1) in a one-off `api-test`: the ingest time, the ingesting process's peak
   RSS (it runs the disk ingest in-process, as `disk-ingest-worker` does) and the Postgres size
   per table. Needs postgres, redis, minio up and the test DB migrated.

The in-container side is `apps/workers/disk/dataset/metrics.py` (its docstring lists the
deviations from a dispatched job: a lower artifact budget for the 1 GiB tmpfs; local segments
instead of presigned downloads). The worker failure rate counts crashes (`analyzer_error`, a
dead or timed-out child) over every analysis of steps 2-4.

Options:
  --rounds N            runs per generated image (default 3)
  --only IDS            comma-separated image ids (default: every generated image)
  --generate            generate the images afresh in the container's /work (else the volume)
  --hostile N           hostile cases (default 15: each mutation once); --seed S (default 0)
  --sparse-gib G        apparent size of the sparse image (default 4); --sparse-files N
  --skip NAME           scenarios | images | hostile | sparse | ingest (repeatable)
  --manage-workers      stop the other running workers for the run, start them again after
  --step-timeout-s S    per step (default 14400)
  --write PATH          the report path (default plans/reports/disk-metric-<YYMMDD>.md, UTC)
  --dry-run             print the plan of steps and their commands, run nothing

Exit status: 0 when every step ran and no analysis crashed; 1 otherwise; 2 refused / usage.
"""

import argparse
import datetime as dt
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "plans" / "reports"
VOLUME = "cyberlab_e2e_samples"
COMPOSE = ["docker", "compose"]
COMPOSE_RUN = [*COMPOSE, "--profile", "test", "run", "--rm", "--no-deps"]
BEGIN, END = "=== DISK METRIC BEGIN ===", "=== DISK METRIC END ==="
STEPS = ("scenarios", "images", "hostile", "sparse", "ingest")
CAVEAT = "generated images and replayed Windows rows only"
INFRA = ("postgres", "redis", "redis-broker", "minio")
# Stopped by --manage-workers while the metric runs (when running), started again afterwards.
OTHERS = (
    "web",
    "gateway",
    "api",
    "ingest-worker",
    "ingest-beat",
    "enrich-worker",
    "analyst-worker",
    "static-worker",
    "pcap-worker",
    "memory-worker",
    "report-worker",
    "retention-worker",
    "disk-ingest-worker",
    "pcap-worker-test",
    "static-worker-test",
    "enrich-worker-test",
    "analyst-worker-test",
    "memory-worker-test",
    "report-worker-test",
    "retention-worker-test",
    "disk-worker-test",
    "disk-ingest-worker-test",
    "ai-mock",
    "ti-mock",
)
INGEST_TEST = "tests/integration/test_disk_ingest_caps.py"


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argument lists, no shell
        command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "MSYS_NO_PATHCONV": "1"}, check=False, **kwargs,
    )  # fmt: skip


def worker_command(step: str, args: argparse.Namespace) -> list[str]:
    base = [*COMPOSE_RUN, "-e", "PYTHONDONTWRITEBYTECODE=1"]
    module = ["python", "-m", "dataset.metrics"]
    if step == "scenarios":
        return [*base, "disk-worker-test", *module, "scenarios"]
    if step == "images":
        extra = ["--rounds", str(args.rounds)]
        if args.only:
            extra += ["--only", args.only]
        if args.generate:
            extra.append("--generate")
        return [
            *base, "-v", f"{VOLUME}:/samples:ro", "disk-worker-test", *module, "images",
            "--images", "/samples/disk", *extra,
        ]  # fmt: skip
    if step == "hostile":
        return [
            *base, "disk-worker-test", *module, "hostile",
            "--count", str(args.hostile), "--seed", str(args.seed),
        ]  # fmt: skip
    if step == "sparse":
        return [
            *base, "disk-worker-test", *module, "sparse",
            "--gib", str(args.sparse_gib), "--files", str(args.sparse_files),
        ]  # fmt: skip
    if step == "ingest":
        return [
            *COMPOSE_RUN, "-e", "DISK_INGEST_CAPS=1", "api-test",
            "uv", "run", "pytest", "-q", "-s", "-p", "no:cacheprovider", INGEST_TEST,
        ]  # fmt: skip
    raise ValueError(step)


def run_step(step: str, args: argparse.Namespace) -> dict[str, Any]:
    command = worker_command(step, args)
    print(f"\n▶ {step}\n  $ {shlex.join(command)}", flush=True)
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list
            command, cwd=ROOT, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=sys.stderr, timeout=args.step_timeout_s,
            env={**os.environ, "MSYS_NO_PATHCONV": "1"}, check=False,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        return {"status": "failed", "detail": f"timed out after {args.step_timeout_s} s"}
    seconds = round(time.monotonic() - started, 1)
    out = proc.stdout
    if step == "ingest":
        lines = [line for line in out.splitlines() if '"metric": "disk_ingest_caps"' in line]
        if proc.returncode or not lines:
            tail = out[-3000:]
            return {"status": "failed", "detail": f"exit {proc.returncode}", "tail": tail}
        return {"status": "ok", "seconds": seconds, "data": json.loads(lines[-1])}
    if proc.returncode or BEGIN not in out:
        return {"status": "failed", "detail": f"exit {proc.returncode}", "tail": out[-3000:]}
    data = json.loads(out[out.index(BEGIN) + len(BEGIN) : out.index(END)])
    print(f"✔ {step} ({seconds} s)", flush=True)
    return {"status": "ok", "seconds": seconds, "data": data}


# --- workers ------------------------------------------------------------------------------------


def running_services() -> set[str]:
    proc = run(
        [*COMPOSE, "--profile", "test", "--profile", "e2e", "ps", "--status", "running",
         "--services"]
    )  # fmt: skip
    return set(proc.stdout.split()) if proc.returncode == 0 else set()


def stop_others() -> list[str]:
    stopped = sorted(s for s in running_services() if s in OTHERS)
    if stopped:
        print(f"stopping for the run: {', '.join(stopped)}", flush=True)
        proc = run([*COMPOSE, "--profile", "test", "--profile", "e2e", "stop", *stopped])
        if proc.returncode:
            sys.stderr.write(proc.stderr[-2000:])
            raise SystemExit(f"disk_metrics: could not stop {', '.join(stopped)}")
    return stopped


def start_again(stopped: list[str]) -> None:
    if not stopped:
        return
    print(f"starting again: {', '.join(stopped)}", flush=True)
    proc = run([*COMPOSE, "--profile", "test", "--profile", "e2e", "up", "-d", "--no-deps",
                *stopped])  # fmt: skip
    if proc.returncode:
        sys.stderr.write(proc.stderr[-2000:])
        hint = f"docker compose up -d {' '.join(stopped)}"
        sys.stderr.write(f"disk_metrics: start them by hand: {hint}\n")


def host_notes(stopped: list[str]) -> list[str]:
    notes = []
    info = run(["docker", "info", "--format", "{{.MemTotal}} {{.NCPU}} {{.ServerVersion}}"])
    if info.returncode == 0 and info.stdout.strip():
        mem, cpus, version = (info.stdout.split() + ["?", "?", "?"])[:3]
        gib = f"{int(mem) / 2**30:.1f} GiB" if mem.isdigit() else mem
        notes.append(f"Docker engine {version}: {gib} RAM, {cpus} CPUs")
    for image in ("cyberlab/disk-worker:dev", "cyberlab/api:dev"):
        got = run(["docker", "image", "inspect", "--format", "{{.Id}}", image])
        if got.returncode == 0:
            notes.append(f"{image} ({got.stdout.strip()[:19]})")
    versions = run([*COMPOSE_RUN, "--entrypoint", "cat", "disk-worker-test",
                    "/etc/cyberlab/versions.json"])  # fmt: skip
    if versions.returncode == 0 and versions.stdout.strip().startswith("{"):
        notes.append(f"disk image versions: {versions.stdout.strip()}")
    notes.append(f"running during the metric: {', '.join(sorted(running_services())) or 'none'}")
    if stopped:
        notes.append(f"stopped for the run (--manage-workers): {', '.join(stopped)}")
    return notes


# --- report -------------------------------------------------------------------------------------


def _ratio(num: int, den: int) -> str:
    return "n/a" if not den else f"{num / den:.2f}"


def _pct(num: int, den: int) -> str:
    return "n/a" if not den else f"{num / den:.1%}"


def _s(value: float | None, scale: float = 1.0) -> str:
    return "n/a" if value is None else f"{value / scale:.2f} s"


def _mib(value: float | int | None, scale: int = 1024**2) -> str:
    return "n/a" if value is None else f"{value / scale:.0f} MiB"


def detector_table(counts: dict[str, dict[str, int]]) -> list[str]:
    rows = [
        "| Detection method | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    tp = fp = fn = 0
    for method, c in sorted(counts.items()):
        tp, fp, fn = tp + c["tp"], fp + c["fp"], fn + c["fn"]
        rows.append(
            f"| `{method}` | {c['tp']} | {c['fp']} | {c['fn']} | "
            f"{_ratio(c['tp'], c['tp'] + c['fp'])} | {_ratio(c['tp'], c['tp'] + c['fn'])} |"
        )
    rows.append(f"| **all** | {tp} | {fp} | {fn} | {_ratio(tp, tp + fp)} | {_ratio(tp, tp + fn)} |")
    return rows


def latency_table(stages: dict[str, Any]) -> list[str]:
    rows = ["| Stage | Runs | p50 | p95 |", "|---|---:|---:|---:|"]
    for name, v in stages.items():
        rows.append(f"| {name} | {v['n']} | {_s(v['p50'], 1000)} | {_s(v['p95'], 1000)} |")
    return rows


def rss_table(rows_in: list[dict[str, Any]]) -> list[str]:
    rows = [
        "| Image / case | Partition | FS | Entries claimed | Walk rows | Walk status | "
        "Peak RSS (high-water) |",
        "|---|---:|---|---:|---:|---|---:|",
    ]
    for r in rows_in:
        peak = "n/a" if r.get("peak_kib") is None else f"{r['peak_kib'] / 1024:.0f} MiB"
        mark = "" if r.get("raised") else " (not raised)"
        rows.append(
            f"| {r['image']} | {r.get('partition')} | {r.get('fs_type')} | "
            f"{r.get('entries_claimed')} | {r.get('walk_rows')} | {r.get('walk_status')} | "
            f"{peak}{mark} |"
        )
    return rows


def section_images(data: dict[str, Any]) -> list[str]:
    images = data["images"]
    runs = sum(len(v["runs"]) for v in images.values())
    ok = sum(v["parse_ok"] for v in images.values())
    out = [
        "## Detectors on the generated images (real engine)",
        "",
        f"Source: `{data['source']}`; profile `{data['profile']}`; {data['rounds']} round(s); "
        "scored on round 1 against each image's `expected_findings` (a label matches on "
        "method, type and its path in the finding's subject or attributes; `info` findings "
        "ignored; any other finding is a false positive of its method).",
        "",
        *detector_table(data["detectors"]),
        "",
    ]
    for name, v in images.items():
        scored = v["scored"]
        for kind in ("missed", "extra", "not_applicable"):
            for line in scored[kind]:
                out.append(f"- {name} {kind.replace('_', ' ')}: {line}")
    out += [
        "",
        "## Parse success",
        "",
        f"Generated images: {ok}/{runs} runs ({_pct(ok, runs)}) succeeded with every ground-truth "
        "partition's file-system status and the expected EWF media-hash status.",
        "",
        "| Image | Format | Segments | Size | Parse OK | Job p50 / p95 | Problems |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for name, v in images.items():
        job = v["job_s"]
        out.append(
            f"| {name} | {v['format']} | {v['segments']} | {_mib(v['bytes'])} | "
            f"{v['parse_ok']}/{len(v['runs'])} | {_s(job['p50'])} / {_s(job['p95'])} | "
            f"{'; '.join(v['parse_problems']) or '-'} |"
        )
    job = data["job_s"]
    out += [
        "",
        "## Latency per stage and per job (generated images)",
        "",
        f"Per job, every run of every image: p50 {_s(job['p50'])}, p95 {_s(job['p95'])} "
        f"({job['n']} runs). Per stage (every partition's run counted; `skipped` excluded):",
        "",
        *latency_table(data["stages"]),
        "",
    ]
    replay = data.get("replay") or {}
    if replay:
        run_ = replay["run"]
        by = ", ".join(f"`{m}` {n}" for m, n in sorted(replay["findings_by_method"].items()))
        out += [
            "## Replay timeline run (labelled `timeline_engine: replay`)",
            "",
            f"`{replay['image']}` with the test-only replay engine (the hand-written Windows "
            f"psort rows, not events of this image): outcome {run_['outcome']}, "
            f"timeline engine `{run_['timeline_engine']}`, {run_['job_s']} s. Findings by method: "
            f"{by or 'none'}.",
            "",
        ]
    return out


def section_hostile(data: dict[str, Any]) -> list[str]:
    outcomes = ", ".join(f"{k} {v}" for k, v in sorted(data["outcomes"].items()))
    f = data["failures"]
    out = [
        "## Hostile set (phase 4 mutations)",
        "",
        f"{data['count']} cases, seed {data['seed']}: {outcomes}. Crashes: {f['crashed']} "
        f"({', '.join(f['codes']) or '-'}); tool processes surviving a job: {f['survivors']}; "
        f"audit-hook events: {f['audit_events']}.",
        "",
        "| Case | Outcome | Error code | Job | Audit events | Survivors |",
        "|---|---|---|---:|---:|---:|",
    ]
    for c in data["cases"]:
        out.append(
            f"| {c['case']} | {c['outcome']} | {c.get('error_code') or '-'} | "
            f"{c.get('job_s', 'n/a')} s | {c.get('audit_events', 0)} | {c.get('survivors', 0)} |"
        )
    return [*out, ""]


def section_sparse(data: dict[str, Any], gib: int) -> list[str]:
    if "skipped" in data:
        return ["## Throughput (sparse full run)", "", f"Skipped: {data['skipped']}.", ""]
    shape = data["shape"]
    ex = data["extrapolated_s"]
    files_s = data["files_per_s"]
    mib_s = data["hash_mib_per_s"]
    return [
        "## Throughput (sparse `full` run)",
        "",
        f"A {gib} GiB apparent ext4 image ({_mib(shape['allocated_bytes'])} allocated) holding "
        f"{shape['files']} generated files ({_mib(shape['file_bytes'])}); outcome "
        f"{data['run']['outcome']} in {data['run']['job_s']} s. Walk: {data['walk_rows']} rows, "
        f"{data['hashed_files']} files / {_mib(data['hashed_bytes'])} hashed in "
        f"{data['walk_ms'] / 1000:.1f} s: "
        f"{'n/a' if files_s is None else f'{files_s:.0f}'} rows/s, "
        f"{'n/a' if mib_s is None else f'{mib_s:.0f}'} MiB/s hashed.",
        "",
        f"Linear extrapolation of the walk stage: 500 000 files {_s(ex['500k_files'])}; "
        f"16 GiB hashed {_s(ex['16_gib_hashed'])} (the triage hash budget; holes and file "
        "sizes differ on real media).",
        "",
    ]


def section_ingest(data: dict[str, Any]) -> list[str]:
    shape = data["shape"]
    pg = data["pg_bytes"]
    return [
        "## Ingest at the caps (phase 7's capped stream)",
        "",
        f"{shape['file']} files, {shape['event']} events, {shape['finding']} findings, "
        f"{shape['ioc']} IOCs, {shape['timeline']} timeline lines ({shape['lines']} lines, "
        f"{_mib(shape['compressed'])} compressed, {_mib(shape['decompressed'])} decompressed): "
        f"ingested in {data['ingest_s']} s; peak RSS of the ingesting process "
        f"{_mib(data['peak_rss_bytes'])} (the 1 GiB `disk-ingest-worker` limit).",
        "",
        "| Table | Postgres bytes added |",
        "|---|---:|",
        *[f"| {t} | {_mib(n)} |" for t, n in pg.items()],
        f"| **all** | {_mib(sum(pg.values()))} |",
        "",
    ]


def write_report(
    args: argparse.Namespace, results: dict[str, dict[str, Any]], notes: list[str], seconds: float
) -> Path:
    now = dt.datetime.now(dt.timezone.utc)
    path = Path(args.write) if args.write else REPORTS / f"disk-metric-{now:%y%m%d}.md"
    command = "python scripts/disk_metrics.py " + shlex.join(sys.argv[1:])
    lines = [
        "# M9 disk analyzer metrics (§14)",
        "",
        f"Generated {now:%Y-%m-%d %H:%M} UTC by `{command.strip()}` in {seconds / 60:.1f} min.",
        "",
        f"**Synthetic caveat: {CAVEAT}.** The images are phase 4's generated set (our own "
        "content, built without any mount) and the Windows event rows come from the test-only "
        "replay engine; the scenario set was designed alongside the detectors. These numbers "
        "show that the analyzer behaves as specified on that data, not its real-world "
        "detection quality or capacity. Latencies are this host, one worker, one job at a time.",
        "",
        "| Step | Status | Duration |",
        "|---|---|---:|",
    ]
    for step in STEPS:
        r = results.get(step, {"status": "skipped"})
        detail = f" ({r['detail']})" if r.get("detail") else ""
        lines.append(f"| {step} | {r['status']}{detail} | {r.get('seconds', '-')} s |")
    lines.append("")
    scen = results.get("scenarios", {}).get("data")
    if scen:
        lines += [
            "## Detectors on the labelled scenario set (`dataset.evaluate`)",
            "",
            scen["table"],
            "",
        ]
        lines += [f"- FP {x}" for x in scen["false_positives"]]
        lines += [f"- FN {x}" for x in scen["false_negatives"]]
        lines.append("")
    images = results.get("images", {}).get("data")
    if images:
        lines += section_images(images)
    hostile = results.get("hostile", {}).get("data")
    if hostile:
        lines += section_hostile(hostile)
    sparse = results.get("sparse", {}).get("data")
    if sparse:
        lines += section_sparse(sparse, args.sparse_gib)
    rss = (images or {}).get("rss", []) + (hostile or {}).get("rss", [])
    rss += (sparse or {}).get("rss", [])
    if rss:
        lines += [
            "## Walk RSS against the claimed inode / MFT entry count (RT30)",
            "",
            "The high-water mark of the job's stage processes after each walk "
            "(`getrusage(RUSAGE_CHILDREN)`); exact for the walk when it raised the mark.",
            "",
            *rss_table(rss),
            "",
        ]
    ingest = results.get("ingest", {}).get("data")
    if ingest:
        lines += section_ingest(ingest)
    failures = [r["data"]["failures"] for s, r in results.items()
                if s in ("images", "hostile") and r.get("data")]  # fmt: skip
    total = sum(f["runs"] for f in failures) + (1 if sparse and "run" in sparse else 0)
    crashed = sum(f["crashed"] for f in failures)
    if sparse and sparse.get("run", {}).get("outcome") == "crash":
        crashed += 1
    lines += [
        "## Worker failure rate",
        "",
        f"{crashed} crashes over {total} analyses ({_pct(crashed, total)}): a crash is an "
        "`analyzer_error`, a dead child or a harness timeout; diagnostics and known job "
        "failures (e.g. `unsupported_disk_format`, `insufficient_disk`) are clean outcomes.",
        "",
        "## TESTING line",
        "",
        "```",
        testing_line(results),
        "```",
        "",
        "## Host",
        "",
        *[f"- {n}" for n in notes],
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    sidecar = path.with_suffix(".json")
    sidecar.write_text(
        json.dumps({"command": command, "results": results}, indent=1, default=str) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def testing_line(results: dict[str, dict[str, Any]]) -> str:
    """The one-line summary docs/TESTING.md takes (phase 13 copies it)."""
    parts = []
    images = results.get("images", {}).get("data")
    if images:
        tp = sum(c["tp"] for c in images["detectors"].values())
        fp = sum(c["fp"] for c in images["detectors"].values())
        fn = sum(c["fn"] for c in images["detectors"].values())
        runs = sum(len(v["runs"]) for v in images["images"].values())
        ok = sum(v["parse_ok"] for v in images["images"].values())
        job = images["job_s"]
        parts.append(
            f"images P {_ratio(tp, tp + fp)} / R {_ratio(tp, tp + fn)}, parse {_pct(ok, runs)}, "
            f"job p50 {_s(job['p50'])} / p95 {_s(job['p95'])}"
        )
    hostile = results.get("hostile", {}).get("data")
    if hostile:
        parts.append(
            f"hostile {hostile['count']}: "
            + ", ".join(f"{k} {v}" for k, v in sorted(hostile["outcomes"].items()))
        )
    ingest = results.get("ingest", {}).get("data")
    if ingest:
        parts.append(
            f"ingest at caps {ingest['ingest_s']} s, RSS {_mib(ingest['peak_rss_bytes'])}"
        )
    return f"disk metric ({CAVEAT}): " + ("; ".join(parts) or "no step ran")


# --- main ---------------------------------------------------------------------------------------


def refuse(message: str) -> int:
    sys.stderr.write(f"disk_metrics: {message}\n")
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--only", default="")
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--hostile", type=int, default=15)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--sparse-gib", type=int, default=4)
    parser.add_argument("--sparse-files", type=int, default=20_000)
    parser.add_argument("--skip", choices=STEPS, action="append", default=[])
    parser.add_argument("--manage-workers", action="store_true")
    parser.add_argument("--step-timeout-s", type=int, default=14_400)
    parser.add_argument("--write", default=None, metavar="PATH")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be >= 1")
    if args.hostile < 0 or args.sparse_gib < 0:
        parser.error("--hostile and --sparse-gib are >= 0")
    steps = [s for s in STEPS if s not in args.skip]
    if args.hostile == 0 and "hostile" in steps:
        steps.remove("hostile")
    if args.sparse_gib == 0 and "sparse" in steps:
        steps.remove("sparse")

    if args.dry_run:
        print("disk_metrics plan (nothing is run):")
        if args.manage_workers:
            print(f"  stop the running services among: {', '.join(OTHERS)}")
        for step in steps:
            print(f"  {step}: {shlex.join(worker_command(step, args))}")
        print(f"  write the report: {args.write or REPORTS / 'disk-metric-<YYMMDD>.md'} (+ .json)")
        if args.manage_workers:
            print("  start the stopped services again")
        return 0
    if Path("/srv/api").is_dir() or Path("/srv/workers").is_dir():
        return refuse("run this on the host (python scripts/disk_metrics.py), not in a container")
    if shutil.which("docker") is None:
        return refuse("docker is not installed or not on PATH; the metric needs the Docker stack")
    if run(["docker", "info", "--format", "{{.ServerVersion}}"]).returncode:
        return refuse("the Docker engine is not reachable (start Docker, then retry)")
    if "ingest" in steps:
        up = running_services()
        missing = [s for s in INFRA if s not in up]
        if missing:
            return refuse(
                f"the ingest step needs {', '.join(missing)} up "
                "(docker compose up -d --wait postgres redis redis-broker minio), "
                "or pass --skip ingest"
            )

    started = time.monotonic()
    stopped = stop_others() if args.manage_workers else []
    results: dict[str, dict[str, Any]] = {}
    try:
        for step in steps:
            results[step] = run_step(step, args)
            if results[step]["status"] != "ok":
                print(f"✖ {step}: {results[step].get('detail')}", flush=True)
                sys.stderr.write(str(results[step].get("tail", ""))[-2000:] + "\n")
        notes = host_notes(stopped)
    finally:
        start_again(stopped)
    path = write_report(args, results, notes, time.monotonic() - started)
    shown = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
    print(f"written: {shown} (+ {Path(shown).with_suffix('.json').name})")
    failed = [s for s, r in results.items() if r["status"] != "ok"]
    crashed = sum(
        r["data"]["failures"]["crashed"]
        for s, r in results.items()
        if s in ("images", "hostile") and r.get("data")
    )
    sparse = results.get("sparse", {}).get("data") or {}
    crashed += int(sparse.get("run", {}).get("outcome") == "crash")
    if failed or crashed:
        print(f"disk_metrics: failed steps {failed or '-'}, crashed analyses {crashed}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
