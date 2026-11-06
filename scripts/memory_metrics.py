#!/usr/bin/env python3
"""The §14 numbers of the memory analyzer (M8 phase 11): a heavy step, run alone with only the
infra stack and the memory worker up, never part of `pnpm verify`.

    python scripts/memory_metrics.py --fuzz-log <fuzz output> [--sparse] [--replays 3]

1. Detector precision / recall: `python -m dataset.evaluate` (phase 3's labelled scenarios).
2. Latency per plugin and per job (p50 / p95) and parse success: `tests/fuzz/metrics_run.py`
   runs every phase-4 synthetic image `--replays` times through the real pipeline in
   `memory-worker-test` (heavy lane); `--sparse` adds the probe-smoke identify scan of a sparse
   8 GiB file.
3. Parse success over the fuzz set: the `FUZZ_SUMMARY` line of a fuzz-lite run
   (`MEMORY_FUZZ=1 pytest -s tests/fuzz`), read from `--fuzz-log`.

Writes `plans/reports/memory-metric-YYMMDD.md`. The numbers cover synthetic Linux images and
the replayed Windows rows of the dataset only: no third-party memory image is ever run.
Stdlib only; the containers run through `scripts/lane-test.sh` (bash).
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LANE = ["bash", "scripts/lane-test.sh", "4", "--service", "memory-worker-test"]


def lane(*command: str, heavy: bool = False) -> str:
    argv = [*LANE, *(["--heavy"] if heavy else []), *command]
    print("$ " + " ".join(argv), file=sys.stderr, flush=True)
    done = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        sys.stderr.write(done.stdout[-4000:] + done.stderr[-4000:])
        raise SystemExit(f"lane command failed ({done.returncode})")
    return done.stdout


def tagged(text: str, tag: str) -> dict[str, Any]:
    for line in text.splitlines():
        if line.startswith(tag + " "):
            return dict(json.loads(line[len(tag) + 1 :]))
    raise SystemExit(f"no {tag} line in the output")


def pct(values: list[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    cuts = statistics.quantiles(ordered, n=100, method="inclusive")
    return int(round(cuts[int(q * 100) - 1]))


def latency_table(runs: list[dict[str, Any]]) -> str:
    per_plugin: dict[str, list[int]] = defaultdict(list)
    per_image: dict[str, list[int]] = defaultdict(list)
    for run in runs:
        per_image[run["image"]].append(run["job_ms"])
        for plugin, ms in run["plugins_ms"].items():
            per_plugin[plugin].append(ms)
    lines = ["| Step | n | p50 (s) | p95 (s) |", "|---|---:|---:|---:|"]
    for name, values in sorted(per_plugin.items()):
        lines.append(f"| `{name}` | {len(values)} | {pct(values, .5) / 1000:.1f} | "
                     f"{pct(values, .95) / 1000:.1f} |")  # fmt: skip
    lines += ["", "| Job (image) | n | p50 (s) | p95 (s) |", "|---|---:|---:|---:|"]
    for name, values in sorted(per_image.items()):
        lines.append(f"| `{name}` | {len(values)} | {pct(values, .5) / 1000:.1f} | "
                     f"{pct(values, .95) / 1000:.1f} |")  # fmt: skip
    every = [r["job_ms"] for r in runs]
    lines.append(f"| all jobs | {len(every)} | {pct(every, .5) / 1000:.1f} | "
                 f"{pct(every, .95) / 1000:.1f} |")  # fmt: skip
    return "\n".join(lines)


def parse_table(runs: list[dict[str, Any]]) -> tuple[str, int, int]:
    expected = {"symbols_missing.raw": "symbols_missing"}
    rows = defaultdict(lambda: defaultdict(int))  # type: ignore[var-annotated]
    good = 0
    for run in runs:
        rows[run["image"]][run["outcome"]] += 1
        good += run["outcome"] == expected.get(run["image"], "result")
    lines = ["| Image | Outcomes |", "|---|---|"]
    for image, outcomes in sorted(rows.items()):
        shown = ", ".join(f"{k} × {v}" for k, v in sorted(outcomes.items()))
        lines.append(f"| `{image}` | {shown} |")
    return "\n".join(lines), good, len(runs)


def fuzz_section(fuzz: dict[str, Any] | None) -> str:
    if fuzz is None:
        return "Not run in this report (no `--fuzz-log`)."
    outcomes = fuzz["outcomes"]
    clean = sum(outcomes.values())
    lines = [
        f"{fuzz['runs']} runs (seed {fuzz['seed']}), every one ended cleanly (a result, the "
        "symbols-missing diagnostic or a known job code; no surviving tool process, zero audit "
        f"events, peak probe RSS {fuzz['peak_child_rss_mib']} MiB below `RLIMIT_AS`): {clean} / "
        f"{fuzz['runs']}. Total {fuzz['seconds_total']} s, slowest case {fuzz['seconds_max']} s.",
        "",
        "| Outcome | Runs |",
        "|---|---:|",
        *(f"| `{k}` | {v} |" for k, v in sorted(outcomes.items())),
        "",
        "| Case family | Outcomes |",
        "|---|---|",
        *(
            f"| `{family}` | " + ", ".join(f"{k} × {v}" for k, v in sorted(o.items())) + " |"
            for family, o in sorted(fuzz["by_family"].items())
        ),
    ]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="memory_metrics")
    parser.add_argument("--fuzz-log", type=Path, help="output of a fuzz-lite run (-s)")
    parser.add_argument("--replays", type=int, default=3)
    parser.add_argument("--sparse", action="store_true", help="include the sparse 8 GiB scan")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    evaluation = lane("python", "-m", "dataset.evaluate")
    collect = ["python", "-m", "tests.fuzz.metrics_run", "--replays", str(args.replays)]
    metrics = tagged(lane(*collect, *(["--sparse"] if args.sparse else []), heavy=True), "METRICS")
    fuzz = None
    if args.fuzz_log:
        fuzz = tagged(args.fuzz_log.read_text(encoding="utf-8", errors="replace"), "FUZZ_SUMMARY")

    runs = metrics["runs"]
    parse, good, total = parse_table(runs)
    sparse = metrics.get("sparse_8gib_identify")
    sparse_text = (
        f"identify on a sparse 8 GiB file: {sparse['seconds']} s, ended `{sparse['end']}`, peak "
        f"probe RSS {sparse['peak_child_rss_mib']} MiB."
        if sparse
        else "Not measured in this report (run with `--sparse` when the host has the RAM)."
    )
    today = datetime.now(UTC)
    out = args.out or ROOT / "plans" / "reports" / f"memory-metric-{today:%y%m%d}.md"
    out.write_text(
        f"""# Memory analyzer metrics ({today:%Y-%m-%d})

Generated by `scripts/memory_metrics.py` (M8 phase 11). **Synthetic caveat:** every number
below comes from our own synthetic Linux images (`samples/memgen`, a fictional
`6.1.0-cyberlab-synthetic` kernel with our own ISF) run through the real Volatility 2.28.2, and
from the hand-written scenario rows of the detector dataset. No third-party or real memory
image was run (parent decision); Windows is never executed by Volatility here. These numbers
show the pipeline behaves as specified, not its accuracy or speed on real machines.

## Detector precision / recall (phase 3 dataset)

{evaluation.strip()}

## Parse success

Phase-4 images, {metrics['replays']} replays each (expected: a result, and the
symbols-missing diagnostic for the changed banner): **{good} / {total}**.

{parse}

### Fuzz-lite

{fuzz_section(fuzz)}

## Latency (real engine, triage profile, {metrics['replays']} replays)

Each step is a fresh sandboxed Volatility process (identify is not in the header and is part
of the job time).

{latency_table(runs)}

### Probe smoke: full-image scan

{sparse_text}

### Ingest at the caps

Not measured by this script: the API suite's ingest tests cover every cap functionally
(`test_memory_ingest*.py`); a timed harness is follow-up work.
""",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
