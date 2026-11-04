#!/usr/bin/env python3
"""Print the "IOC enrichment success" metric table (M4 phase 7).

Runs the `metric` test (apps/api/tests/ti/test_enrichment_metric.py) in the api-test
container and prints the table it reports: 600 lookups over the six real adapters under
seeded synthetic faults, with a virtual clock, then a second pass for the cache. The test
asserts the floors (success >= 0.95 per provider, no ineligible value sent). Standard library
only; run it from the repo root with the stack's postgres, redis and redis-broker up:

  python scripts/ti_eval.py            # print the table
  python scripts/ti_eval.py --write    # also write plans/reports/ti-metric-261105.md

Options:
  --write [PATH]  write the table as a Markdown report (default above)
  --deps          let compose start api-test's dependencies (default: --no-deps)

Exit status: the test's (non-zero when a floor fails or the table is missing).
"""

import argparse
import datetime as dt
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "plans" / "reports" / "ti-metric-261105.md"
BEGIN = "=== TI METRIC BEGIN ==="
END = "=== TI METRIC END ==="
PYTEST = ["uv", "run", "pytest", "-q", "-s", "-p", "no:cacheprovider", "-m", "metric", "tests/ti"]
HEADER = """# IOC enrichment success: resilience under synthetic faults

Generated {date} by `python scripts/ti_eval.py --write` (test
`apps/api/tests/ti/test_enrichment_metric.py`, marker `metric`).

What this measures (RT24): 600 lookups, 100 per real adapter (VirusTotal, AbuseIPDB, URLhaus,
MalwareBazaar, OTX, MISP), through the real enrich-worker slices, broker limiter, retries,
cooldowns and `waiting`/resume path. The real adapters parse the committed fixture bodies
(`apps/api/tests/fixtures/ti/manifest.json`). Faults are drawn from a seeded RNG, and the clock
is virtual (provider latency, timeouts, backoff, cooldowns and beat resumes take no real time).
With 3 attempts per lookup, the 0.95 floor mostly measures the retry and resume logic, not the
providers. No live keys were used, so no live-run summary is recorded here.

"""


def extract(output: str) -> str | None:
    start = output.find(BEGIN)
    end = output.find(END, start + 1)
    if start < 0 or end < 0:
        return None
    return output[start + len(BEGIN) : end].strip("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", nargs="?", const=str(REPORT), default=None, metavar="PATH")
    parser.add_argument("--deps", action="store_true", help="start api-test's dependencies")
    args = parser.parse_args()

    command = ["docker", "compose", "--profile", "test", "run", "--rm"]
    if not args.deps:
        command.append("--no-deps")
    command += ["api-test", *PYTEST]
    proc = subprocess.run(  # noqa: S603 - a fixed argument list, no shell
        command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    table = extract(proc.stdout)
    if table is None:
        sys.stderr.write(proc.stdout[-4000:] + proc.stderr[-4000:])
        sys.stderr.write("\nti_eval: the metric table was not printed (see the output above)\n")
        return proc.returncode or 1
    print(table)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout[proc.stdout.find(END) :][-4000:])
        sys.stderr.write(f"\nti_eval: the metric test failed (exit {proc.returncode})\n")
    elif args.write:
        path = Path(args.write)
        date = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC")
        path.write_text(HEADER.format(date=date) + table + "\n", encoding="utf-8", newline="\n")
        print(f"\nwritten: {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
