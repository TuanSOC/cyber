#!/usr/bin/env python3
"""Print the AI analyst evaluation tables (M5 phase 6). Standard library only.

Offline (default, no network, what CI runs): the `tests/ai_eval` invariant and replay tests in
the api-test container; prints the FakeProvider and HostileProvider tables over every case
(real pipeline) and the replay table over the committed cassettes.

  python scripts/ai_eval.py                  # main test lane (cyberlab_test)
  python scripts/ai_eval.py --lane 6         # a parallel-development lane (scripts/lane-test.sh)
  python scripts/ai_eval.py --doubles        # also the phase-1 doubles table (harness self-test)

Live (local only, never in CI; needs AI_EVAL_LIVE=1 and a key file in .secrets/):

  AI_EVAL_LIVE=1 python scripts/ai_eval.py --provider anthropic --model claude-sonnet-5 \
      --runs 3 [--record] [--write] [--cases pcap_beacon,static_packed_like]

  Rounds of: render every case through the real pipeline in api-test (cassette misses are
  queued in a scratch Docker volume), then answer the queue in analyst-worker-test (the only
  test container with egress) through the real adapter; finally replay and score. Temperature
  cannot be set on these models, so n runs per case are reported as mean and minimum.
  --record copies the cassettes (sanitized: parsed output, usage, model, stop reason) into
  apps/api/tests/fixtures/ai_eval/cassettes/; --write writes plans/reports/ai-metric-YYMMDD.md.
  The key file (default .secrets/ai_eval_<provider>.key) is mounted read-only, never passed
  in an environment variable or printed.

Exit status: the tests' (non-zero when a floor fails or a table is missing).
"""

import argparse
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "=== AI EVAL TABLE BEGIN ==="
END = "=== AI EVAL TABLE END ==="
VOLUME = "cyberlab_ai_eval"
PYTEST = ["uv", "run", "pytest", "-q", "-s", "-p", "no:cacheprovider"]
OFFLINE = ["tests/ai_eval/test_ai_eval_invariants.py", "tests/ai_eval/test_ai_eval_replay.py"]
COMPOSE_RUN = ["docker", "compose", "--profile", "test", "run", "--rm", "--no-deps"]
def bash() -> str:
    """Git Bash on Windows (a bare `bash` there may be WSL's), plain `bash` elsewhere."""
    if os.environ.get("BASH_EXE"):
        return os.environ["BASH_EXE"]
    if os.name == "nt" and (git := shutil.which("git")):
        for root in Path(git).parents[:3]:  # .../Git/{cmd,bin,mingw64/bin}/git.exe
            for candidate in (root / "bin" / "bash.exe", root / "usr" / "bin" / "bash.exe"):
                if candidate.is_file():
                    return str(candidate)
    return "bash"


HEADER = """# AI evidence citation accuracy: {title}

Generated {date} by `python scripts/ai_eval.py {args}` (M5 phase 6 harness,
`apps/api/tests/ai_eval/`). Cases: committed snapshots in
`apps/api/tests/fixtures/ai_eval/cases/` (clean and prompt-injected twins), golden files in
`.../golden/`. Live answers were recorded once and scored by replay, so these numbers are
reproducible with `test_ai_eval_replay.py` when the cassettes were committed (`--record`).

"""


def run(command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argument lists, no shell
        command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, **(env or {})},
    )


def tables(output: str) -> list[str]:
    out, start = [], 0
    while (begin := output.find(BEGIN, start)) >= 0:
        end = output.find(END, begin)
        if end < 0:
            break
        out.append(output[begin + len(BEGIN) : end].strip("\n"))
        start = end + len(END)
    return out


def offline(args: argparse.Namespace) -> int:
    files = OFFLINE + (["tests/ai_eval/test_ai_eval_harness.py"] if args.doubles else [])
    if args.lane:
        command = [bash(), "scripts/lane-test.sh", str(args.lane), *PYTEST, *files]
    else:
        command = [*COMPOSE_RUN, "api-test", *PYTEST, *files]
    proc = run(command)
    found = tables(proc.stdout)
    for table in found:
        print(table + "\n")
    skipped = re.findall(r"SKIPPED \[\d+\] [^\n]*", proc.stdout)
    for line in skipped:
        print(line)
    if not found:
        sys.stderr.write(proc.stdout[-4000:] + proc.stderr[-4000:])
        sys.stderr.write("\nai_eval: no table was printed (see the output above)\n")
        return proc.returncode or 1
    if proc.returncode:
        sys.stderr.write(proc.stdout[-3000:])
        sys.stderr.write(f"\nai_eval: the evaluation tests failed (exit {proc.returncode})\n")
    if args.write:
        write_report(args, "offline (FakeProvider, HostileProvider, replay)", found)
    return proc.returncode


def write_report(args: argparse.Namespace, title: str, found: list[str]) -> None:
    today = dt.datetime.now(dt.UTC)
    path = Path(args.write) if args.write != "default" else (
        ROOT / "plans" / "reports" / f"ai-metric-{today.strftime('%y%m%d')}.md"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    header = HEADER.format(
        title=title, date=today.strftime("%Y-%m-%d %H:%M UTC"), args=" ".join(sys.argv[1:])
    )
    path.write_text(header + "\n\n".join(found) + "\n", encoding="utf-8", newline="\n")
    print(f"written: {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")


def live(args: argparse.Namespace) -> int:
    if os.environ.get("AI_EVAL_LIVE") != "1":
        sys.stderr.write("ai_eval: live mode needs AI_EVAL_LIVE=1 (local only, never in CI)\n")
        return 2
    key_file = Path(args.key_file or ROOT / ".secrets" / f"ai_eval_{args.provider}.key")
    if not key_file.is_file():
        sys.stderr.write(f"ai_eval: no key file at {key_file} (one line, the API key)\n")
        return 2
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d%H%M%S")
    base = f"/eval/{stamp}"
    volume = ["-v", f"{VOLUME}:/eval"]
    common = {
        "AI_EVAL_LIVE": "1", "AI_EVAL_PROVIDER": args.provider, "AI_EVAL_MODEL": args.model,
        "AI_EVAL_RUNS": str(args.runs), "AI_EVAL_STORE": f"{base}/cassettes",
        "AI_EVAL_PENDING": f"{base}/pending.json", "AI_EVAL_CASES": args.cases or "",
    }  # fmt: skip
    env_flags = [x for k, v in common.items() for x in ("-e", f"{k}={v}")]
    run(["docker", "volume", "create", VOLUME])
    prep = run([*COMPOSE_RUN, "--user", "0", *volume, "api-test", "sh", "-c",
                f"mkdir -p {base}/cassettes && chmod -R 0777 /eval"])  # fmt: skip
    if prep.returncode:
        sys.stderr.write(prep.stderr[-2000:])
        return prep.returncode
    test = "tests/ai_eval/test_ai_eval_live.py"
    for round_ in range(1, 6):
        collect = run([*COMPOSE_RUN, *volume, *env_flags, "-e", "AI_EVAL_STAGE=collect",
                       "api-test", *PYTEST, "-m", "ai_eval", test])  # fmt: skip
        match = re.search(r"AI_EVAL_PENDING=(\d+)", collect.stdout)
        if collect.returncode or match is None:
            sys.stderr.write(collect.stdout[-4000:] + collect.stderr[-2000:])
            return collect.returncode or 1
        count = int(match.group(1))
        print(f"round {round_}: {count} provider calls pending")
        if count == 0:
            break
        call = run([*COMPOSE_RUN, *volume, "-v", f"{key_file.resolve()}:/run/ai_eval_key:ro",
                    "-e", "AI_EVAL_LIVE=1", "-e", "AI_EVAL_KEY_FILE=/run/ai_eval_key",
                    "-e", f"AI_EVAL_PROVIDER={args.provider}", "analyst-worker-test",
                    "python", "-m", "tests.ai_eval.live_call", f"{base}/pending.json",
                    f"{base}/cassettes"])  # fmt: skip
        print(call.stdout.strip().splitlines()[-1] if call.stdout.strip() else "")
        if call.returncode:
            sys.stderr.write(call.stdout[-2000:] + call.stderr[-3000:])
            return call.returncode
    else:
        sys.stderr.write("ai_eval: calls still pending after 5 rounds\n")
        return 1
    record = ["-e", "AI_EVAL_RECORD=1"] if args.record else []
    score = run([*COMPOSE_RUN, *volume, *env_flags, *record, "-e", "AI_EVAL_STAGE=score",
                 "api-test", *PYTEST, "-m", "ai_eval", test])  # fmt: skip
    found = tables(score.stdout)
    for table in found:
        print(table + "\n")
    floors = re.search(r"LIVE FLOORS[^\n]*", score.stdout)
    if floors:
        print(floors.group(0))
        found.append(floors.group(0))
    if score.returncode:
        sys.stderr.write(score.stdout[-3000:])
    if args.write and found:
        write_report(args, f"live {args.provider} {args.model} (n={args.runs})", found)
    return score.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--provider", choices=["anthropic", "gemini"], default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--cases", default="", help="comma-separated case names (default: all)")
    parser.add_argument("--record", action="store_true", help="commit the recorded cassettes")
    parser.add_argument("--write", nargs="?", const="default", default=None, metavar="PATH")
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--lane", type=int, default=None, help="offline: lane 2..7")
    parser.add_argument("--doubles", action="store_true", help="offline: add the doubles table")
    args = parser.parse_args()
    if args.provider is None:
        return offline(args)
    if not args.model:
        parser.error("--model is required with --provider")
    return live(args)


if __name__ == "__main__":
    sys.exit(main())
