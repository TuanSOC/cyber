#!/usr/bin/env python3
"""Regenerate the AI evaluation cases from real pipeline runs (M5 phase 6, heavy step RT13).

Standard library only; run from the repo root with the shared infra stack up and nothing else
heavy running (it starts one-off `pcap-worker-test` (2 GB) and `static-worker-test` (3 GB)
containers, one after the other):

  python scripts/ai_eval_snapshot.py             # workers, then normalize, then case tests
  python scripts/ai_eval_snapshot.py --reuse     # normalize the last worker output again
  python scripts/ai_eval_snapshot.py --lane 6    # run the case tests in lane 6

1. pcap-worker-test: `dataset.generate --inject` into the container's /tmp, then
   `analyzer.analyze_file` on every capture and twin (test Suricata rules, as the detector
   evaluation does); the result streams go to the Docker volume `cyberlab_ai_eval`.
2. static-worker-test: `samples.generate --inject` (no mingw builds, no archives kept), then
   `analyzer.analyze_file` with capa on and FLOSS where labelled; streams + hashes to the volume.
   Sample bytes stay inside the container: the host never sees them (host AV quarantines the
   packer-marker sample; the EICAR file is never copied out).
3. api-test: `tests.ai_eval.snapshot` validates every stream as ingest does, converts it with
   ingest's own row builders, trims, maps each `labels.json` plant to its row and writes the
   cases (`provenance.source = pipeline`) over the hand-trimmed ones.
4. The case tests (`test_ai_eval_cases.py`): every case seeds, every golden key resolves.

No broker queue is used (the analyzers are called in-process), so no `test.*` queue is touched.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VOLUME = "cyberlab_ai_eval"
SNAP = "/eval/snapshot"
COMPOSE_RUN = ["docker", "compose", "--profile", "test", "run", "--rm", "--no-deps", "-T"]

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


PCAP_DRIVER = r'''
import json, os, shutil, subprocess, uuid
from pathlib import Path
from cyberlab_worker import sandbox
from dataset.generate import generate
from pcap_worker import analyzer
from tests.integration.test_engines import LIMITS, TEST_RULES

os.environ["SURICATA_RULES"] = TEST_RULES
out = Path("/eval/snapshot/pcap")
out.mkdir(parents=True, exist_ok=True)
data = Path("/tmp/ai-eval-pcap")
shutil.rmtree(data, ignore_errors=True)
paths = generate(data, inject=True)
shutil.copyfile(data / "labels.json", out / "labels.json")
work = Path(os.environ.get("WORK_DIR", "/work"))
for n, (name, path) in enumerate(sorted(paths.items())):
    dirs = sandbox.prepare(work, f"ai-eval-{n}")
    try:
        shutil.copyfile(path, dirs.capture)
        dirs.capture.chmod(0o444)
        job = uuid.uuid4()
        result = analyzer.analyze_file(dirs, job, LIMITS, analyzer.Budget(LIMITS))
        shutil.copyfile(result, out / f"{name}.ndjson.gz")
        meta = {"job_id": str(job), "size": path.stat().st_size}
        (out / f"{name}.json").write_text(json.dumps(meta))
        print("pcap", name, flush=True)
    finally:
        sandbox.cleanup(dirs)
shutil.rmtree(data, ignore_errors=True)
subprocess.run(["chmod", "-R", "a+rX", "/eval/snapshot"], check=True)
'''

STATIC_DRIVER = r'''
import hashlib, json, shutil, subprocess, uuid
from dataclasses import replace
from pathlib import Path
from cyberlab_jobs.static import Profile
from cyberlab_worker import sandbox
from samples.generate import generate
from static_worker import analyzer
from static_worker.engines.workspace import Budget
from tests.conftest import BASE_WORK, WORK
from tests.helpers import FAST, LIMITS, fresh_dirs, place

SCENARIOS = %(scenarios)r
BASE_WORK.chmod(0o711)
WORK.mkdir(mode=0o711, exist_ok=True)
out = Path("/eval/snapshot/static")
out.mkdir(parents=True, exist_ok=True)
data = Path("/tmp/ai-eval-static")
shutil.rmtree(data, ignore_errors=True)
paths = generate(data, mingw=False, inject=True)
labels = json.loads((data / "labels.json").read_text())
(out / "labels.json").write_text(json.dumps(labels))
for name, path in sorted(paths.items()):
    if name.removesuffix("__injected") not in SCENARIOS:
        continue
    label = labels[name]
    engines = replace(FAST, capa_enabled=True, floss_enabled=bool(label.get("floss")))
    dirs = fresh_dirs(f"ai-eval-{name}")
    try:
        place(dirs, path)
        job = uuid.uuid4()
        result = analyzer.analyze_file(
            dirs, job, Profile(label["profile"]), LIMITS, Budget(LIMITS), engines
        )
        shutil.copyfile(result, out / f"{name}.ndjson.gz")
        body = path.read_bytes()
        meta = {
            "job_id": str(job), "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "sha1": hashlib.sha1(body).hexdigest(), "md5": hashlib.md5(body).hexdigest(),
        }
        (out / f"{name}.json").write_text(json.dumps(meta))
        print("static", name, flush=True)
    finally:
        sandbox.cleanup(dirs)
shutil.rmtree(data, ignore_errors=True)
shutil.rmtree(WORK, ignore_errors=True)
subprocess.run(["chmod", "-R", "a+rX", "/eval/snapshot"], check=True)
'''

STATIC_SCENARIOS = [
    "benign_pe32", "benign_pe64", "packed_like", "injection_imports", "keylogger_imports",
    "test_marker", "antidebug_imports", "credential_imports", "persistence_imports",
    "downloader_imports", "pe_anomalies", "benign_elf", "stack_string", "near_miss_apis",
    "near_miss_packer", "near_miss_icon", "eicar",
]  # fmt: skip


def step(title: str, command: list[str], stdin: str | None = None) -> None:
    print(f"== {title}", flush=True)
    proc = subprocess.run(command, cwd=ROOT, input=stdin, text=True)  # noqa: S603
    if proc.returncode:
        sys.exit(f"ai_eval_snapshot: {title} failed (exit {proc.returncode})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reuse", action="store_true", help="skip the worker runs")
    parser.add_argument("--lane", type=int, default=None, help="lane for the case tests")
    parser.add_argument("--no-tests", action="store_true")
    args = parser.parse_args()
    volume = ["-v", f"{VOLUME}:/eval"]
    if not args.reuse:
        subprocess.run(["docker", "volume", "create", VOLUME], cwd=ROOT, check=True)  # noqa: S603, S607
        step("reset the snapshot folder", [*COMPOSE_RUN, "--user", "0", *volume,
             "--entrypoint", "sh", "pcap-worker-test", "-c",
             f"rm -rf {SNAP} && mkdir -p {SNAP} && chmod 0777 /eval {SNAP}"])  # fmt: skip
        step("pcap pipeline (pcap-worker-test)", [*COMPOSE_RUN, "--user", "0", *volume,
             "--entrypoint", "python", "pcap-worker-test", "-"], PCAP_DRIVER)  # fmt: skip
        driver = STATIC_DRIVER % {"scenarios": STATIC_SCENARIOS}
        step("static pipeline (static-worker-test)", [*COMPOSE_RUN, "--user", "0", *volume,
             "--entrypoint", "python", "static-worker-test", "-"], driver)  # fmt: skip
    step("normalize into cases (api-test)", [*COMPOSE_RUN, "-v", f"{VOLUME}:/eval:ro",
         "api-test", "uv", "run", "python", "-m", "tests.ai_eval.snapshot", SNAP])  # fmt: skip
    if not args.no_tests:
        tests = ["uv", "run", "pytest", "-q", "-p", "no:cacheprovider",
                 "tests/ai_eval/test_ai_eval_cases.py"]  # fmt: skip
        if args.lane:
            step("case tests", [bash(), "scripts/lane-test.sh", str(args.lane), *tests])
        else:
            step("case tests", [*COMPOSE_RUN, "api-test", *tests])
    print("cases regenerated: review `git diff apps/api/tests/fixtures/ai_eval/cases`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
