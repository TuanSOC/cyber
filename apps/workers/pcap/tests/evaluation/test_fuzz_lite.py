"""Fuzz-lite (§13 parser vulnerabilities posture): mutated captures never hang or crash.

Each mutant is a dataset capture with random byte flips, truncation or duplicated slices.
Every run must end within the job budget either with a valid result stream or with a
JobFailed carrying a stable code, and leave no tool process behind. This is a robustness
smoke test, not a substitute for the upstream projects' own fuzzing.
"""

import os
import random
import shutil
import time
import uuid
from pathlib import Path

import pytest
from cyberlab_jobs import JobLimits
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from dataset.generate import generate
from pcap_worker import analyzer
from tests.integration.test_engines import TEST_RULES, parse

MUTANTS = 50
LIMITS = JobLimits(
    max_bytes=16 * 1024**2,
    timeout_s=120,
    tool_timeout_s=60,
    max_flows=5_000,
    max_records_per_kind=5_000,
    max_findings=500,
    max_result_bytes=16 * 1024**2,
)
EXPECTED_FAILURES = {"unparseable_capture", "unsupported_capture_format", "zeek_failed"}

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="runs inside the pcap-worker image")


def mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        choice = rng.random()
        if choice < 0.5:  # flip a handful of bytes (header bytes included)
            for _ in range(rng.randint(1, 40)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif choice < 0.75:  # truncate
            del buf[rng.randrange(24, len(buf)) :]
        else:  # duplicate a slice somewhere else
            start = rng.randrange(len(buf))
            chunk = buf[start : start + rng.randint(1, 2000)]
            at = rng.randrange(len(buf))
            buf[at:at] = chunk
    return bytes(buf)


def test_mutated_captures_end_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SURICATA_RULES", TEST_RULES)
    seeds = Path("/tmp/fuzz-dataset")
    shutil.rmtree(seeds, ignore_errors=True)
    corpus = [p.read_bytes() for name, p in generate(seeds).items() if name != "mixed"]
    rng = random.Random(4242)
    outcomes: dict[str, int] = {}
    work = Path(os.environ.get("WORK_DIR", "/work"))
    for i in range(MUTANTS):
        dirs = sandbox.prepare(work, f"fuzz-{i}")
        dirs.capture.write_bytes(mutate(rng, rng.choice(corpus)))
        dirs.capture.chmod(0o444)
        started = time.monotonic()
        try:
            result = analyzer.analyze_file(dirs, uuid.uuid4(), LIMITS, analyzer.Budget(LIMITS))
            parse(result)  # a produced stream is always valid
            outcome = "result"
        except JobFailed as exc:
            assert exc.code in EXPECTED_FAILURES, exc
            outcome = exc.code
        finally:
            sandbox.cleanup(dirs)
        assert time.monotonic() - started < LIMITS.timeout_s
        assert sandbox.tool_pids() == []
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    print(f"fuzz-lite outcomes over {MUTANTS} mutants: {outcomes}")
    assert sum(outcomes.values()) == MUTANTS
