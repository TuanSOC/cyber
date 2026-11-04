"""Fuzz-lite (§13 parser vulnerabilities posture): mutated PE/ELF never hang or crash.

Each mutant is a sample with random byte flips (headers included), truncation, duplicated
slices or a corrupted header field (e_lfanew, section count, directory sizes). Every run must
end within the job budget either with a valid result stream or with a JobFailed carrying a
stable code, and leave no tool process behind. Engines: ClamAV (test DB), YARA, every probe;
capa and FLOSS are exercised on the first mutants only (10-40 s each). Outcomes, including
per-engine error codes, are printed (and written to FUZZ_OUT when set). This is a
robustness smoke test, not a substitute for the upstream projects' own fuzzing.
"""

import json
import os
import random
import struct
import time
import uuid
from collections import Counter
from dataclasses import replace

from cyberlab_jobs.static import Profile
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from static_worker import analyzer
from static_worker.engines.workspace import Budget
from tests.conftest import SampleSet, in_container
from tests.helpers import FAST, LIMITS, fresh_dirs, parse, place

MUTANTS = 50
WITH_EMULATORS = 4
FUZZ_LIMITS = LIMITS.model_copy(update={"timeout_s": 240, "tool_timeout_s": 120})
EXPECTED_FAILURES: set[str] = set()  # every mutant must still produce a result stream

pytestmark = in_container


def mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        choice = rng.random()
        if choice < 0.35:  # flip a handful of bytes, biased towards the headers
            for _ in range(rng.randint(1, 40)):
                end = 1024 if rng.random() < 0.6 else len(buf)
                buf[rng.randrange(min(end, len(buf)))] = rng.randrange(256)
        elif choice < 0.55:  # truncate
            del buf[rng.randrange(64, len(buf)) :]
        elif choice < 0.75:  # duplicate a slice somewhere else
            start = rng.randrange(len(buf))
            chunk = buf[start : start + rng.randint(1, 4000)]
            at = rng.randrange(len(buf))
            buf[at:at] = chunk
        elif buf[:2] == b"MZ" and len(buf) > 0x100:  # hostile header fields
            e_lfanew = int.from_bytes(buf[0x3C:0x40], "little")
            field = rng.choice(["count", "dir", "lfanew"])
            if field == "lfanew":
                struct.pack_into("<I", buf, 0x3C, rng.choice([0, 0xFFFFFFFF, len(buf) - 2]))
            elif field == "count" and e_lfanew + 8 < len(buf):
                struct.pack_into("<H", buf, e_lfanew + 6, rng.choice([0, 0xFFFF, 96]))
            elif e_lfanew + 0x80 < len(buf):
                at = e_lfanew + 0x78 + 8 * rng.randrange(8)
                if at + 8 <= len(buf):
                    struct.pack_into("<II", buf, at, rng.randrange(2**32), rng.randrange(2**32))
        elif buf[:4] == b"\x7fELF" and len(buf) > 64:
            at = rng.choice([0x20, 0x28, 0x3C, 0x3E])  # phoff, shoff, shnum, shstrndx
            size = 8 if at in (0x20, 0x28) else 2
            buf[at : at + size] = rng.randbytes(size)
    return bytes(buf)


def test_mutated_samples_end_cleanly(sample_set: SampleSet) -> None:
    corpus = [
        path.read_bytes()
        for name, path in sorted(sample_set.paths.items())
        if sample_set.labels[name]["file_format"] in ("pe", "elf")
    ]
    rng = random.Random(4242)
    outcomes: Counter[str] = Counter()
    engine_errors: Counter[str] = Counter()
    formats: Counter[str] = Counter()
    slowest = 0.0
    for i in range(MUTANTS):
        engines = replace(FAST, capa_enabled=i < WITH_EMULATORS, floss_enabled=i < WITH_EMULATORS)
        dirs = fresh_dirs(f"fuzz-{i}")
        started = time.monotonic()
        try:
            place(dirs, mutate(rng, rng.choice(corpus)))
            result = analyzer.analyze_file(
                dirs, uuid.uuid4(), Profile.FULL, FUZZ_LIMITS, Budget(FUZZ_LIMITS), engines
            )
            out = parse(result)  # a produced stream is always valid
            outcome = "result_with_engine_errors" if out["header"].engine_errors else "result"
            engine_errors.update(out["header"].engine_errors)
            formats[out["header"].file_format] += 1
        except JobFailed as exc:
            assert exc.code in EXPECTED_FAILURES, exc
            outcome = exc.code
        finally:
            sandbox.cleanup(dirs)
        elapsed = time.monotonic() - started
        slowest = max(slowest, elapsed)
        assert elapsed < FUZZ_LIMITS.timeout_s
        assert sandbox.tool_pids() == []
        outcomes[outcome] += 1
    summary = {
        "mutants": MUTANTS,
        "outcomes": dict(outcomes),
        "engine_errors": dict(engine_errors),
        "file_formats": dict(formats),
        "slowest_s": round(slowest, 1),
    }
    print(f"fuzz-lite: {json.dumps(summary)}")
    if target := os.environ.get("FUZZ_OUT"):
        with open(target, "w") as f:
            json.dump(summary, f, indent=2)
    assert sum(outcomes.values()) == MUTANTS
