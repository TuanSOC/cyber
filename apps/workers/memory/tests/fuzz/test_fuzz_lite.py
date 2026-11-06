"""Fuzz-lite of the real memory pipeline (M8 phase 11; heavy, alone, `MEMORY_FUZZ=1`).

Every case runs root's `analyze_image` with the real engine (Volatility 2.28.2 in the
sandboxed probe: tool uid, seccomp, rlimits, offline) and must end cleanly: a result, the
symbols-missing diagnostic, or a job failure with a known `memory.v1` code; afterwards no
tool process is left, every probe's audit counts are zero, and the probes' peak RSS stayed
below `RLIMIT_AS`. A hang, a crash of the test process or a container restart fails the run.

- 50 seeded mutants of the synthetic Linux image (`samples.memgen.mutate`: truncation, page
  corruption, a cyclic `tasks` list, self parents, huge `comm` / argv, invalid pointers, a
  page-table loop, zero length, LiME / ELF headers with lying or overlapping ranges);
- a random 64 MiB blob behind each format magic the stackers look for (LiME, AVML, ELF,
  VMware, Windows crash dumps, QEMU) and a plain random blob;
- compressed and archive files: refused by root before any probe (RT19);
- 10 hostile ISFs (deep nesting, huge arrays, wrong types, oversize, cycles, ...) stored for
  the synthetic banner in a temp store (bypassing `import`, which would refuse most of them).

The outcome counts are printed as one `FUZZ_SUMMARY {json}` line (scripts/memory_metrics.py).

    scripts/lane-test.sh 4 --service memory-worker-test --heavy \\
        sh -c "MEMORY_FUZZ=1 pytest -q -s -p no:cacheprovider tests/fuzz"
"""

import base64
import json
import lzma
import os
import random
import resource
import shutil
import struct
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("volatility3")
pytest.importorskip("resource")

from cyberlab_jobs.memory import (  # noqa: E402
    MEMORY_ERROR_CODES,
    LinuxBanner,
    MemoryJobV1,
    MemoryLimits,
)
from cyberlab_worker import sandbox  # noqa: E402
from cyberlab_worker.errors import JobFailed  # noqa: E402

from memory_worker import analyzer  # noqa: E402
from memory_worker.config import load  # noqa: E402
from memory_worker.engines.volatility import VolatilityEngine  # noqa: E402
from memory_worker.engines.workspace import STATUS, Workspace  # noqa: E402
from memory_worker.normalize.reader import read_status  # noqa: E402
from memory_worker.probe.guard import FAMILIES  # noqa: E402
from memory_worker.symbols import import_isf, reindex  # noqa: E402
from memory_worker.symbols.store import SymbolStore  # noqa: E402
from samples.memgen import (  # noqa: E402
    BANNER,
    build,
    isf,
    isf_xz,
    mutate,  # noqa: E402
    scenario,
    wrap,
)
from tests.conftest import BASE_WORK  # noqa: E402
from tests.replay_helpers import LIMITS  # noqa: E402
from tests.symbols_helpers import new_store, put  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("MEMORY_FUZZ") != "1", reason="heavy: MEMORY_FUZZ=1, alone, --heavy lane"
)

SEED = 11
MUTANTS = 50
BLOB_BYTES = 64 * 1024**2
# Tight per-probe limits: a looping probe is killed in 2 minutes, not the default 20.
FUZZ_LIMITS = MemoryLimits.model_validate(
    {**LIMITS.model_dump(), "timeout_s": 1200, "identify_timeout_s": 120, "tool_timeout_s": 120}
)
OUTCOMES: Counter[str] = Counter()
FAMILY_OUTCOMES: dict[str, Counter[str]] = {}
SECONDS: list[float] = []


@pytest.fixture(scope="module", autouse=True)
def summary() -> Iterator[None]:
    yield
    if OUTCOMES:
        record = {
            "seed": SEED,
            "runs": sum(OUTCOMES.values()),
            "outcomes": dict(sorted(OUTCOMES.items())),
            "by_family": {k: dict(sorted(v.items())) for k, v in sorted(FAMILY_OUTCOMES.items())},
            "seconds_total": round(sum(SECONDS), 1),
            "seconds_max": round(max(SECONDS), 1),
            "peak_child_rss_mib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss >> 10,
        }
        print("\nFUZZ_SUMMARY " + json.dumps(record, sort_keys=True))


@pytest.fixture(scope="module")
def benign_store() -> Iterator[Path]:
    """The synthetic ISF imported and indexed once, outside the per-session work dir that
    `sandbox.prepare` resets (the tool uid traverses /work and reads the 0555 / 0444 store)."""
    parent = BASE_WORK / f"fuzz-store-{uuid.uuid4().hex[:8]}"
    parent.mkdir(mode=0o755)
    root = new_store(parent)
    source = parent / "cyberlab.json.xz"
    source.write_bytes(isf_xz(BANNER))
    import_isf.import_file(root, source)
    source.unlink()
    reindex.reindex(root, required_root=Path(os.path.abspath(root)))
    yield root
    shutil.rmtree(parent, ignore_errors=True)


def _job(size: int) -> MemoryJobV1:
    return MemoryJobV1.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "evidence_id": str(uuid.uuid4()),
            "expected_sha256": "a" * 64,
            "size_bytes": max(size, 1),
            "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=1",
            "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"k": "v"}},
            "ingest_token": "t" * 43,
            "profile": "triage",
            "os_hint": "auto",
            "limits": FUZZ_LIMITS.model_dump(),
        }
    )


def _probe_dirs(dirs: sandbox.JobDirs) -> list[sandbox.JobDirs]:
    outs = sorted(d for d in dirs.root.iterdir() if d.name.endswith("-out"))
    return [sandbox.JobDirs(root=dirs.root, input=dirs.input, out=d) for d in outs]


def run_case(
    dirs: sandbox.JobDirs, store: Path, data: bytes | Callable[[Path], None], family: str
) -> str:
    """Analyze one image and return its outcome; assert it ended cleanly."""
    ws = Workspace(dirs, store)
    if callable(data):
        data(ws.image)
    else:
        ws.image.write_bytes(data)
    os.chmod(ws.image, 0o444)
    size = ws.image.stat().st_size
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    started = time.monotonic()
    try:
        analyzer.analyze_image(ws, _job(size), VolatilityEngine(config), SymbolStore(store))
        outcome = "result"
    except analyzer.DiagnosticResult:
        outcome = "symbols_missing"
    except JobFailed as exc:
        assert exc.code in MEMORY_ERROR_CODES, exc.code
        outcome = exc.code
    SECONDS.append(time.monotonic() - started)
    assert sandbox.tool_pids() == []
    for run in _probe_dirs(dirs):
        try:
            with sandbox.open_output(run, STATUS) as f:
                status = read_status(f)
        except (OSError, ValueError):
            continue  # killed on timeout: no status
        if status is not None:
            assert {k: status.audit.get(k, 0) for k in FAMILIES} == dict.fromkeys(FAMILIES, 0)
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
    assert peak < config.plugin_rlimit_as
    OUTCOMES[outcome] += 1
    FAMILY_OUTCOMES.setdefault(family, Counter())[outcome] += 1
    print(f"{family}: {outcome} ({SECONDS[-1]:.1f} s)")
    return outcome


# --- mutants of the synthetic image ------------------------------------------------------


@pytest.mark.parametrize("n", range(MUTANTS))
def test_mutant_ends_cleanly(dirs: sandbox.JobDirs, benign_store: Path, n: int) -> None:
    mutant = mutate.mutant(SEED, n)
    outcome = run_case(dirs, benign_store, mutant.data, mutant.family)
    if mutant.family == "zero_length":
        assert outcome in ("os_undetermined", "memory_parse_failed")


# --- random blobs behind format magics -------------------------------------------------------

MAGICS: dict[str, bytes] = {
    "lime": struct.pack("<IIQQQ", 0x4C694D45, 1, 0, BLOB_BYTES - 33, 0),
    "avml": struct.pack("<IIQQQ", 0x4C4D5641, 2, 0, BLOB_BYTES, 0),
    "elf": b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHI", 4, 62, 1),
    "vmware": b"\xd2\xbe\xd2\xbe" + struct.pack("<II", 0, 1),
    "crash64": b"PAGEDU64",
    "crash32": b"PAGEDUMP",
    "qemu": b"QEVM" + struct.pack(">I", 3),
    "random": b"",
}


@pytest.mark.parametrize("name", sorted(MAGICS))
def test_random_blob_behind_a_format_magic(
    dirs: sandbox.JobDirs, benign_store: Path, name: str
) -> None:
    rng = random.Random(f"{SEED}:{name}")

    def write(path: Path) -> None:
        with open(path, "wb") as f:
            f.write(MAGICS[name])
            for _ in range(BLOB_BYTES // (4 * 1024**2)):
                f.write(rng.randbytes(4 * 1024**2))

    outcome = run_case(dirs, benign_store, write, f"blob_{name}")
    assert outcome != "result" or name == "random"


# --- compressed and archived files: refused before any probe -------------------------------

ARCHIVES = {
    "gzip": b"\x1f\x8b\x08\x00",
    "zip": b"PK\x03\x04",
    "xz": lzma.compress(b"x" * 1024),
    "bzip2": b"BZh91AY&SY",
    "zstd": b"\x28\xb5\x2f\xfd",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "rar": b"Rar!\x1a\x07\x01\x00",
}


@pytest.mark.parametrize("name", sorted(ARCHIVES))
def test_compressed_files_are_refused_before_any_probe(
    dirs: sandbox.JobDirs, benign_store: Path, name: str
) -> None:
    data = ARCHIVES[name] + random.Random(name).randbytes(4096)
    assert run_case(dirs, benign_store, data, f"archive_{name}") == "unsupported_memory_format"
    assert _probe_dirs(dirs) == []


# --- hostile ISFs in a temp store ---------------------------------------------------------


def _hostile(name: str) -> bytes:
    doc = isf(BANNER)
    task = doc["user_types"]["task_struct"]["fields"]
    char = {"kind": "base", "name": "char"}
    if name == "deep_nesting":
        pass  # spliced in as text by _dump_deep
    elif name == "huge_array":
        task["comm"]["type"] = {"kind": "array", "count": 2**40, "subtype": char}
    elif name == "wrong_types":
        doc["base_types"]["int"]["size"] = "four"
        task["pid"]["offset"] = "0x20"
    elif name == "negative_offsets":
        task["pid"]["offset"] = -(2**40)
        task["tasks"]["offset"] = -16
    elif name == "missing_task_struct":
        del doc["user_types"]["task_struct"]
    elif name == "self_containing_struct":
        loop = {"kind": "struct", "name": "list_head"}
        doc["user_types"]["list_head"]["fields"]["next"]["type"] = loop
    elif name == "huge_symbol_address":
        doc["symbols"]["init_task"]["address"] = 2**70
        doc["symbols"]["init_top_pgt"]["address"] = -1
    elif name == "oversize":
        doc["metadata"]["producer"]["version"] = "9" * (48 * 1024**2)
    elif name == "unknown_references":
        task["mm"]["type"] = {"kind": "pointer", "subtype": {"kind": "struct", "name": "nope"}}
        task["cred"]["type"] = {"kind": "enum", "name": "missing_enum"}
    elif name == "not_json":
        return lzma.compress(
            b'{"metadata": {"format": "6.2.0"}, "symbols": {"linux_banner": '
            + json.dumps(
                {"constant_data": base64.b64encode((BANNER + "\n\0").encode()).decode()}
            ).encode()
            + b", [[["
        )
    raw = json.dumps(doc).encode() if name != "deep_nesting" else _dump_deep(doc)
    return lzma.compress(raw, format=lzma.FORMAT_XZ)


def _dump_deep(doc: dict[str, Any]) -> bytes:
    """json.dumps recurses too deep for 20 000 levels: splice the nesting in as text."""
    placeholder = {"kind": "base", "name": "__DEEP__"}
    doc["user_types"]["task_struct"]["fields"]["comm"]["type"] = placeholder
    text = json.dumps(doc)
    deep = '{"kind": "array", "count": 1, "subtype": ' * 20_000
    inner = '{"kind": "base", "name": "char"}' + "}" * 20_000
    return text.replace(json.dumps(placeholder), deep + inner).encode()


HOSTILE_ISFS = (
    "deep_nesting", "huge_array", "wrong_types", "negative_offsets", "missing_task_struct",
    "self_containing_struct", "huge_symbol_address", "oversize", "unknown_references", "not_json",
)  # fmt: skip


@pytest.mark.parametrize("name", HOSTILE_ISFS)
def test_a_hostile_isf_in_the_store_ends_cleanly(dirs: sandbox.JobDirs, name: str) -> None:
    root = new_store(dirs.root / f"isf-{name}")
    os.chmod(root.parent, 0o755)
    put(root, LinuxBanner(banner=BANNER), _hostile(name))
    try:  # the real indexer may refuse it; the probe then indexes the store itself
        reindex.reindex(root, required_root=Path(os.path.abspath(root)))
    except reindex.ReindexRefused:
        pass
    image = wrap(build(scenario("linux_benign")), "raw")
    run_case(dirs, root, image, f"isf_{name}")
