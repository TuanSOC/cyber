"""Fuzz-lite over hostile disk images (M9 phase 13; RT6, RT13, RT30). Heavy: run alone.

    docker compose --profile test run --rm --no-deps -e DISK_FUZZ=1 disk-worker-test \
        pytest -q -p no:cacheprovider tests/fuzz

Every input goes through the real worker path (`tests/fuzz/harness.py`: `pipeline.run_job`,
every stage sandboxed, Plaso when a Linux / Windows tree is collected) and must end cleanly: a
result, a per-stage error, or a job failure with a known code; no tool process survives any
stage; the audit hooks count no network or process event; the free space of the work volume
never falls below the watchdog floor; the tools' peak RSS stays under the largest RLIMIT_AS.

Inputs, generated here into the test tmpfs (never committed, never downloaded):
- 60 mutations of phase 4's hostile mode (`samples.diskgen.mutate.CATALOG`: FAT, ext4, NTFS,
  MBR / GPT and EWF bases; 15 mutations x 4 seeds), in 6 chunks of 10 whose inputs are deleted
  after each chunk, so one chunk's leftovers cannot accumulate;
- the specials: an E01 claiming a media size above DISK_MAX_MEDIA_BYTES and a deep tree with a
  path over 4 096 bytes (both in the catalog), a sparse NTFS whose `$MFT` claims a 1 TiB data
  run (RT30; built here from `ntfs_flat`), and a random 64 MiB blob behind each container magic
  root refuses (`disk_worker/formats.py`; refused by root before any probe runs).
Counts by outcome go to `DISK_FUZZ_REPORT` (conftest).
"""

import os
import random
import shutil
import struct
from pathlib import Path

import pytest

from disk_worker import formats
from samples.diskgen import SECTOR, mutate, tools
from samples.diskgen.images import ALIGN, Generator
from tests.fuzz import harness

if os.environ.get("DISK_FUZZ") != "1":
    pytest.skip("heavy: DISK_FUZZ=1 in disk-worker-test, alone", allow_module_level=True)
if not hasattr(os, "geteuid") or os.geteuid() != 0:
    pytest.skip("runs as root inside the disk worker image", allow_module_level=True)

ROUNDS = 4
CHUNK = 10
SEED = 1300
BLOB_BYTES = 64 * 1024**2
CASES: list[tuple[str, int, str]] = [
    (name, SEED + r * 100 + i, "full" if r % 2 else "triage")
    for r in range(ROUNDS)
    for i, name in enumerate(mutate.CATALOG)
]
CHUNKS = [CASES[i : i + CHUNK] for i in range(0, len(CASES), CHUNK)]


def _check_expectation(name: str, run: harness.Run) -> None:
    if name == "refused_magic":
        assert run.outcome == "failed:unsupported_disk_format", run.outcome
        assert run.stages == [], "a probe ran on a refused container"
    if name == "ewf_huge_media":
        # The media-size cap (RT6): refused, never verified for hours.
        assert run.code == "unsupported_disk_format", run.outcome
        assert not any(s.stage == "verify" and s.duration_ms > 60_000 for s in run.stages)


@pytest.mark.parametrize("chunk", range(len(CHUNKS)), ids=lambda c: f"chunk{c}")
def test_hostile_mutations_end_cleanly(chunk: int) -> None:
    gen = Generator(harness.inputs_dir(f"chunk{chunk}"))
    runs: list[harness.Run] = []
    try:
        for i, (name, seed, profile) in enumerate(CHUNKS[chunk]):
            directory = gen.out / "hostile" / f"{chunk * CHUNK + i:03d}_{name}"
            try:
                case = mutate.run_one(gen, name, seed, directory)
            except tools.ToolMissing as exc:
                skipped = {
                    "name": f"{name}/{seed}",
                    "outcome": "skipped_tool_missing",
                    "clean": True,
                    "reason": str(exc),
                }
                harness.record_raw("mutations", skipped)
                continue
            run = harness.run_case(f"{name}/{seed}", case.segments, profile=profile)
            harness.record("mutations", run, mutation=name, seed=seed, profile=profile)
            runs.append(run)
            _check_expectation(name, run)
            shutil.rmtree(directory, ignore_errors=True)
    finally:
        shutil.rmtree(gen.out, ignore_errors=True)
    unclean = [(r.name, r.outcome, r.problems) for r in runs if not r.clean]
    assert unclean == []


def _mft_record0(data: bytes) -> tuple[int, int]:
    """(absolute offset of `$MFT`'s record 0, the record size) of an MBR image's first NTFS."""
    vbr = ALIGN * SECTOR
    if data[vbr + 3 : vbr + 11] != b"NTFS    ":
        raise ValueError("no NTFS boot sector")
    bps = struct.unpack_from("<H", data, vbr + 11)[0]
    cluster = bps * data[vbr + 13]
    mft = vbr + struct.unpack_from("<Q", data, vbr + 48)[0] * cluster
    raw_size = struct.unpack_from("<b", data, vbr + 64)[0]
    record = cluster * raw_size if raw_size > 0 else 1 << -raw_size
    if data[mft : mft + 4] != b"FILE":
        raise ValueError("no FILE record at $MFT")
    return mft, record


def huge_mft(src: Path, dst: Path, claimed: int = 1 << 40) -> int:
    """Copy of an NTFS image whose `$MFT` `$DATA` attribute claims `claimed` bytes (allocated,
    data and initialized sizes). Nothing backs the claim: the run list is unchanged, so the
    image stays small (the "sparse" huge MFT of RT30). Returns the patched attribute offset."""
    data = bytearray(src.read_bytes())
    mft, record = _mft_record0(data)
    off = mft + struct.unpack_from("<H", data, mft + 0x14)[0]
    while off + 16 <= mft + record:
        kind, length = struct.unpack_from("<II", data, off)
        if kind == 0xFFFFFFFF or length == 0:
            break
        if kind == 0x80 and data[off + 8] == 1:  # non-resident $DATA
            fields = (off + 0x28, off + 0x30, off + 0x38)
            # The update sequence owns the last two bytes of every sector of the record.
            if any((f - mft) % SECTOR >= SECTOR - 2 - 8 for f in fields):
                raise ValueError("the size fields straddle a fixup")
            for f in fields:
                struct.pack_into("<Q", data, f, claimed)
            dst.write_bytes(bytes(data))
            return off
        off += length
    raise ValueError("no non-resident $DATA in $MFT")


def test_a_sparse_ntfs_claiming_a_huge_mft_ends_cleanly() -> None:
    gen = Generator(harness.inputs_dir("huge_mft"))
    try:
        try:
            base = gen.build("ntfs_flat")
        except tools.ToolMissing as exc:
            pytest.skip(str(exc))
        target = gen.out / "huge_mft.raw"
        huge_mft(base.raw, target)
        run = harness.run_case("ntfs_huge_mft", [target])
        harness.record("specials", run, claimed_mft_bytes=1 << 40)
    finally:
        shutil.rmtree(gen.out, ignore_errors=True)
    assert run.clean, run.problems
    walk = [s for s in run.stages if s.stage == "walk"]
    # The walk is bounded (rows, RLIMIT_AS -> `walk_memory`, timeout), never unbounded.
    assert all(s.status.value in ("ok", "truncated", "failed", "timeout") for s in walk)


def _blobs() -> list[tuple[str, int, bytes]]:
    out = [(f"{name}@{off}", off, magic) for off, magic, name in formats._REFUSED_HEAD]
    out.append(("vhd_footer", -1, b"conectix"))
    return out


@pytest.mark.parametrize("label,offset,magic", _blobs(), ids=lambda v: str(v)[:24])
def test_a_random_blob_behind_a_refused_magic_is_refused_by_root(
    label: str, offset: int, magic: bytes
) -> None:
    d = harness.inputs_dir("blob")
    blob = bytearray(random.Random(f"blob/{label}").randbytes(BLOB_BYTES))
    if offset >= 0:
        blob[offset : offset + len(magic)] = magic
    else:
        blob[-512:-504] = magic  # a VHD footer behind random bytes
    path = d / "image.raw"
    path.write_bytes(bytes(blob))
    del blob
    try:
        run = harness.run_case(f"blob/{label}", [path])
        harness.record("refused_magic_blobs", run, magic=label)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    assert run.clean, run.problems
    assert run.outcome == "failed:unsupported_disk_format", run.outcome
    assert run.stages == [], "root must refuse before any probe"
