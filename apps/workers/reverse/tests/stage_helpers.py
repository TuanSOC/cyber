"""Helpers of the phase-2 / phase-3 unit tests: tiny header-only PE / ELF builders (for
root's magic check and the replay marker), the test `ReLimits`, a job, and the stage-row
fixtures. Never a real program: a header and a marker line, nothing to run."""

import json
import struct
import uuid
from pathlib import Path
from typing import Any

from cyberlab_jobs.reverse import ReJobV1, ReLimits

STAGE_ROWS = Path(__file__).resolve().parent / "fixtures" / "stage_rows"
SHA = "e" * 64

LIMITS = ReLimits(
    max_bytes=16 * 1024**2,
    timeout_s=3600,
    tool_timeout_s=1800,
    analysis_timeout_s=1500,
    decompile_timeout_s=30,
    quick_timeout_s=300,
    max_functions=20_000,
    max_call_edges=100_000,
    max_imports=10_000,
    max_import_refs=50_000,
    max_strings=20_000,
    max_string_refs=50_000,
    max_decompiled=300,
    max_code_bytes=64 * 1024,
    max_code_total_bytes=32 * 1024**2,
    max_findings=2_000,
    max_iocs=10_000,
    max_result_bytes=256 * 1024**2,
    max_work_bytes=2 * 1024**3,
)


def pe_header(
    *,
    machine: int = 0x8664,
    pe32_plus: bool = True,
    image_base: int = 0x140000000,
    clr: bool = False,
    marker: str | None = None,
) -> bytes:
    data = bytearray(1024)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    opt_size = 240 if pe32_plus else 224
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, opt_size, 0x22)
    opt = 0x98
    if pe32_plus:
        struct.pack_into("<H", data, opt, 0x20B)
        struct.pack_into("<Q", data, opt + 24, image_base)
        count_off, dirs = opt + 108, opt + 112
    else:
        struct.pack_into("<H", data, opt, 0x10B)
        struct.pack_into("<I", data, opt + 28, image_base)
        count_off, dirs = opt + 92, opt + 96
    struct.pack_into("<I", data, count_off, 16)
    if clr:
        struct.pack_into("<II", data, dirs + 14 * 8, 0x2008, 0x48)
    if marker:
        line = f"CYBERLAB-REPLAY {marker}\n".encode()
        data[0x300 : 0x300 + len(line)] = line
    return bytes(data)


def elf_header(
    *,
    machine: int = 62,
    elf64: bool = True,
    e_type: int = 3,
    big_endian: bool = False,
    loads: tuple[int, ...] = (0x0, 0x1000),
    marker: str | None = None,
) -> bytes:
    data = bytearray(1024)
    data[0:4] = b"\x7fELF"
    data[4] = 2 if elf64 else 1
    data[5] = 2 if big_endian else 1
    data[6] = 1
    order = ">" if big_endian else "<"
    struct.pack_into(f"{order}HH", data, 16, e_type, machine)
    if elf64:
        phoff, phentsize = 64, 56
        struct.pack_into(f"{order}Q", data, 32, phoff)
        struct.pack_into(f"{order}HH", data, 54, phentsize, len(loads))
        for i, vaddr in enumerate(loads):
            struct.pack_into(f"{order}IIQQ", data, phoff + i * phentsize, 1, 5, 0, vaddr)
    else:
        phoff, phentsize = 52, 32
        struct.pack_into(f"{order}I", data, 28, phoff)
        struct.pack_into(f"{order}HH", data, 42, phentsize, len(loads))
        for i, vaddr in enumerate(loads):
            struct.pack_into(f"{order}IIII", data, phoff + i * phentsize, 1, 0, vaddr, vaddr)
    if marker:
        line = f"CYBERLAB-REPLAY {marker}\n".encode()
        data[0x300 : 0x300 + len(line)] = line
    return bytes(data)


def job(
    *,
    profile: str = "full",
    file_format: str = "pe",
    decompile: tuple[int, ...] = (),
    size: int = 1024,
    limits: ReLimits = LIMITS,
) -> ReJobV1:
    return ReJobV1.model_validate(
        {
            "job_id": str(uuid.uuid4()),
            "organization_id": str(uuid.uuid4()),
            "evidence_id": str(uuid.uuid4()),
            "source_job_id": str(uuid.uuid4()),
            "expected_sha256": SHA,
            "size_bytes": size,
            "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=t",
            "result_post": {"url": "http://minio:9000/results", "fields": {"key": "k"}},
            "ingest_token": "t" * 43,
            "profile": profile,
            "file_format": file_format,
            "decompile_addresses": list(decompile),
            "limits": limits.model_dump(),
        }
    )


def rows(case: str, stage: str) -> list[dict[str, Any]]:
    text = (STAGE_ROWS / case / f"{stage}.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def decompiled_entries(case: str = "pe_full") -> tuple[int, ...]:
    return tuple(int(r["function_entry"]) for r in rows(case, "decompile"))
