"""M10 phase 12: helpers of the RE pipeline tests on the real workers.

The pipeline tests upload phase-4 builds (`pnpm re:gen`: benign C programs compiled by the
RE worker's dev image, never executed) from `RE_PIPELINE_SAMPLES` (the generated set, e.g.
`/samples/re` with the `cyberlab_e2e_samples` volume mounted read-only), let the real
`static-worker-test` run its automatic static `full` job, request RE jobs that the real
`re-worker-test` runs (Ghidra offline, radare2 for `quick`), and feed every report to the
real ingest handler. Two inputs are built here instead, in memory and never runnable: an
ARM ELF (refused at request time) and a PE carrying a CLR directory without an `mscoree`
import (the worker's diagnostic).
"""

import gzip
import json
import os
import struct
import uuid
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.reverse import ReResultHeader

from app.core.clients import get_minio
from app.core.config import get_settings
from app.modules.analysis import dispatch
from tests.analysis_helpers import (
    _connection,
    broker_queue,
    jobs_for,
    new_case,
    purge_test_queues,
    run_ingest_until,
    upload,
)
from tests.factories import Registered, csrf

FINAL = {"succeeded", "failed"}
# ClamAV, capa and FLOSS on a small mingw build (the M3 pipeline uses 300 s for a stub).
STATIC_TIMEOUT_S = 600.0
# One Ghidra `full` job: two JVM starts, auto-analysis and decompilation of a small build;
# far below the job deadline (ANALYSIS_RE_TIMEOUT_S 3600) on the 2-CPU test worker.
RE_TIMEOUT_S = 1800.0
# A small decompile budget, so a build of a few hundred functions keeps some functions
# undecompiled for the "Decompile this function" run (RT10).
SMALL_BUDGET = 8


def samples_dir() -> Path | None:
    raw = os.environ.get("RE_PIPELINE_SAMPLES", "")
    path = Path(raw) if raw else None
    return path if path is not None and (path / "labels.json").is_file() else None


requires_samples = pytest.mark.skipif(
    samples_dir() is None,
    reason="RE_PIPELINE_SAMPLES does not name the generated phase-4 set (pnpm re:gen)",
)


def labels() -> dict[str, Any]:
    directory = samples_dir()
    assert directory is not None
    data: dict[str, Any] = json.loads((directory / "labels.json").read_text(encoding="utf-8"))
    return data


def sample(name: str) -> tuple[bytes, dict[str, Any]]:
    """The build's bytes and its label; skips when the generator recorded it as skipped."""
    all_labels = labels()
    if name not in all_labels:
        reason = all_labels.get("_skipped", {}).get(name.removesuffix("_stripped"), "absent")
        pytest.skip(f"{name} was not generated: {reason}")
    label = all_labels[name]
    directory = samples_dir()
    assert directory is not None
    return (directory / label["file"]).read_bytes(), label


def truth_rva(label: dict[str, Any], function: str) -> int:
    """The compiler-truth RVA (from the file's preferred base) of a named function."""
    directory = samples_dir()
    assert directory is not None
    truth = json.loads((directory / label["truth"]).read_text(encoding="utf-8"))
    [rva] = [f["rva"] for f in truth["functions"] if f["name"] == function]
    return int(rva)


def hex_int(value: str) -> int:
    return int(value, 16)


def purge_re_queues() -> None:
    """The shared test queues and `test.reverse` (left over jobs of an aborted run)."""
    purge_test_queues()
    with _connection() as conn:
        conn.default_channel.client.delete(broker_queue("reverse"))


async def static_job(reg: Registered, content: bytes, filename: str) -> tuple[str, str]:
    """Upload, then wait for the automatic static `full` job. Returns (evidence, job)."""
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), content, filename)
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert (job["analyzer"], job["profile"]) == ("static", "full"), job
    seen = await run_ingest_until(job["id"], FINAL, timeout_s=STATIC_TIMEOUT_S)
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert job["status"] == "succeeded", seen
    return str(evidence["id"]), str(job["id"])


async def request_re(reg: Registered, evidence_id: str, **body: Any) -> dict[str, Any]:
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "reverse", **body},
        headers=csrf(reg.client),
    )
    assert response.status_code == 201, response.text
    job: dict[str, Any] = response.json()
    assert job["analyzer"] == "reverse"
    return job


async def finish(reg: Registered, evidence_id: str, job_id: str) -> dict[str, Any]:
    """Run the ingest until the RE job is final; returns its job row."""
    seen = await run_ingest_until(job_id, FINAL, timeout_s=RE_TIMEOUT_S)
    [job] = [j for j in await jobs_for(reg.client, reg.org_id, evidence_id) if j["id"] == job_id]
    assert job["status"] in FINAL, seen
    return dict(job)


async def get(reg: Registered, path: str, **params: Any) -> Any:
    response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}{path}", params=params)
    assert response.status_code == 200, f"{path}: {response.status_code} {response.text}"
    return response.json()


async def all_functions(reg: Registered, job_id: str, **params: Any) -> list[dict[str, Any]]:
    """Every function of a job (offset pages of 100, library functions included)."""
    out: list[dict[str, Any]] = []
    while True:
        page = await get(
            reg,
            f"/analyses/{job_id}/reverse/functions",
            limit=100,
            offset=len(out),
            include_library="true",
            **params,
        )
        out.extend(page["items"])
        if not page["items"] or len(out) >= page["total"]:
            return out


def result_header(org_id: object, job_id: str) -> ReResultHeader:
    key = dispatch.result_key(uuid.UUID(str(org_id)), uuid.UUID(job_id))
    response = get_minio().get_object(get_settings().results_bucket, key)
    try:
        first = gzip.decompress(response.read()).split(b"\n", 1)[0]
    finally:
        response.close()
        response.release_conn()
    return ReResultHeader.model_validate_json(first)


def assert_never_executed_offline(header: ReResultHeader) -> None:
    """The in-pipeline proof of a real run: no audit-hook refusal after the JVM start, and
    the effective JVM arguments carry our hardening and no agent (root compared the whole
    list with the expected one, RT1; a mismatch would have failed the job
    `jvm_start_failed`). Unexpected decompile children (RT15) fail the job as well, so a
    succeeded job also proves none was recorded (detection, not prevention)."""
    assert all(count == 0 for count in header.audit.values()), header.audit
    if header.engine == "ghidra":
        assert "-XX:+DisableAttachMechanism" in header.jvm_args, header.jvm_args
        agents = ("-agentlib", "-agentpath", "-javaagent", "-Xrunjdwp", "-Xdebug")
        assert not [a for a in header.jvm_args if a.startswith(agents)], header.jvm_args


# --- inputs built here (never runnable) --------------------------------------------------------


def arm_elf() -> bytes:
    """A 32-bit little-endian ARM ELF executable: one PT_LOAD, `.text` (`mov r0, #0; bx lr`)
    and `.shstrtab`. A valid header for the static worker, refused by the RE request (x86 /
    x86-64 only)."""
    text = struct.pack("<II", 0xE3A00000, 0xE12FFF1E)
    names = b"\0.text\0.shstrtab\0"
    text_off = 52 + 32
    names_off = text_off + len(text)
    sh_off = (names_off + len(names) + 3) & ~3
    total = sh_off + 3 * 40
    base = 0x10000
    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2,  # ET_EXEC
        40,  # EM_ARM
        1,
        base + text_off,  # entry
        52,  # program headers
        sh_off,
        0x05000200,  # EABI5, soft float
        52,
        32,
        1,
        40,
        3,
        2,  # .shstrtab
    )
    phdr = struct.pack("<IIIIIIII", 1, 0, base, base, total, total, 5, 0x1000)
    sections = b"\0" * 40
    shdr = "<IIIIIIIIII"
    sections += struct.pack(shdr, 1, 1, 6, base + text_off, text_off, len(text), 0, 0, 4, 0)
    sections += struct.pack(shdr, 7, 3, 0, 0, names_off, len(names), 0, 0, 1, 0)
    data = header + phdr + text + names
    data += b"\0" * (sh_off - len(data)) + sections
    assert len(data) == total
    return data


def clr_pe() -> bytes:
    """A PE32+ (amd64) whose CLR data directory (index 14) points at a 72-byte CLR header in
    `.text`, with no import directory at all (so no `mscoree.dll` import): the API's managed
    check passes it and the worker's magic check ends it as `unsupported_managed_code`."""
    e_lfanew = 0x40
    file_align, section_align = 0x200, 0x1000
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    coff = e_lfanew + 4
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, 240, 0x0022)
    opt = coff + 20
    struct.pack_into(
        "<HBBIIIII",
        data,
        opt,
        0x20B,  # PE32+
        14,
        0,
        file_align,  # SizeOfCode
        0,
        0,
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
    )
    struct.pack_into(
        "<QIIHHHHHHIIIIHHQQQQII",
        data,
        opt + 24,
        0x140000000,  # ImageBase
        section_align,
        file_align,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,  # SizeOfImage
        0x200,  # SizeOfHeaders
        0,
        3,  # console
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,  # NumberOfRvaAndSizes
    )
    dirs = opt + 24 + 88
    struct.pack_into("<II", data, dirs + 14 * 8, 0x1010, 72)  # CLR runtime header
    section = opt + 240
    text = (b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", data, section, *text)
    data[0x200] = 0xC3  # ret
    struct.pack_into("<IHH", data, 0x210, 72, 2, 5)  # cb, runtime 2.5; metadata left empty
    struct.pack_into("<I", data, 0x210 + 16, 1)  # COMIMAGE_FLAGS_ILONLY
    return bytes(data)
