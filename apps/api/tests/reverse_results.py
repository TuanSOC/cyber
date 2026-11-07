"""M10 phase 7 test helpers: a source static job through the real static ingest, an RE
request, and `re.v1` result streams retargeted from the phase-1 fixtures.

The fixtures (`packages/py-jobs/tests/fixtures/reverse/`, hand-written, labelled synthetic)
carry fixed job ids and a placeholder program identity (`e` * 64, 48 640 bytes); `lines()`
reads one without its trailer and retargets it to a job and its evidence record, so tests
can splice in hostile lines; `pcap_results.encode()` appends a matching trailer and gzips.
"""

import json
import uuid
from typing import Any

from cyberlab_jobs.static import (
    CapabilityRecord,
    ElfInfo,
    ImportRecord,
    PeInfo,
    SectionRecord,
)
from httpx import Response
from pydantic import BaseModel

from tests import pcap_results as pr
from tests import static_results as sr
from tests.analysis_helpers import SentJobs, new_case, pe_bytes, upload
from tests.factories import Registered, csrf
from tests.reverse_helpers import FIXTURES

WORKER = "re-worker/test"
PE = "pe_full.ndjson"
ELF = "elf_full.ndjson"
QUICK = "quick.ndjson"
DIAGNOSTIC = "unsupported_arch.ndjson"
CAPA_BASE = 0x140000000
# pe_full: inject_remote [0x1400011e0, 0x140001320), resolve_apis [0x140001320, 0x140001440).
INJECT_REMOTE = 0x1400011E0
RESOLVE_APIS = 0x140001320
LOCATIONS = {
    "inject thread": [0x140001280, 0x1400012A0],
    "link function at runtime on Windows": [0x140001400],
    "connect to URL": [],
    "write file outside any function": [0x140009000],
}


def elf_bytes() -> bytes:
    """An ELF64 header (ET_EXEC, x86-64) and zeros: never a runnable program."""
    data = bytearray(256)
    data[0:7] = b"\x7fELF\x02\x01\x01"
    data[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
    data[18:20] = (62).to_bytes(2, "little")  # EM_X86_64
    return bytes(data)


def pe_info(**fields: Any) -> PeInfo:
    return sr.pe(machine="amd64", image_base=CAPA_BASE, **fields)


def elf_info(**fields: Any) -> ElfInfo:
    values: dict[str, Any] = {
        "elf_class": 64,
        "machine": "EM_X86_64",
        "elf_type": "ET_EXEC",
        "entry_point": 0x401040,
        "stripped": False,
        **fields,
    }
    return ElfInfo.model_validate(values)


def capabilities(locations: dict[str, list[int]] = LOCATIONS) -> list[CapabilityRecord]:
    return [
        CapabilityRecord(name=name, namespace="test/re", matches=max(1, len(locs)), locations=locs)
        for name, locs in locations.items()
    ]


async def static_source(
    sent: SentJobs,
    reg: Registered,
    *,
    content: bytes | None = None,
    filename: str = "sample.exe",
    info: BaseModel | None = None,
    records: list[BaseModel] | None = None,
    capa_base: int | None = CAPA_BASE,
    case_id: str | None = None,
) -> tuple[str, uuid.UUID]:
    """Upload a PE (default) and finish its automatic static `full` job through the real
    static ingest with `info` (PE / ELF facts), capabilities with locations and the capa
    base. Returns (evidence id, static job id)."""
    content = pe_bytes() if content is None else content
    case_id = case_id or await new_case(reg)
    evidence = await upload(reg.client, reg.org_id, case_id, content, filename)
    item = sent[-1]
    assert item.analyzer == "static" and item.profile == "full", item
    info = pe_info() if info is None else info
    fmt = "elf" if isinstance(info, ElfInfo) else "pe"
    body = [info, *(capabilities() if records is None else records)]
    header: dict[str, Any] = {"file_format": fmt}
    if capa_base is not None:
        header["capa_base_address"] = capa_base
    raw = sr.lines(item.job_id, sr.sample_for(content), body, with_pe=False, **header)
    await pr.deliver(item, pr.encode(raw))
    return str(evidence["id"]), item.job_id


def managed_imports() -> list[BaseModel]:
    return [ImportRecord(library="MSCOREE.dll", function="_CorExeMain"), *capabilities()]


def elf_sections() -> list[BaseModel]:
    """A classic x86-64 executable: the first allocated section just above 0x400000."""
    return [
        SectionRecord(index=1, name=".interp", virtual_address=0x400318, virtual_size=28,
                      raw_size=28, entropy=3.0, flags=["alloc"]),  # fmt: skip
        SectionRecord(index=2, name=".text", virtual_address=0x401000, virtual_size=0x800,
                      raw_size=0x800, entropy=6.0, flags=["alloc", "execute"]),  # fmt: skip
        SectionRecord(index=3, name=".comment", virtual_address=0, virtual_size=16,
                      raw_size=16, entropy=2.0, flags=[]),  # fmt: skip
    ]


async def request_re(reg: Registered, evidence_id: str, **body: Any) -> Response:
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "reverse", **body},
        headers=csrf(reg.client),
    )


# --- re.v1 streams ---------------------------------------------------------------------------


def parsed(name: str = PE) -> list[dict[str, Any]]:
    """The fixture's lines as dicts, trailer dropped."""
    objs = [json.loads(line) for line in (FIXTURES / name).read_bytes().splitlines()]
    assert objs[-1]["kind"] == "trailer"
    return objs[:-1]


def retarget(
    objs: list[dict[str, Any]], job_id: uuid.UUID | str, *, size: int, sha256: str
) -> list[dict[str, Any]]:
    out = []
    for obj in objs:
        obj = dict(obj)
        if obj["kind"] == "header":
            obj["job_id"] = str(job_id)
        elif obj["kind"] == "program":
            obj["size_bytes"], obj["sha256"] = size, sha256
        out.append(obj)
    return out


def dumps(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode() + b"\n"


def lines(job_id: uuid.UUID | str, *, size: int, sha256: str, name: str = PE) -> list[bytes]:
    return [dumps(o) for o in retarget(parsed(name), job_id, size=size, sha256=sha256)]


def encode(objs: list[dict[str, Any]]) -> bytes:
    return pr.encode([dumps(o) for o in objs])


def stream(job_id: uuid.UUID | str, *, size: int, sha256: str, name: str = PE) -> bytes:
    return pr.encode(lines(job_id, size=size, sha256=sha256, name=name))


def fixture_counts(name: str = PE) -> dict[str, int]:
    """Lines per record kind of a fixture (no header, program or trailer)."""
    counts: dict[str, int] = {}
    for obj in parsed(name)[2:]:
        counts[obj["kind"]] = counts.get(obj["kind"], 0) + 1
    return counts

