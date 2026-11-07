"""M10 phase 12: reverse engineering end to end on the real workers (default lane only).

Skipped unless `RE_PIPELINE_SAMPLES` names the generated phase-4 set (`pnpm re:gen`; the gate
mounts the `cyberlab_e2e_samples` volume read-only and sets it). The real `static-worker-test`
runs the automatic static `full` job (capa locations included), the real `re-worker-test`
runs Ghidra offline (`full`) and radare2 (`quick`), and every report goes through the real
ingest handler. Nothing here executes a sample: the builds are benign C programs compiled by
the RE worker's dev image, analyzed as data.

- `m3_injector` (win64, -O0, stripped): every read route, the capability -> function join on
  the real capa and Ghidra outputs, the never-executed / offline header proof, the
  `explain_function` context and verifier over the real rows (offline, no provider), the
  platform-wide heavy cap while the job is active (RT2), then "Decompile this function" on a
  function the first job did not decompile, and the old job's link to the newer one (RT10);
- the same build through `quick` (radare2, no decompilation);
- `elf_net` PIE and non-PIE: the real-engine proof of the file-VA join (RT8).
"""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.ai.context import builder
from app.modules.ai.contracts import AiRunRequest, AiTask, CitationStatus, ClaimStatus
from app.modules.ai.models import AiOrgSettings
from app.modules.ai.verify import verify_output
from app.modules.analysis import repository as analysis_repo
from tests import re_pipeline_helpers as rp
from tests.ai_helpers import seed_ai_settings
from tests.analysis_helpers import new_case, upload
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant

pytestmark = rp.requires_samples

INJECTOR = "m3_injector_win64_O0_stripped"
ELF_BUILDS = ["elf_net_linux_O0_stripped", "elf_net_linux_nopie_O0_stripped"]
CANARY = "cnry-re-pipeline-0123456789"
DECOMPILED = {"ok", "truncated"}


@pytest.fixture(autouse=True)
def _clean_queues() -> Iterator[None]:
    rp.purge_re_queues()
    yield
    rp.purge_re_queues()


@pytest.fixture
def small_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """A few decompiled functions per job, so some stay undecompiled (RT10)."""
    monkeypatch.setattr(get_settings(), "re_max_decompiled", rp.SMALL_BUDGET)


def _hex(value: int) -> str:
    return f"0x{value:x}"


async def _heavy_cap_refuses_while_active(
    reg: Registered, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RT2: with the cap at the current platform-wide count (this RE job included), a
    memory request on another upload is refused without naming any other job."""
    async with tenant_session(reg.org_id, reg.user_id) as session:
        active = await analysis_repo.count_heavy_active(session)
    assert active >= 1
    settings = get_settings()
    original = settings.analysis_heavy_max_active
    monkeypatch.setattr(settings, "analysis_heavy_max_active", active)
    try:
        other = await upload(
            reg.client, reg.org_id, await new_case(reg), b"\0" * 4096, "memory-busy.bin"
        )
        response = await reg.client.post(
            f"/api/v1/orgs/{reg.org_id}/evidence/{other['id']}/analyses",
            json={"analyzer": "memory"},
            headers=csrf(reg.client),
        )
    finally:
        monkeypatch.setattr(settings, "analysis_heavy_max_active", original)
    assert response.status_code == 429, response.text
    error = response.json()["error"]
    assert (error["code"], error["reason"]) == ("too_many_active_jobs", "heavy_analysis_busy")


async def _explain_verifies(reg: Registered, job_id: str, function_id: str, code: str) -> None:
    """`explain_function` over the real rows: G1 / Q1 first, a quote of the real code is
    verified, a citation of a label that was never sent is not (offline: no provider)."""
    case_id = uuid.UUID(await new_case(reg))
    t = Tenant(reg.org_id, reg.user_id, case_id)
    await seed_ai_settings(t)
    async with tenant_session(reg.org_id, reg.user_id) as s:
        row = await s.scalar(
            select(AiOrgSettings).where(AiOrgSettings.organization_id == reg.org_id)
        )
        assert row is not None
        req = AiRunRequest(
            task=AiTask.EXPLAIN_FUNCTION,
            job_id=uuid.UUID(job_id),
            target_id=uuid.UUID(function_id),
        )
        ctx = (await builder.build_run(s, reg.org_id, reg.user_id, req, row)).root
    assert [i.label for i in ctx.items][:2] == ["G1", "Q1"], [i.label for i in ctx.items]
    sent = str(ctx.items[1].fields["code"])
    # A short line of the code as the transforms sent it (literals may be cut / defanged).
    quote = next(
        (line.strip() for line in sent.splitlines() if 12 <= len(line.strip()) <= 80),
        sent.strip()[:40],
    )
    parsed: dict[str, Any] = {
        "observed": [
            {
                "id": "a",
                "text": "The decompiled code of the function contains this statement.",
                "confidence": "medium",
                "citations": [{"ref": "Q1", "field": "code", "quote": quote}],
            },
            {
                "id": "b",
                "text": "Another function's code was never sent.",
                "confidence": "high",
                "citations": [{"ref": "Q9", "field": "code", "quote": "WriteFile(h,buf,n)"}],
            },
        ],
        "overall_confidence": {"level": "medium", "rationale": "Code only."},
    }
    async with tenant_session(reg.org_id, reg.user_id) as s:
        verified = await verify_output(s, reg.org_id, ctx.scope, ctx, ctx.refs, parsed, CANARY)
    by_label = {c.label: c for c in verified.citations}
    assert by_label["Q1"].status is CitationStatus.VERIFIED, by_label["Q1"]
    assert by_label["Q9"].status is CitationStatus.INVALID
    assert verified.claims["O1"].status is ClaimStatus.SUPPORTED
    assert verified.claims["O2"].status is ClaimStatus.UNSUPPORTED
    assert code  # the stored code is what the context was built from


async def test_injector_full_end_to_end_then_decompile_this_function(
    monkeypatch: pytest.MonkeyPatch, small_budget: None
) -> None:
    content, label = rp.sample(INJECTOR)
    reg = await register(org_name=f"RE pipeline {uuid.uuid4().hex[:6]}")
    evidence_id, static_job = await rp.static_job(reg, content, "injector.exe")

    first = await rp.request_re(reg, evidence_id, profile="full")
    assert first["source_job_id"] == static_job and first["status"] == "queued"
    await _heavy_cap_refuses_while_active(reg, monkeypatch)
    job = await rp.finish(reg, evidence_id, first["id"])
    assert job["status"] == "succeeded", job

    header = rp.result_header(reg.org_id, first["id"])
    assert (header.engine, header.code_kind, header.profile) == ("ghidra", "pseudo_c", "full")
    assert {s.stage: s.status for s in header.stages} == {"analyze": "ok", "decompile": "ok"}
    rp.assert_never_executed_offline(header)

    base = f"/analyses/{first['id']}/reverse"
    summary = await rp.get(reg, base)
    assert (summary["format"], summary["arch"], summary["engine"]) == ("pe", "x86_64", "ghidra")
    assert summary["source_job_id"] == static_job and summary["newer_job_id"] is None
    assert summary["preferred_base"] == summary["image_base"]  # a PE loads at ImageBase
    assert summary["counts"].get("functions", 0) > 0, summary["counts"]

    # The injection function at its compiler-truth address (stripped: a generated name).
    entry = rp.hex_int(summary["preferred_base"]) + rp.truth_rva(label, "inject")
    functions = await rp.all_functions(reg, first["id"])
    by_entry = {rp.hex_int(f["entry"]): f for f in functions}
    inject = by_entry[entry]
    assert inject["decompile_status"] in DECOMPILED, inject
    assert inject["capabilities"] >= 1, inject

    detail = await rp.get(reg, f"{base}/functions/{_hex(entry)}")
    assert detail["callers"], detail  # main calls it
    imported = {i["name"] for i in detail["imports"]}
    assert imported & {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, imported
    assert detail["capabilities"], detail
    assert detail["finding_ids"], "the per-function API-set heuristic cites this function"

    code = await rp.get(reg, f"{base}/functions/{_hex(entry)}/code")
    assert code["code_kind"] == "pseudo_c" and code["code_sha256"]
    assert "VirtualAllocEx" in code["code"] or "WriteProcessMemory" in code["code"], code
    imports = await rp.get(reg, f"{base}/imports", q="VirtualAllocEx")
    assert any(i["library"].lower() == "kernel32.dll" for i in imports["items"]), imports
    strings = await rp.get(reg, f"{base}/strings", q="CyberLab capa fixture")
    assert strings["items"] and strings["items"][0]["function_count"] >= 1, strings

    # Capabilities of the static job link to the injection function (real capa, real Ghidra).
    caps = await rp.get(reg, f"/analyses/{static_job}/capabilities", limit=100)
    linked: set[int] = set()
    for cap in caps["items"]:
        if not cap["functions"]:
            continue
        found = await rp.get(reg, f"/analyses/{static_job}/capabilities/{cap['id']}/functions")
        assert found["re_job_id"] == first["id"]
        linked |= {rp.hex_int(f["function"]["entry"]) for f in found["functions"]}
    assert entry in linked, (sorted(linked), entry)

    await _explain_verifies(reg, first["id"], inject["id"], code["code"])

    # RT10: "Decompile this function" on one the first job did not decompile.
    candidates = [
        f
        for f in functions
        if f["decompile_status"] == "not_selected" and not f["is_thunk"] and not f["is_external"]
    ]
    assert candidates, "the small budget leaves undecompiled functions"
    wanted = min(candidates, key=lambda f: (f["is_library"], rp.hex_int(f["entry"])))
    second = await rp.request_re(
        reg, evidence_id, profile="full", decompile_addresses=[wanted["entry"]]
    )
    job = await rp.finish(reg, evidence_id, second["id"])
    assert job["status"] == "succeeded", job
    rp.assert_never_executed_offline(rp.result_header(reg.org_id, second["id"]))
    newer = await rp.get(reg, f"/analyses/{second['id']}/reverse/functions/{wanted['entry']}")
    assert newer["function"]["decompile_status"] in DECOMPILED, newer["function"]
    assert newer["function"]["priority_reason"] == "requested"
    newer_summary = await rp.get(reg, f"/analyses/{second['id']}/reverse")
    assert newer_summary["decompile_addresses"] == [wanted["entry"]]
    old_summary = await rp.get(reg, base)
    assert old_summary["newer_job_id"] == second["id"]


async def test_quick_profile_runs_radare2_without_decompilation() -> None:
    content, label = rp.sample(INJECTOR)
    reg = await register(org_name=f"RE quick {uuid.uuid4().hex[:6]}")
    evidence_id, static_job = await rp.static_job(reg, content, "injector.exe")
    job = await rp.request_re(reg, evidence_id, profile="quick")
    done = await rp.finish(reg, evidence_id, job["id"])
    assert done["status"] == "succeeded", done

    header = rp.result_header(reg.org_id, job["id"])
    assert (header.engine, header.code_kind) == ("radare2", "disasm")
    assert [s.stage for s in header.stages] == ["r2"] and not header.jvm_args
    rp.assert_never_executed_offline(header)

    base = f"/analyses/{job['id']}/reverse"
    summary = await rp.get(reg, base)
    assert summary["engine"] == "radare2" and summary["source_job_id"] == static_job
    functions = await rp.all_functions(reg, job["id"])
    assert functions and all(f["decompile_status"] == "not_selected" for f in functions)
    entry = rp.hex_int(summary["preferred_base"]) + rp.truth_rva(label, "inject")
    response = await reg.client.get(
        f"/api/v1/orgs/{reg.org_id}{base}/functions/{_hex(entry)}/code"
    )
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] in {"code_not_available", "function_not_found"}


@pytest.mark.parametrize("build", ELF_BUILDS, ids=["pie", "non-pie"])
async def test_elf_capabilities_link_on_file_virtual_addresses(build: str) -> None:
    """RT8: Ghidra rebases a PIE (its image base differs from the file's preferred base);
    capa's locations still land in the compiler-truth function through the file-VA join."""
    content, label = rp.sample(build)
    reg = await register(org_name=f"RE ELF {uuid.uuid4().hex[:6]}")
    evidence_id, static_job = await rp.static_job(reg, content, f"{build}.elf")
    job = await rp.request_re(reg, evidence_id, profile="full")
    done = await rp.finish(reg, evidence_id, job["id"])
    assert done["status"] == "succeeded", done
    rp.assert_never_executed_offline(rp.result_header(reg.org_id, job["id"]))

    base = f"/analyses/{job['id']}/reverse"
    summary = await rp.get(reg, base)
    assert summary["format"] == "elf" and summary["arch"] == "x86_64"
    if label["pie"]:
        assert rp.hex_int(summary["preferred_base"]) == 0
    else:
        assert rp.hex_int(summary["preferred_base"]) >= 0x400000

    caps = await rp.get(reg, f"/analyses/{static_job}/capabilities", limit=100)
    located = [c for c in caps["items"] if c["locations"]]
    assert located, "capa reported no located capability for the ELF build"
    want = rp.truth_rva(label, "open_channel")
    rvas: set[int] = set()
    for cap in located:
        found = await rp.get(reg, f"/analyses/{static_job}/capabilities/{cap['id']}/functions")
        for ref in found["functions"]:
            detail = await rp.get(reg, f"{base}/functions/{ref['function']['entry']}")
            rvas.add(rp.hex_int(detail["function"]["rva"]))
    assert want in rvas, (sorted(rvas), want)
    assert summary["counts"].get("capa_linked", 0) >= 1, summary["counts"]
