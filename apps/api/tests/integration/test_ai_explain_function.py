"""`explain_function` over a seeded reverse-engineering job (M10 phase 9).

The real selector, builder and verifier over the phase-1 `pe_full` fixture rows
(`reverse_helpers.seed_re_job`), plus what the seed helper leaves out: the RE findings and
IOCs and the capa capability links (`re_function_capabilities`). Proves the context order
(G first, Q second), determinism (same DB, same `context_sha256`), the task rules (reverse
job only, the target must be a function of that job), the scope (the source static job's
capability rows are citable), the verifier over G / Q rows, and that an incident's digest of
a reverse job never carries functions or code.
"""

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.ai.context import builder
from app.modules.ai.contracts import (
    AiRunRequest,
    AiTask,
    CitationReason,
    CitationStatus,
    ClaimStatus,
    ContextBuildError,
    FrozenContext,
    RefKind,
)
from app.modules.ai.models import AiOrgSettings
from app.modules.ai.verify import verify_output
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc
from app.modules.reverse_engineering.models import ReFunction, ReFunctionCapability
from app.modules.static_analysis.models import MalwareCapability
from tests.ai_helpers import seed_ai_settings
from tests.analysis_helpers import new_case
from tests.factories import register
from tests.integration.seed import Tenant
from tests.reverse_helpers import seed_re_job, seed_static_source_job

INJECT_REMOTE = 0x1400011E0
BEACON = 0x140001440
DECODE_CONFIG = 0x140001610
CANARY = "cnry-5e6f708192a3b4c5d6"


async def _tenant(name: str) -> Tenant:
    owner = await register(org_name=name)
    case_id = uuid.UUID(await new_case(owner))
    t = Tenant(owner.org_id, owner.user_id, case_id)
    await seed_ai_settings(t)
    return t


async def _settings(t: Tenant) -> AiOrgSettings:
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.scalar(select(AiOrgSettings).where(AiOrgSettings.organization_id == t.org_id))
    assert row is not None
    return row


async def _seed_links_and_findings(t: Tenant, re_job: uuid.UUID, static_job: uuid.UUID) -> None:
    """What phase 7's ingest writes besides the fixture rows: the capa links (RT8), one
    finding per located function and the IOCs of the referenced strings."""
    ts = datetime(2026, 11, 1, 8, 0, tzinfo=UTC)
    async with tenant_session(t.org_id, t.owner_id) as s:
        caps = {
            c.name: c
            for c in await s.scalars(
                select(MalwareCapability).where(MalwareCapability.job_id == static_job)
            )
        }
        common: dict[str, Any] = {"organization_id": t.org_id, "job_id": re_job}
        s.add(
            ReFunctionCapability(
                **common,
                function_entry=Decimal(INJECT_REMOTE),
                capability_id=caps["inject thread"].id,
                file_va=Decimal(0x140001280),
            )
        )
        s.add(
            AnalysisFinding(
                **common,
                ts=ts,
                finding_id=uuid.uuid4(),
                type="api_injection",
                title="Remote memory allocation, write and thread creation in one function",
                description="Static observation of the decompiled program; not a verdict.",
                severity="medium",
                confidence=0.6,
                detection_method="heuristic:re_api_set_function@1",
                evidence_refs=[f"function:{INJECT_REMOTE:#x}"],
                attributes={"function_entry": f"{INJECT_REMOTE:#x}", "api_set": "api_injection"},
            )
        )
        for kind, value in (("url", "http://203.0.113.10/gate.php"), ("ip", "203.0.113.10")):
            s.add(
                Ioc(
                    **common,
                    type=kind,
                    value=value,
                    first_seen=ts,
                    last_seen=ts,
                    count=1,
                    source="re_string",
                )
            )


async def _function_id(t: Tenant, job: uuid.UUID, entry: int) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        found = await s.scalar(
            select(ReFunction.id).where(ReFunction.job_id == job, ReFunction.entry == entry)
        )
    assert found is not None
    return found


async def _build(t: Tenant, req: AiRunRequest) -> FrozenContext:
    row = await _settings(t)
    async with tenant_session(t.org_id, t.owner_id) as s:
        return (await builder.build_run(s, t.org_id, t.owner_id, req, row)).root


async def _seeded() -> tuple[Tenant, uuid.UUID, uuid.UUID]:
    t = await _tenant(f"RE AI {uuid.uuid4().hex[:6]}")
    static_job = await seed_static_source_job(t)
    re_job = await seed_re_job(t, static_job)
    await _seed_links_and_findings(t, re_job, static_job)
    return t, re_job, static_job


async def test_the_context_is_deterministic_with_the_target_first_and_its_code_second() -> None:
    t, re_job, static_job = await _seeded()
    target = await _function_id(t, re_job, INJECT_REMOTE)
    req = AiRunRequest(task=AiTask.EXPLAIN_FUNCTION, job_id=re_job, target_id=target)
    first = await _build(t, req)
    second = await _build(t, req)
    assert first.sha256 == second.sha256
    labels = [i.label for i in first.items]
    assert labels[:3] == ["G1", "Q1", "J1"]
    assert first.refs[0].ref_table == "re_functions" and first.refs[0].ref_id == str(target)
    assert first.refs[1].ref_table == "re_decompilations"
    g1, q1, j1 = first.items[:3]
    assert g1.fields["name"] == "inject_remote" and g1.fields["entry"] == "0x1400011e0"
    assert g1.fields["capabilities.01"] == "inject thread"
    assert "VirtualAllocEx" in str(q1.fields["code"])
    assert j1.fields["engine"] == "replay" and j1.fields["arch"] == "x86_64"
    c1 = next(r for r in first.refs if r.label == "C1")
    assert c1.job_id == static_job  # the capability is a row of the source static job
    assert first.scope.job_ids == (re_job, static_job)
    assert any(r.label == "F1" for r in first.refs)
    # Callee facts only: one Q item, the target's.
    assert [i.label for i in first.items if i.kind is RefKind.CODE] == ["Q1"]
    assert {i.fields["name"] for i in first.items[3:] if i.kind is RefKind.FUNCTION} >= {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    }


async def test_a_function_without_code_gets_the_limitation_and_its_iocs() -> None:
    t, re_job, _ = await _seeded()
    target = await _function_id(t, re_job, BEACON)  # decompile timeout in the fixture
    req = AiRunRequest(task=AiTask.EXPLAIN_FUNCTION, job_id=re_job, target_id=target)
    ctx = await _build(t, req)
    assert not any(i.kind is RefKind.CODE for i in ctx.items)
    note = str(ctx.items[0].fields["code_note"])
    assert note.startswith("not decompiled (timeout)") and "Decompile this function" in note
    iocs = [i for i in ctx.items if i.kind is RefKind.IOC]
    assert {i.fields["type"] for i in iocs} == {"url", "ip"}


async def test_task_rules() -> None:
    t, re_job, static_job = await _seeded()
    other_t, other_job, _ = await _seeded()
    foreign = await _function_id(other_t, other_job, INJECT_REMOTE)
    for req, code in (
        (
            AiRunRequest(task=AiTask.EXPLAIN_FUNCTION, job_id=re_job, target_id=foreign),
            "target_not_found",
        ),
        (
            AiRunRequest(task=AiTask.EXPLAIN_FUNCTION, job_id=re_job, target_id=uuid.uuid4()),
            "target_not_found",
        ),
        (
            AiRunRequest(
                task=AiTask.EXPLAIN_FUNCTION,
                job_id=static_job,
                target_id=await _function_id(t, re_job, INJECT_REMOTE),
            ),
            "task_not_applicable",
        ),
    ):
        with pytest.raises(ContextBuildError) as err:
            await _build(t, req)
        assert err.value.code == code


async def test_the_verifier_checks_g_and_q_rows_in_scope() -> None:
    t, re_job, _ = await _seeded()
    target = await _function_id(t, re_job, INJECT_REMOTE)
    req = AiRunRequest(task=AiTask.EXPLAIN_FUNCTION, job_id=re_job, target_id=target)
    ctx = await _build(t, req)
    parsed = {
        "observed": [
            {
                "id": "a",
                "text": "The function calls VirtualAllocEx on the target process.",
                "confidence": "high",
                "citations": [
                    {"ref": "Q1", "field": "code", "quote": "VirtualAllocEx(hProcess,(LPVOID)0x0"}
                ],
            },
            {
                "id": "b",
                "text": "The capa rule inject thread is located here.",
                "confidence": "medium",
                "citations": [{"ref": "C1", "field": "name", "quote": "inject thread"}],
            },
            {
                "id": "c",
                "text": "Another function writes a file.",
                "confidence": "high",
                "citations": [{"ref": "Q2", "field": "code", "quote": "WriteFile(h,buf,n)"}],
            },
        ],
        "overall_confidence": {"level": "medium", "rationale": "Code and capa agree."},
    }
    async with tenant_session(t.org_id, t.owner_id) as s:
        verified = await verify_output(s, t.org_id, ctx.scope, ctx, ctx.refs, parsed, CANARY)
    by_label = {c.label: c for c in verified.citations}
    assert by_label["Q1"].status is CitationStatus.VERIFIED
    assert by_label["C1"].status is CitationStatus.VERIFIED  # the source job is in scope
    assert by_label["Q2"].status is CitationStatus.INVALID
    assert by_label["Q2"].reason is CitationReason.UNKNOWN_LABEL
    assert verified.claims["O1"].status is ClaimStatus.SUPPORTED
    assert verified.claims["O3"].status is ClaimStatus.UNSUPPORTED


async def test_an_incident_digest_of_a_reverse_job_never_carries_functions_or_code() -> None:
    t, re_job, _ = await _seeded()
    row = await _settings(t)
    req = AiRunRequest(task=AiTask.INCIDENT_SUMMARY, investigation_id=t.investigation_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        built = await builder.build_run(s, t.org_id, t.owner_id, req, row)
    children = [c for c in built.children if c.scope.job_ids == (re_job,)]
    for child in children:
        kinds = {i.kind for i in child.items}
        assert RefKind.CODE not in kinds and RefKind.FUNCTION not in kinds
        assert "VirtualAllocEx(hProcess" not in child.canonical_json()
    assert RefKind.CODE not in {i.kind for i in built.root.items}
