"""The verifier's DB re-query (M5 phase 5): every cited row is re-read in the org's tenant
session and checked against the run's scope. A label mapped to another org's row, a row of
another job of the same org, a flow matched by `flow_ref` alone, a missing row and an
unknown ref table are all invalid; investigation scope widens to its jobs and evidence."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import (
    AiScope,
    AiTask,
    CitationReason,
    CitationStatus,
    ClaimStatus,
    ContextItem,
    ContextRef,
    FieldValue,
    FrozenContext,
    RefKind,
    RunScope,
    VerifiedOutput,
)
from app.modules.ai.verify import fields_sha256, verify_output
from app.modules.analysis.models import AnalysisJob
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkFlow
from tests.ai_helpers import seed_job
from tests.integration.seed import Tenant, seed_tenant

CANARY = "cnry-0123456789abcdef"


async def _finding(t: Tenant, job_id: uuid.UUID, title: str) -> uuid.UUID:
    row_id = uuid.uuid4()
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            AnalysisFinding(
                id=row_id,
                organization_id=t.org_id,
                job_id=job_id,
                ts=datetime(2026, 11, 5, 10, 0, tzinfo=UTC),
                finding_id=uuid.uuid4(),
                type="beacon",
                title=title,
                description="d",
                severity="high",
                confidence=0.9,
                detection_method="interval",
                evidence_refs=[],
                attributes={},
            )
        )
    return row_id


async def _flow(t: Tenant, job_id: uuid.UUID, flow_ref: str) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            NetworkFlow(
                organization_id=t.org_id,
                job_id=job_id,
                ts=datetime(2026, 11, 5, 10, 0, tzinfo=UTC),
                proto="tcp",
                orig_bytes=1,
                resp_bytes=1,
                total_bytes=2,
                orig_pkts=1,
                resp_pkts=1,
                flow_ref=flow_ref,
            )
        )


async def _evidence_of(t: Tenant, job_id: uuid.UUID) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = await s.scalar(select(AnalysisJob.evidence_id).where(AnalysisJob.id == job_id))
    assert evidence is not None
    return evidence


Entry = tuple[str, RefKind, str, str, uuid.UUID | None]  # label, kind, table, ref_id, job


def _context(entries: list[Entry], scope: RunScope) -> FrozenContext:
    items: list[ContextItem] = []
    refs: list[ContextRef] = []
    for label, kind, table, ref_id, job in entries:
        fields: dict[str, FieldValue] = {"title": f"record {label}"}
        items.append(ContextItem(label=label, kind=kind, fields=fields))
        refs.append(
            ContextRef(
                label=label,
                kind=kind,
                ref_table=table,
                ref_id=ref_id,
                job_id=job,
                fields_sha256=fields_sha256(fields),
            )
        )
    return FrozenContext(
        task=AiTask.SUMMARIZE_PCAP, scope=scope, items=tuple(items), refs=tuple(refs)
    )


async def _verify(t: Tenant, ctx: FrozenContext) -> VerifiedOutput:
    parsed: dict[str, Any] = {
        "interpretation": [
            {
                "id": item.label,
                "text": f"About {item.label}",
                "confidence": "low",
                "citations": [{"ref": item.label, "field": "title"}],
            }
            for item in ctx.items
        ],
        "timeline": [
            {"text": "First beacon", "citations": [{"ref": "F1"}]},
            {"text": "The flow", "citations": [{"ref": "N1"}]},
        ],
        "overall_confidence": {"level": "low", "rationale": "Scope test."},
    }
    async with tenant_session(t.org_id, t.owner_id) as session:
        return await verify_output(session, t.org_id, ctx.scope, ctx, ctx.refs, parsed, CANARY)


def _statuses(result: VerifiedOutput) -> dict[str, tuple[str, str | None]]:
    return {
        c.label: (c.status.value, c.reason.value if c.reason else None)
        for c in result.citations
        if c.section == "interpretation"
    }


async def test_rows_are_requeried_inside_the_org_and_the_run_scope() -> None:
    a = await seed_tenant("verifya")
    b = await seed_tenant("verifyb")
    job = await seed_job(a)
    sibling = await seed_job(a)  # same org, not in this run's scope
    foreign_job = await seed_job(b)
    own = await _finding(a, job, "own finding")
    sibling_row = await _finding(a, sibling, "sibling finding")
    # A forged ref: the label maps to another org's row (inserted by that org).
    foreign = await _finding(b, foreign_job, "foreign finding")
    await _flow(a, job, "CflowOwn0001")
    await _flow(a, sibling, "CflowSib0001")
    evidence = await _evidence_of(a, job)
    foreign_evidence = await _evidence_of(b, foreign_job)

    scope = RunScope(scope=AiScope.JOB, job_ids=(job,))
    entries: list[Entry] = [
        ("J1", RefKind.JOB, "analysis_jobs", str(job), job),
        ("J2", RefKind.JOB, "analysis_jobs", str(sibling), sibling),
        ("F1", RefKind.FINDING, "analysis_findings", str(own), job),
        ("F2", RefKind.FINDING, "analysis_findings", str(sibling_row), sibling),
        ("F3", RefKind.FINDING, "analysis_findings", str(sibling_row), job),  # forged job
        ("F4", RefKind.FINDING, "analysis_findings", str(foreign), job),
        ("F5", RefKind.FINDING, "analysis_findings", str(uuid.uuid4()), job),
        ("F6", RefKind.FINDING, "analysis_findings", "not-a-uuid", job),
        ("F7", RefKind.FINDING, "network_alerts", str(own), job),  # wrong table
        ("N1", RefKind.FLOW, "network_flows", "CflowOwn0001", job),
        ("N2", RefKind.FLOW, "network_flows", "CflowSib0001", job),  # flow_ref alone
        ("N3", RefKind.FLOW, "network_flows", "CflowSib0001", sibling),
        ("N4", RefKind.FLOW, "network_flows", "CflowOwn0001", None),
        ("K1", RefKind.EVIDENCE, "evidence", str(evidence), None),
        ("K2", RefKind.EVIDENCE, "evidence", str(foreign_evidence), None),
        ("V1", RefKind.INVESTIGATION, "investigations", str(a.investigation_id), None),
        ("V2", RefKind.INVESTIGATION, "users", str(a.owner_id), None),  # unknown table
    ]
    result = await _verify(a, _context(entries, scope))
    verified = ("verified", None)
    assert _statuses(result) == {
        "J1": verified,
        "J2": ("invalid", "out_of_scope"),
        "F1": verified,
        "F2": ("invalid", "out_of_scope"),
        "F3": ("invalid", "out_of_scope"),
        "F4": ("invalid", "row_missing"),
        "F5": ("invalid", "row_missing"),
        "F6": ("invalid", "row_missing"),
        "F7": ("invalid", "row_missing"),
        "N1": verified,
        "N2": ("invalid", "row_missing"),
        "N3": ("invalid", "out_of_scope"),
        "N4": ("invalid", "out_of_scope"),
        "K1": verified,
        "K2": ("invalid", "row_missing"),
        "V1": ("invalid", "out_of_scope"),
        "V2": ("invalid", "out_of_scope"),
    }
    # Claim ids are rewritten in order: F1 is the third interpretation, F4 the sixth.
    assert result.claims["I3"].status is ClaimStatus.SUPPORTED
    assert result.claims["I6"].status is ClaimStatus.UNSUPPORTED
    # Timeline times come from the cited rows (findings and flows have one).
    assert result.claims["timeline:0"].status is ClaimStatus.SUPPORTED
    assert result.claims["timeline:1"].status is ClaimStatus.SUPPORTED
    assert result.metrics.citations_verified == 6  # J1 F1 N1 K1 + two timeline citations


async def test_investigation_scope_covers_its_jobs_and_evidence() -> None:
    a = await seed_tenant("verifyinv")
    b = await seed_tenant("verifyinvb")
    job = await seed_job(a)
    second = await seed_job(a)
    foreign_job = await seed_job(b)
    own = await _finding(a, second, "second job finding")
    foreign = await _finding(b, foreign_job, "foreign finding")
    await _flow(a, job, "CflowInv0001")
    evidence = await _evidence_of(a, second)

    scope = RunScope(
        scope=AiScope.INVESTIGATION, job_ids=(job, second), investigation_id=a.investigation_id
    )
    entries: list[Entry] = [
        ("J1", RefKind.JOB, "analysis_jobs", str(job), job),
        ("J2:F1", RefKind.FINDING, "analysis_findings", str(own), second),
        ("J2:F2", RefKind.FINDING, "analysis_findings", str(foreign), second),
        ("F1", RefKind.FINDING, "analysis_findings", str(own), second),
        ("N1", RefKind.FLOW, "network_flows", "CflowInv0001", job),
        ("K1", RefKind.EVIDENCE, "evidence", str(evidence), None),
        ("V1", RefKind.INVESTIGATION, "investigations", str(a.investigation_id), None),
        ("V2", RefKind.INVESTIGATION, "investigations", str(b.investigation_id), None),
    ]
    result = await _verify(a, _context(entries, scope))
    statuses = _statuses(result)
    for label in ("J1", "J2:F1", "F1", "N1", "K1", "V1"):
        assert statuses[label] == ("verified", None), label
    assert statuses["J2:F2"] == ("invalid", "row_missing")
    assert statuses["V2"] == ("invalid", "row_missing")
    assert all(c.status is not CitationStatus.VERIFIED for c in result.citations if c.label == "V2")
    assert result.metrics.by_reason == {CitationReason.ROW_MISSING: 2}
