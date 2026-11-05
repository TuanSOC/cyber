"""Citation resolution (M6 phase 3): verified AI citations only, field copies whose
`fields_sha256` matches a recomputation, rows of another case or org never resolved
(dropped and counted), stable `C` numbering, deep links from ids only, and the
`report_citations` rows written at finalize."""

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.ai.context import fields as F
from app.modules.ai.contracts import CitationResult, CitationStatus, RefKind
from app.modules.ai.models import AiCitation, AiOutput
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert
from app.modules.reports.citations import field_copy, fields_sha256
from app.modules.reports.models import ReportCitation
from tests.case_helpers import seed_case
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.report_helpers import SigningKeys, purge_reports_test_bucket, use_signing_keys
from tests.security.idor_cases_reports import (
    API,
    Dispatched,
    ai_run_on,
    api_create,
    api_finalize,
    api_patch,
    api_preview,
    draft,
    fake_case_iocs,
    fake_dispatch,
    owner_case,
    pcap_job,
    rows_of,
)


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    installed = use_signing_keys(monkeypatch, tmp_path)
    fake_case_iocs(monkeypatch)
    yield installed
    purge_reports_test_bucket()


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch, keys: SigningKeys) -> Dispatched:
    return fake_dispatch(monkeypatch)


async def _report(reg: Registered, t: Tenant, **include: object) -> str:
    report = (await api_create(reg, t)).json()
    response = await api_patch(reg, report["id"], draft=draft(**include))
    assert response.status_code == 200, response.text
    return str(report["id"])


async def _add_unverified(t: Tenant, run_id: uuid.UUID, ref_id: str, job_id: uuid.UUID) -> None:
    async with tenant_session(t.org_id, None) as s:
        output = await s.scalar(select(AiOutput).where(AiOutput.run_id == run_id))
        assert output is not None
        c = CitationResult(
            claim_path="observed[0].citations[9]",
            section="observed",
            claim_id="o1",
            label="A1",
            kind=RefKind.ALERT,
            ref_id=ref_id,
            job_id=job_id,
            status=CitationStatus.UNVERIFIED,
        )
        s.add(
            AiCitation(
                organization_id=t.org_id,
                output_id=output.id,
                run_id=run_id,
                claim_path=c.claim_path,
                section=c.section,
                claim_id=c.claim_id,
                label=c.label,
                kind=c.kind.value if c.kind else None,
                ref_id=c.ref_id,
                job_id=c.job_id,
                status=c.status.value,
            )
        )


async def test_only_verified_ai_citations_and_matching_field_hashes(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    findings = await rows_of(t, AnalysisFinding, job)
    alerts = await rows_of(t, NetworkAlert, job)
    run = await ai_run_on(
        t, job, claims=[("o1", "Periodic connections", [("finding", str(findings[0].id))])]
    )
    await _add_unverified(t, run, str(alerts[0].id), job)
    report_id = await _report(reg, t, ai_runs=[str(run)])
    snap = (await api_preview(reg, report_id)).json()["snapshot"]
    cited = snap["citations"]["items"]
    assert [(c["kind"], c["ref_id"], c["source"]) for c in cited] == [
        ("finding", str(findings[0].id), "ai")
    ]
    [c] = cited
    assert c["ref_table"] == "analysis_findings" and c["job_id"] == str(job)
    # The copy is the M5 allow-list of the row, defanged, and its hash is recomputable.
    assert fields_sha256(c["fields"]) == c["fields_sha256"]
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(AnalysisFinding, findings[0].id)
        assert row is not None
        assert field_copy(F.finding_fields(row)[0]) == c["fields"]
    assert c["path"] == f"/o/{reg.org_id}/pcap/{job}?tab=findings&ref={findings[0].id}"
    [finding] = [f for f in snap["findings"]["items"] if f["finding_id"] == str(findings[0].id)]
    assert finding["cite_no"] == 1
    assert not any(a["cite_no"] for a in snap["alerts"]["items"])


async def test_rows_of_another_case_or_org_are_never_resolved(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    other_case = await seed_case(t, title="Other case")
    other_t = Tenant(t.org_id, t.owner_id, other_case)
    _, other_job = await pcap_job(reg, other_t)
    foreign_reg, foreign_t = await owner_case(org_name="Foreign Org")
    _, foreign_job = await pcap_job(foreign_reg, foreign_t)
    mine = await rows_of(t, AnalysisFinding, job)
    theirs = await rows_of(other_t, AnalysisFinding, other_job)
    foreign = await rows_of(foreign_t, AnalysisFinding, foreign_job)
    report_id = await _report(
        reg,
        t,
        cited_rows=[
            {"kind": "finding", "ref_id": str(mine[0].id)},
            {"kind": "finding", "ref_id": str(theirs[0].id)},
            {"kind": "finding", "ref_id": str(foreign[0].id)},
            {"kind": "evidence", "ref_id": str(uuid.uuid4())},
            {"kind": "job", "ref_id": "not-a-uuid"},
        ],
    )
    snap = (await api_preview(reg, report_id)).json()["snapshot"]
    refs = [c["ref_id"] for c in snap["citations"]["items"]]
    assert refs == [str(mine[0].id)]
    assert snap["citations"]["dropped_out_of_scope"] == 4
    text = str(snap)
    assert str(theirs[0].id) not in text and str(foreign[0].id) not in text


async def test_numbering_is_stable_and_written_at_finalize(sent: Dispatched) -> None:
    reg, t = await owner_case()
    evidence_id, job = await pcap_job(reg, t)
    findings = await rows_of(t, AnalysisFinding, job)
    alerts = await rows_of(t, NetworkAlert, job)
    report_id = await _report(
        reg,
        t,
        cited_rows=[
            {"kind": "alert", "ref_id": str(alerts[1].id)},
            {"kind": "evidence", "ref_id": str(evidence_id)},
            {"kind": "finding", "ref_id": str(findings[1].id)},
            {"kind": "job", "ref_id": str(job)},
        ],
    )
    first = (await api_preview(reg, report_id)).json()["snapshot"]["citations"]
    second = (await api_preview(reg, report_id)).json()["snapshot"]["citations"]
    assert first == second
    # First use in document order: evidence, jobs, findings, alerts.
    assert [c["kind"] for c in first["items"]] == ["evidence", "job", "finding", "alert"]
    assert [c["cite_no"] for c in first["items"]] == [1, 2, 3, 4]
    assert first["items"][0]["path"] == f"/o/{reg.org_id}/evidence/{evidence_id}"
    assert first["items"][1]["path"] == f"/o/{reg.org_id}/pcap/{job}"

    response = await api_finalize(reg, report_id)
    assert response.status_code == 201, response.text
    version_id = uuid.UUID(response.json()["id"])
    content = (
        await reg.client.get(f"{API}/{reg.org_id}/reports/{report_id}/versions/1/content")
    ).json()
    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = list(
            await s.scalars(
                select(ReportCitation)
                .where(ReportCitation.version_id == version_id)
                .order_by(ReportCitation.cite_no)
            )
        )
    assert [(r.cite_no, r.kind, r.ref_id, r.fields_sha256, r.source) for r in rows] == [
        (c["cite_no"], c["kind"], c["ref_id"], c["fields_sha256"], "selection")
        for c in content["citations"]["items"]
    ]
