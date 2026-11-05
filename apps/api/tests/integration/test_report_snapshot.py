"""The snapshot builder (M6 phase 3): sections, caps and totals, trusted hashes, defanging
once (RT24), analyst text kept whole (RT9), AI sections (supported claims, labelled
hypotheses, omitted counts, RT15), the document-control table (RT23) and the preview
(nothing stored or audited, units against the budget, RT1)."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs.report import canonical_json, render_units
from cyberlab_jobs.results import FindingRecord
from sqlalchemy import func, select

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.evidence.models import EvidenceHash
from app.modules.pcap_analysis.models import AnalysisFinding
from app.modules.reports.models import Report, ReportVersion
from app.modules.reports.schemas import ReportDraft
from app.modules.reports.snapshot import build_snapshot
from tests import pcap_results
from tests.case_helpers import seed_mapping, seed_note, seed_status_event
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


async def _build(t: Tenant, report_id: str) -> Any:
    async with tenant_session(t.org_id, t.owner_id, snapshot_read=True) as s:
        report = await s.get(Report, uuid.UUID(report_id))
        assert report is not None
        return await build_snapshot(s, t.org_id, t.owner_id, report, now=datetime.now(UTC))


async def _new(reg: Any, t: Tenant, **include: Any) -> str:
    report = (await api_create(reg, t)).json()
    sections = include.pop("sections", {"executive_summary": "Summary"})
    response = await api_patch(
        reg, report["id"], distribution="SOC", draft=draft(sections=sections, **include)
    )
    assert response.status_code == 200, response.text
    return str(report["id"])


def _hostile_finding() -> FindingRecord:
    return FindingRecord(
        ts=pcap_results.at(60),
        finding_id=uuid.UUID(int=3),
        type="c2",
        title="Beacon to http://evil.example/x",
        description="Callback to evil.example every minute",
        severity="high",
        confidence=0.75,
        detection_method="heuristic:beaconing@1",
        attributes={"attack_ids": "T1071.001"},
    )


async def test_sections_caps_totals_and_trusted_hashes(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    records = [*pcap_results.sample_records(), _hostile_finding()]
    evidence_id, job_id = await pcap_job(reg, t, records)
    await seed_status_event(t, t.investigation_id, reason="Triage started")
    report_id = await _new(
        reg,
        t,
        findings={"min_severity": "medium", "max": 2},
        alerts={"min_severity": "info", "max": 1},
    )
    built = await _build(t, report_id)
    snap = built.snapshot
    assert snap.case.case_ref.startswith("CASE-")
    assert [e.reason for e in snap.case.status_history] == ["Triage started"]
    # Findings: three at medium+ (beaconing medium, port scan high, c2 high), capped at 2.
    assert snap.findings.total == 3 and len(snap.findings.items) == 2
    assert [f.severity for f in snap.findings.items] == ["high", "high"]
    assert snap.alerts.total == 2 and len(snap.alerts.items) == 1
    assert snap.alerts.items[0].severity == "high"  # Suricata 1 first
    # Trusted hashes from the upload, never the analyzer's.
    async with tenant_session(t.org_id, t.owner_id) as s:
        hashes = {
            str(a.value): v
            for a, v in (
                await s.execute(
                    select(EvidenceHash.algorithm, EvidenceHash.value).where(
                        EvidenceHash.evidence_id == evidence_id
                    )
                )
            ).all()
        }
    [item] = [e for e in snap.evidence.items if e.evidence_id == evidence_id]
    assert (item.sha256, item.sha1, item.md5) == (hashes["sha256"], hashes["sha1"], hashes["md5"])
    assert snap.custody.total >= 1 and snap.custody.items[0].ip is not None
    [job] = [j for j in snap.jobs.items if j.job_id == job_id]
    assert job.analyzer == "pcap" and job.tool_versions
    assert built.counts["findings"] == {"included": 2, "total": 3}


async def test_evidence_text_is_defanged_once_and_analyst_text_is_not(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    await pcap_job(reg, t, [*pcap_results.sample_records(), _hostile_finding()])
    report_id = await _new(
        reg,
        t,
        findings={"min_severity": "high"},
        sections={"executive_summary": "See https://intranet.example.org/case"},
    )
    snap = (await _build(t, report_id)).snapshot
    [c2] = [f for f in snap.findings.items if f.category == "c2"]
    assert c2.title == "Beacon to hxxp[:]//evil[.]example/x"
    assert "evil[.]example" in c2.description
    assert c2.attack_ids == ["T1071.001"] and c2.score == "0.75"
    assert snap.sections.executive_summary == "See https://intranet.example.org/case"


async def test_a_20000_character_vietnamese_summary_is_kept_whole(sent: Dispatched) -> None:
    reg, t = await owner_case()
    summary = ("Tóm tắt sự cố: máy trạm kết nối định kỳ. " * 1000)[:20_000]
    assert len(summary) == 20_000
    report_id = await _new(reg, t, sections={"executive_summary": summary})
    response = await api_finalize(reg, report_id)
    assert response.status_code == 201, response.text
    content = await reg.client.get(f"{API}/{reg.org_id}/reports/{report_id}/versions/1/content")
    assert content.json()["sections"]["executive_summary"] == summary


async def test_ai_sections_hold_supported_claims_and_labelled_hypotheses(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    findings = await rows_of(t, AnalysisFinding, job)
    run = await ai_run_on(
        t,
        job,
        claims=[
            ("o1", "INT_IP_1 beaconed every 60 seconds", [("finding", str(findings[0].id))]),
            ("o2", "The traffic is an unsupported guess", []),
        ],
        unsupported=["o2"],
        pseudonym_map={"INT_IP_1": "10.0.0.5"},
        next_steps=["Run `sudo rm -rf /tmp/x` on the host"],
    )
    report_id = await _new(reg, t, ai_runs=[str(run)])
    snap = (await _build(t, report_id)).snapshot
    [section] = snap.ai.items
    assert section.omitted_unsupported == 1
    observed = [c for c in section.claims if c.section == "observed"]
    assert [c.text for c in observed] == ["10.0.0.5 beaconed every 60 seconds"]
    assert observed[0].status == "supported" and observed[0].cite_nos
    hypotheses = [c for c in section.claims if c.section == "hypotheses"]
    assert [c.status for c in hypotheses] == ["hypothesis"]
    [step] = [c for c in section.claims if c.section == "next_steps"]
    assert "command_like" in step.flags
    assert section.disclaimer and section.context_sha256
    cited = {c.cite_no: c for c in snap.citations.items}
    assert cited[observed[0].cite_nos[0]].source == "ai"


async def test_notes_attack_and_document_order_numbering(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    findings = await rows_of(t, AnalysisFinding, job)
    note = await seed_note(
        t,
        bodies=("Old body", "Current body"),
        refs=[{"kind": "finding", "ref_id": str(findings[0].id), "job_id": str(job)}],
    )
    await seed_mapping(t, technique_id="T1071.001", status="confirmed")
    await seed_mapping(t, technique_id="T1046", status="suspected")
    report_id = await _new(
        reg,
        t,
        notes=[str(note)],
        attack={"statuses": ["confirmed"]},
        cited_rows=[{"kind": "job", "ref_id": str(job)}],
    )
    snap = (await _build(t, report_id)).snapshot
    [n] = snap.notes.items
    assert (n.version, n.body) == (2, "Current body") and n.cite_nos
    assert [a.technique_id for a in snap.attack.items] == ["T1071.001"]
    assert snap.attack.items[0].name and snap.attack.items[0].tactics
    # The job row is cited by the selection and numbered where it is first used (jobs).
    [j] = [x for x in snap.jobs.items if x.job_id == job]
    assert j.cite_no == 1
    [finding] = [f for f in snap.findings.items if f.finding_id == str(findings[0].id)]
    assert finding.cite_no == n.cite_nos[0] == 2


async def test_preview_stores_and_audits_nothing(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    await pcap_job(reg, t)
    report_id = await _new(reg, t)
    async with tenant_session(t.org_id, None) as s:
        audits = await s.scalar(select(func.count()).select_from(AuditLog))
    response = await api_preview(reg, report_id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["snapshot"]["report"]["version"] == 1
    assert body["section_counts"]["findings"]["total"] == 2
    assert body["render_units"] > 0 and body["over_budget"] is False
    assert body["snapshot_bytes"] > 0 and body["max_render_units"] > body["render_units"]
    async with tenant_session(t.org_id, None) as s:
        assert await s.scalar(select(func.count()).select_from(AuditLog)) == audits
        assert await s.scalar(select(func.count()).select_from(ReportVersion)) == 0


async def test_build_is_deterministic_for_the_same_draft(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    await pcap_job(reg, t)
    report_id = await _new(reg, t)
    now = datetime.now(UTC)
    outs = []
    for _ in range(2):
        async with tenant_session(t.org_id, t.owner_id, snapshot_read=True) as s:
            report = await s.get(Report, uuid.UUID(report_id))
            assert report is not None
            outs.append((await build_snapshot(s, t.org_id, t.owner_id, report, now=now)).snapshot)
    assert canonical_json(outs[0]) == canonical_json(outs[1])
    assert render_units(outs[0]) == render_units(outs[1])
    assert ReportDraft.model_validate({}).include.jobs == "latest"
