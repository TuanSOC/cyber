"""`GET /cited-by` (M6 phase 3): the AI outputs (verified citations only, canary-leak outputs
never) and the report versions that cite one row, scoped to the org."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.ai.models import AiCitation, AiOutput
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert
from app.modules.reports.cited_by import cited_by
from tests.factories import register
from tests.report_helpers import purge_reports_test_bucket, use_signing_keys
from tests.security.idor_cases_reports import (
    API,
    Dispatched,
    ai_run_on,
    api_create,
    api_finalize,
    api_patch,
    draft,
    fake_case_iocs,
    fake_dispatch,
    owner_case,
    pcap_job,
    rows_of,
)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Dispatched]:
    use_signing_keys(monkeypatch, tmp_path)
    fake_case_iocs(monkeypatch)
    yield fake_dispatch(monkeypatch)
    purge_reports_test_bucket()


async def test_cited_by_lists_ai_outputs_and_report_versions(sent: Dispatched) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    findings = await rows_of(t, AnalysisFinding, job)
    alerts = await rows_of(t, NetworkAlert, job)
    target = str(findings[0].id)
    run = await ai_run_on(
        t,
        job,
        claims=[
            ("o1", "Periodic connections", [("finding", target)]),
            ("o2", "Same destination", [("finding", target)]),
        ],
    )
    await ai_run_on(t, job, claims=[("o1", "Leaked", [("finding", target)])], flags=["canary_leak"])
    report = (await api_create(reg, t, title="Cites the finding")).json()
    await api_patch(
        reg,
        report["id"],
        draft=draft(
            ai_runs=[str(run)],
            cited_rows=[{"kind": "alert", "ref_id": str(alerts[0].id)}],
        ),
    )
    assert (await api_finalize(reg, report["id"])).status_code == 201

    response = await reg.client.get(
        f"{API}/{reg.org_id}/cited-by", params={"kind": "finding", "ref_id": target}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert [(o["run_id"], o["claims"], o["task"]) for o in body["ai_outputs"]] == [
        (str(run), 2, "summarize_pcap")
    ]
    [version] = body["report_versions"]
    assert version["report_id"] == report["id"] and version["version"] == 1
    assert version["title"] == "Cites the finding" and version["cite_nos"]

    alert = (
        await reg.client.get(
            f"{API}/{reg.org_id}/cited-by",
            params={"kind": "alert", "ref_id": str(alerts[0].id), "job_id": str(job)},
        )
    ).json()
    assert alert["ai_outputs"] == [] and len(alert["report_versions"]) == 1
    nothing = (
        await reg.client.get(
            f"{API}/{reg.org_id}/cited-by", params={"kind": "alert", "ref_id": str(alerts[1].id)}
        )
    ).json()
    assert nothing["ai_outputs"] == [] and nothing["report_versions"] == []

    # The frozen entry point answers the same; another org sees nothing of it.
    async with tenant_session(t.org_id, t.owner_id) as s:
        direct = await cited_by(s, t.org_id, "finding", target)
    assert [str(o.run_id) for o in direct.ai_outputs] == [str(run)]
    other = await register(org_name="Other Org")
    foreign = await other.client.get(
        f"{API}/{other.org_id}/cited-by", params={"kind": "finding", "ref_id": target}
    )
    assert foreign.status_code == 200
    assert foreign.json()["ai_outputs"] == [] and foreign.json()["report_versions"] == []
    bad = await reg.client.get(
        f"{API}/{reg.org_id}/cited-by", params={"kind": "finding", "ref_id": "x y"}
    )
    assert bad.status_code == 422


async def test_unverified_citations_are_not_listed(sent: Dispatched) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    findings = await rows_of(t, AnalysisFinding, job)
    run = await ai_run_on(t, job, claims=[("o1", "x", [])])
    async with tenant_session(t.org_id, None) as s:
        output = await s.scalar(select(AiOutput).where(AiOutput.run_id == run))
        assert output is not None
        for status in ("invalid", "unverified"):
            s.add(
                AiCitation(
                    organization_id=t.org_id,
                    output_id=output.id,
                    run_id=run,
                    claim_path=f"observed[0].citations[{status == 'invalid'}]",
                    section="observed",
                    claim_id="o1",
                    label="F1",
                    kind="finding",
                    ref_id=str(findings[1].id),
                    job_id=job,
                    status=status,
                )
            )
    body = (
        await reg.client.get(
            f"{API}/{reg.org_id}/cited-by",
            params={"kind": "finding", "ref_id": str(findings[1].id)},
        )
    ).json()
    assert body["ai_outputs"] == []
