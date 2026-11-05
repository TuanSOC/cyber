"""Finalize (M6 phase 3): atomic version rows, v1 then v2, append-only versions, the PDF-only
render queue, publish failures, the read / write split (RT14) with stale drafts and orphans,
the TLP re-check against the current case TLP (RT7), the profile rules (RT8) and the size and
render budgets (RT1)."""

import logging
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DBAPIError

from app.core.config import get_settings
from app.core.errors import Conflict
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.investigations.models import Investigation
from app.modules.reports import dispatch
from app.modules.reports import storage as report_storage
from app.modules.reports.models import Report, ReportCitation, ReportRender, ReportVersion
from tests.case_helpers import set_case_policy
from tests.integration.seed import Tenant
from tests.report_helpers import SigningKeys, purge_reports_test_bucket, use_signing_keys
from tests.security.idor_cases_reports import (
    API,
    Dispatched,
    api_create,
    api_finalize,
    api_get,
    api_patch,
    draft,
    fake_case_iocs,
    fake_dispatch,
    owner_case,
    pcap_job,
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


async def _count(t: Tenant, model: Any, **where: Any) -> int:
    async with tenant_session(t.org_id, t.owner_id) as s:
        stmt = select(func.count()).select_from(model)
        for name, value in where.items():
            stmt = stmt.where(getattr(model, name) == value)
        return int(await s.scalar(stmt) or 0)


async def _actions(t: Tenant) -> list[str]:
    async with tenant_session(t.org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog.action)
            .where(AuditLog.organization_id == t.org_id)
            .order_by(AuditLog.occurred_at)
        )
        return list(rows)


async def _report(reg: Any, t: Tenant, **include: Any) -> str:
    report = (await api_create(reg, t)).json()
    patched = await api_patch(
        reg,
        report["id"],
        distribution="SOC team",
        draft=draft(sections={"executive_summary": "Beaconing seen."}, **include),
    )
    assert patched.status_code == 200, patched.text
    return str(report["id"])


async def test_finalize_writes_v1_then_v2(sent: Dispatched) -> None:
    reg, t = await owner_case()
    await pcap_job(reg, t)
    report_id = await _report(reg, t)

    first = await api_finalize(reg, report_id, change_note="Initial report")
    assert first.status_code == 201, first.text
    v1 = first.json()
    assert v1["version"] == 1 and v1["kid"] == "test-report-1"
    assert v1["change_note"] == "Initial report"
    rid = uuid.UUID(report_id)
    assert await _count(t, ReportVersion, report_id=rid) == 1
    version_id = uuid.UUID(v1["id"])
    citations = await _count(t, ReportCitation, version_id=version_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(ReportVersion, version_id)
        assert row is not None
        assert row.object_key == f"{t.org_id}/{rid}/1/snapshot.json"
        assert row.manifest["snapshot_sha256"] == row.snapshot_sha256 == v1["snapshot_sha256"]
        assert row.section_counts["findings"]["total"] == 2
    # The PDF only, queued in the write transaction and published after the commit (RT5).
    assert sent.created == [(version_id, "pdf")]
    assert len(sent.sent) == 1
    assert await _count(t, ReportRender, version_id=version_id) == 1
    assert "report.finalized" in await _actions(t)

    detail = await api_get(reg, report_id)
    assert detail["report"]["latest_version"] == 1
    second = await api_finalize(reg, report_id, change_note="Second edition")
    assert second.status_code == 201, second.text
    assert second.json()["version"] == 2
    async with tenant_session(t.org_id, t.owner_id) as s:
        again = await s.get(ReportVersion, version_id)
        assert again is not None and again.snapshot_sha256 == v1["snapshot_sha256"]
    assert await _count(t, ReportCitation, version_id=version_id) == citations
    versions = (await reg.client.get(f"{API}/{reg.org_id}/reports/{report_id}/versions")).json()
    assert [v["version"] for v in versions["items"]] == [1, 2]
    content = await reg.client.get(f"{API}/{reg.org_id}/reports/{report_id}/versions/2/content")
    control = content.json()["report"]["document_control"]
    assert [(c["version"], c["change_note"]) for c in control] == [(1, "Initial report")]
    assert control[0]["snapshot_sha256_short"] == v1["snapshot_sha256"][:12]
    assert content.json()["report"]["change_note"] == "Second edition"


@pytest.mark.parametrize("table", ["report_versions", "report_citations"])
async def test_versions_and_citations_are_append_only(sent: Dispatched, table: str) -> None:
    reg, t = await owner_case()
    _, job = await pcap_job(reg, t)
    report_id = await _report(reg, t, cited_rows=[{"kind": "job", "ref_id": str(job)}])
    assert (await api_finalize(reg, report_id)).status_code == 201
    for statement in (
        f"UPDATE {table} SET organization_id = organization_id",
        f"DELETE FROM {table}",
    ):
        with pytest.raises(DBAPIError):
            async with tenant_session(t.org_id, t.owner_id) as s:
                await s.execute(text(statement))


async def test_a_publish_failure_still_answers_201(
    monkeypatch: pytest.MonkeyPatch, sent: Dispatched
) -> None:
    async def broken(render_ids: Any) -> None:
        raise RuntimeError("broker down")

    monkeypatch.setattr(dispatch, "dispatch_render", broken)
    reg, t = await owner_case()
    report_id = await _report(reg, t)
    response = await api_finalize(reg, report_id)
    assert response.status_code == 201, response.text
    assert await _count(t, ReportRender) == 1


async def test_a_refused_render_never_undoes_the_version(
    monkeypatch: pytest.MonkeyPatch, sent: Dispatched
) -> None:
    async def busy(*args: Any) -> Any:
        raise Conflict("busy", code="render_busy")

    monkeypatch.setattr(dispatch, "create_render", busy)
    reg, t = await owner_case()
    report_id = await _report(reg, t)
    response = await api_finalize(reg, report_id)
    assert response.status_code == 201, response.text
    assert await _count(t, ReportVersion) == 1
    assert await _count(t, ReportRender) == 0


async def test_an_edit_between_read_and_write_is_stale_and_leaves_an_orphan(
    monkeypatch: pytest.MonkeyPatch, sent: Dispatched, caplog: pytest.LogCaptureFixture
) -> None:
    reg, t = await owner_case()
    report_id = await _report(reg, t)
    real_put = report_storage.put_snapshot

    async def put_then_edit(key: str, data: bytes) -> str:
        version = await real_put(key, data)
        # Another analyst saves the draft while the snapshot is being stored (RT14).
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                update(Report)
                .where(Report.id == uuid.UUID(report_id))
                .values(title="Edited meanwhile", revision=Report.revision + 1)
            )
        return version

    monkeypatch.setattr(report_storage, "put_snapshot", put_then_edit)
    with caplog.at_level(logging.WARNING, logger="app.modules.reports.storage"):
        response = await api_finalize(reg, report_id)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "stale_draft"
    assert await _count(t, ReportVersion) == 0
    assert any("orphan report snapshot" in r.getMessage() for r in caplog.records)
    assert sent.created == []


async def test_a_case_tlp_raised_after_the_draft_needs_the_acknowledgement(
    sent: Dispatched,
) -> None:
    reg, t = await owner_case()
    report_id = await _report(reg, t)  # amber, from the case
    await set_case_policy(t, t.investigation_id, tlp="red")
    refused = await api_finalize(reg, report_id)
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "tlp_below_case"
    assert await _count(t, ReportVersion) == 0
    acknowledged = await api_finalize(reg, report_id, acknowledge_tlp_downgrade=True)
    assert acknowledged.status_code == 201, acknowledged.text
    assert acknowledged.json()["tlp"] == "amber"
    assert "report.tlp_downgraded" in await _actions(t)


async def test_a_case_tlp_raised_during_the_build_is_rechecked_at_write(
    monkeypatch: pytest.MonkeyPatch, sent: Dispatched
) -> None:
    reg, t = await owner_case()
    report_id = await _report(reg, t)
    real_put = report_storage.put_snapshot

    async def put_then_raise(key: str, data: bytes) -> str:
        version = await real_put(key, data)
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                update(Investigation)
                .where(Investigation.id == t.investigation_id)
                .values(tlp="red")
            )
        return version

    monkeypatch.setattr(report_storage, "put_snapshot", put_then_raise)
    response = await api_finalize(reg, report_id)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "tlp_below_case"
    assert await _count(t, ReportVersion) == 0


async def test_profile_rules(sent: Dispatched) -> None:
    reg, t = await owner_case()
    report = (await api_create(reg, t, profile="external")).json()
    no_distribution = await api_finalize(reg, report["id"], acknowledge_external_review=True)
    assert no_distribution.status_code == 422
    assert no_distribution.json()["error"]["code"] == "distribution_required"
    assert (await api_patch(reg, report["id"], distribution="Partner CERT")).status_code == 200
    no_ack = await api_finalize(reg, report["id"])
    assert no_ack.status_code == 422
    assert no_ack.json()["error"]["code"] == "external_review_required"
    ok = await api_finalize(reg, report["id"], acknowledge_external_review=True)
    assert ok.status_code == 201, ok.text
    assert ok.json()["profile"] == "external"

    red = (await api_create(reg, t, tlp="red")).json()
    refused = await api_finalize(reg, red["id"])
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "distribution_required"


async def test_the_render_budget_and_the_size_limit_refuse_before_signing(
    monkeypatch: pytest.MonkeyPatch, sent: Dispatched
) -> None:
    reg, t = await owner_case()
    await pcap_job(reg, t)
    report_id = await _report(reg, t)
    settings = get_settings()
    monkeypatch.setattr(settings, "report_max_render_units", 1_000)
    too_big = await api_finalize(reg, report_id)
    assert too_big.status_code == 422, too_big.text
    error = too_big.json()["error"]
    assert error["code"] == "report_too_large_to_render"
    assert error["render_units"] > 1_000 and error["max_render_units"] == 1_000
    assert set(error["section_units"]) >= {"findings", "citations", "report"}
    monkeypatch.setattr(settings, "report_max_render_units", 10_000_000)
    monkeypatch.setattr(settings, "report_max_snapshot_bytes", 1_024)
    too_large = await api_finalize(reg, report_id)
    assert too_large.status_code == 422
    assert too_large.json()["error"]["code"] == "report_too_large"
    assert await _count(t, ReportVersion) == 0
    assert sent.created == []


async def test_stale_revision_and_rate_limit(
    monkeypatch: pytest.MonkeyPatch, sent: Dispatched
) -> None:
    reg, t = await owner_case()
    report_id = await _report(reg, t)
    stale = await api_finalize(reg, report_id, revision=1)
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale_draft"
    monkeypatch.setattr(get_settings(), "report_finalize_per_user_10min", 1)
    limited = await api_finalize(reg, report_id)
    assert limited.status_code == 429
