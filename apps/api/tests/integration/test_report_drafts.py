"""Report drafts (M6 phase 3): create / list / read / update / discard, optimistic revisions,
the TLP downgrade rule, archived cases, selection scope and viewer permissions."""

import uuid

import pytest
from sqlalchemy import select, update

from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.organizations.models import MemberRole
from app.modules.reports import repository
from tests.case_helpers import seed_case, seed_collection, seed_note, set_case_policy
from tests.factories import add_member, csrf, login, make_user, unique_email
from tests.report_helpers import new_signing_keys, seed_version
from tests.security.idor_cases_reports import (
    API,
    ai_run_on,
    api_create,
    api_get,
    api_patch,
    draft,
    owner_case,
    pcap_job,
)


async def _actions(org_id: uuid.UUID) -> list[str]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog.action)
            .where(AuditLog.organization_id == org_id)
            .order_by(AuditLog.occurred_at)
        )
        return list(rows)


async def test_create_defaults_to_the_case_tlp_and_lists() -> None:
    reg, t = await owner_case()
    await set_case_policy(t, t.investigation_id, tlp="amber_strict")
    created = await api_create(reg, t, title="  First report ")
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["tlp"] == "amber_strict"
    assert body["title"] == "First report"
    assert body["revision"] == 1 and body["latest_version"] == 0 and body["latest"] is None
    assert body["case_ref"].startswith("CASE-")

    case_list = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/reports"
    )
    assert [r["id"] for r in case_list.json()["items"]] == [body["id"]]
    org_list = await reg.client.get(f"{API}/{reg.org_id}/reports", params={"status": "draft"})
    assert [r["id"] for r in org_list.json()["items"]] == [body["id"]]
    detail = await api_get(reg, body["id"])
    assert detail["draft"]["include"]["jobs"] == "latest"
    assert detail["versions"] == []
    assert "report.created" in await _actions(reg.org_id)


async def test_list_pages_with_a_cursor() -> None:
    reg, t = await owner_case()
    ids = [(await api_create(reg, t, title=f"R{i}")).json()["id"] for i in range(3)]
    original = repository.PAGE_SIZE
    repository.PAGE_SIZE = 2
    try:
        first = (await reg.client.get(f"{API}/{reg.org_id}/reports")).json()
        assert len(first["items"]) == 2 and first["next_cursor"]
        second = (
            await reg.client.get(
                f"{API}/{reg.org_id}/reports", params={"cursor": first["next_cursor"]}
            )
        ).json()
    finally:
        repository.PAGE_SIZE = original
    seen = [r["id"] for r in first["items"]] + [r["id"] for r in second["items"]]
    assert sorted(seen) == sorted(ids) and second["next_cursor"] is None
    bad = await reg.client.get(f"{API}/{reg.org_id}/reports", params={"cursor": "%%%"})
    assert bad.status_code == 400


async def test_update_requires_the_current_revision() -> None:
    reg, t = await owner_case()
    report = (await api_create(reg, t)).json()
    ok = await api_patch(
        reg,
        report["id"],
        revision=1,
        title="Renamed",
        distribution="SOC team",
        draft=draft(sections={"executive_summary": "Summary"}),
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["report"]["revision"] == 2
    assert ok.json()["draft"]["sections"]["executive_summary"] == "Summary"
    stale = await api_patch(reg, report["id"], revision=1, title="Lost update")
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "stale_draft"
    assert (await api_get(reg, report["id"]))["report"]["title"] == "Renamed"


async def test_tlp_below_the_case_needs_org_update_and_the_acknowledgement() -> None:
    reg, t = await owner_case()
    await set_case_policy(t, t.investigation_id, tlp="red")
    refused = await api_create(reg, t, tlp="green")
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "tlp_below_case"
    created = await api_create(reg, t, tlp="green", acknowledge_tlp_downgrade=True)
    assert created.status_code == 201, created.text
    assert "report.tlp_downgraded" in await _actions(reg.org_id)

    # An analyst (no org.update) cannot lower it, even acknowledged.
    email = unique_email("analyst")
    analyst_id = await make_user(email)
    await add_member(reg.org_id, analyst_id, MemberRole.ANALYST)
    analyst = await login(email)
    other = (await api_create(reg, t)).json()
    response = await analyst.patch(
        f"{API}/{reg.org_id}/reports/{other['id']}",
        json={"revision": 1, "tlp": "amber", "acknowledge_tlp_downgrade": True},
        headers=csrf(analyst),
    )
    assert response.status_code == 403
    raised = await analyst.patch(
        f"{API}/{reg.org_id}/reports/{other['id']}",
        json={"revision": 1, "title": "Analyst edit"},
        headers=csrf(analyst),
    )
    assert raised.status_code == 200, raised.text


async def test_archived_case_refuses_new_reports_and_edits() -> None:
    reg, t = await owner_case()
    report = (await api_create(reg, t)).json()
    async with tenant_session(reg.org_id, None) as s:
        await s.execute(
            update(Investigation)
            .where(Investigation.id == t.investigation_id)
            .values(status=InvestigationStatus.ARCHIVED)
        )
    created = await api_create(reg, t)
    assert created.status_code == 409
    assert created.json()["error"]["code"] == "investigation_archived"
    edit = await api_patch(reg, report["id"], title="x")
    assert edit.status_code == 409
    assert edit.json()["error"]["code"] == "investigation_archived"


async def test_discard_only_without_versions() -> None:
    reg, t = await owner_case()
    first = (await api_create(reg, t)).json()
    discarded = await reg.client.post(
        f"{API}/{reg.org_id}/reports/{first['id']}/discard", headers=csrf(reg.client)
    )
    assert discarded.status_code == 200, discarded.text
    assert discarded.json()["report"]["status"] == "discarded"
    again = await api_patch(reg, first["id"], title="Zombie")
    assert again.status_code == 409 and again.json()["error"]["code"] == "report_discarded"

    second = (await api_create(reg, t)).json()
    await seed_version(t, uuid.UUID(second["id"]), new_signing_keys())
    refused = await reg.client.post(
        f"{API}/{reg.org_id}/reports/{second['id']}/discard", headers=csrf(reg.client)
    )
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "report_has_versions"


@pytest.mark.parametrize("field", ["notes", "collections", "jobs", "ai_runs"])
async def test_selections_must_be_in_the_case(field: str) -> None:
    reg, t = await owner_case()
    report = (await api_create(reg, t)).json()
    other_case = await seed_case(t, title="Other case")
    _, job = await pcap_job(reg, t)
    if field == "notes":
        inside = await seed_note(t)
        outside = await seed_note(t, other_case)
        good, bad = draft(notes=[str(inside)]), draft(notes=[str(outside)])
    elif field == "collections":
        inside = await seed_collection(t)
        outside = await seed_collection(t, other_case, name="Elsewhere")
        good = draft(iocs={"case_iocs": False, "collections": [str(inside)]})
        bad = draft(iocs={"case_iocs": False, "collections": [str(outside)]})
    elif field == "jobs":
        good, bad = draft(jobs=[str(job)]), draft(jobs=[str(uuid.uuid4())])
    else:
        run = await ai_run_on(t, job, claims=[("o1", "Beacon", [])])
        refused = await ai_run_on(t, job, claims=[("o1", "x", [])], status="refused")
        good, bad = draft(ai_runs=[str(run)]), draft(ai_runs=[str(refused)])
    ok = await api_patch(reg, report["id"], draft=good)
    assert ok.status_code == 200, ok.text
    out = await api_patch(reg, report["id"], draft=bad)
    assert out.status_code == 422, out.text
    assert out.json()["error"]["code"] == "selection_out_of_scope"


async def test_canary_leak_runs_are_not_selectable() -> None:
    reg, t = await owner_case()
    report = (await api_create(reg, t)).json()
    _, job = await pcap_job(reg, t)
    leaked = await ai_run_on(t, job, claims=[("o1", "x", [])], flags=["canary_leak"])
    out = await api_patch(reg, report["id"], draft=draft(ai_runs=[str(leaked)]))
    assert out.status_code == 422


async def test_draft_limits_are_checked_by_the_schema() -> None:
    reg, t = await owner_case()
    report = (await api_create(reg, t)).json()
    too_long = await api_patch(
        reg, report["id"], draft=draft(sections={"executive_summary": "x" * 20_001})
    )
    assert too_long.status_code == 422
    nul = await api_patch(reg, report["id"], draft=draft(sections={"scope": "a\x00b"}))
    assert nul.status_code == 422
    # Eight sections of 20 000 Vietnamese characters fit the 1 MiB draft (RT9).
    big = {
        name: "Việt" * 5_000
        for name in (
            "executive_summary",
            "scope",
            "methodology",
            "impact",
            "root_cause",
            "actions_taken",
            "recommendations",
            "lessons_learned",
        )
    }
    ok = await api_patch(reg, report["id"], draft=draft(sections=big))
    assert ok.status_code == 200, ok.text


async def test_viewer_reads_but_cannot_write() -> None:
    reg, t = await owner_case()
    report = (await api_create(reg, t)).json()
    email = unique_email("viewer")
    viewer_id = await make_user(email)
    await add_member(reg.org_id, viewer_id, MemberRole.VIEWER)
    viewer = await login(email)
    base = f"{API}/{reg.org_id}"
    assert (await viewer.get(f"{base}/reports/{report['id']}")).status_code == 200
    assert (await viewer.get(f"{base}/reports")).status_code == 200
    writes = [
        viewer.post(
            f"{base}/investigations/{t.investigation_id}/reports",
            json={"title": "x"},
            headers=csrf(viewer),
        ),
        viewer.patch(
            f"{base}/reports/{report['id']}",
            json={"revision": 1, "title": "x"},
            headers=csrf(viewer),
        ),
        viewer.post(f"{base}/reports/{report['id']}/discard", headers=csrf(viewer)),
        viewer.post(f"{base}/reports/{report['id']}/preview", headers=csrf(viewer)),
        viewer.post(
            f"{base}/reports/{report['id']}/finalize", json={"revision": 1}, headers=csrf(viewer)
        ),
    ]
    for request in writes:
        assert (await request).status_code == 403
