"""Retention runs (M7 phase 3): the manual run request (mode from the DB, RT1; one run per
org at a time), the list and detail routes with their items, the permissions, and time
slicing (a run that runs out of its slice is requeued with the same id and resumes)."""

import uuid
from typing import Any

import pytest
from sqlalchemy import text

from app.core.tenancy import tenant_session
from app.modules.organizations.models import MemberRole
from app.workers import retention as worker_module
from tests.factories import add_member, csrf, login, make_user, unique_email
from tests.integration.seed import Tenant
from tests.integration.test_retention_preview import _cite
from tests.integration.test_retention_purge import (
    Captured,
    aged,
    captured,
    items,
    owner_tenant,
    run_once,
    run_row,
)
from tests.ops_helpers import AgedCase, backdate_policy, seed_retention_policy

API = "/api/v1/orgs"
__all__ = ["aged", "captured"]


async def test_a_manual_run_takes_its_mode_from_the_policy(captured: Captured) -> None:
    reg, t = await owner_tenant()
    c = reg.client
    url = f"{API}/{t.org_id}/retention/runs"
    await seed_retention_policy(t, ti_results_days=400, pending_enforce=True)
    first = await c.post(url, json={}, headers=csrf(c))
    assert first.status_code == 202, first.text
    body = first.json()
    assert (body["mode"], body["trigger"], body["status"]) == ("dry_run", "manual", "queued")
    assert body["policy"] == {
        "ti_results_days": 400,
        "ai_runs_days": None,
        "closed_case_days": None,
    }
    assert body["requested_by"] == str(reg.user_id)
    # One run per org at a time.
    busy = await c.post(url, json={}, headers=csrf(c))
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "retention_run_active"
    assert (await worker_module.run_org(t.org_id, uuid.UUID(body["id"]))).status == "completed"

    # Enforce in force: a manual run enforces, unless the caller asks for a dry run.
    await backdate_policy(t, enforce_days_ago=1)
    enforce = (await c.post(url, json={}, headers=csrf(c))).json()
    assert enforce["mode"] == "enforce"
    await worker_module.run_org(t.org_id, uuid.UUID(enforce["id"]))
    dry = (await c.post(url, json={"dry_run": True}, headers=csrf(c))).json()
    assert dry["mode"] == "dry_run"
    assert [task for task, _ in captured.published] == ["retention.run_org"] * 3
    assert (await c.post(url, json={"mode": "enforce"}, headers=csrf(c))).status_code == 422


async def test_runs_list_and_detail(captured: Captured, aged: tuple[Any, Tenant, AgedCase]) -> None:
    reg, t, case = aged
    await seed_retention_policy(t, closed_case_days=30, enforce=True)
    c = reg.client
    run = (await c.post(f"{API}/{t.org_id}/retention/runs", json={}, headers=csrf(c))).json()
    outcome = await worker_module.run_org(t.org_id, uuid.UUID(run["id"]))
    assert outcome.status == "completed", outcome.counts

    listed = (await c.get(f"{API}/{t.org_id}/retention/runs")).json()
    assert listed["total"] == 1
    item = listed["items"][0]
    assert (item["id"], item["status"], item["mode"]) == (run["id"], "completed", "enforce")
    assert item["started_at"] and item["finished_at"]
    assert item["counts"]["closed_case"]["candidates"] > 0
    assert set(item["counts"]) == {"ti_results", "ai_runs", "closed_case"}

    detail = (await c.get(f"{API}/{t.org_id}/retention/runs/{run['id']}")).json()
    assert detail["items_total"] == len(await items(t.org_id, uuid.UUID(run["id"])))
    assert detail["items"] and all("object_key" not in i for i in detail["items"])
    assert {i["outcome"] for i in detail["items"]} <= {"purged", "kept_cited"}
    assert detail["sample"]
    assert str(case.pcap_evidence_id) in {i["ref_id"] for i in detail["items"]}
    missing = await c.get(f"{API}/{t.org_id}/retention/runs/{uuid.uuid4()}")
    assert missing.status_code == 404

    # M7 follow-up: per-outcome counts, an outcome filter and paging.
    url = f"{API}/{t.org_id}/retention/runs/{run['id']}"
    total = detail["items_total"]
    assert detail["items_matching"] == total and sum(detail["outcome_counts"].values()) == total
    assert set(detail["outcome_counts"]) <= {"purged", "kept_cited"}
    purged = detail["outcome_counts"]["purged"]
    only = (await c.get(url, params={"outcome": "purged"})).json()
    assert only["items_total"] == total and only["items_matching"] == purged
    assert {i["outcome"] for i in only["items"]} == {"purged"}
    assert len(only["items"]) == min(purged, 100)
    none = (await c.get(url, params={"outcome": "skipped_hold"})).json()
    assert (none["items"], none["items_matching"]) == ([], 0)
    first = (await c.get(url, params={"limit": 1})).json()
    second = (await c.get(url, params={"limit": 1, "offset": 1})).json()
    assert [i["id"] for i in first["items"]] == [detail["items"][0]["id"]]
    if total > 1:
        assert [i["id"] for i in second["items"]] == [detail["items"][1]["id"]]
    for bad in ({"outcome": "deleted"}, {"limit": 0}, {"limit": 101}, {"offset": -1}):
        assert (await c.get(url, params=bad)).status_code == 422, bad

    email = unique_email("analyst")
    await add_member(t.org_id, await make_user(email), MemberRole.ANALYST)
    analyst = await login(email)
    assert (await analyst.get(f"{API}/{t.org_id}/retention/runs")).status_code == 403
    no_run = await analyst.post(f"{API}/{t.org_id}/retention/runs", json={}, headers=csrf(analyst))
    assert no_run.status_code == 403


async def test_a_run_out_of_its_slice_is_requeued_and_resumes(
    captured: Captured, aged: tuple[Any, Tenant, AgedCase], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, t, case = aged
    await seed_retention_policy(t, closed_case_days=30, ai_runs_days=30, enforce=True)
    await worker_module.sweep()
    [(org_id, run_id)] = captured.enqueued
    original = worker_module._Run.timed_out
    monkeypatch.setattr(worker_module._Run, "timed_out", lambda self: True)
    first = await worker_module.run_org(org_id, run_id)
    assert first.status == "running"
    assert captured.enqueued == [(org_id, run_id), (org_id, run_id)]  # same run id
    row = await run_row(org_id, run_id)
    assert row.status == "running" and row.finished_at is None

    monkeypatch.setattr(worker_module._Run, "timed_out", original)
    resumed = await worker_module.run_org(org_id, run_id)
    assert resumed.status == "completed"
    row = await run_row(org_id, run_id)
    assert row.counts["_slices"]["n"] == 2
    assert row.counts["ai_runs"]["candidates"] == 2
    purged = {i["ref_id"] for i in await items(t.org_id, run_id) if i["ref_table"] == "evidence"}
    assert purged == {str(case.pcap_evidence_id), str(case.static_evidence_id)}
    # A final run is never resumed.
    assert (await worker_module.run_org(org_id, run_id)).status == "completed"


async def test_cited_bulk_rows_survive_an_enforce_run(
    captured: Captured, aged: tuple[Any, Tenant, AgedCase]
) -> None:
    _, t, case = aged
    async with tenant_session(t.org_id, None) as s:
        flow_id = (
            await s.execute(
                text("SELECT id FROM network_flows WHERE job_id = :j ORDER BY id LIMIT 1"),
                {"j": case.pcap_job_id},
            )
        ).scalar_one()
    await _cite(t, case.investigation_id, [("flow", "network_flows", str(flow_id))])
    await seed_retention_policy(t, closed_case_days=30, enforce=True)
    run_id = await run_once(captured, t.org_id)
    kept = [i for i in await items(t.org_id, run_id) if i["outcome"] == "kept_cited"]
    assert [(i["ref_table"], i["ref_id"], i["rows"]) for i in kept] == [
        ("network_flows", str(case.pcap_job_id), 1)
    ]
    async with tenant_session(t.org_id, None) as s:
        left = (await s.execute(text("SELECT id FROM network_flows"))).scalars().all()
    assert left == [flow_id]
    assert (await run_row(t.org_id, run_id)).counts["closed_case"]["kept_cited"] == 1
