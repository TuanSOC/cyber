"""The shared selector and the API preview (M7 phase 3):

- an aged closed (or archived) case is selected; a reopened one, one closed too recently, one
  without a status event (closed before M6) and one with a running job are not (RT24);
- held cases are excluded, and so are cases whose hold was released less than the delay ago
  (RT1); an org hold excludes everything;
- cited TI, AI and bulk rows are kept (`kept_cited`, RT23);
- a TI answer reused by a recent `cached` item is kept, and an AI run tree with one recent or
  cited member is kept whole (RT10);
- the counts are deterministic; the preview records a manual dry-run run and is audited.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text, update

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import AiTask
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.organizations.models import MemberRole
from app.modules.reports.models import ReportCitation
from app.modules.retention.select import EffectivePolicy, candidates
from app.modules.threat_intel.models import TiEnrichmentRun, TiResult, TiRunItem
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key
from tests.ai_helpers import seed_ai_run
from tests.case_helpers import seed_case, seed_evidence, seed_job_on
from tests.factories import add_member, csrf, login, make_user, unique_email
from tests.integration.seed import Tenant
from tests.integration.test_retention_purge import (
    ALL,
    Captured,
    aged,
    captured,
    owner_tenant,
    select_now,
)
from tests.ops_helpers import (
    AgedCase,
    _finish_ai_run,
    days_ago,
    retention_session,
    seed_hold,
    seed_released_hold,
    seed_retention_policy,
)
from tests.report_helpers import new_signing_keys, seed_report, seed_version

API = "/api/v1/orgs"
__all__ = ["aged", "captured"]


async def _event(t: Tenant, case_id: uuid.UUID, frm: str, to: str, at: datetime) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "INSERT INTO investigation_status_events (organization_id, investigation_id, "
                "from_status, to_status, reason, actor_id, occurred_at) VALUES "
                "(:o, :i, :f, :t, 'Reason', :a, :at)"
            ),
            {"o": t.org_id, "i": case_id, "f": frm, "t": to, "a": t.owner_id, "at": at},
        )
        await s.execute(
            update(Investigation)
            .where(Investigation.id == case_id)
            .values(status=InvestigationStatus(to))
        )


async def _closed_case(
    t: Tenant, *, closed_days_ago: float = 400, status: str = "closed", event: bool = True
) -> tuple[uuid.UUID, uuid.UUID]:
    """A light case: one evidence row (no object) and a backdated closing event."""
    case_id = await seed_case(t, title=f"Light {status}")
    evidence_id = await seed_evidence(t, case_id)
    if event:
        await _event(t, case_id, "open", status, days_ago(closed_days_ago))
    else:
        async with tenant_session(t.org_id, t.owner_id) as s:
            await s.execute(
                update(Investigation)
                .where(Investigation.id == case_id)
                .values(status=InvestigationStatus(status))
            )
    return case_id, evidence_id


def _evidence_ids(found: Any) -> set[str]:
    return {c.ref_id for c in found.candidates if c.ref_table == "evidence"}


async def test_which_cases_are_selected(captured: Captured) -> None:
    _, t = await owner_tenant()
    aged_closed, aged_ev = await _closed_case(t)
    archived, archived_ev = await _closed_case(t, status="archived")
    recent, recent_ev = await _closed_case(t, closed_days_ago=10)
    no_event, no_event_ev = await _closed_case(t, event=False)
    reopened, reopened_ev = await _closed_case(t)
    await _event(t, reopened, "closed", "in_progress", days_ago(5))
    reclosed, reclosed_ev = await _closed_case(t)
    await _event(t, reclosed, "closed", "in_progress", days_ago(20))
    await _event(t, reclosed, "in_progress", "closed", days_ago(10))
    busy, busy_ev = await _closed_case(t)
    await seed_job_on(t, busy_ev, "pcap", status="running")

    found = await select_now(t.org_id, EffectivePolicy(None, None, 30, enforce=False))
    assert _evidence_ids(found) == {str(aged_ev), str(archived_ev)}
    for excluded in (recent_ev, no_event_ev, reopened_ev, reclosed_ev, busy_ev):
        assert str(excluded) not in _evidence_ids(found)
    assert {c.investigation_id for c in found.candidates} == {aged_closed, archived}
    assert found.counts["closed_case"].candidates == 2
    assert not {recent, no_event, busy, reopened, reclosed} & {
        c.investigation_id for c in found.candidates
    }


async def test_holds_exclude_cases_including_during_the_release_delay(captured: Captured) -> None:
    _, t = await owner_tenant()
    held, held_ev = await _closed_case(t)
    released_recently, recent_ev = await _closed_case(t)
    released_long_ago, old_ev = await _closed_case(t)
    await seed_hold(t, investigation_id=held)
    await seed_released_hold(t, 1, investigation_id=released_recently)
    await seed_released_hold(t, 30, investigation_id=released_long_ago)
    found = await select_now(t.org_id, EffectivePolicy(None, None, 30, enforce=False))
    assert _evidence_ids(found) == {str(old_ev)}
    assert found.counts["closed_case"].skipped_hold == 2
    assert str(held_ev) not in _evidence_ids(found) and str(recent_ev) not in _evidence_ids(found)

    await seed_hold(t)  # an org hold: nothing at all
    found = await select_now(t.org_id, ALL)
    assert found.candidates == [] and found.counts["closed_case"].candidates == 0


async def _old_ti_result(t: Tenant, value: str, *, job_id: uuid.UUID | None = None) -> uuid.UUID:
    key = compute_ioc_key(IocType.DOMAIN, value)
    finished = days_ago(400)
    run_id = uuid.uuid4()
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            TiEnrichmentRun(
                id=run_id,
                organization_id=t.org_id,
                scope="job" if job_id else "manual",
                job_id=job_id,
                requested_by=t.owner_id,
                providers=["mock"],
                status="completed",
                deadline_at=finished + timedelta(minutes=30),
                started_at=finished - timedelta(minutes=1),
                finished_at=finished,
            )
        )
        await s.flush()
        result = TiResult(
            organization_id=t.org_id,
            run_id=run_id,
            provider="mock",
            ioc_type="domain",
            value_norm=value,
            ioc_key=key,
            status="ok",
            found=False,
            summary={"provider": "mock"},
            fetched_at=finished,
            expires_at=finished + timedelta(hours=1),
        )
        s.add(result)
        await s.flush()
        s.add(
            TiRunItem(
                run_id=run_id,
                organization_id=t.org_id,
                seq=0,
                provider="mock",
                ioc_type="domain",
                value_norm=value,
                ioc_key=key,
                state="done",
                result_id=result.id,
            )
        )
    return result.id


async def _cite(t: Tenant, case_id: uuid.UUID, refs: list[tuple[str, str, str]]) -> None:
    """A finalized report version on the case citing (kind, ref_table, ref_id)."""
    report_id = await seed_report(t, case_id)
    version = await seed_version(t, report_id, new_signing_keys())
    async with tenant_session(t.org_id, t.owner_id) as s:
        for n, (kind, table, ref_id) in enumerate(refs, start=1):
            s.add(
                ReportCitation(
                    organization_id=t.org_id,
                    version_id=version.version_id,
                    cite_no=n,
                    kind=kind,
                    ref_table=table,
                    ref_id=ref_id,
                    fields_sha256=hashlib.sha256(secrets.token_bytes(8)).hexdigest(),
                    source="selection",
                )
            )


async def test_cited_rows_reuse_and_run_trees_are_kept(
    captured: Captured, aged: tuple[Any, Tenant, AgedCase]
) -> None:
    _, t, case = aged
    cited_ti = await _old_ti_result(t, "cited.example.com")
    free_ti = await _old_ti_result(t, "free.example.com")
    # AI: a second old tree with one recent member, and an old tree whose parent is cited.
    light, light_ev = await _closed_case(t)
    job = await seed_job_on(t, light_ev, "pcap")
    lt = Tenant(t.org_id, t.owner_id, light)
    young_parent = await seed_ai_run(lt, job_id=job)
    young_child = await seed_ai_run(
        lt, job_id=job, task=AiTask.JOB_DIGEST, parent_run_id=young_parent
    )
    await _finish_ai_run(t, young_parent, days_ago(400))
    await _finish_ai_run(t, young_child, days_ago(1))
    cited_run = await seed_ai_run(lt, job_id=job)
    await _finish_ai_run(t, cited_run, days_ago(400))
    async with tenant_session(t.org_id, None) as s:
        flow_id = (
            await s.execute(
                text("SELECT id FROM network_flows WHERE job_id = :j ORDER BY id LIMIT 1"),
                {"j": case.pcap_job_id},
            )
        ).scalar_one()
        flows = (
            await s.execute(
                text("SELECT count(*) FROM network_flows WHERE job_id = :j"),
                {"j": case.pcap_job_id},
            )
        ).scalar_one()
    await _cite(
        t,
        light,
        [
            ("ti_result", "ti_results", str(cited_ti)),
            ("flow", "network_flows", str(flow_id)),
            ("job", "ai_runs", str(cited_run)),
        ],
    )

    found = await select_now(t.org_id)
    ti = {c.ref_id for c in found.candidates if c.category == "ti_results"}
    assert ti == {str(free_ti)}  # the reused aged answer and the cited one stay
    assert found.counts["ti_results"].kept_cited == 1
    ai = {c.ref_id for c in found.candidates if c.category == "ai_runs"}
    assert ai == {str(case.ai_parent_run_id), str(case.ai_child_run_id)}
    assert found.counts["ai_runs"].kept_cited == 1
    flows_candidate = [
        c
        for c in found.candidates
        if c.ref_table == "network_flows" and c.ref_id == str(case.pcap_job_id)
    ]
    assert len(flows_candidate) == 1 and flows_candidate[0].rows == flows - 1
    assert found.counts["closed_case"].kept_cited >= 1

    # Determinism: the same rows and `now` give the same set.
    at = datetime.now(UTC)
    async with retention_session(t.org_id) as s:
        first = await candidates(s, t.org_id, ALL, now=at, limit=10_000)
    async with retention_session(t.org_id) as s:
        second = await candidates(s, t.org_id, ALL, now=at, limit=10_000)
    assert first == second
    # The limit lists fewer but counts all (AI trees are never split).
    async with retention_session(t.org_id) as s:
        small = await candidates(s, t.org_id, ALL, now=at, limit=1)
    assert small.truncated and small.counts == first.counts
    assert len([c for c in small.candidates if c.category == "ai_runs"]) == 2


async def test_the_preview_route(captured: Captured, aged: tuple[Any, Tenant, AgedCase]) -> None:
    reg, t, case = aged
    await seed_retention_policy(t, closed_case_days=90, enforce=True)
    c = reg.client
    response = await c.post(f"{API}/{t.org_id}/retention/preview", json={}, headers=csrf(c))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["policy"] == {"ti_results_days": None, "ai_runs_days": None, "closed_case_days": 90}
    assert body["counts"]["closed_case"]["candidates"] > 0
    assert body["counts"]["ai_runs"]["candidates"] == 0
    assert body["truncated"] is False and body["holds_active"] == 0
    assert {s["category"] for s in body["sample"]} == {"closed_case"}
    assert all("object_key" not in s for s in body["sample"])
    # Values in the body replace the effective ones (null = keep forever).
    wider = await c.post(
        f"{API}/{t.org_id}/retention/preview",
        json={"ai_runs_days": 30, "closed_case_days": None},
        headers=csrf(c),
    )
    assert wider.status_code == 200
    assert wider.json()["counts"]["ai_runs"]["candidates"] == 2
    assert wider.json()["counts"]["closed_case"]["candidates"] == 0
    floor = await c.post(
        f"{API}/{t.org_id}/retention/preview", json={"ti_results_days": 7}, headers=csrf(c)
    )
    assert floor.status_code == 422 and floor.json()["error"]["code"] == "policy_floor"

    # Recorded as manual dry-run runs, audited; nothing deleted.
    runs = (await c.get(f"{API}/{t.org_id}/retention/runs")).json()
    assert runs["total"] == 2
    assert {(r["mode"], r["trigger"], r["status"]) for r in runs["items"]} == {
        ("dry_run", "manual", "completed")
    }
    detail = (await c.get(f"{API}/{t.org_id}/retention/runs/{runs['items'][-1]['id']}")).json()
    assert detail["sample"] and detail["items_total"] == 0
    async with tenant_session(t.org_id, None) as s:
        audited = (
            await s.execute(
                text("SELECT count(*) FROM audit_logs WHERE action = 'retention.previewed'")
            )
        ).scalar_one()
        flows = (await s.execute(text("SELECT count(*) FROM network_flows"))).scalar_one()
    assert audited == 2 and flows > 0
    assert case.pcap_evidence_id

    email = unique_email("analyst")
    await add_member(t.org_id, await make_user(email), MemberRole.ANALYST)
    analyst = await login(email)
    denied = await analyst.post(
        f"{API}/{t.org_id}/retention/preview", json={}, headers=csrf(analyst)
    )
    assert denied.status_code == 403
