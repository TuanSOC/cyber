"""`GET /orgs/{org}/analyses?investigation_id=&latest_per_evidence=` (M5 phase 4)."""

import re
import uuid
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisStatus
from app.modules.analysis.repository import matching_jobs
from tests import pcap_results as pr
from tests.analysis_helpers import SentJobs, jobs_for, new_case, upload
from tests.factories import Registered, csrf, register

API = "/api/v1/orgs"


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _pcap_job(reg: Registered, evidence_id: str) -> str:
    response = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def _list(reg: Registered, **params: Any) -> Any:
    response = await reg.client.get(f"{API}/{reg.org_id}/analyses", params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def _setup(reg: Registered) -> dict[str, Any]:
    """Case A: e1 (static auto + two pcap runs, the first succeeded) and e2 (static auto).
    Case B: e3 (static auto)."""
    case_a, case_b = await new_case(reg), await new_case(reg)
    e1 = await upload(reg.client, reg.org_id, case_a, b"first evidence", "one.bin")
    e2 = await upload(reg.client, reg.org_id, case_a, b"second evidence", "two.bin")
    e3 = await upload(reg.client, reg.org_id, case_b, b"third evidence", "three.bin")
    pcap_old = await _pcap_job(reg, e1["id"])
    await pr.seed_results(reg.org_id, uuid.UUID(pcap_old))
    pcap_new = await _pcap_job(reg, e1["id"])  # queued
    static = {
        e["id"]: [
            j["id"]
            for j in await jobs_for(reg.client, reg.org_id, e["id"])
            if j["analyzer"] == "static"
        ][0]
        for e in (e1, e2, e3)
    }
    return {
        "case_a": case_a,
        "case_b": case_b,
        "e1": e1["id"],
        "e2": e2["id"],
        "pcap_old": pcap_old,
        "pcap_new": pcap_new,
        "static": static,
        "e3": e3["id"],
    }


async def test_investigation_filter_and_latest_per_evidence(sent: SentJobs) -> None:
    reg = await register()
    s = await _setup(reg)
    page = await _list(reg, investigation_id=s["case_a"])
    ids = [j["id"] for j in page["items"]]
    expected = {s["pcap_old"], s["pcap_new"], s["static"][s["e1"]], s["static"][s["e2"]]}
    assert set(ids) == expected and page["total"] == 4
    assert all(j["investigation_id"] == s["case_a"] for j in page["items"])
    created = [j["created_at"] for j in page["items"]]
    assert created == sorted(created, reverse=True)  # newest first, as before

    latest = await _list(reg, investigation_id=s["case_a"], latest_per_evidence="true")
    assert {j["id"] for j in latest["items"]} == {
        s["pcap_new"],
        s["static"][s["e1"]],
        s["static"][s["e2"]],
    }
    assert latest["total"] == 3

    succeeded = await _list(
        reg, investigation_id=s["case_a"], latest_per_evidence="true", status="succeeded"
    )
    assert [j["id"] for j in succeeded["items"]] == [s["pcap_old"]]

    pcap_only = await _list(reg, investigation_id=s["case_a"], analyzer="pcap")
    assert {j["id"] for j in pcap_only["items"]} == {s["pcap_old"], s["pcap_new"]}

    paged = await _list(reg, investigation_id=s["case_a"], limit=1, offset=1)
    assert paged["total"] == 4 and [j["id"] for j in paged["items"]] == ids[1:2]

    case_b = await _list(reg, investigation_id=s["case_b"])
    assert [j["id"] for j in case_b["items"]] == [s["static"][s["e3"]]]

    # Without the new filters the org-wide list is unchanged; latest also works org-wide.
    everything = await _list(reg)
    assert everything["total"] == 5
    org_latest = await _list(reg, latest_per_evidence="true")
    assert org_latest["total"] == 4


async def test_foreign_or_unknown_investigation_is_404(sent: SentJobs) -> None:
    victim = await register(org_name="Victim")
    s = await _setup(victim)
    attacker = await register(org_name="Attacker")
    for reg, case in ((attacker, s["case_a"]), (victim, str(uuid.uuid4()))):
        response = await reg.client.get(
            f"{API}/{reg.org_id}/analyses", params={"investigation_id": case}
        )
        assert response.status_code == 404, response.text
    bad = await victim.client.get(
        f"{API}/{victim.org_id}/analyses", params={"investigation_id": "nope"}
    )
    assert bad.status_code == 422


async def test_investigation_filter_uses_the_indexes(sent: SentJobs) -> None:
    reg = await register()
    s = await _setup(reg)
    stmt = matching_jobs(
        reg.org_id,
        investigation_id=uuid.UUID(s["case_a"]),
        status=AnalysisStatus.SUCCEEDED,
        latest_per_evidence=True,
    )
    sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    async with tenant_session(reg.org_id, reg.user_id) as session:
        await session.execute(text("SET LOCAL enable_seqscan = off"))
        plan = "\n".join(row[0] for row in await session.execute(text(f"EXPLAIN {sql}")))
    # Both tables are reachable through an index for the case filter (no forced seq scan).
    assert "Seq Scan" not in plan, plan
    assert re.search(r"Index (Only )?Scan using \S+ on evidence", plan), plan
    assert re.search(r"Index (Only )?Scan using \S+ on analysis_jobs", plan), plan
