"""`ref=` row filters on the pcap and static result routes (citation deep links, M5 phase 4)."""

import uuid
from typing import Any

import pytest

from app.modules.analysis import dispatch
from tests import pcap_results as pr
from tests import static_results
from tests.analysis_helpers import SentJobs, jobs_for, new_case, upload
from tests.factories import Registered, csrf, register

API = "/api/v1/orgs"
PCAP_ROUTES = ("findings", "alerts", "iocs", "records", "timeline")
STATIC_ROUTES = ("signatures", "capabilities", "strings", "imports")


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _jobs(reg: Registered) -> tuple[str, str]:
    """(pcap job, static job), both with results, on one evidence."""
    case_id = await new_case(reg)
    evidence = await upload(reg.client, reg.org_id, case_id, b"ref evidence", "ref.bin")
    [static_job] = [
        j["id"]
        for j in await jobs_for(reg.client, reg.org_id, evidence["id"])
        if j["analyzer"] == "static"
    ]
    await static_results.seed_results(reg.org_id, uuid.UUID(static_job))
    response = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )
    pcap_job = response.json()["id"]
    await pr.seed_results(reg.org_id, uuid.UUID(pcap_job))
    return pcap_job, static_job


async def _get(reg: Registered, job: str, route: str, **params: Any) -> Any:
    return await reg.client.get(f"{API}/{reg.org_id}/analyses/{job}/{route}", params=params)


async def _rows(reg: Registered, job: str, route: str) -> list[dict[str, Any]]:
    response = await _get(reg, job, route, limit=100)
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    assert len(items) >= 2, route  # a ref filter must narrow a real page
    return items


@pytest.mark.parametrize(
    ("route", "static"),
    [*((r, False) for r in PCAP_ROUTES), *((r, True) for r in STATIC_ROUTES)],
)
async def test_ref_returns_exactly_that_row(route: str, static: bool, sent: SentJobs) -> None:
    reg = await register()
    pcap_job, static_job = await _jobs(reg)
    job = static_job if static else pcap_job
    rows = await _rows(reg, job, route)
    target = rows[-1]
    response = await _get(reg, job, route, ref=target["id"])
    assert response.status_code == 200, response.text
    assert response.json() == {"items": [target], "total": 1}
    # Unknown row, a row of another job (same org), and a malformed id.
    other = static_job if not static else pcap_job
    for ref in (str(uuid.uuid4()), (await _first_id(reg, other)) or str(uuid.uuid4())):
        missing = await _get(reg, job, route, ref=ref)
        assert missing.status_code == 404, (route, missing.text)
    assert (await _get(reg, job, route, ref="F1")).status_code == 422


async def _first_id(reg: Registered, job: str) -> str | None:
    """Any result row id of the other job (findings / iocs exist for both analyzers)."""
    response = await _get(reg, job, "findings", limit=1)
    items = response.json()["items"] if response.status_code == 200 else []
    return items[0]["id"] if items else None


async def test_ref_combines_with_the_other_filters(sent: SentJobs) -> None:
    reg = await register()
    pcap_job, _ = await _jobs(reg)
    findings = await _rows(reg, pcap_job, "findings")
    high = next(f for f in findings if f["severity"] == "high")
    ok = await _get(reg, pcap_job, "findings", ref=high["id"], severity="high")
    assert ok.json()["total"] == 1
    filtered_out = await _get(reg, pcap_job, "findings", ref=high["id"], severity="low")
    assert filtered_out.status_code == 404


async def test_flows_are_referenced_by_flow_ref_within_the_job(sent: SentJobs) -> None:
    reg = await register()
    pcap_job, static_job = await _jobs(reg)
    response = await _get(reg, pcap_job, "flows", ref="C00000002")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1 and body["items"][0]["flow_ref"] == "C00000002"
    assert (await _get(reg, pcap_job, "flows", ref="C99999999")).status_code == 404
    assert (await _get(reg, pcap_job, "flows", ref="bad ref")).status_code == 422
    # The same uid in another job of the org is not this job's flow (RT16).
    other = await _get(reg, static_job, "flows", ref="C00000002")
    assert other.status_code == 404


async def test_ref_never_crosses_organizations(sent: SentJobs) -> None:
    victim = await register(org_name="Victim")
    pcap_job, _ = await _jobs(victim)
    target = (await _rows(victim, pcap_job, "findings"))[0]
    attacker = await register(org_name="Attacker")
    for org in (victim.org_id, attacker.org_id):
        response = await attacker.client.get(
            f"{API}/{org}/analyses/{pcap_job}/findings", params={"ref": target["id"]}
        )
        assert response.status_code == 404
    # The attacker's own job cannot be used to read the victim's row either.
    own_job, _ = await _jobs(attacker)
    response = await _get(attacker, own_job, "findings", ref=target["id"])
    assert response.status_code == 404
