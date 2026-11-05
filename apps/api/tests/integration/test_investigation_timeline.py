"""Merged investigation timeline route (M5 phase 4)."""

import uuid
from datetime import datetime
from typing import Any

import pytest
from cyberlab_jobs.results import TimelineEvent

from app.modules.analysis import dispatch
from tests import pcap_results as pr
from tests import static_results
from tests.analysis_helpers import SentJobs, jobs_for, new_case, upload
from tests.factories import Registered, csrf, register
from tests.pcap_results import at

API = "/api/v1/orgs"


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _pcap_job(reg: Registered, evidence_id: str) -> uuid.UUID:
    response = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


async def _case(reg: Registered) -> tuple[str, str, uuid.UUID, uuid.UUID]:
    """A case with one evidence that has a succeeded static job and a succeeded pcap job."""
    case_id = await new_case(reg)
    evidence = await upload(reg.client, reg.org_id, case_id, b"timeline evidence", "e.bin")
    jobs = await jobs_for(reg.client, reg.org_id, evidence["id"])
    [static_job] = [j for j in jobs if j["analyzer"] == "static"]
    await static_results.seed_results(reg.org_id, uuid.UUID(static_job["id"]))
    pcap_job = await _pcap_job(reg, evidence["id"])
    await pr.seed_results(reg.org_id, pcap_job)
    return case_id, evidence["id"], uuid.UUID(static_job["id"]), pcap_job


async def _get(reg: Registered, case_id: str, **params: Any) -> Any:
    response = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{case_id}/timeline", params=params
    )
    assert response.status_code == 200, response.text
    return response.json()


def _key(entry: dict[str, Any]) -> tuple[datetime, str, str]:
    return (datetime.fromisoformat(entry["ts"]), entry["kind"], entry["ref_id"])


async def test_merges_every_source_in_order(sent: SentJobs) -> None:
    reg = await register()
    case_id, evidence_id, static_job, pcap_job = await _case(reg)
    body = await _get(reg, case_id, limit=500)
    items = body["items"]
    assert body["next_cursor"] is None
    assert items == sorted(items, key=_key)
    kinds = [e["kind"] for e in items]
    # Custody (upload, analysis requested, analyzed ...), job lifecycle, capture and findings.
    assert "custody_uploaded" in kinds
    assert kinds.count("analysis_requested") == 2
    assert kinds.count("analysis_succeeded") == 2
    capture = [e for e in items if e["kind"] == "capture_event"]
    assert [e["title"] for e in capture] == ["Capture start", "Periodic connections", "Capture end"]
    assert all(e["ts_source"] == "capture" and e["job_id"] == str(pcap_job) for e in capture)
    alerts = [e for e in items if e["kind"] == "alert"]
    assert sorted(e["title"] for e in alerts) == ["ET POLICY test signature", "ET SCAN probe"]
    assert {e["severity"] for e in alerts} == {"high", "low"}
    findings = [e for e in items if e["kind"] == "finding"]
    # Only static findings (pcap findings are already capture events), at analysis time.
    assert sorted(e["title"] for e in findings) == [
        "Process-injection API set present",
        "Section with packer-like entropy",
    ]
    assert all(e["ts_source"] == "analysis_time" for e in findings)
    assert all(e["job_id"] == str(static_job) and e["ref_kind"] == "finding" for e in findings)
    recorded = [e for e in items if e["kind"].startswith(("custody_", "analysis_"))]
    assert all(e["ts_source"] == "recorded" for e in recorded)
    assert all(e["evidence_id"] == evidence_id for e in items)
    upload_entry = next(e for e in items if e["kind"] == "custody_uploaded")
    assert upload_entry["title"] == "Evidence uploaded: e.bin"
    assert upload_entry["ref_kind"] == "custody" and upload_entry["job_id"] is None
    # Capture time (2024) sorts before the platform events of today.
    assert kinds[0] == "capture_event"


async def test_cursor_pages_cover_everything_once(sent: SentJobs) -> None:
    reg = await register()
    case_id, *_ = await _case(reg)
    everything = (await _get(reg, case_id, limit=500))["items"]
    seen: list[dict[str, Any]] = []
    cursor = None
    while True:
        params: dict[str, Any] = {"limit": 3}
        if cursor:
            params["cursor"] = cursor
        page = await _get(reg, case_id, **params)
        assert len(page["items"]) <= 3
        seen.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == everything


async def test_only_the_latest_pcap_job_contributes(sent: SentJobs) -> None:
    reg = await register()
    case_id, evidence_id, _, first = await _case(reg)
    second = await _pcap_job(reg, evidence_id)
    records = [TimelineEvent(ts=at(7), event="first_contact", title="Second run contact")]
    await pr.seed_results(reg.org_id, second, pr.stream(second, records))
    items = (await _get(reg, case_id, limit=500))["items"]
    capture = [e for e in items if e["kind"] == "capture_event"]
    assert [e["title"] for e in capture] == ["Second run contact"]
    assert all(e["job_id"] == str(second) for e in capture)
    assert not [e for e in items if e["kind"] == "alert"]  # the latest run has no alerts
    # Lifecycle events of both runs stay.
    assert {e["ref_id"] for e in items if e["kind"] == "analysis_succeeded"} >= {
        str(first),
        str(second),
    }


async def test_errors_and_isolation(sent: SentJobs) -> None:
    victim = await register(org_name="Victim")
    case_id, *_ = await _case(victim)
    attacker = await register(org_name="Attacker")
    for org in (victim.org_id, attacker.org_id):
        response = await attacker.client.get(f"{API}/{org}/investigations/{case_id}/timeline")
        assert response.status_code == 404, response.text
    unknown = await victim.client.get(
        f"{API}/{victim.org_id}/investigations/{uuid.uuid4()}/timeline"
    )
    assert unknown.status_code == 404
    bad = await victim.client.get(
        f"{API}/{victim.org_id}/investigations/{case_id}/timeline", params={"cursor": "!!nope"}
    )
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "invalid_cursor"
    too_many = await victim.client.get(
        f"{API}/{victim.org_id}/investigations/{case_id}/timeline", params={"limit": 501}
    )
    assert too_many.status_code == 422


async def test_empty_case_has_an_empty_timeline() -> None:
    reg = await register()
    case_id = await new_case(reg)
    assert await _get(reg, case_id) == {"items": [], "next_cursor": None}
