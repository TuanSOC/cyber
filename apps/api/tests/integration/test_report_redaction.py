"""Redaction profiles (M6 phase 3; RT2, RT8): in `external`, no seeded internal IP, host,
user, custody IP, note, deep link or `base_url` survives anywhere in the canonical bytes
(single-label hosts and bare usernames in free text included), and one report-level
pseudonym map covers every section and AI run; `internal` reverses each run's pseudonyms."""

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.core.config import get_settings
from app.modules.pcap_analysis.models import AnalysisFinding
from app.modules.reports.citations import fields_sha256
from tests import pcap_results
from tests.case_helpers import seed_note, seed_status_event
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.report_helpers import purge_reports_test_bucket, use_signing_keys
from tests.security.idor_cases_reports import (
    API,
    Dispatched,
    ai_run_on,
    api_create,
    api_finalize,
    api_patch,
    dns,
    draft,
    fake_case_iocs,
    fake_dispatch,
    owner_case,
    pcap_job,
    rows_of,
    static_job,
    user_string,
)

PSEUDONYM = re.compile(r"\b(?:INT_IP|INT_HOST|USER)_\d+\b")


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Dispatched]:
    use_signing_keys(monkeypatch, tmp_path)
    fake_case_iocs(monkeypatch)
    monkeypatch.setattr(get_settings(), "public_base_url", "https://cyberlab.example.org")
    yield fake_dispatch(monkeypatch)
    purge_reports_test_bucket()


async def _finalized(reg: Registered, report_id: str, **body: Any) -> bytes:
    response = await api_finalize(reg, report_id, **body)
    assert response.status_code == 201, response.text
    version = response.json()["version"]
    content = await reg.client.get(
        f"{API}/{reg.org_id}/reports/{report_id}/versions/{version}/content"
    )
    assert content.status_code == 200, content.text
    return content.content


async def _seeded_case() -> tuple[Registered, Tenant, dict[str, Any]]:
    reg, t = await owner_case(title="Incident on FIN-SRV-01")
    await seed_status_event(
        t, t.investigation_id, reason="jdoe reported FIN-SRV-01 from 10.20.30.40"
    )
    records = [*pcap_results.sample_records(), dns("FIN-SRV-01"), dns("files.corp", 12)]
    evidence_id, job = await pcap_job(reg, t, records, filename="FIN-SRV-01.pcap")
    await static_job(reg, t, [user_string("C:\\Users\\jdoe\\AppData\\Local\\Temp\\drop.exe")])
    # Included in reports: the note also reaches the case timeline (a `note` entry whose
    # title is the body), which the external profile must drop too (phase 9 e2e finding).
    note = await seed_note(
        t, bodies=("NOTE-SECRET-42 seen on FIN-SRV-01",), include_in_reports=True
    )
    return reg, t, {"evidence_id": evidence_id, "job": job, "note": note}


async def test_external_leaves_no_internal_value(sent: Dispatched) -> None:
    reg, t, seeded = await _seeded_case()
    report = (await api_create(reg, t, profile="external")).json()
    summary = (
        "FIN-SRV-01 contacted evil.example; jdoe opened the attachment on 10.20.30.40 "
        "and files.corp was mounted."
    )
    patched = await api_patch(
        reg,
        report["id"],
        distribution="Partner CERT (FIN-SRV-01 owners)",
        draft=draft(
            sections={"executive_summary": summary, "scope": "Workstation fin-srv-01"},
            notes=[str(seeded["note"])],
            cited_rows=[{"kind": "evidence", "ref_id": str(seeded["evidence_id"])}],
            iocs={"case_iocs": True},
        ),
    )
    assert patched.status_code == 200, patched.text
    data = await _finalized(reg, report["id"], acknowledge_external_review=True)
    text = data.decode("utf-8")
    lowered = text.lower()
    for sentinel in (
        "fin-srv-01",
        "jdoe",
        "10.20.30.40",
        "10.0.0.5",
        "10.0.0.9",
        "10.0.0.1",
        "files.corp",
        "files[.]corp",
        "note-secret-42",
        "cyberlab.example.org",
        "/o/",
        reg.email.lower(),
        reg.email.split("@")[0].lower(),
    ):
        assert sentinel not in lowered, sentinel
    snap = json.loads(data)
    assert snap["report"]["base_url"] is None
    assert snap["report"]["generated_by"] == "Owner"
    assert snap["notes"]["items"] == []
    assert [i for i in snap["timeline"]["items"] if i["kind"] == "note"] == []
    assert snap["notes"] == {"items": [], "total": 0}
    assert all(c["ip"] is None and c["user_agent"] is None for c in snap["custody"]["items"])
    assert all(c["path"] is None for c in snap["citations"]["items"])
    assert {e["actor"] for e in snap["case"]["status_history"]} == {"Owner"}
    # One mapping: the same host has the same pseudonym in the title, the summary, the
    # status reason and the evidence filename.
    host = re.search(r"INT_HOST_\d+", snap["case"]["title"])
    assert host is not None
    assert host.group(0) in snap["sections"]["executive_summary"]
    assert host.group(0) in snap["sections"]["scope"]
    assert host.group(0) in snap["case"]["status_history"][0]["reason"]
    assert any(e["filename"].startswith(host.group(0)) for e in snap["evidence"]["items"])
    assert "USER_" in snap["sections"]["executive_summary"]
    for c in snap["citations"]["items"]:
        assert fields_sha256(c["fields"]) == c["fields_sha256"]


async def test_one_report_level_map_across_ai_runs(sent: Dispatched) -> None:
    reg, t = await owner_case()
    _, job_a = await pcap_job(reg, t)
    _, job_b = await pcap_job(reg, t, filename="second.pcap")
    fa = await rows_of(t, AnalysisFinding, job_a)
    fb = await rows_of(t, AnalysisFinding, job_b)
    # Both runs call their own (different) host INT_HOST_1.
    run_a = await ai_run_on(
        t,
        job_a,
        claims=[("o1", "Beacon from INT_HOST_1 every minute", [("finding", str(fa[0].id))])],
        pseudonym_map={"INT_HOST_1": "alpha.corp"},
    )
    run_b = await ai_run_on(
        t,
        job_b,
        claims=[("o1", "INT_HOST_1 resolved a rare domain", [("finding", str(fb[0].id))])],
        pseudonym_map={"INT_HOST_1": "beta.corp"},
    )
    internal = (await api_create(reg, t)).json()
    external = (await api_create(reg, t, profile="external")).json()
    for report in (internal, external):
        response = await api_patch(
            reg,
            report["id"],
            distribution="IR partners",
            draft=draft(
                sections={"executive_summary": "alpha.corp is the beaconing host."},
                ai_runs=[str(run_a), str(run_b)],
            ),
        )
        assert response.status_code == 200, response.text

    inside = json.loads(await _finalized(reg, internal["id"]))
    texts = {run["run_id"]: run["claims"][0]["text"] for run in inside["ai"]["items"]}
    assert texts[str(run_a)] == "Beacon from alpha[.]corp every minute"
    assert texts[str(run_b)] == "beta[.]corp resolved a rare domain"

    outside_bytes = await _finalized(reg, external["id"], acknowledge_external_review=True)
    assert b"alpha" not in outside_bytes and b"beta" not in outside_bytes
    outside = json.loads(outside_bytes)
    names = {
        run["run_id"]: PSEUDONYM.findall(run["claims"][0]["text"]) for run in outside["ai"]["items"]
    }
    [a] = names[str(run_a)]
    [b] = names[str(run_b)]
    assert a != b
    assert PSEUDONYM.findall(outside["sections"]["executive_summary"]) == [a]
