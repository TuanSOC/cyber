"""The real AI analyst pipeline (M5 phase 11): the API (`POST .../ai/runs`, the real context
builder over seeded results, the real `runs.dispatch`) -> broker (`test.analyst`) ->
`analyst-worker-test` (ACL user `analyst`, the dev AI seal key pair, its own limiter and
budget, `AI_CALL_TIMEOUT_S=8`) -> the `mock` adapter over `egress` -> `ai-mock` -> the real
verifier -> `ai_outputs` / `ai_citations` -> `GET .../ai/runs/{id}`.

No test beat runs: a waiting run is made due and `ai.resume` is sent by the test. `api-test`
cannot reach `ai-mock` (egress only), so what it received is read from the request mirror
it writes to the `ai_mock_state` volume (`TEST_AI_MOCK_STATE_FILE`, read-only here).

Behaviour is chosen by `ai-mock:<marker>` values seeded into the evidence (a finding title).
Only the default lane runs these (the worker serves broker db 1 and `cyberlab_test`).
"""

import asyncio
import json
import os
import time
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
from cyberlab_jobs import AI_RESUME, Queues
from cyberlab_jobs.results import (
    AlertRecord,
    DnsRecord,
    FindingRecord,
    HttpRecord,
    IocRecord,
    TimelineEvent,
    TlsRecord,
)
from httpx import AsyncClient
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import func, select, update

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.ai.budget import Budget
from app.modules.ai.models import AiRunIndex
from app.modules.analysis import dispatch
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert
from tests import pcap_results as pr
from tests.ai_api_helpers import API, enable_ai, put_settings, request_run
from tests.analysis_helpers import SentJobs, new_case, upload
from tests.factories import Registered, csrf, register
from tests.pcap_results import at, flow

MOCK_KEY = os.environ.get("TEST_AI_MOCK_EXPECTED_KEY", "cyberlab-ai-mock-key")
STATE_FILE = Path(os.environ.get("TEST_AI_MOCK_STATE_FILE", "/srv/ai-mock-state/ai-mock-last.json"))
FINAL = ("completed", "partial", "failed", "refused")
SETTLE_S = 90.0


def _default_lane() -> bool:
    return urlparse(get_settings().broker_url).path in ("/1", "")


pytestmark = pytest.mark.skipif(
    not _default_lane() or not STATE_FILE.parent.is_dir(),
    reason="needs analyst-worker-test + ai-mock (default test lane, ai_mock_state mounted)",
)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    """Analysis jobs are not run (their results are seeded); AI runs are really sent."""
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


@pytest.fixture
def broker() -> Iterator[Redis]:
    client = Redis.from_url(get_settings().broker_url)
    yield client


# --- seeding ---------------------------------------------------------------------------------


def records(marker: str = "", *, extra: list[BaseModel] | None = None) -> list[BaseModel]:
    """A small capture's results; `marker` goes into the first finding's title."""
    title = f"Beacon to 203.0.113.50 {marker}".strip()
    return [
        flow(1, src_ip="10.0.0.5", dst_ip="203.0.113.50", dst_port=8080),
        DnsRecord(
            ts=at(10),
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
            flow_ref="C00000001",
            query="update.example.net",
            qtype="A",
            answers=["203.0.113.50"],
        ),
        *(
            AlertRecord(
                ts=at(40 + i),
                src_ip="10.0.0.5",
                dst_ip="203.0.113.50",
                flow_ref="C00000001",
                signature_id=2_000_001,
                rev=1,
                signature="ET MALWARE beacon",
                severity=1,
            )
            for i in range(2)
        ),
        FindingRecord(
            ts=at(50),
            src_ip="10.0.0.5",
            src_port=40001,
            dst_ip="203.0.113.50",
            dst_port=8080,
            finding_id=uuid.UUID(int=1),
            type="beaconing",
            title=title,
            description="Periodic connections to 203.0.113.50 every 60 s",
            severity="high",
            confidence=0.9,
            detection_method="heuristic:beaconing@1",
            evidence_refs=["C00000001"],
            attributes={"interval_s": 60.0, "n": 15},
        ),
        IocRecord(
            type="ip",
            value="203.0.113.50",
            first_seen=at(1),
            last_seen=at(50),
            count=9,
            source="conn",
        ),
        TimelineEvent(ts=at(0), event="capture_start", title="Capture start"),
        TimelineEvent(ts=at(50), event="finding", title="Beacon to 203.0.113.50", severity="high"),
        *(extra or []),
    ]


# Internal values of the privacy case that must never leave (pseudonymization on).
SECRETS = (
    "10.0.0.5",
    "10.0.0.9",
    "192.168.1.20",
    "198.51.100.7",
    "fileserver.corp",
    "portal.acme.example",
    "intranet",
    "wpad",
    "alice",
    "hunter2",
    "abc123secret",
    "s3cr3t",
)


def privacy_records() -> list[BaseModel]:
    return [
        flow(1, src_ip="10.0.0.5", dst_ip="203.0.113.50", dst_port=8080),
        DnsRecord(
            ts=at(10),
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
            flow_ref="C00000001",
            query="wpad",
            qtype="A",
            rcode="NXDOMAIN",
        ),
        DnsRecord(ts=at(11), flow_ref="C00000001", query="fileserver.corp", answers=["10.0.0.9"]),
        HttpRecord(
            ts=at(20),
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            flow_ref="C00000001",
            method="POST",
            host="intranet",
            uri="/login?user=bob&password=hunter2#frag",
            status_code=200,
            user_agent="curl/8",
        ),
        TlsRecord(
            ts=at(30),
            flow_ref="C00000001",
            server_name="portal.acme.example",
            cert_subject="CN=portal.acme.example,O=Acme",
        ),
        AlertRecord(
            ts=at(40),
            src_ip="198.51.100.7",
            dst_ip="203.0.113.50",
            flow_ref="C00000001",
            signature_id=2_000_001,
            rev=1,
            signature="ET MALWARE beacon",
            severity=1,
        ),
        FindingRecord(
            ts=at(50),
            src_ip="10.0.0.5",
            src_port=40001,
            dst_ip="203.0.113.50",
            dst_port=8080,
            finding_id=uuid.UUID(int=1),
            type="beaconing",
            title="Beacon from 10.0.0.5 to fileserver.corp",
            description=(
                "User C:\\Users\\alice\\AppData polls "
                "https://cdn.example.com/p.js?token=abc123secret#x and "
                "cdn.example.com/q?session=abc123secret every 60 s"
            ),
            severity="high",
            confidence=0.9,
            detection_method="heuristic:beaconing@1",
            evidence_refs=["C00000001"],
            attributes={"interval_s": 60.0, "auth_token": "s3cr3t", "password": "hunter2"},
        ),
        FindingRecord(
            ts=at(5),
            src_ip="192.168.1.20",
            finding_id=uuid.UUID(int=2),
            type="port_scan",
            title="Port scan from 192.168.1.20",
            description="Scan of 10.0.0.9",
            severity="medium",
            confidence=0.5,
            detection_method="heuristic:port_scan@1",
        ),
        TimelineEvent(ts=at(50), event="finding", title="Beacon from 10.0.0.5", severity="high"),
    ]


async def _ready(**settings: Any) -> Registered:
    reg = await register()
    await enable_ai(reg.client, reg.org_id, key=MOCK_KEY, **settings)
    return reg


async def _pcap_job(
    reg: Registered, body: list[BaseModel], case_id: str | None = None
) -> uuid.UUID:
    case_id = case_id or await new_case(reg)
    evidence = await upload(
        reg.client, reg.org_id, case_id, f"evidence {uuid.uuid4()}".encode(), "capture.bin"
    )
    created = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )
    assert created.status_code == 201, created.text
    job = uuid.UUID(created.json()["id"])
    await pr.seed_results(reg.org_id, job, pr.stream(job, body))
    return job


# --- driving runs ----------------------------------------------------------------------------


def _send_resume() -> None:
    from app.workers.celery_app import celery_app  # broker client only

    celery_app.send_task(
        AI_RESUME, kwargs={"message": {}}, queue=Queues(get_settings().queue_prefix).analyst
    )


async def _make_due(org_id: uuid.UUID, run_id: uuid.UUID) -> None:
    async with tenant_session(org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == run_id, AiRunIndex.status == "waiting")
            .values(resume_at=func.now() - timedelta(seconds=1), dispatched_at=None)
        )


async def _detail(client: AsyncClient, org_id: uuid.UUID, run_id: uuid.UUID) -> dict[str, Any]:
    response = await client.get(f"{API}/{org_id}/ai/runs/{run_id}")
    assert response.status_code == 200, response.text
    return dict(response.json())


async def _settle(
    reg: Registered,
    run_id: uuid.UUID,
    *,
    timeout_s: float = SETTLE_S,
    resume: bool = True,
    seen: set[str] | None = None,
) -> dict[str, Any]:
    """Poll the run until it is final; a waiting run is made due and resumed (no beat)."""
    deadline = time.monotonic() + timeout_s
    while True:
        detail = await _detail(reg.client, reg.org_id, run_id)
        if seen is not None:
            seen.add(detail["status"])
        if detail["status"] in FINAL:
            return detail
        if time.monotonic() > deadline:
            pytest.fail(f"run {run_id} still {detail['status']} after {timeout_s} s")
        if resume and detail["status"] == "waiting":
            await _make_due(reg.org_id, run_id)
            await asyncio.to_thread(_send_resume)
        await asyncio.sleep(1.0)


async def _run(reg: Registered, **body: Any) -> uuid.UUID:
    created = await request_run(reg.client, reg.org_id, **body)
    assert created.status_code == 202, created.text
    return uuid.UUID(created.json()["run"]["id"])


async def _summarize(marker: str, **settings: Any) -> tuple[Registered, uuid.UUID]:
    reg = await _ready(**settings)
    job = await _pcap_job(reg, records(marker))
    return reg, await _run(reg, task="summarize_pcap", job_id=str(job))


def _mock_state() -> dict[str, Any]:
    try:
        return dict(json.loads(STATE_FILE.read_text()))
    except (OSError, ValueError):
        return {"body": None, "counters": {}}


def _claims(output: dict[str, Any]) -> list[dict[str, Any]]:
    return [*output["observed"], *output["interpretation"]]


def _citations(output: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for claim in _claims(output) for c in claim["citations"]]


# --- every task ------------------------------------------------------------------------------


async def _targets(reg: Registered, job: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    async with tenant_session(reg.org_id, reg.user_id) as s:
        finding = await s.scalar(select(AnalysisFinding.id).where(AnalysisFinding.job_id == job))
        alert = await s.scalar(select(NetworkAlert.id).where(NetworkAlert.job_id == job))
    assert finding is not None and alert is not None
    return finding, alert


async def test_every_pcap_task_completes_with_verified_citations(sent: SentJobs) -> None:
    reg = await _ready()
    job = await _pcap_job(reg, records())
    finding, alert = await _targets(reg, job)
    bodies: list[dict[str, Any]] = [
        {"task": "summarize_pcap", "job_id": str(job)},
        {"task": "ioc_correlation", "job_id": str(job)},
        {"task": "attack_mapping", "job_id": str(job)},
        {"task": "explain_finding", "job_id": str(job), "target_id": str(finding)},
        {"task": "explain_alert", "job_id": str(job), "target_id": str(alert)},
    ]
    for body in bodies:
        run_id = await _run(reg, **body)
        detail = await _settle(reg, run_id)
        assert (detail["status"], detail["error_code"]) == ("completed", None), body
        output = detail["output"]
        assert output is not None and detail["output_withheld"] is False
        verified = [c for c in _citations(output) if c["status"] == "verified"]
        assert verified, (body, json.dumps(output)[:2500])
        # Deep links only on verified citations; the run carries provenance.
        assert all(c["link"] is None for c in _citations(output) if c["status"] != "verified")
        assert detail["served_model"] and detail["usage"]["total_tokens"] > 0
        assert detail["citation_accuracy"] is not None and detail["citation_accuracy"] > 0


async def test_an_incident_maps_its_jobs_and_reduces_their_digests(sent: SentJobs) -> None:
    reg = await _ready()
    case_id = await new_case(reg)
    first = await _pcap_job(reg, records(), case_id)
    second = await _pcap_job(reg, records(), case_id)
    run_id = await _run(reg, task="incident_summary", investigation_id=case_id)
    detail = await _settle(reg, run_id, timeout_s=150)
    assert detail["status"] == "completed", detail["error_code"]
    children = detail["child_runs"]
    assert {c["job_id"] for c in children} == {str(first), str(second)}
    assert all(c["status"] == "completed" for c in children)
    output = detail["output"]
    assert output is not None
    timeline = output["timeline"]
    assert timeline, "the reduce answer has timeline entries"
    # Timestamps come from the cited record rows (never from model text).
    stamped = [t for t in timeline if t["status"] == "supported"]
    assert stamped and all(t["ts"] is not None for t in stamped)
    for entry in stamped:
        datetime.fromisoformat(entry["ts"])


# --- typed outcomes --------------------------------------------------------------------------


async def test_a_rate_limit_waits_then_completes(sent: SentJobs) -> None:
    reg, run_id = await _summarize(f"ai-mock:429-once-{uuid.uuid4().hex[:12]}")
    seen: set[str] = set()
    detail = await _settle(reg, run_id, seen=seen)
    assert "waiting" in seen
    assert detail["status"] == "completed"
    async with tenant_session(reg.org_id, None) as s:
        index = await s.get(AiRunIndex, run_id)
    assert index is not None and index.calls == 1  # the unbilled 429 used no call


async def test_a_refusal_is_final_with_its_category(sent: SentJobs) -> None:
    reg, run_id = await _summarize("ai-mock:refuse")
    detail = await _settle(reg, run_id)
    assert (detail["status"], detail["error_code"]) == ("refused", "refused")
    assert detail["refusal_category"] == "cyber" and detail["output"] is None


@pytest.mark.parametrize(
    ("marker", "code"),
    [
        ("ai-mock:spend", "spend_limit"),
        ("ai-mock:maxtokens", "max_tokens"),
        ("ai-mock:malformed", "invalid_output"),
        ("ai-mock:schema", "invalid_output"),
    ],
)
async def test_failures_are_typed(sent: SentJobs, marker: str, code: str) -> None:
    reg, run_id = await _summarize(marker)
    detail = await _settle(reg, run_id)
    assert (detail["status"], detail["error_code"]) == ("failed", code)
    assert detail["output"] is None
    if code == "invalid_output":
        assert detail["metrics"]["repaired"] is True  # one repair retry, then final


async def test_a_canary_echo_is_withheld(sent: SentJobs) -> None:
    """`ai-mock:echo` echoes the instructions, where the real prompt puts the canary (the
    user turn): the verifier flags it and the API never returns the body."""
    reg, run_id = await _summarize("ai-mock:echo")
    detail = await _settle(reg, run_id)
    assert (detail["status"], detail["error_code"]) == ("failed", "canary_leak")
    assert "canary_leak" in detail["flags"]
    assert detail["output"] is None and detail["output_withheld"] is True
    kept = await reg.client.get(
        f"{API}/{reg.org_id}/ai/runs/{run_id}", params={"pseudonyms": "keep"}
    )
    assert kept.json()["output"] is None
    # The canary itself is never stored: only its hash.
    assert len(detail["metrics"]["canary_sha256"]) == 64
    assert "My instructions mention" not in kept.text


async def test_fabricated_citations_are_invalid_and_claims_unsupported(sent: SentJobs) -> None:
    reg, run_id = await _summarize("ai-mock:fabricate")
    detail = await _settle(reg, run_id)
    assert detail["status"] == "completed"
    output = detail["output"]
    observed = {c["id"]: c for c in output["observed"]}
    invented = observed["O1"]  # cites F999, which was never sent
    assert invented["status"] == "unsupported"
    assert all(c["status"] == "invalid" and c["link"] is None for c in invented["citations"])
    misquoted = observed["O2"]  # a real label with a quote that is not in the evidence
    assert misquoted["status"] == "unsupported"
    assert all(c["status"] != "verified" for c in misquoted["citations"])
    assert detail["claims_unsupported"] >= 2


async def test_an_injected_verdict_is_flagged_and_never_linked(sent: SentJobs) -> None:
    reg, run_id = await _summarize("ai-mock:inject")
    detail = await _settle(reg, run_id)
    assert detail["status"] == "completed"
    output = detail["output"]
    assert "verdict_language" in output["flags"]
    assert output["next_steps"] == []
    text = json.dumps(output)
    assert "http://" not in text and "https://" not in text


async def test_a_spent_org_budget_fails_the_run(sent: SentJobs) -> None:
    reg, run_id = await _summarize("", daily_token_budget=1000)
    detail = await _settle(reg, run_id)
    assert (detail["status"], detail["error_code"]) == ("failed", "budget_exhausted")
    assert detail["usage"]["total_tokens"] == 0


async def test_ai_disabled_mid_run_fails_it(sent: SentJobs) -> None:
    reg, run_id = await _summarize("ai-mock:429-nora")  # waits until the next minute
    deadline = time.monotonic() + 30
    while (await _detail(reg.client, reg.org_id, run_id))["status"] != "waiting":
        assert time.monotonic() < deadline
        await asyncio.sleep(0.5)
    off = await put_settings(reg.client, reg.org_id, ai_enabled=False)
    assert off.status_code == 200, off.text
    detail = await _settle(reg, run_id)
    assert (detail["status"], detail["error_code"]) == ("failed", "ai_disabled")


async def test_the_deadline_ends_a_waiting_run(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run rate-limited until past its deadline ends `failed/deadline` (the deadline is set
    by the API at creation: the minimum, 60 s, here; it is immutable afterwards)."""
    monkeypatch.setattr(get_settings(), "ai_run_deadline_s", 60)
    reg, run_id = await _summarize("ai-mock:429-nora")
    detail = await _settle(reg, run_id, timeout_s=120)
    assert (detail["status"], detail["error_code"]) == ("failed", "deadline")
    async with tenant_session(reg.org_id, None) as s:
        index = await s.get(AiRunIndex, run_id)
    assert index is not None and index.calls == 0  # every 429 was given back


async def test_a_call_just_under_the_timeout_completes(sent: SentJobs) -> None:
    """RT7: no transaction is held across the call (the worker's timeout is 8 s here)."""
    reg, run_id = await _summarize("ai-mock:slow-5")
    detail = await _settle(reg, run_id)
    assert detail["status"] == "completed"


async def test_calls_beyond_the_timeout_stay_charged_and_stop_at_the_cap(sent: SentJobs) -> None:
    """RT2: each timed-out call keeps its full reservation charged; never a fourth call."""
    before = _mock_state()["counters"].get("slow", 0)
    reg, run_id = await _summarize("ai-mock:slow")
    detail = await _settle(reg, run_id, timeout_s=180)
    assert (detail["status"], detail["error_code"]) == ("failed", "provider_error")
    calls = get_settings().ai_max_calls_per_run
    assert _mock_state()["counters"].get("slow", 0) - before == calls
    assert detail["metrics"]["usage_unknown"] is True
    assert detail["usage"]["total_tokens"] > calls * get_settings().ai_max_output_tokens


async def test_a_lost_budget_key_is_seeded_from_the_database(sent: SentJobs, broker: Redis) -> None:
    """RT9: the broker lost the day key (restart / flush) mid-day: the next reservation
    starts from what `ai_runs.usage` says was used today, so the budget still holds."""
    reg = await _ready()
    job = await _pcap_job(reg, records())
    first = await _settle(reg, await _run(reg, task="summarize_pcap", job_id=str(job)))
    assert first["status"] == "completed"
    budget = Budget(broker, get_settings().queue_prefix)
    assert await broker.delete(budget.day_key(reg.org_id)) == 1
    second = await _settle(reg, await _run(reg, task="ioc_correlation", job_id=str(job)))
    assert second["status"] == "completed"
    used = first["usage"]["total_tokens"] + second["usage"]["total_tokens"]
    assert await budget.used_today(reg.org_id) == used


# --- outbound privacy ------------------------------------------------------------------------


async def test_nothing_internal_leaves_with_pseudonymization_on(sent: SentJobs) -> None:
    reg = await _ready(internal_cidrs=["198.51.100.0/24"], internal_suffixes=["acme.example"])
    job = await _pcap_job(reg, privacy_records())
    run_id = await _run(reg, task="summarize_pcap", job_id=str(job))
    detail = await _settle(reg, run_id)
    assert detail["status"] == "completed"
    state = _mock_state()
    body = state["body"]
    assert state["path"] == "/v1/analyze" and isinstance(body, dict)
    sent_text = f"{body['system']}\n{body['user']}"
    assert "INT_IP_" in sent_text and "INT_HOST_" in sent_text  # pseudonyms, not the values
    lowered = sent_text.lower()
    leaked = [s for s in SECRETS if s.lower() in lowered]
    assert leaked == []
    # Credential-looking attributes are never selected (neither their names nor values);
    # URL query keys are kept (`uri_query_keys`), their values never.
    assert "auth_token" not in sent_text
    # The provider key travels in a header only, never in the body.
    assert MOCK_KEY not in json.dumps(body)
    # The member sees the original names again (pseudonyms reversed in the read model).
    assert "INT_IP_" not in json.dumps(detail["output"])
