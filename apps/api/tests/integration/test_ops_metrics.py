"""`GET /orgs/{org}/ops/metrics?window=` (M7 phase 5): the org's own numbers from its tenant
tables (not `job_outcomes`), equal to a hand count on the seed; another org's jobs are absent;
`audit.read` only (viewer and analyst 403)."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from cyberlab_jobs.static import Profile
from sqlalchemy import update

from app.core.tenancy import tenant_session
from app.modules.ai import lifecycle as ai_lifecycle
from app.modules.ai.contracts import AiErrorCode, AiRunStatus
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex, AnalysisStatus, Analyzer
from app.modules.evidence.models import Evidence
from app.modules.organizations.models import MemberRole
from app.modules.reports.models import ReportRender, ReportRenderIndex
from app.modules.threat_intel.lifecycle import finalize_run
from tests.ai_helpers import seed_ai_run, seed_job
from tests.analysis_helpers import new_case
from tests.factories import Registered, add_member, login, make_user, register, unique_email
from tests.integration.seed import Tenant
from tests.ops_helpers import retention_session
from tests.report_helpers import new_signing_keys, seed_render, seed_report, seed_version
from tests.ti_helpers import seed_run

URL = "/api/v1/orgs/{org_id}/ops/metrics"


def now() -> datetime:
    return datetime.now(UTC)


async def tenant_of(reg: Registered) -> Tenant:
    return Tenant(reg.org_id, reg.user_id, uuid.UUID(await new_case(reg)))


async def job(
    t: Tenant,
    analyzer: str,
    status: str,
    *,
    code: str | None = None,
    queue_ms: int | None = None,
    run_ms: int | None = None,
    ago: timedelta = timedelta(minutes=30),
) -> uuid.UUID:
    """A job inserted directly in its final state with exact timestamps (an INSERT fires no
    outcome trigger, and the org route never reads job_outcomes anyway)."""
    kind = Analyzer(analyzer)
    finished = now() - ago
    started = None if run_ms is None else finished - timedelta(milliseconds=run_ms)
    created = (started or finished) - timedelta(milliseconds=queue_ms or 0)
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=t.investigation_id,
            original_filename="capture.pcap" if kind is Analyzer.PCAP else "sample.bin",
            detected_mime="application/octet-stream",
            detected_description="data",
            size_bytes=1024,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
        await s.flush()
        row = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=evidence.id,
            analyzer=kind,
            profile=Profile.FULL if kind is Analyzer.STATIC else None,
            status=AnalysisStatus(status),
            error_code=code,
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
            created_at=created,
            started_at=started,
            finished_at=None if status in ("queued", "running") else finished,
        )
        s.add(row)
        await s.flush()
        s.add(
            AnalysisJobIndex(
                job_id=row.id,
                organization_id=t.org_id,
                analyzer=kind,
                status=AnalysisStatus(status),
                deadline_at=now() + timedelta(minutes=10),
            )
        )
    return row.id


async def _render(t: Tenant, fmt: str, **values: Any) -> uuid.UUID:
    report = await seed_report(t)
    version = await seed_version(t, report, new_signing_keys(), store=False)
    render_id, _ = await seed_render(t, version.version_id, fmt=fmt)
    async with tenant_session(t.org_id, None) as s:
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(status="running", started_at=now())
        )
        await s.flush()
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(finished_at=now(), **values)
        )
        await s.execute(
            update(ReportRenderIndex)
            .where(ReportRenderIndex.render_id == render_id)
            .values(status=values["status"])
        )
    return render_id


async def seed_org(t: Tenant) -> None:
    # pcap in the last hour: 3 succeeded, 1 parse failure, 1 never started (infra).
    for i in (1, 2, 3):
        await job(t, "pcap", "succeeded", queue_ms=100 * i, run_ms=1000 * i)
    await job(t, "pcap", "failed", code="unparseable_capture", queue_ms=400, run_ms=4000)
    await job(t, "pcap", "failed", code="never_started")
    # Two days ago: only in the 7d window.
    await job(t, "pcap", "succeeded", queue_ms=10, run_ms=10, ago=timedelta(days=2))
    # static (profile full): 1 succeeded, 1 parse failure.
    await job(t, "static", "succeeded", queue_ms=50, run_ms=500)
    await job(t, "static", "failed", code="invalid_result", queue_ms=50, run_ms=700)
    # Active now.
    await job(t, "pcap", "queued")
    await job(t, "static", "running", run_ms=1)
    # TI: one run failed by the deadline (no error code, class other) and one still queued.
    run = await seed_run(t)
    async with tenant_session(t.org_id, None) as s:
        assert await finalize_run(s, t.org_id, run, abandon_reason="deadline") == "failed"
    await seed_run(t)
    # AI: one completed, one failed provider_error.
    ai_job = await seed_job(t)
    for status, code in (
        (AiRunStatus.COMPLETED, None),
        (AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR),
    ):
        ai_run = await seed_ai_run(t, job_id=ai_job)
        async with tenant_session(t.org_id, None) as s:
            assert await ai_lifecycle.finalize(s, ai_run, status, code) == status
    # Renders: one failed oom, one succeeded then purged by retention (still a success).
    await _render(t, "pdf", status="failed", error_code="oom")
    purged = await _render(
        t, "pdf", status="succeeded", sha256="b" * 64, bytes=10, object_version_id="v1"
    )
    async with retention_session(t.org_id) as s:
        await s.execute(
            update(ReportRender).where(ReportRender.id == purged).values(status="purged")
        )


def _by_kind(body: dict[str, Any]) -> dict[tuple[str, str | None], dict[str, Any]]:
    return {(item["kind"], item["subkind"]): item for item in body["items"]}


async def test_the_numbers_equal_a_hand_count_and_other_orgs_are_absent() -> None:
    owner = await register(org_name="Ops Metrics Org")
    other = await register(org_name="Other Ops Org")
    await seed_org(await tenant_of(owner))
    # The other org's jobs must not leak into the owner's numbers.
    other_t = await tenant_of(other)
    for _ in range(4):
        await job(other_t, "pcap", "failed", code="zeek_failed", queue_ms=1, run_ms=99999)
    await job(other_t, "pcap", "queued")

    response = await owner.client.get(URL.format(org_id=owner.org_id), params={"window": "24h"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["window"] == "24h"
    items = _by_kind(body)
    assert list(items) == [
        ("pcap", None),
        ("static", "full"),
        ("ti", "mock"),
        ("ai", "mock"),
        ("report", "pdf"),
    ]
    pcap = items[("pcap", None)]
    assert (pcap["total"], pcap["succeeded"], pcap["failed"]) == (5, 3, 2)
    assert pcap["failure_ratio"] == 0.4
    assert pcap["parse_success_ratio"] == 0.75  # 3 / (3 + 1 parse failure)
    # percentile_cont over runs [1000, 2000, 3000, 4000] and queues [100, ..., 400]
    # (the never-started job has no durations).
    assert (pcap["run_p50_ms"], pcap["run_p95_ms"]) == (2500, 3850)
    assert (pcap["queue_p50_ms"], pcap["queue_p95_ms"]) == (250, 385)
    assert pcap["error_classes"] == {"parse": 1, "infra": 1}
    static = items[("static", "full")]
    assert (static["total"], static["failed"], static["parse_success_ratio"]) == (2, 1, 0.5)
    assert static["error_classes"] == {"parse": 1}
    assert (static["run_p50_ms"], static["queue_p50_ms"]) == (600, 50)
    ti = items[("ti", "mock")]
    assert (ti["total"], ti["failed"], ti["failure_ratio"]) == (1, 1, 1.0)
    assert ti["parse_success_ratio"] is None and ti["error_classes"] == {"other": 1}
    ai = items[("ai", "mock")]
    assert (ai["total"], ai["succeeded"], ai["failed"]) == (2, 1, 1)
    assert ai["error_classes"] == {"provider": 1} and ai["parse_success_ratio"] is None
    report = items[("report", "pdf")]
    assert (report["total"], report["succeeded"], report["failed"]) == (2, 1, 1)
    assert report["error_classes"] == {"infra": 1}
    assert body["active"] == {"pcap": 1, "static": 1, "ti": 1, "ai": 0, "report": 0}

    week = (await owner.client.get(URL.format(org_id=owner.org_id), params={"window": "7d"})).json()
    assert _by_kind(week)[("pcap", None)]["total"] == 6
    assert _by_kind(week)[("pcap", None)]["succeeded"] == 4

    # The other org sees only its own jobs.
    theirs = (await other.client.get(URL.format(org_id=other.org_id))).json()
    assert [(i["kind"], i["total"], i["failed"]) for i in theirs["items"]] == [("pcap", 4, 4)]
    assert theirs["active"]["pcap"] == 1


async def test_an_empty_org_and_the_default_window() -> None:
    owner = await register(org_name="Quiet Ops Org")
    response = await owner.client.get(URL.format(org_id=owner.org_id))
    assert response.status_code == 200
    body = response.json()
    assert body["window"] == "24h" and body["items"] == []
    assert body["active"] == {"pcap": 0, "static": 0, "ti": 0, "ai": 0, "report": 0}
    assert body["recent_failures"] == []
    bad = await owner.client.get(URL.format(org_id=owner.org_id), params={"window": "30d"})
    assert bad.status_code == 422


async def test_only_audit_readers_see_the_metrics() -> None:
    owner = await register(org_name="Ops RBAC Org")
    for role in (MemberRole.VIEWER, MemberRole.ANALYST):
        email = unique_email(role.value)
        user_id = await make_user(email)
        await add_member(owner.org_id, user_id, role)
        client = await login(email)
        response = await client.get(URL.format(org_id=owner.org_id))
        assert response.status_code == 403, (role, response.text)
    admin_email = unique_email("admin")
    await add_member(owner.org_id, await make_user(admin_email), MemberRole.ADMIN)
    admin = await login(admin_email)
    assert (await admin.get(URL.format(org_id=owner.org_id))).status_code == 200
    outsider = await register(org_name="Ops Outsider Org")
    assert (await outsider.client.get(URL.format(org_id=owner.org_id))).status_code == 404


async def test_the_five_most_recent_failures_of_the_org_only() -> None:
    """M7 follow-up: `recent_failures` (newest first, whatever the window), classified."""
    owner = await register(org_name="Ops Failures Org")
    other = await register(org_name="Other Failures Org")
    t = await tenant_of(owner)
    codes = [
        "zeek_failed",
        "timed_out",
        "invalid_result",
        "sample_too_large",
        "enqueue_failed",
        "analyzer_failed",
    ]
    ids = []
    for i, code in enumerate(codes):
        analyzer = "static" if i % 2 else "pcap"
        # Oldest first: hours 6, 5, ... 1 ago; the oldest is 8 days old (outside the 7d window).
        ago = timedelta(days=8) if i == 0 else timedelta(hours=len(codes) - i)
        ids.append(await job(t, analyzer, "failed", code=code, run_ms=10, ago=ago))
    await job(t, "pcap", "succeeded", run_ms=10, ago=timedelta(minutes=1))
    await job(await tenant_of(other), "pcap", "failed", code="zeek_failed", ago=timedelta(0))

    body = (await owner.client.get(URL.format(org_id=owner.org_id), params={"window": "1h"})).json()
    failures = body["recent_failures"]
    assert [f["job_id"] for f in failures] == [str(i) for i in reversed(ids[1:])]
    newest = failures[0]
    assert (newest["kind"], newest["subkind"]) == ("static", "full")
    assert (newest["error_code"], newest["error_class"]) == ("analyzer_failed", "other")
    assert newest["href"] == f"/malware/{ids[5]}"
    assert newest["investigation_id"] == str(t.investigation_id)
    assert newest["evidence_id"] and newest["finished_at"]
    by_id = {f["job_id"]: f for f in failures}
    assert by_id[str(ids[4])]["error_class"] == "infra"
    assert by_id[str(ids[3])]["error_class"] == "input"
    assert (by_id[str(ids[2])]["kind"], by_id[str(ids[2])]["error_class"]) == ("pcap", "parse")
    assert by_id[str(ids[2])]["href"] == f"/pcap/{ids[2]}" and by_id[str(ids[2])]["subkind"] is None
    assert (by_id[str(ids[1])]["error_code"], by_id[str(ids[1])]["error_class"]) == (
        "timed_out",
        "infra",
    )
    # The other org's failure never shows.
    theirs = (await other.client.get(URL.format(org_id=other.org_id))).json()
    assert len(theirs["recent_failures"]) == 1
    assert theirs["recent_failures"][0]["job_id"] not in {str(i) for i in ids}
