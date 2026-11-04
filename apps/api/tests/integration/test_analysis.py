"""Analysis jobs: API rules, ingest message handling and the reaper (dispatch captured)."""

import io
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select, update

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch, lifecycle
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from app.workers import ingest, reaper
from tests import pcap_results
from tests.analysis_helpers import SentJobs, jobs_for, new_case, tiny_pcap, upload
from tests.factories import add_member, csrf, login, make_user, register, unique_email


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


def _message(item: dispatch.DispatchInput, **fields: Any) -> dict[str, Any]:
    return {
        "job_id": str(item.job_id),
        "organization_id": str(item.organization_id),
        "ingest_token": item.ingest_token,
        "event": "started",
        "worker_version": "pcap-worker/test",
        **fields,
    }


async def _run(reg: Any, evidence_id: str) -> Any:
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )


async def _job(job_id: uuid.UUID, org_id: uuid.UUID) -> AnalysisJob:
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
        assert job is not None
        return job


# --- API ---------------------------------------------------------------------------------


async def test_capture_upload_queues_an_automatic_job(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())

    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert job["status"] == "queued" and job["auto"] is True and job["analyzer"] == "pcap"
    assert job["evidence_filename"] == "capture.pcap"
    [item] = sent
    assert item.sha256 == evidence["hashes"]["sha256"] and item.size_bytes == len(tiny_pcap())

    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/custody")
    ).json()["items"]
    assert sorted(e["action"] for e in custody) == ["analysis_requested", "uploaded"]


@pytest.mark.parametrize(
    "content",
    [b"not a capture", b"\x1f\x8b\x08\x00" + tiny_pcap(), b""],
    ids=["text", "gzip-wrapped", "empty"],
)
async def test_non_capture_upload_queues_nothing(sent: SentJobs, content: bytes) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), content)
    assert await jobs_for(reg.client, reg.org_id, evidence["id"]) == []
    assert sent == []


async def test_manual_run_and_active_job_conflict(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), b"plain bytes")

    first = await _run(reg, evidence["id"])
    assert first.status_code == 201, first.text
    assert first.json()["auto"] is False and first.json()["status"] == "queued"
    again = await _run(reg, evidence["id"])
    assert again.status_code == 409 and again.json()["error"]["code"] == "analysis_active"
    assert len(sent) == 1


async def test_rerun_after_final_state_keeps_history(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    await ingest.handle_event(
        _message(sent[0], event="finished", outcome="failed", error_code="x_y")
    )

    rerun = await _run(reg, evidence["id"])
    assert rerun.status_code == 201
    jobs = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert [j["status"] for j in jobs] == ["queued", "failed"]


async def test_viewer_cannot_run_but_can_read(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    email = unique_email("viewer")
    await add_member(reg.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = await login(email)

    denied = await viewer.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(viewer),
    )
    assert denied.status_code == 403
    assert len(await jobs_for(viewer, reg.org_id, evidence["id"])) == 1
    listed = await viewer.get(f"/api/v1/orgs/{reg.org_id}/analyses", params={"status": "queued"})
    assert listed.json()["total"] == 1


async def test_queue_cap_per_org(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "max_active_analyses_per_org", 2)
    reg = await register()
    case = await new_case(reg)
    for _ in range(2):
        await upload(reg.client, reg.org_id, case, tiny_pcap())
    third = await upload(reg.client, reg.org_id, case, tiny_pcap())

    assert await jobs_for(reg.client, reg.org_id, third["id"]) == []  # auto-run skipped
    manual = await _run(reg, third["id"])
    assert manual.status_code == 429 and manual.json()["error"]["code"] == "analysis_queue_full"
    async with tenant_session(reg.org_id, None) as session:
        skipped = await session.scalar(
            select(AuditLog).where(AuditLog.action == "analysis.skipped")
        )
    assert skipped is not None and skipped.details == {"reason": "analysis_queue_full"}


async def test_oversized_capture_is_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "pcap_max_bytes", 10)
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    response = await _run(reg, evidence["id"])
    assert response.status_code == 413 and response.json()["error"]["code"] == "capture_too_large"


async def test_archived_evidence_is_refused(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), b"plain")
    await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/archive", headers=csrf(reg.client)
    )
    response = await _run(reg, evidence["id"])
    assert response.status_code == 409 and response.json()["error"]["code"] == "evidence_archived"


async def test_enqueue_failure_fails_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(item: dispatch.DispatchInput) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(dispatch, "send", broken)
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())  # upload ok
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert (job["status"], job["error_code"]) == ("failed", "enqueue_failed")


async def test_message_carries_presigned_urls_not_credentials(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    message = dispatch.build_message(sent[0]).model_dump(mode="json")
    text = str(message)
    settings = get_settings()
    assert settings.minio_secret_key not in text
    assert "X-Amz-Signature" in message["evidence_url"]
    assert sent[0].storage_version_id in message["evidence_url"]
    key = dispatch.result_key(sent[0].organization_id, sent[0].job_id)
    assert message["result_post"]["fields"]["key"] == key
    assert message["limits"]["max_bytes"] == settings.pcap_max_bytes


# --- ingest ------------------------------------------------------------------------------


async def test_started_then_failed_transitions(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]

    await ingest.handle_event(_message(item))
    job = await _job(item.job_id, item.organization_id)
    assert job.status == "running" and job.started_at and job.worker_version == "pcap-worker/test"

    await ingest.handle_event(
        _message(item, event="finished", outcome="failed", error_code="integrity_mismatch")
    )
    job = await _job(item.job_id, item.organization_id)
    assert (job.status, job.error_code) == ("failed", "integrity_mismatch")

    # Late/duplicate messages never reopen a final job.
    await ingest.handle_event(_message(item))
    assert (await _job(item.job_id, item.organization_id)).status == "failed"


async def test_success_needs_the_result_object(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]
    await ingest.handle_event(_message(item))

    missing = _message(item, event="finished", outcome="succeeded", result_version_id="nope")
    await ingest.handle_event(missing)
    job = await _job(item.job_id, item.organization_id)
    assert (job.status, job.error_code) == ("failed", "invalid_result")

    rerun = (await _run(reg, evidence["id"])).json()
    item = sent[-1]
    assert str(item.job_id) == rerun["id"]
    data = pcap_results.stream(item.job_id)
    stored = get_minio().put_object(
        get_settings().results_bucket,
        dispatch.result_key(item.organization_id, item.job_id),
        io.BytesIO(data),
        len(data),
    )
    await ingest.handle_event(_message(item))
    await ingest.handle_event(
        _message(item, event="finished", outcome="succeeded", result_version_id=stored.version_id)
    )
    job = await _job(item.job_id, item.organization_id)
    assert job.status == "succeeded" and job.result_version_id == stored.version_id

    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/custody")
    ).json()["items"]
    analyzed = [e for e in custody if e["action"] == "analyzed"]
    assert len(analyzed) == 1 and analyzed[0]["details"]["system"] is True
    assert analyzed[0]["actor_id"] == str(reg.user_id)


@pytest.mark.parametrize("tamper", ["token", "org", "job"])
async def test_unauthenticated_messages_are_dropped(sent: SentJobs, tamper: str) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]
    message = _message(item, event="finished", outcome="failed", error_code="forged")
    if tamper == "token":
        message["ingest_token"] = "x" * 43
    elif tamper == "org":
        message["organization_id"] = str((await register()).org_id)
    else:
        message["job_id"] = str(uuid.uuid4())

    await ingest.handle_event(message)
    assert (await _job(item.job_id, item.organization_id)).status == "queued"


async def test_malformed_messages_are_dropped(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]
    for message in ({}, {"job_id": "x"}, {**_message(item), "unexpected": True}):
        await ingest.handle_event(message)
    assert (await _job(item.job_id, item.organization_id)).status == "queued"


# --- reaper ------------------------------------------------------------------------------


async def _expire(job_id: uuid.UUID) -> None:
    async with tenant_session(None, None) as session:
        await session.execute(
            update(AnalysisJobIndex)
            .where(AnalysisJobIndex.job_id == job_id)
            .values(deadline_at=lifecycle.now() - timedelta(seconds=1))
        )


async def test_reaper_fails_stale_queued_and_running_jobs(sent: SentJobs) -> None:
    reg = await register()
    case = await new_case(reg)
    await upload(reg.client, reg.org_id, case, tiny_pcap())
    await upload(reg.client, reg.org_id, case, tiny_pcap())
    queued, running = sent
    await ingest.handle_event(_message(running))
    for item in sent:
        await _expire(item.job_id)

    assert await reaper.reap() == 2
    assert (await _job(queued.job_id, queued.organization_id)).error_code == "never_started"
    assert (await _job(running.job_id, running.organization_id)).error_code == "timed_out"

    # A (valid) success report arriving after the reaper changes nothing.
    data = b"late result"
    stored = get_minio().put_object(
        get_settings().results_bucket,
        dispatch.result_key(running.organization_id, running.job_id),
        io.BytesIO(data),
        len(data),
    )
    await ingest.handle_event(
        _message(
            running, event="finished", outcome="succeeded", result_version_id=stored.version_id
        )
    )
    assert (await _job(running.job_id, running.organization_id)).error_code == "timed_out"
    assert await reaper.reap() == 0


async def test_reaper_ignores_jobs_within_deadline(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    assert await reaper.reap() == 0
    assert (await _job(sent[0].job_id, sent[0].organization_id)).status == "queued"


async def test_final_jobs_are_immutable_in_the_database(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]
    await ingest.handle_event(_message(item, event="finished", outcome="failed", error_code="x"))
    with pytest.raises(Exception, match="final"):
        async with tenant_session(item.organization_id, None) as session:
            await session.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == item.job_id)
                .values(status="queued", error_code=None)
            )


async def test_reaper_skips_a_job_whose_deadline_moved(sent: SentJobs) -> None:
    """The stale list is read unlocked; a `started` report in between must win."""
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]
    await _expire(item.job_id)
    await ingest.handle_event(_message(item))  # started: fresh running deadline
    assert await reaper.reap() == 0
    assert (await _job(item.job_id, item.organization_id)).status == "running"


async def test_permanent_ingest_errors_fail_the_job(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]

    async def denied(job: AnalysisJob, version_id: str, dest: Path) -> None:
        raise PermissionError("AccessDenied")

    monkeypatch.setattr(ingest, "_download_result", denied)
    await ingest.handle_event(
        _message(item, event="finished", outcome="succeeded", result_version_id="v1")
    )
    job = await _job(item.job_id, item.organization_id)
    assert (job.status, job.error_code) == ("failed", "ingest_error")


async def test_transient_ingest_errors_are_retried(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]

    async def down(job: AnalysisJob, version_id: str, dest: Path) -> None:
        raise ConnectionError("minio restarting")

    monkeypatch.setattr(ingest, "_download_result", down)
    with pytest.raises(ConnectionError):
        await ingest.handle_event(
            _message(item, event="finished", outcome="succeeded", result_version_id="v1")
        )
    assert (await _job(item.job_id, item.organization_id)).status == "queued"


async def test_global_queue_cap(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "max_active_analyses_global", 1)
    first, second = await register(), await register()
    await upload(first.client, first.org_id, await new_case(first), tiny_pcap())
    evidence = await upload(second.client, second.org_id, await new_case(second), b"plain")
    response = await _run(second, evidence["id"])
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "analysis_queue_full"


async def test_job_index_is_scoped_for_tenant_sessions(sent: SentJobs) -> None:
    first, second = await register(), await register()
    await upload(first.client, first.org_id, await new_case(first), tiny_pcap())
    item = sent[0]
    async with tenant_session(second.org_id, None) as session:
        assert await session.get(AnalysisJobIndex, item.job_id) is None
    async with tenant_session(None, None) as session:  # system context sees it
        assert await session.get(AnalysisJobIndex, item.job_id) is not None
    with pytest.raises(Exception, match="permission denied"):
        async with tenant_session(first.org_id, None) as session:
            await session.execute(
                update(AnalysisJobIndex)
                .where(AnalysisJobIndex.job_id == item.job_id)
                .values(organization_id=second.org_id)
            )


async def test_database_refuses_illegal_transitions(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    item = sent[0]
    await ingest.handle_event(_message(item))  # running
    with pytest.raises(Exception, match="illegal analysis job transition"):
        async with tenant_session(item.organization_id, None) as session:
            await session.execute(
                update(AnalysisJob).where(AnalysisJob.id == item.job_id).values(status="queued")
            )
