"""M8 phase 6: the `memory.v1` job message, its queue, and the memory deadlines."""

import base64
import json
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from cyberlab_jobs import MEMORY_ANALYZE
from cyberlab_jobs.memory import MemoryJobV1
from sqlalchemy import update

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import analyzers, dispatch, lifecycle
from app.modules.analysis.models import AnalysisJobIndex, Analyzer
from app.modules.memory_analysis.dispatch import memory_limits
from app.workers import ingest, reaper
from tests import memory_results as mr
from tests.analysis_helpers import SentJobs


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


def _policy(fields: dict[str, str]) -> dict[str, Any]:
    raw = fields.get("policy") or fields.get("Policy")
    assert raw, fields.keys()
    return dict(json.loads(base64.b64decode(raw)))


@pytest.mark.parametrize(
    ("body", "profile", "os_hint"),
    [({}, "triage", "auto"), ({"profile": "full", "os_hint": "windows"}, "full", "windows")],
)
async def test_dispatch_builds_a_valid_memory_job(
    sent: SentJobs, body: dict[str, Any], profile: str, os_hint: str
) -> None:
    reg, evidence_id, item = await mr.queued_job(sent, **body)
    message = dispatch.build_message(item)
    assert isinstance(message, MemoryJobV1)
    dumped = message.model_dump(mode="json")
    assert MemoryJobV1.model_validate(dumped) == message  # round-trips the frozen contract

    settings = get_settings()
    assert dumped["schema_version"] == "memory.v1"
    assert (dumped["profile"], dumped["os_hint"]) == (profile, os_hint)
    assert dumped["evidence_id"] == evidence_id
    assert dumped["expected_sha256"] == mr.IMAGE_SHA256
    assert dumped["size_bytes"] == len(mr.IMAGE)
    # The GET pins the exact stored version and outlives a late start.
    query = parse_qs(urlparse(dumped["evidence_url"]).query)
    assert query["versionId"] == [item.storage_version_id]
    assert "X-Amz-Signature" in query
    expires = settings.analysis_queue_ttl_s + settings.analysis_memory_timeout_s
    assert query["X-Amz-Expires"] == [str(expires)]
    assert settings.need("minio_secret_key") not in str(dumped)
    # The result goes to the one M2 key, capped at the memory result size.
    key = dispatch.result_key(item.organization_id, item.job_id)
    assert dumped["result_post"]["fields"]["key"] == key
    conditions = _policy(dumped["result_post"]["fields"])["conditions"]
    assert ["content-length-range", 0, settings.memory_max_result_bytes] in conditions
    assert dumped["limits"] == memory_limits(settings).model_dump()
    assert dumped["limits"]["max_bytes"] == settings.memory_max_bytes
    assert dumped["limits"]["max_result_bytes"] == settings.memory_max_result_bytes
    assert dumped["limits"]["timeout_s"] == settings.analysis_memory_timeout_s

    task, queue = dispatch.task_and_queue(item.analyzer, settings)
    assert (task, queue) == (MEMORY_ANALYZE, f"{settings.queue_prefix}memory")
    assert queue.startswith("test.")


def test_memory_parameters_are_the_memory_settings() -> None:
    settings = get_settings()
    assert analyzers.max_bytes(settings, Analyzer.MEMORY) == settings.memory_max_bytes
    assert analyzers.timeout_s(settings, Analyzer.MEMORY) == settings.analysis_memory_timeout_s
    assert analyzers.max_result_bytes(settings, Analyzer.MEMORY) == settings.memory_max_result_bytes
    limits = memory_limits(settings)
    assert limits.tool_timeout_s < limits.timeout_s
    assert limits.max_lines() == settings.memory_max_result_lines()


async def test_a_started_memory_job_gets_the_memory_deadline(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    before = lifecycle.now()
    await ingest.handle_event(
        {
            "job_id": str(item.job_id),
            "organization_id": str(item.organization_id),
            "ingest_token": item.ingest_token,
            "event": "started",
            "worker_version": mr.WORKER,
        }
    )
    async with tenant_session(None, None) as session:
        index = await session.get(AnalysisJobIndex, item.job_id)
        assert index is not None and index.status == "running"
        deadline = index.deadline_at
    budget = timedelta(seconds=get_settings().analysis_memory_timeout_s + ingest.RUNNING_GRACE_S)
    assert before + budget <= deadline <= lifecycle.now() + budget

    # Past it, the reaper fails the run `timed_out`.
    async with tenant_session(None, None) as session:
        await session.execute(
            update(AnalysisJobIndex)
            .where(AnalysisJobIndex.job_id == item.job_id)
            .values(deadline_at=lifecycle.now() - timedelta(seconds=1))
        )
    assert await reaper.reap() >= 1
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "timed_out")


async def test_a_memory_job_never_started_is_reaped(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    async with tenant_session(None, None) as session:
        index = await session.get(AnalysisJobIndex, item.job_id)
        assert index is not None
        ttl = timedelta(seconds=get_settings().analysis_queue_ttl_s)
        assert abs(index.deadline_at - (lifecycle.now() + ttl)) < timedelta(minutes=1)
        await session.execute(
            update(AnalysisJobIndex)
            .where(AnalysisJobIndex.job_id == item.job_id)
            .values(deadline_at=lifecycle.now() - timedelta(seconds=1))
        )
    assert await reaper.reap() >= 1
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "never_started")
