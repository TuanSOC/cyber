"""M9 phase 7: the `disk.v1` job message, its queue and the disk deadlines."""

import base64
import json
import uuid
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from cyberlab_jobs import DISK_ANALYZE
from cyberlab_jobs.disk import DiskJobV1

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import analyzers, dispatch, lifecycle
from app.modules.analysis.models import Analyzer
from app.modules.disk_forensics.dispatch import disk_limits
from app.modules.evidence.models import Evidence
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs
from tests.disk_results import sent as sent  # noqa: F401 (fixture)


def _policy(fields: dict[str, str]) -> dict[str, Any]:
    raw = fields.get("policy") or fields.get("Policy")
    assert raw, fields.keys()
    return dict(json.loads(base64.b64decode(raw)))


@pytest.mark.parametrize(
    ("body", "profile", "os_hint"),
    [({}, "triage", "auto"), ({"profile": "full", "os_hint": "linux"}, "full", "linux")],
)
async def test_dispatch_builds_a_valid_disk_job(
    sent: SentJobs, body: dict[str, Any], profile: str, os_hint: str
) -> None:
    reg, ids, item = await dr.queued_job(sent, segments=3, **body)
    before = lifecycle.now()
    message = dispatch.build_message(item)
    assert isinstance(message, DiskJobV1)
    dumped = message.model_dump(mode="json")
    assert DiskJobV1.model_validate(dumped) == message  # round-trips the frozen contract

    settings = get_settings()
    assert dumped["schema_version"] == "disk.v1"
    assert (dumped["profile"], dumped["os_hint"]) == (profile, os_hint)
    assert "cache_key" not in dumped  # RT1
    async with tenant_session(reg.org_id, None) as session:
        stored = {i: await session.get(Evidence, uuid.UUID(i)) for i in ids}
    expires = settings.analysis_queue_ttl_s + settings.analysis_disk_timeout_s
    for ordinal, (segment, evidence_id) in enumerate(zip(dumped["segments"], ids, strict=True)):
        evidence = stored[evidence_id]
        assert evidence is not None
        assert (segment["ordinal"], segment["evidence_id"]) == (ordinal, evidence_id)
        assert segment["size_bytes"] == evidence.size_bytes
        assert segment["expected_sha256"] == item.segments[ordinal].sha256
        # Each GET pins the exact stored version and outlives a late start.
        query = parse_qs(urlparse(segment["url"]).query)
        assert query["versionId"] == [evidence.storage_version_id]
        assert query["X-Amz-Expires"] == [str(expires)]
        assert "X-Amz-Signature" in query
    assert settings.need("minio_secret_key") not in str(dumped)
    # The result goes to the one M2 key, capped at the disk result size.
    key = dispatch.result_key(item.organization_id, item.job_id)
    assert dumped["result_post"]["fields"]["key"] == key
    conditions = _policy(dumped["result_post"]["fields"])["conditions"]
    assert ["content-length-range", 0, settings.disk_max_result_bytes] in conditions
    assert dumped["limits"] == disk_limits(settings, profile).model_dump(mode="json")
    assert dumped["limits"]["max_image_bytes"] == settings.disk_max_image_bytes
    # The worker's budget (RT5) never outlives the reaper's deadline of a started run.
    deadline = message.deadline_at
    budget = timedelta(seconds=settings.analysis_disk_timeout_s)
    assert before + budget <= deadline <= lifecycle.now() + budget

    task, queue = dispatch.task_and_queue(item.analyzer, settings)
    assert (task, queue) == (DISK_ANALYZE, f"{settings.queue_prefix}disk")
    assert queue.startswith("test.")


def test_disk_parameters_are_the_disk_settings() -> None:
    settings = get_settings()
    assert analyzers.max_bytes(settings, Analyzer.DISK) == settings.disk_max_upload_bytes
    assert analyzers.timeout_s(settings, Analyzer.DISK) == settings.analysis_disk_timeout_s
    assert analyzers.max_result_bytes(settings, Analyzer.DISK) == settings.disk_max_result_bytes
    for profile in ("triage", "full"):
        limits = disk_limits(settings, profile)
        assert limits.max_lines() == settings.disk_max_result_lines()
        assert all(s.timeout_s < limits.timeout_s for s in limits.stages.values())
        assert limits.hash_budget_bytes <= settings.disk_max_image_bytes
