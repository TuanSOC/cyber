"""M9 phase 7: the disk analysis request (dispatch captured; no disk worker needed).

One transaction: the job (profile, OS hint), its ordered `analysis_job_segments`, the restricted
default of EVERY segment, a custody entry per segment and the audit entry. `extract` is never
requestable; the disk active-job caps answer 429.
"""

import uuid
from typing import Any

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.disk_forensics.models import AnalysisJobSegment
from app.modules.memory_analysis.models import MemorySensitivity
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs, jobs_for, new_case, upload
from tests.disk_results import sent as sent  # noqa: F401 (fixture)
from tests.factories import Registered, csrf, register


async def _custody(reg: Registered, evidence_id: str) -> list[dict[str, Any]]:
    response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/custody")
    return list(response.json()["items"])


async def test_a_disk_request_stores_the_ordered_set_in_one_transaction(sent: SentJobs) -> None:
    reg, ids, item = await dr.queued_job(sent, segments=3, profile="full", os_hint="windows")
    assert (item.profile, item.os_hint) == ("full", "windows")
    assert [str(s.evidence_id) for s in item.segments] == ids
    assert [s.ordinal for s in item.segments] == [0, 1, 2]
    job = (await reg.client.get(f"/api/v1/orgs/{reg.org_id}/analyses/{item.job_id}")).json()
    assert (job["analyzer"], job["profile"], job["os_hint"], job["status"], job["auto"]) == (
        "disk",
        "full",
        "windows",
        "queued",
        False,
    )
    async with tenant_session(reg.org_id, None) as session:
        rows = (
            await session.execute(
                select(AnalysisJobSegment.ordinal, AnalysisJobSegment.evidence_id)
                .where(AnalysisJobSegment.job_id == item.job_id)
                .order_by(AnalysisJobSegment.ordinal)
            )
        ).all()
        [audited] = list(
            await session.scalars(select(AuditLog).where(AuditLog.action == "analysis.requested"))
        )
    assert [(o, str(e)) for o, e in rows] == list(enumerate(ids))
    assert audited.details is not None and audited.details["segments"] == ids
    for ordinal, evidence_id in enumerate(ids):
        [requested] = [
            e for e in await _custody(reg, evidence_id) if e["action"] == "analysis_requested"
        ]
        assert requested["details"]["job_id"] == str(item.job_id)
        if ordinal:
            assert requested["details"]["ordinal"] == ordinal


async def test_every_segment_is_restricted_by_the_request(sent: SentJobs) -> None:
    """A segment uploaded without `kind=disk` (no default at upload) is restricted by the job."""
    reg = await register()
    case = await new_case(reg)
    first = (await dr.upload_disk(reg, case, dr.SEGMENT + b"\x01")).json()["id"]
    plain = await upload(reg.client, reg.org_id, case, b"\x00" * 2048, "host.E02")
    assert sent and sent[-1].analyzer == "static"  # the plain upload's automatic `av` run
    response = await dr.run_disk(reg, first, [first, plain["id"]])
    assert response.status_code == 201, response.text
    async with tenant_session(reg.org_id, None) as session:
        rows = (
            await session.execute(
                select(
                    MemorySensitivity.evidence_id,
                    MemorySensitivity.state,
                    MemorySensitivity.source,
                )
            )
        ).all()
    states = {str(e): (state, source) for e, state, source in rows}
    assert states == {
        first: ("restricted", "disk"),
        plain["id"]: ("restricted", "disk"),
    }


@pytest.mark.parametrize(
    "body",
    [
        {"analyzer": "disk", "profile": "extract"},
        {"analyzer": "disk", "profile": "av"},
        {"analyzer": "disk", "os_hint": "macos"},
        {"analyzer": "disk", "segments": []},
        {"analyzer": "static", "profile": "av"},
    ],
)
async def test_invalid_disk_requests_are_rejected(sent: SentJobs, body: dict[str, Any]) -> None:
    reg = await register()
    evidence = (await dr.upload_disk(reg, await new_case(reg))).json()
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json={"segments": [evidence["id"]], **body},
        headers=csrf(reg.client),
    )
    assert response.status_code == 422, response.text
    assert await jobs_for(reg.client, reg.org_id, evidence["id"]) == [] and sent == []


async def test_one_active_disk_job_per_org(sent: SentJobs) -> None:
    reg, _, _ = await dr.queued_job(sent)
    other = (await dr.upload_disk(reg, await new_case(reg), dr.SEGMENT + b"\x09")).json()["id"]
    busy = await dr.run_disk(reg, other)
    assert busy.status_code == 429 and busy.json()["error"]["code"] == "analysis_queue_full"
    assert await jobs_for(reg.client, reg.org_id, other) == []


async def test_the_global_disk_cap(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "disk_max_active_total", 1)
    await dr.queued_job(sent)
    second = await register()
    evidence = (await dr.upload_disk(second, await new_case(second))).json()["id"]
    refused = await dr.run_disk(second, evidence)
    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "analysis_queue_full"


async def test_a_lost_enqueue_fails_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.modules.analysis import dispatch

    async def broken(_: Any) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(dispatch, "send", broken)
    reg = await register()
    evidence = (await dr.upload_disk(reg, await new_case(reg))).json()["id"]
    response = await dr.run_disk(reg, evidence)
    assert response.status_code == 201, response.text
    assert (response.json()["status"], response.json()["error_code"]) == (
        "failed",
        "enqueue_failed",
    )
    # The set stays recorded (audited, immutable) even though the job never ran.
    async with tenant_session(reg.org_id, None) as session:
        count = len(
            (
                await session.execute(
                    select(AnalysisJobSegment.ordinal).where(
                        AnalysisJobSegment.job_id == uuid.UUID(response.json()["id"])
                    )
                )
            ).all()
        )
    assert count == 1
