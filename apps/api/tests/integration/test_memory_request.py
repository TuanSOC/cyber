"""M8 phase 6: memory intake (`kind=memory`) and the memory analysis request.

Dispatch is captured (no memory worker needed). The restricted state itself is written by
phase 8's `apply_memory_default`; these tests assert that it is called in the right
transaction, and the state where phase 8 is in.
"""

import shutil
import uuid
from collections import namedtuple
from typing import Any

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.audit.models import AuditLog
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis import sensitivity
from app.modules.memory_analysis.models import MemorySensitivity
from tests import memory_results as mr
from tests.analysis_helpers import SentJobs, jobs_for, new_case, tiny_pcap, upload
from tests.factories import Registered, csrf, register

MIB = 1024**2


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


Call = tuple[uuid.UUID, uuid.UUID, uuid.UUID]


@pytest.fixture
def defaults(monkeypatch: pytest.MonkeyPatch) -> list[Call]:
    """Every `apply_memory_default` call (org, evidence, actor); the real one still runs."""
    calls: list[Call] = []
    real = sensitivity.apply_memory_default

    async def spy(
        session: Any, org_id: uuid.UUID, evidence_id: uuid.UUID, actor: uuid.UUID
    ) -> bool:
        calls.append((org_id, evidence_id, actor))
        return await real(session, org_id, evidence_id, actor)

    monkeypatch.setattr(sensitivity, "apply_memory_default", spy)
    return calls


async def _audits(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars())


async def _evidence(org_id: uuid.UUID, evidence_id: str) -> Evidence:
    async with tenant_session(org_id, None) as session:
        evidence = await session.get(Evidence, uuid.UUID(evidence_id))
    assert evidence is not None
    return evidence


async def _memory_upload(reg: Registered, content: bytes = mr.IMAGE, **kw: Any) -> Any:
    response = await mr.upload_memory(reg, await new_case(reg), content, **kw)
    assert response.status_code == 201, response.text
    return response.json()


# --- intake ------------------------------------------------------------------------------


async def test_a_memory_upload_is_declared_and_never_auto_analyzed(
    sent: SentJobs, defaults: list[Call]
) -> None:
    """RT3: a 1 MiB file would otherwise get an automatic static `av` job."""
    reg = await register()
    evidence = await _memory_upload(reg, b"\x01" * MIB, filename="image.bin")
    assert await jobs_for(reg.client, reg.org_id, evidence["id"]) == [] and sent == []
    assert evidence["declared_type"] == "memory" and evidence["type_mismatch"] is False
    stored = await _evidence(reg.org_id, evidence["id"])
    assert (stored.declared_type, stored.type_mismatch) == ("memory", False)
    # The TLP:RED default ran once, in the upload (same org, evidence and uploader).
    assert defaults == [(reg.org_id, uuid.UUID(evidence["id"]), reg.user_id)]


async def test_a_memory_upload_is_restricted_in_its_own_transaction(sent: SentJobs) -> None:
    """Needs phase 8's `apply_memory_default` (the phase-1 stub changes nothing)."""
    reg = await register()
    evidence = await _memory_upload(reg)
    async with tenant_session(reg.org_id, None) as session:
        marker = await session.get(MemorySensitivity, uuid.UUID(evidence["id"]))
        policy = await session.get(EvidenceSharePolicy, uuid.UUID(evidence["id"]))
    assert marker is not None and marker.state == "restricted"
    assert marker.defaulted_by == reg.user_id
    assert policy is not None and policy.ai_excluded and policy.ti_excluded


async def test_the_default_rolls_back_with_a_failed_upload(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default is part of the upload transaction: if it fails, no evidence exists."""

    async def broken(*_: Any) -> bool:
        raise RuntimeError("sensitivity default failed")

    monkeypatch.setattr(sensitivity, "apply_memory_default", broken)
    reg = await register()
    case = await new_case(reg)
    try:
        response = await mr.upload_memory(reg, case)
    except RuntimeError as exc:  # the test transport re-raises app exceptions
        assert "sensitivity default failed" in str(exc)
    else:
        assert response.status_code == 500, response.text
    async with tenant_session(reg.org_id, None) as session:
        assert (await session.execute(select(Evidence.id))).first() is None


async def test_an_image_extension_alone_declares_memory_but_changes_nothing_else(
    sent: SentJobs, defaults: list[Call]
) -> None:
    reg = await register()
    evidence = await _memory_upload(reg, b"\x01" * 1024, filename="host.vmem", kind=None)
    assert evidence["declared_type"] == "memory" and evidence["type_mismatch"] is False
    # Without `kind=memory`: the M3 automatic AV scan, no sensitivity default at upload.
    [job] = await jobs_for(reg.client, reg.org_id, evidence["id"])
    assert (job["analyzer"], job["profile"]) == ("static", "av")
    assert defaults == []


async def test_a_memory_upload_has_its_own_size_limit(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "max_evidence_bytes", 1024)
    monkeypatch.setattr(settings, "memory_max_bytes", 8192)
    reg = await register()
    case = await new_case(reg)
    # Above the evidence limit, within the memory limit: only `kind=memory` accepts it.
    plain = await mr.upload_memory(reg, case, b"\x00" * 4096, kind=None)
    assert plain.status_code == 413 and plain.json()["error"]["code"] == "payload_too_large"
    memory = await mr.upload_memory(reg, case, b"\x00" * 4096)
    assert memory.status_code == 201, memory.text
    too_big = await mr.upload_memory(reg, case, b"\x00" * 8193)
    assert too_big.status_code == 413
    assert too_big.json()["error"]["code"] == "memory_image_too_large"


async def test_a_memory_upload_needs_spool_space(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage(10, 10, 0))
    reg = await register()
    case = await new_case(reg)
    refused = await mr.upload_memory(reg, case)
    assert refused.status_code == 507 and refused.json()["error"]["code"] == (
        "insufficient_storage"
    )
    # Other uploads do not check (unchanged M7 behaviour).
    assert (await mr.upload_memory(reg, case, kind=None)).status_code == 201
    async with tenant_session(reg.org_id, None) as session:
        assert len((await session.execute(select(Evidence.id))).all()) == 1


# --- request -----------------------------------------------------------------------------


async def test_a_memory_request_queues_a_job_with_its_defaults(
    sent: SentJobs, defaults: list[Call]
) -> None:
    reg, evidence_id, item = await mr.queued_job(sent)
    assert (item.profile, item.os_hint) == ("triage", "auto")
    job = (await reg.client.get(f"/api/v1/orgs/{reg.org_id}/analyses/{item.job_id}")).json()
    assert (job["analyzer"], job["profile"], job["os_hint"], job["status"], job["auto"]) == (
        "memory",
        "triage",
        "auto",
        "queued",
        False,
    )
    # Once at upload, once at the request (idempotent; covers uploads without the kind).
    assert defaults == [(reg.org_id, uuid.UUID(evidence_id), reg.user_id)] * 2
    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/custody")
    ).json()["items"]
    [requested] = [e for e in custody if e["action"] == "analysis_requested"]
    assert requested["details"]["analyzer"] == "memory"
    assert (requested["details"]["profile"], requested["details"]["os_hint"]) == (
        "triage",
        "auto",
    )
    [audited] = await _audits(reg.org_id, "analysis.requested")
    assert audited.details is not None
    assert {k: audited.details[k] for k in ("analyzer", "profile", "os_hint")} == {
        "analyzer": "memory",
        "profile": "triage",
        "os_hint": "auto",
    }


async def test_a_memory_request_on_a_plain_upload_applies_the_default(
    sent: SentJobs, defaults: list[Call]
) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap(), "x.pcap")
    response = await mr.run_memory(reg, evidence["id"], profile="full", os_hint="linux")
    assert response.status_code == 201, response.text
    assert (response.json()["profile"], response.json()["os_hint"]) == ("full", "linux")
    assert defaults == [(reg.org_id, uuid.UUID(evidence["id"]), reg.user_id)]
    assert [(i.analyzer, i.profile, i.os_hint) for i in sent] == [
        ("pcap", None, None),
        ("memory", "full", "linux"),
    ]


@pytest.mark.parametrize(
    "body",
    [
        {"analyzer": "memory", "profile": "av"},
        {"analyzer": "memory", "os_hint": "macos"},
        {"analyzer": "pcap", "os_hint": "windows"},
        {"analyzer": "static", "profile": "triage"},
        {"analyzer": "memory", "plugins": ["windows.handles"]},
    ],
)
async def test_invalid_memory_requests_are_rejected(sent: SentJobs, body: dict[str, Any]) -> None:
    reg = await register()
    evidence = await _memory_upload(reg)
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json=body,
        headers=csrf(reg.client),
    )
    assert response.status_code == 422, response.text
    assert await jobs_for(reg.client, reg.org_id, evidence["id"]) == []


async def test_memory_size_refusals(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register()
    case = await new_case(reg)
    empty = (await mr.upload_memory(reg, case, b"")).json()
    refused = await mr.run_memory(reg, empty["id"])
    assert refused.status_code == 422 and refused.json()["error"]["code"] == ("memory_image_empty")
    image = (await mr.upload_memory(reg, case)).json()
    monkeypatch.setattr(get_settings(), "memory_max_bytes", len(mr.IMAGE) - 1)
    too_big = await mr.run_memory(reg, image["id"])
    assert too_big.status_code == 413
    assert too_big.json()["error"]["code"] == "memory_image_too_large"
    assert sent == []


async def test_one_active_memory_job_per_org(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    # api-test raises the caps (tests create many jobs): restore the plan's per-org default.
    monkeypatch.setattr(get_settings(), "memory_max_active_per_org", 1)
    reg, _, _ = await mr.queued_job(sent)
    case = await new_case(reg)
    other = (await mr.upload_memory(reg, case)).json()
    full = await mr.run_memory(reg, other["id"])
    assert full.status_code == 429 and full.json()["error"]["code"] == "analysis_queue_full"
    # The memory cap is its own: a static run in the same org is still accepted.
    static = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{other['id']}/analyses",
        json={"analyzer": "static", "profile": "av"},
        headers=csrf(reg.client),
    )
    assert static.status_code == 201, static.text


async def test_the_global_memory_cap(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "memory_max_active_total", 1)
    await mr.queued_job(sent)
    second = await register()
    evidence = (await mr.upload_memory(second, await new_case(second))).json()
    refused = await mr.run_memory(second, evidence["id"])
    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "analysis_queue_full"
