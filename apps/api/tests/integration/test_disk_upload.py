"""M9 phase 7: disk image intake (`kind=disk`).

A disk segment is restricted (source `disk`, AI and TI excluded) in its upload transaction,
labelled from its magic, held to its own size limit, and never analyzed automatically (no
static `av`: the M8 RT3 rule).
"""

import shutil
import uuid
from collections import namedtuple
from typing import Any

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.filetypes import EWF_LABEL, RAW_DISK_LABEL
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.evidence import sensitivity
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis.models import MemorySensitivity
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs, jobs_for, new_case
from tests.disk_results import sent as sent  # noqa: F401 (fixture)
from tests.factories import Registered, register

MIB = 1024**2
EWF_HEAD = b"EVF\x09\x0d\x0a\xff\x00" + b"\x01" * 4088


async def _evidence(org_id: uuid.UUID, evidence_id: str) -> Evidence:
    async with tenant_session(org_id, None) as session:
        evidence = await session.get(Evidence, uuid.UUID(evidence_id))
    assert evidence is not None
    return evidence


async def _sensitivity(reg: Registered, evidence_id: str) -> Any:
    response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}")
    assert response.status_code == 200, response.text
    return response.json()["sensitivity"]


async def test_a_disk_upload_is_restricted_and_never_auto_analyzed(sent: SentJobs) -> None:
    """A 1 MiB file would otherwise get an automatic static `av` job."""
    reg = await register()
    response = await dr.upload_disk(reg, await new_case(reg), b"\x01" * MIB, "image.bin")
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert await jobs_for(reg.client, reg.org_id, evidence["id"]) == [] and sent == []
    assert evidence["declared_type"] == "disk" and evidence["type_mismatch"] is False
    assert await _sensitivity(reg, evidence["id"]) == {"state": "restricted", "source": "disk"}
    evidence_id = uuid.UUID(evidence["id"])
    async with tenant_session(reg.org_id, None) as session:
        marker = await session.get(MemorySensitivity, evidence_id)
        policy = await session.get(EvidenceSharePolicy, evidence_id)
        actions = list(
            await session.scalars(
                select(AuditLog.action).where(AuditLog.target_id == evidence_id)
            )
        )
    assert marker is not None and (marker.state, marker.source) == ("restricted", "disk")
    assert marker.defaulted_by == reg.user_id
    assert policy is not None and policy.ai_excluded and policy.ti_excluded
    assert "disk.sensitivity_defaulted" in actions


async def test_the_default_rolls_back_with_a_failed_upload(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_: Any) -> bool:
        raise RuntimeError("sensitivity default failed")

    monkeypatch.setattr(sensitivity, "apply_restricted_default", broken)
    reg = await register()
    case = await new_case(reg)
    try:
        response = await dr.upload_disk(reg, case)
    except RuntimeError as exc:  # the test transport re-raises app exceptions
        assert "sensitivity default failed" in str(exc)
    else:
        assert response.status_code == 500, response.text
    async with tenant_session(reg.org_id, None) as session:
        assert (await session.execute(select(Evidence.id))).first() is None


@pytest.mark.parametrize(
    ("content", "label"), [(EWF_HEAD, EWF_LABEL), (b"\x00" * 4096, RAW_DISK_LABEL)]
)
async def test_the_content_label_is_metadata_only(
    sent: SentJobs, content: bytes, label: str
) -> None:
    reg = await register()
    evidence = (await dr.upload_disk(reg, await new_case(reg), content, "seg.E01")).json()
    stored = await _evidence(reg.org_id, evidence["id"])
    assert stored.detected_description == label
    assert stored.declared_type == "disk"


async def test_an_e01_name_alone_declares_disk_but_is_still_a_plain_upload(
    sent: SentJobs,
) -> None:
    reg = await register()
    response = await dr.upload_disk(reg, await new_case(reg), EWF_HEAD, "seg.E01", kind=None)
    evidence = response.json()
    assert evidence["declared_type"] == "disk"
    assert await _sensitivity(reg, evidence["id"]) is None  # no `kind=disk`: no default


async def test_a_disk_upload_has_its_own_size_limit(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "max_evidence_bytes", 1024)
    monkeypatch.setattr(settings, "disk_max_upload_bytes", 8192)
    reg = await register()
    case = await new_case(reg)
    plain = await dr.upload_disk(reg, case, b"\x00" * 4096, kind=None)
    assert plain.status_code == 413 and plain.json()["error"]["code"] == "payload_too_large"
    assert (await dr.upload_disk(reg, case, b"\x00" * 4096)).status_code == 201
    too_big = await dr.upload_disk(reg, case, b"\x00" * 8193)
    assert too_big.status_code == 413
    assert too_big.json()["error"]["code"] == "disk_image_too_large"


async def test_an_empty_disk_upload_is_refused(sent: SentJobs) -> None:
    reg = await register()
    response = await dr.upload_disk(reg, await new_case(reg), b"")
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "disk_image_empty"
    async with tenant_session(reg.org_id, None) as session:
        assert (await session.execute(select(Evidence.id))).first() is None


async def test_a_disk_upload_needs_spool_space(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage(10, 10, 0))
    reg = await register()
    refused = await dr.upload_disk(reg, await new_case(reg))
    assert refused.status_code == 507
    assert refused.json()["error"]["code"] == "insufficient_storage"
