"""M9 phase 7: segment-set refusals against stored evidence (every reason the database can
produce; `purged` is covered by `tests/unit/test_disk_segments.py`). A refused set creates
nothing: no job, no segment row, no sensitivity default, nothing dispatched."""

import uuid

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob
from app.modules.memory_analysis.models import MemorySensitivity
from tests import disk_results as dr
from tests.analysis_helpers import SentJobs, new_case, upload
from tests.disk_results import sent as sent  # noqa: F401 (fixture)
from tests.factories import Registered, csrf, register


async def _nothing_created(reg: Registered, sent: SentJobs) -> None:
    assert sent == []
    async with tenant_session(reg.org_id, None) as session:
        assert (await session.execute(select(AnalysisJob.id))).first() is None


async def _refused(
    reg: Registered, path_id: str, segments: list[str], code: str, reason: str | None = None
) -> None:
    response = await dr.run_disk(reg, path_id, segments)
    assert response.status_code in (413, 422), response.text
    error = response.json()["error"]
    assert error["code"] == code, error
    if reason is not None:
        assert error["reason"] == reason, error


async def _two(reg: Registered) -> tuple[str, list[str]]:
    case = await new_case(reg)
    return case, await dr.upload_segments(reg, case, 2)


async def test_the_path_evidence_is_segment_zero(sent: SentJobs) -> None:
    reg = await register()
    _, (a, b) = await _two(reg)
    await _refused(reg, a, [b, a], "disk_segments_invalid", "first_segment")
    await _refused(reg, a, [b], "disk_segments_invalid", "first_segment")
    await _nothing_created(reg, sent)


async def test_a_segment_listed_twice_is_refused_by_schema(sent: SentJobs) -> None:
    reg = await register()
    _, (a, _b) = await _two(reg)
    response = await dr.run_disk(reg, a, [a, a])
    assert response.status_code == 422, response.text
    await _nothing_created(reg, sent)


async def test_unknown_and_foreign_ids_are_not_found(sent: SentJobs) -> None:
    reg = await register()
    _, (a, _b) = await _two(reg)
    await _refused(reg, a, [a, str(uuid.uuid4())], "disk_segments_invalid", "not_found")
    # Another org's evidence answers exactly like an unknown id (no oracle).
    other = await register()
    foreign = (await dr.upload_disk(other, await new_case(other))).json()["id"]
    await _refused(reg, a, [a, foreign], "disk_segments_invalid", "not_found")
    await _nothing_created(reg, sent)


async def test_every_segment_is_in_the_request_case(sent: SentJobs) -> None:
    reg = await register()
    _, (a, _b) = await _two(reg)
    elsewhere = (await dr.upload_disk(reg, await new_case(reg), b"\x07" * 512)).json()["id"]
    await _refused(reg, a, [a, elsewhere], "disk_segments_invalid", "other_investigation")
    await _nothing_created(reg, sent)
    async with tenant_session(reg.org_id, None) as session:
        restricted = list(await session.scalars(select(MemorySensitivity.evidence_id)))
    # Only the uploads' own defaults: the refused request restricted nothing more.
    assert len(restricted) == 3


async def test_archived_and_empty_segments_are_refused(sent: SentJobs) -> None:
    reg = await register()
    case, (a, b) = await _two(reg)
    archived = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{b}/archive", headers=csrf(reg.client)
    )
    assert archived.status_code == 200, archived.text
    await _refused(reg, a, [a, b], "disk_segments_invalid", "archived")
    empty = await upload(reg.client, reg.org_id, case, b"", "empty.E02")
    await _refused(reg, a, [a, empty["id"]], "disk_segments_invalid", "empty")
    await _nothing_created(reg, sent)


async def test_count_and_size_limits(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register()
    _, (a, b) = await _two(reg)
    settings = get_settings()
    monkeypatch.setattr(settings, "disk_max_segments", 1)
    await _refused(reg, a, [a, b], "disk_segments_invalid", "too_many")
    monkeypatch.setattr(settings, "disk_max_segments", 64)
    monkeypatch.setattr(settings, "disk_max_image_bytes", len(dr.SEGMENT) + 1)
    await _refused(reg, a, [a, b], "disk_image_set_too_large")
    monkeypatch.setattr(settings, "disk_max_upload_bytes", len(dr.SEGMENT) - 1)
    await _refused(reg, a, [a, b], "disk_image_too_large")
    await _nothing_created(reg, sent)
