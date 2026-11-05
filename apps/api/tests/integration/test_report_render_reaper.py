"""`reaper.reap_report_renders` (M6 phase 4): renders past their deadline fail with
`timeout` (audited, final), and renders whose publish was lost are re-dispatched with a
message whose token still proves them, a bounded number of times."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from app.core.tenancy import tenant_session
from app.modules.reports import dispatch
from app.modules.reports.models import ReportRender, ReportRenderIndex, ReportVersion
from app.workers import reaper
from tests.integration.test_report_renders import (
    Seeded,
    Sent,
    _purge_reports,  # noqa: F401 - autouse fixture
    audits,
    failed_render,
    seed,
    sent,  # noqa: F401 - fixture
)
from tests.report_helpers import seed_render


async def index_of(render_id: uuid.UUID) -> ReportRenderIndex:
    async with tenant_session(None, None) as session:
        index = await session.get(ReportRenderIndex, render_id)
    assert index is not None
    return index


async def render_of(s: Seeded, render_id: uuid.UUID) -> ReportRender:
    async with tenant_session(s.reg.org_id, None) as session:
        render = await session.get(ReportRender, render_id)
    assert render is not None
    return render


@pytest.mark.parametrize("status", ["queued", "running"])
async def test_a_render_past_its_deadline_fails_with_timeout(status: str, sent: Sent) -> None:  # noqa: F811
    s = await seed()
    expired, _ = await seed_render(s.tenant, s.version.version_id, status=status, deadline_s=-5)
    alive, _ = await seed_render(s.tenant, s.version.version_id, fmt="md", status=status)
    assert await reaper.reap_report_renders() == 1
    render = await render_of(s, expired)
    assert (render.status, render.error_code) == ("failed", "timeout")
    assert render.finished_at is not None
    assert (await index_of(expired)).status == "failed"
    assert (await render_of(s, alive)).status == status
    [audit] = await audits(s.reg.org_id, "report.render_failed")
    assert audit.details["error_code"] == "timeout" and audit.details["by"] == "reaper"
    assert audit.target_id == expired
    assert await reaper.reap_report_renders() == 0  # final: nothing left to do


async def test_a_final_render_past_its_deadline_is_left_alone(sent: Sent) -> None:  # noqa: F811
    s = await seed()
    render_id = await failed_render(s, code="oom")
    async with tenant_session(None, None) as session:
        await session.execute(
            update(ReportRenderIndex)
            .where(ReportRenderIndex.render_id == render_id)
            .values(status="failed", deadline_at=datetime.now(UTC) - timedelta(seconds=5))
        )
    assert await reaper.reap_report_renders() == 0
    assert (await render_of(s, render_id)).error_code == "oom"


async def _undispatched(s: Seeded) -> uuid.UUID:
    """A render created for real whose publish never happened (inputs lost: a restart)."""
    async with tenant_session(s.reg.org_id, s.reg.user_id) as session:
        version = await session.get(ReportVersion, s.version.version_id)
        assert version is not None
        render = await dispatch.create_render(session, s.reg.org_id, s.reg.user_id, version, "pdf")
        render_id = render.id
    dispatch._PENDING.pop(render_id, None)
    return render_id


async def test_a_lost_publish_is_redispatched_with_a_valid_token(
    sent: Sent,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    s = await seed()
    render_id = await _undispatched(s)
    assert await reaper.reap_report_renders() == 0  # too young: the API may still send it
    assert sent == []
    monkeypatch.setattr(reaper, "RENDER_REDISPATCH_AFTER", timedelta(0))
    assert await reaper.reap_report_renders() == 1
    [message] = sent
    assert message.render_id == render_id
    render = await render_of(s, render_id)
    assert dispatch.token_ok(render, message.token)
    index = await index_of(render_id)
    assert index.dispatched_at is not None and index.attempts == 1
    assert message.deadline == index.deadline_at
    assert await reaper.reap_report_renders() == 0  # dispatched: not sent twice


async def test_redispatch_attempts_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[uuid.UUID] = []

    def down(item: dispatch.RenderInput) -> None:
        calls.append(item.render_id)
        raise ConnectionError("broker down")

    monkeypatch.setattr(dispatch, "_send_sync", down)
    monkeypatch.setattr(reaper, "RENDER_REDISPATCH_AFTER", timedelta(0))
    s = await seed()
    render_id = await _undispatched(s)
    for _ in range(reaper.RENDER_MAX_ATTEMPTS + 2):
        await reaper.reap_report_renders()
    assert len(calls) == reaper.RENDER_MAX_ATTEMPTS
    index = await index_of(render_id)
    assert index.dispatched_at is None and index.attempts == reaper.RENDER_MAX_ATTEMPTS
    # It still times out at its deadline.
    async with tenant_session(None, None) as session:
        await session.execute(
            update(ReportRenderIndex)
            .where(ReportRenderIndex.render_id == render_id)
            .values(deadline_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    assert await reaper.reap_report_renders() == 1
    assert (await render_of(s, render_id)).error_code == "timeout"


async def test_the_reap_task_runs_the_render_reaper() -> None:
    import inspect

    from app.workers import tasks

    assert "reap_report_renders" in inspect.getsource(tasks.reap)
