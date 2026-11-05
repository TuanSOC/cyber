"""`report.rendered` in the trusted ingest (M6 phase 4): the org from the index, the token,
open renders only, the uploaded object re-hashed and its size / magic checked (never
parsed), the per-object retention, the typed failure, the audit, and final states that
never change again."""

import hashlib
import io
import uuid
from typing import Any

import pytest
from cyberlab_jobs.report import RENDER_CONTENT_TYPES, ReportRenderedV1
from minio.commonconfig import GOVERNANCE
from sqlalchemy import select

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.reports import dispatch, render_ingest
from app.modules.reports.models import ReportRender, ReportRenderIndex
from tests.integration.test_report_renders import (
    Seeded,
    _purge_reports,  # noqa: F401 - autouse fixture
    audits,
    seed,
)
from tests.report_helpers import reports_test_bucket, seed_render

PDF = b"%PDF-1.7\n% a rendition\n%%EOF\n"


async def queued(s: Seeded, fmt: str = "pdf", status: str = "queued") -> tuple[uuid.UUID, str]:
    return await seed_render(s.tenant, s.version.version_id, fmt=fmt, status=status)


def upload(s: Seeded, render_id: uuid.UUID, data: bytes, fmt: str = "pdf") -> str:
    key = dispatch.render_key(s.reg.org_id, s.report_id, s.version.version, render_id, fmt)
    put = get_minio().put_object(
        reports_test_bucket(),
        key,
        io.BytesIO(data),
        len(data),
        content_type=RENDER_CONTENT_TYPES[fmt],
    )
    return str(put.version_id)


def succeeded(
    render_id: uuid.UUID, token: str, data: bytes, version_id: str, **over: Any
) -> ReportRenderedV1:
    values: dict[str, Any] = {
        "render_id": render_id,
        "token": token,
        "status": "succeeded",
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "pages": 3,
        "object_version_id": version_id,
        "renderer_version": "report-worker/0.2.0+weasyprint-70.0+template-incident_v1.1",
    }
    values.update(over)
    return ReportRenderedV1.model_validate(values)


async def state(s: Seeded, render_id: uuid.UUID) -> tuple[ReportRender, str]:
    async with tenant_session(s.reg.org_id, None) as session:
        render = await session.get(ReportRender, render_id)
    async with tenant_session(None, None) as session:
        index = await session.get(ReportRenderIndex, render_id)
    assert render is not None and index is not None
    return render, index.status


async def test_a_verified_artifact_succeeds_with_retention_and_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "evidence_lock_days", 1)
    s = await seed()
    render_id, token = await queued(s)
    version_id = upload(s, render_id, PDF)
    await render_ingest.handle_rendered(succeeded(render_id, token, PDF, version_id))
    render, index_status = await state(s, render_id)
    assert (render.status, index_status) == ("succeeded", "succeeded")
    assert render.sha256 == hashlib.sha256(PDF).hexdigest() and render.bytes == len(PDF)
    assert render.pages == 3 and render.object_version_id == version_id
    assert render.renderer_version.startswith("report-worker/0.2.0")  # type: ignore[union-attr]
    assert render.started_at is not None and render.finished_at is not None
    key = dispatch.render_key(s.reg.org_id, s.report_id, 1, render_id, "pdf")
    retention = get_minio().get_object_retention(reports_test_bucket(), key, version_id=version_id)
    assert retention is not None and retention.mode == GOVERNANCE
    [audit] = await audits(s.reg.org_id, "report.rendered")
    assert audit.details["format"] == "pdf" and audit.details["version"] == 1
    assert audit.details["bytes"] == len(PDF) and audit.actor_id is None


@pytest.mark.parametrize(
    ("fmt", "data"),
    [("html", b"<!DOCTYPE html><p>x</p>"), ("md", "**TLP\\:AMBER** ⏎".encode())],
)
async def test_text_formats_succeed_when_utf8(fmt: str, data: bytes) -> None:
    s = await seed()
    render_id, token = await queued(s, fmt)
    version_id = upload(s, render_id, data, fmt)
    await render_ingest.handle_rendered(succeeded(render_id, token, data, version_id, pages=None))
    assert (await state(s, render_id))[0].status == "succeeded"


async def test_a_running_render_succeeds_too() -> None:
    s = await seed()
    render_id, token = await queued(s, status="running")
    version_id = upload(s, render_id, PDF)
    await render_ingest.handle_rendered(succeeded(render_id, token, PDF, version_id))
    assert (await state(s, render_id))[0].status == "succeeded"


async def test_a_wrong_token_changes_nothing(caplog: pytest.LogCaptureFixture) -> None:
    s = await seed()
    render_id, _ = await queued(s)
    version_id = upload(s, render_id, PDF)
    await render_ingest.handle_rendered(succeeded(render_id, "x" * 43, PDF, version_id))
    render, index_status = await state(s, render_id)
    assert (render.status, index_status) == ("queued", "queued")
    assert await audits(s.reg.org_id, "report.rendered") == []
    assert "token mismatch" in caplog.text


async def test_another_renders_token_or_an_unknown_render_is_refused() -> None:
    victim, other = await seed(), await seed()
    victim_render, _ = await queued(victim)
    _, other_token = await queued(other)
    version_id = upload(victim, victim_render, PDF)
    await render_ingest.handle_rendered(succeeded(victim_render, other_token, PDF, version_id))
    assert (await state(victim, victim_render))[0].status == "queued"
    await render_ingest.handle_rendered(succeeded(uuid.uuid4(), other_token, PDF, version_id))


@pytest.mark.parametrize(
    "case",
    ["hash", "size", "magic", "missing_version", "other_key", "too_large", "utf8"],
)
async def test_mismatched_artifacts_fail_with_invalid_output(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = await seed()
    fmt = "md" if case == "utf8" else "pdf"
    render_id, token = await queued(s, fmt)
    data = b"\xff\xfe not utf-8" if case == "utf8" else (b"<html>" if case == "magic" else PDF)
    version_id = upload(s, render_id, data, fmt)
    msg = succeeded(render_id, token, data, version_id, pages=None if fmt == "md" else 3)
    if case == "hash":
        msg = succeeded(render_id, token, data, version_id, sha256="0" * 64)
    elif case == "size":
        msg = succeeded(render_id, token, data, version_id, bytes=len(data) + 1)
    elif case == "missing_version":
        msg = succeeded(render_id, token, data, "not-a-version")
    elif case == "other_key":
        other_id, _ = await queued(s, "md")
        msg = succeeded(render_id, token, data, upload(s, other_id, data, "md"))
    elif case == "too_large":
        monkeypatch.setattr(get_settings(), "report_max_artifact_bytes", len(data) - 1)
    await render_ingest.handle_rendered(msg)
    render, index_status = await state(s, render_id)
    assert (render.status, render.error_code, index_status) == (
        "failed",
        "invalid_output",
        "failed",
    )
    assert render.sha256 is None and render.object_version_id is None
    [audit] = await audits(s.reg.org_id, "report.render_failed")
    assert audit.details["error_code"] == "invalid_output"


async def test_a_failed_answer_stores_the_typed_code() -> None:
    s = await seed()
    render_id, token = await queued(s)
    await render_ingest.handle_rendered(
        ReportRenderedV1(
            render_id=render_id,
            token=token,
            status="failed",
            renderer_version="report-worker/test",
            error_code="oom",
        )
    )
    render, index_status = await state(s, render_id)
    assert (render.status, render.error_code, index_status) == ("failed", "oom", "failed")
    [audit] = await audits(s.reg.org_id, "report.render_failed")
    assert audit.details == {
        "report_id": str(s.report_id),
        "version": 1,
        "format": "pdf",
        "error_code": "oom",
    }


async def test_a_final_render_never_changes_again() -> None:
    s = await seed()
    render_id, token = await queued(s)
    version_id = upload(s, render_id, PDF)
    await render_ingest.handle_rendered(succeeded(render_id, token, PDF, version_id))
    await render_ingest.handle_rendered(
        ReportRenderedV1(
            render_id=render_id,
            token=token,
            status="failed",
            renderer_version="report-worker/test",
            error_code="renderer_error",
        )
    )
    other = upload(s, render_id, b"%PDF-1.7 replaced")
    await render_ingest.handle_rendered(succeeded(render_id, token, b"%PDF-1.7 replaced", other))
    render, _ = await state(s, render_id)
    assert render.status == "succeeded" and render.object_version_id == version_id
    assert len(await audits(s.reg.org_id, "report.rendered")) == 1
    assert await audits(s.reg.org_id, "report.render_failed") == []


async def test_invalid_messages_are_dropped(caplog: pytest.LogCaptureFixture) -> None:
    await render_ingest.handle_rendered_message({"render_id": "nope", "token": "secret"})
    await render_ingest.handle_rendered_message(
        {
            "render_id": str(uuid.uuid4()),
            "token": "t" * 43,
            "status": "succeeded",
            "renderer_version": "x",
        }
    )
    assert "invalid message dropped" in caplog.text and "secret" not in caplog.text


async def test_ingest_reads_the_org_from_the_index_only() -> None:
    """The message names no org; the index row decides which tenant is touched."""
    s = await seed()
    render_id, token = await queued(s)
    async with tenant_session(None, None) as session:
        org = await session.scalar(
            select(ReportRenderIndex.organization_id).where(
                ReportRenderIndex.render_id == render_id
            )
        )
    assert org == s.reg.org_id
    assert "org_id" not in ReportRenderedV1.model_fields
