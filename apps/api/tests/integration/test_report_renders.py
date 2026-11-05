"""Report renditions (M6 phase 4): creation (dedupe, caps, permissions, rate limit), the
render message, listing, downloads (headers, audit, re-hash -> 409 integrity_failed) and,
opt-in, the whole pipeline through the real broker and report-worker-test.

The broker publish is captured by default (`sent`): the message is built for real
(presigned GET / POST against MinIO) but not sent.
"""

import base64
import dataclasses
import hashlib
import io
import json
import os
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cyberlab_jobs.report import RENDER_CONTENT_TYPES, ReportRenderMessageV1
from sqlalchemy import select, update

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from app.modules.reports import dispatch, render_ingest
from app.modules.reports.models import ReportRender, ReportRenderIndex
from tests.analysis_helpers import drain_ingest, new_case, purge_test_queues
from tests.factories import (
    Registered,
    add_member,
    csrf,
    login,
    make_user,
    register,
    unique_email,
)
from tests.integration.seed import Tenant
from tests.report_helpers import (
    SeededVersion,
    fake_snapshot,
    new_signing_keys,
    purge_reports_test_bucket,
    reports_test_bucket,
    seed_render,
    seed_report,
    seed_version,
)

API = "/api/v1/orgs/{org}"


@dataclass(frozen=True)
class Seeded:
    reg: Registered
    tenant: Tenant
    report_id: uuid.UUID
    version: SeededVersion

    @property
    def renders_url(self) -> str:
        return (
            f"{API.format(org=self.reg.org_id)}/reports/{self.report_id}/versions/"
            f"{self.version.version}/renders"
        )

    def render_url(self, render_id: uuid.UUID | str) -> str:
        return f"{API.format(org=self.reg.org_id)}/report-renders/{render_id}"


async def seed(*, tlp: str = "amber", reg: Registered | None = None) -> Seeded:
    reg = reg or await register()
    tenant = Tenant(reg.org_id, reg.user_id, uuid.UUID(await new_case(reg)))
    report_id = await seed_report(tenant, tlp=tlp)
    # The snapshot names this report and version, as finalize writes it (the renderer
    # checks the snapshot against the signed manifest).
    golden = fake_snapshot()
    snapshot = fake_snapshot(
        report=golden.report.model_copy(
            update={"report_id": report_id, "version": 1, "tlp": tlp, "document_control": []}
        )
    )
    version = await seed_version(tenant, report_id, new_signing_keys(), snapshot=snapshot, tlp=tlp)
    return Seeded(reg, tenant, report_id, version)


async def succeeded_render(
    s: Seeded,
    fmt: str = "pdf",
    data: bytes = b"%PDF-1.7 rendition",
    *,
    recorded: bytes | None = None,
) -> uuid.UUID:
    """A succeeded render whose artifact is stored at its key (`recorded`: the bytes whose
    hash the row records, when it should differ from what is stored)."""
    render_id, _ = await seed_render(s.tenant, s.version.version_id, fmt=fmt)
    key = dispatch.render_key(s.reg.org_id, s.report_id, s.version.version, render_id, fmt)
    put = get_minio().put_object(
        reports_test_bucket(),
        key,
        io.BytesIO(data),
        len(data),
        content_type=RENDER_CONTENT_TYPES[fmt],
    )
    recorded = data if recorded is None else recorded
    async with tenant_session(s.reg.org_id, s.reg.user_id) as session:
        render = await session.get(ReportRender, render_id)
        assert render is not None
        render.status = "running"
        await session.flush()
        render.status = "succeeded"
        render.sha256 = hashlib.sha256(recorded).hexdigest()
        render.bytes = len(recorded)
        render.pages = 1 if fmt == "pdf" else None
        render.object_version_id = str(put.version_id)
        render.renderer_version = "report-worker/test"
        render.finished_at = datetime.now(UTC)
        await session.execute(
            update(ReportRenderIndex)
            .where(ReportRenderIndex.render_id == render_id)
            .values(status="succeeded")
        )
    return render_id


async def failed_render(s: Seeded, fmt: str = "pdf", code: str = "timeout") -> uuid.UUID:
    render_id, _ = await seed_render(s.tenant, s.version.version_id, fmt=fmt)
    async with tenant_session(s.reg.org_id, None) as session:
        await session.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(status="failed", error_code=code)
        )
    return render_id


async def audits(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars())


class Sent(list[ReportRenderMessageV1]):
    pass


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    """Messages built for real (presigned against MinIO) and captured instead of sent."""
    captured = Sent()

    def capture(item: dispatch.RenderInput) -> None:
        captured.append(dispatch.build_message(item))

    monkeypatch.setattr(dispatch, "_send_sync", capture)
    return captured


@pytest.fixture(autouse=True)
def _purge_reports() -> Iterator[None]:
    yield
    purge_reports_test_bucket()


async def _post(s: Seeded, fmt: str = "pdf", reg: Registered | None = None) -> Any:
    client = (reg or s.reg).client
    return await client.post(s.renders_url, json={"format": fmt}, headers=csrf(client))


# --- creation ------------------------------------------------------------------------------


async def test_a_render_is_queued_indexed_audited_and_dispatched(sent: Sent) -> None:
    s = await seed()
    before = datetime.now(UTC)
    response = await _post(s)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "queued" and body["format"] == "pdf"
    assert body["version_id"] == str(s.version.version_id)
    render_id = uuid.UUID(body["id"])
    async with tenant_session(None, None) as session:
        index = await session.get(ReportRenderIndex, render_id)
    assert index is not None and index.status == "queued" and index.attempts == 1
    assert index.dispatched_at is not None
    deadline = index.deadline_at - before
    assert timedelta(seconds=590) < deadline < timedelta(seconds=620)
    [audit] = await audits(s.reg.org_id, "report.render_requested")
    assert audit.details == {
        "report_id": str(s.report_id),
        "version": s.version.version,
        "format": "pdf",
    }
    [message] = sent
    assert message.render_id == render_id and message.org_id == s.reg.org_id
    assert message.snapshot_sha256 == s.version.sha256
    assert message.snapshot_bytes == len(s.version.snapshot)
    assert f"versionId={s.version.object_version_id}" in message.snapshot_url
    assert base64.b64decode(message.manifest_b64) == s.version.manifest
    assert (message.signature, message.kid) == (s.version.signature, s.version.kid)
    assert message.finalized_at == datetime.fromisoformat(
        json.loads(s.version.manifest)["finalized_at"]
    )
    assert message.upload.fields["key"] == (
        f"{s.reg.org_id}/{s.report_id}/{s.version.version}/{render_id}.pdf"
    )
    assert message.upload.fields["Content-Type"] == "application/pdf"
    assert message.upload.url.endswith(f"/{get_settings().reports_bucket}")
    async with tenant_session(s.reg.org_id, None) as session:
        render = await session.get(ReportRender, render_id)
    assert render is not None and dispatch.token_ok(render, message.token)


async def test_the_renderer_fetches_the_snapshot_and_may_upload_only_its_artifact(
    sent: Sent,
) -> None:
    """The presigned URLs work exactly as far as they should."""
    import httpx

    s = await seed()
    assert (await _post(s, "md")).status_code == 202
    [message] = sent
    snapshot = httpx.get(message.snapshot_url, timeout=10)
    assert snapshot.status_code == 200 and snapshot.content == s.version.snapshot

    def upload(content: bytes, **fields: str) -> httpx.Response:
        return httpx.post(
            message.upload.url,
            data={**message.upload.fields, **fields},
            files={"file": ("report.md", content, "text/markdown")},
            timeout=10,
        )

    assert upload(b"").status_code >= 400  # content-length-range starts at 1
    other_key = f"{s.reg.org_id}/{s.report_id}/{s.version.version}/other.md"
    assert upload(b"x", key=other_key).status_code >= 400
    assert upload(b"x", **{"Content-Type": "text/html"}).status_code >= 400
    ok = upload(b"# fine")
    assert ok.status_code in (200, 201, 204), ok.text
    assert ok.headers.get("x-amz-version-id")


async def test_the_same_format_is_deduplicated(sent: Sent) -> None:
    s = await seed()
    first = await _post(s)
    second = await _post(s)
    assert (first.status_code, second.status_code) == (202, 200)
    assert first.json()["id"] == second.json()["id"]
    assert len(sent) == 1
    assert len(await audits(s.reg.org_id, "report.render_requested")) == 1
    other = await _post(s, "md")
    assert other.status_code == 202 and other.json()["id"] != first.json()["id"]


async def test_a_succeeded_render_is_returned_and_a_failed_one_is_not(sent: Sent) -> None:
    s = await seed()
    done = await succeeded_render(s)
    again = await _post(s)
    assert again.status_code == 200 and again.json()["id"] == str(done)
    failed = await failed_render(s, "md")
    retry = await _post(s, "md")
    assert retry.status_code == 202 and retry.json()["id"] != str(failed)


async def test_the_per_org_cap_answers_render_busy(sent: Sent) -> None:
    s = await seed()
    assert get_settings().report_active_renders_per_org == 2
    assert (await _post(s, "pdf")).status_code == 202
    assert (await _post(s, "html")).status_code == 202
    busy = await _post(s, "md")
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "render_busy"
    # A deduplicated request still answers while the org is at its cap.
    assert (await _post(s, "pdf")).status_code == 200


async def test_the_global_cap_answers_render_busy(
    sent: Sent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "report_active_renders_global", 1)
    first, second = await seed(), await seed()
    assert (await _post(first)).status_code == 202
    busy = await _post(second)
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "render_busy"


async def test_a_lost_publish_leaves_the_render_queued_for_the_reaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def down(item: dispatch.RenderInput) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(dispatch, "_send_sync", down)
    s = await seed()
    response = await _post(s)
    assert response.status_code == 202
    async with tenant_session(None, None) as session:
        index = await session.get(ReportRenderIndex, uuid.UUID(response.json()["id"]))
    assert index is not None and index.dispatched_at is None and index.attempts == 0


async def test_permissions_and_unknown_versions(sent: Sent) -> None:
    s = await seed()
    email = unique_email("viewer")
    viewer_id = await make_user(email)
    await add_member(s.reg.org_id, viewer_id, MemberRole.VIEWER)
    viewer_client = await login(email)
    viewer_reg = dataclasses.replace(s.reg, client=viewer_client, user_id=viewer_id)
    denied = await _post(s, reg=viewer_reg)
    assert denied.status_code == 403
    render_id = await succeeded_render(s)
    assert (await viewer_client.get(s.renders_url)).status_code == 200
    assert (await viewer_client.get(s.render_url(render_id))).status_code == 200
    assert (await viewer_client.get(s.render_url(render_id) + "/download")).status_code == 200
    missing = s.renders_url.replace(f"/versions/{s.version.version}/", "/versions/99/")
    assert (await s.reg.client.get(missing)).status_code == 404
    assert (
        await s.reg.client.post(missing, json={"format": "pdf"}, headers=csrf(s.reg.client))
    ).status_code == 404
    bad = await s.reg.client.post(
        s.renders_url, json={"format": "docx"}, headers=csrf(s.reg.client)
    )
    assert bad.status_code == 422
    assert (await s.reg.client.get(s.render_url(uuid.uuid4()))).status_code == 404


async def test_render_requests_are_rate_limited(
    sent: Sent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "report_renders_per_user_10min", 2)
    s = await seed()
    assert (await _post(s)).status_code == 202
    assert (await _post(s)).status_code == 200
    limited = await _post(s)
    assert limited.status_code == 429 and "Retry-After" in limited.headers


async def test_list_and_get(sent: Sent) -> None:
    s = await seed()
    done = await succeeded_render(s)
    queued = uuid.UUID((await _post(s, "md")).json()["id"])
    listed = (await s.reg.client.get(s.renders_url)).json()["items"]
    assert [r["id"] for r in listed] == [str(done), str(queued)]
    got = (await s.reg.client.get(s.render_url(done))).json()
    assert got["status"] == "succeeded" and got["sha256"] and got["pages"] == 1
    assert got["renderer_version"] == "report-worker/test"


# --- downloads -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fmt", "tlp", "filename", "csp"),
    [
        ("pdf", "amber", "CASE-00001_v1_TLP-AMBER.pdf", "sandbox"),
        ("md", "red", "CASE-00001_v1_TLP-RED.md", "sandbox"),
        (
            "html",
            "amber_strict",
            "CASE-00001_v1_TLP-AMBER+STRICT.html",
            "sandbox; default-src 'none'; style-src 'unsafe-inline'",
        ),
    ],
)
async def test_a_download_is_an_audited_sandboxed_attachment(
    fmt: str, tlp: str, filename: str, csp: str
) -> None:
    s = await seed(tlp=tlp)
    data = {"pdf": b"%PDF-1.7 x", "md": "**TLP:RED** ⏎".encode(), "html": b"<!DOCTYPE html>"}[fmt]
    render_id = await succeeded_render(s, fmt, data)
    response = await s.reg.client.get(s.render_url(render_id) + "/download")
    assert response.status_code == 200
    assert response.content == data
    headers = response.headers
    assert headers["content-type"].startswith(RENDER_CONTENT_TYPES[fmt].split(";")[0])
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert headers["content-security-policy"] == csp
    disposition = headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert "filename*=UTF-8''" + filename.replace("+", "%2B") in disposition
    [audit] = await audits(s.reg.org_id, "report.downloaded")
    assert audit.details == {
        "report_id": str(s.report_id),
        "version": 1,
        "format": fmt,
        "tlp": tlp,
    }
    assert audit.actor_id == s.reg.user_id and audit.target_id == render_id


async def test_a_tampered_artifact_is_refused_and_audited() -> None:
    s = await seed()
    render_id = await succeeded_render(s, data=b"%PDF-1.7 stored", recorded=b"%PDF-1.7 signed")
    response = await s.reg.client.get(s.render_url(render_id) + "/download")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "integrity_failed"
    assert len(await audits(s.reg.org_id, "report.integrity_failed")) == 1
    assert await audits(s.reg.org_id, "report.downloaded") == []


async def test_a_render_that_has_not_succeeded_cannot_be_downloaded(sent: Sent) -> None:
    s = await seed()
    queued = (await _post(s)).json()["id"]
    response = await s.reg.client.get(s.render_url(queued) + "/download")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "render_not_ready"


async def test_another_orgs_render_is_not_found() -> None:
    victim, attacker = await seed(), await seed()
    render_id = await succeeded_render(victim)
    for path in ("", "/download"):
        url = attacker.render_url(render_id) + path
        assert (await attacker.reg.client.get(url)).status_code == 404
    foreign = victim.renders_url.replace(str(victim.reg.org_id), str(attacker.reg.org_id))
    assert (await attacker.reg.client.get(foreign)).status_code == 404


# --- the whole pipeline (opt-in, heavy) ----------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("REPORT_E2E"),
    reason="REPORT_E2E=1 with report-worker-test consuming this lane's broker db",
)
async def test_end_to_end_pdf() -> None:
    """Finalized version -> POST render -> real broker -> report-worker-test (sandboxed
    WeasyPrint) -> presigned upload -> report.rendered -> ingest re-hash -> download."""
    purge_test_queues()  # declares the ingest binding, as the trusted side does
    s = await seed()
    response = await _post(s)
    assert response.status_code == 202, response.text
    render_id = response.json()["id"]
    status = "queued"
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline and status in ("queued", "running"):
        for message in drain_ingest(2.0):
            await render_ingest.handle_rendered_message(message)
        status = (await s.reg.client.get(s.render_url(render_id))).json()["status"]
    body = (await s.reg.client.get(s.render_url(render_id))).json()
    assert body["status"] == "succeeded", body
    assert body["pages"] >= 1 and body["renderer_version"].startswith("report-worker/")
    download = await s.reg.client.get(s.render_url(render_id) + "/download")
    assert download.status_code == 200
    assert download.content.startswith(b"%PDF-")
    assert hashlib.sha256(download.content).hexdigest() == body["sha256"]
    assert len(download.content) == body["bytes"]
    assert len(await audits(s.reg.org_id, "report.rendered")) == 1
