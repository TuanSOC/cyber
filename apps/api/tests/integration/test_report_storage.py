"""Snapshot storage (M6 phase 3, RT6, RT11): finalize stores the canonical bytes in
`reports-test` under `{org}/{report}/{version}/snapshot.json`, records the exact object
version, sets a per-object GOVERNANCE retention on it, and the `content` / `snapshot` routes
serve exactly those bytes (refusing a tampered object)."""

import hashlib
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cyberlab_jobs.report import canonical_json, parse_snapshot

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.organizations.models import MemberRole
from app.modules.reports import storage as report_storage
from app.modules.reports.models import ReportVersion
from tests.factories import add_member, login, make_user, unique_email
from tests.integration.test_report_signing import tampered_version
from tests.report_helpers import (
    REPORTS_TEST_BUCKET,
    SigningKeys,
    purge_reports_test_bucket,
    seed_report,
    seed_version,
    use_signing_keys,
)
from tests.security.idor_cases_reports import (
    API,
    Dispatched,
    api_create,
    api_finalize,
    api_patch,
    draft,
    fake_case_iocs,
    fake_dispatch,
    owner_case,
    pcap_job,
)


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    installed = use_signing_keys(monkeypatch, tmp_path)
    fake_case_iocs(monkeypatch)
    yield installed
    purge_reports_test_bucket()


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch, keys: SigningKeys) -> Dispatched:
    return fake_dispatch(monkeypatch)


async def test_finalize_stores_the_exact_version_with_retention(
    monkeypatch: pytest.MonkeyPatch, sent: Dispatched
) -> None:
    monkeypatch.setattr(get_settings(), "evidence_lock_days", 1)
    assert report_storage.bucket() == REPORTS_TEST_BUCKET
    reg, t = await owner_case()
    await pcap_job(reg, t)
    report = (await api_create(reg, t)).json()
    await api_patch(reg, report["id"], draft=draft())
    before = datetime.now(UTC)
    response = await api_finalize(reg, report["id"])
    assert response.status_code == 201, response.text
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(ReportVersion, uuid.UUID(response.json()["id"]))
    assert row is not None
    assert row.object_key == f"{t.org_id}/{report['id']}/1/snapshot.json"
    stored = get_minio().get_object(
        REPORTS_TEST_BUCKET, row.object_key, version_id=row.object_version_id
    )
    try:
        data = stored.read()
    finally:
        stored.close()
        stored.release_conn()
    assert hashlib.sha256(data).hexdigest() == row.snapshot_sha256
    assert len(data) == row.snapshot_bytes
    assert canonical_json(parse_snapshot(data)) == data
    until = await report_storage.get_retention(row.object_key, row.object_version_id)
    assert until is not None
    assert before + timedelta(hours=23) < until < before + timedelta(days=1, hours=1)

    # A later put to the same key never changes what is served (exact version reads).
    get_minio().put_object(REPORTS_TEST_BUCKET, row.object_key, io.BytesIO(b"{}"), 2)
    base = f"{API}/{reg.org_id}/reports/{report['id']}/versions/1"
    content = await reg.client.get(f"{base}/content")
    assert content.status_code == 200
    assert content.content == data
    assert content.headers["cache-control"] == "no-store"
    assert content.headers["content-type"].startswith("application/json")
    download = await reg.client.get(f"{base}/snapshot")
    assert download.status_code == 200 and download.content == data
    assert download.headers["content-disposition"].startswith("attachment;")
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in download.headers["content-security-policy"]


async def test_the_content_route_refuses_a_tampered_object(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    report_id = await seed_report(t)
    number = await tampered_version(t, report_id, keys)
    content = await reg.client.get(
        f"{API}/{reg.org_id}/reports/{report_id}/versions/{number}/content"
    )
    assert content.status_code == 409
    assert content.json()["error"]["code"] == "integrity_failed"


async def test_viewer_content_needs_evidence_read_only(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    report_id = await seed_report(t)
    seeded = await seed_version(t, report_id, keys)
    email = unique_email("viewer")
    await add_member(reg.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = await login(email)
    response = await viewer.get(f"{API}/{reg.org_id}/reports/{report_id}/versions/1/content")
    assert response.status_code == 200
    assert response.content == seeded.snapshot
