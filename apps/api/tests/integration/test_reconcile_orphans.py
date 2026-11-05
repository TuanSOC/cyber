"""The orphan reconcile script covers the report bucket (M6 phase 9): a snapshot or a render
artifact that no row records is listed as orphaned, a recorded version whose object is gone
as missing, and a recorded snapshot / succeeded render is neither. The script itself runs
with RLS off as the superuser; here its queries run in the tenant's own RLS scope and the
listing under the tenant's key prefix, so other tests' objects never count."""

import hashlib
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.core.clients import get_minio
from app.core.tenancy import tenant_session
from app.modules.reports import dispatch
from app.modules.reports.models import ReportRender
from app.scripts import reconcile_orphans
from tests.integration.seed import Tenant
from tests.report_helpers import (
    REPORTS_TEST_BUCKET,
    SigningKeys,
    purge_reports_test_bucket,
    seed_report,
    seed_version,
    use_signing_keys,
)
from tests.security.idor_cases_reports import owner_case


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    yield use_signing_keys(monkeypatch, tmp_path)
    purge_reports_test_bucket()


def _put(key: str, data: bytes) -> str:
    result = get_minio().put_object(REPORTS_TEST_BUCKET, key, io.BytesIO(data), len(data))
    return str(result.version_id)


async def _recorded(t: Tenant) -> set[tuple[str, str]]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        conn = await s.connection()
        return await reconcile_orphans.recorded_versions(conn, reconcile_orphans.REPORT_RECORDS)


async def test_report_objects_without_a_row_are_listed(keys: SigningKeys) -> None:
    _, t = await owner_case()
    report_id = await seed_report(t)
    seeded = await seed_version(t, report_id, keys)

    # A succeeded render recorded with its artifact version.
    pdf = b"%PDF-1.7 reconcile"
    render_id = uuid.uuid4()
    pdf_key = dispatch.render_key(t.org_id, report_id, seeded.version, render_id, "pdf")
    pdf_version = _put(pdf_key, pdf)
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            ReportRender(
                id=render_id,
                organization_id=t.org_id,
                version_id=seeded.version_id,
                format="pdf",
                status="succeeded",
                token_sha256=hashlib.sha256(b"token").hexdigest(),
                sha256=hashlib.sha256(pdf).hexdigest(),
                bytes=len(pdf),
                pages=1,
                object_version_id=pdf_version,
                renderer_version="test",
                requested_by=t.owner_id,
                started_at=datetime.now(UTC),
                finished_at=datetime.now(UTC),
            )
        )

    # Orphans: a snapshot put whose finalize never wrote its row, a second version written
    # to a recorded key, and an artifact uploaded for a render that recorded nothing.
    stale_key = f"{t.org_id}/{report_id}/{seeded.version + 1}/snapshot.json"
    stale = _put(stale_key, b"{}")
    overwrite = _put(seeded.object_key, b"{}")
    refused_key = dispatch.render_key(t.org_id, report_id, seeded.version, uuid.uuid4(), "html")
    refused = _put(refused_key, b"<p>refused</p>")

    stored = await reconcile_orphans.stored_versions(REPORTS_TEST_BUCKET, f"{t.org_id}/")
    recorded = await _recorded(t)
    assert (seeded.object_key, seeded.object_version_id) in recorded
    assert (pdf_key, pdf_version) in recorded
    result = reconcile_orphans.compare(REPORTS_TEST_BUCKET, stored, recorded)
    assert result["bucket"] == REPORTS_TEST_BUCKET
    assert result["orphaned_versions"] == sorted(
        [
            {"key": stale_key, "version_id": stale},
            {"key": seeded.object_key, "version_id": overwrite},
            {"key": refused_key, "version_id": refused},
        ],
        key=lambda o: (o["key"], o["version_id"]),
    )
    assert result["missing_content"] == []


async def test_a_recorded_version_without_its_object_is_missing(keys: SigningKeys) -> None:
    _, t = await owner_case()
    report_id = await seed_report(t)
    seeded = await seed_version(t, report_id, keys, store=False)
    stored = await reconcile_orphans.stored_versions(REPORTS_TEST_BUCKET, f"{t.org_id}/")
    result = reconcile_orphans.compare(REPORTS_TEST_BUCKET, stored, await _recorded(t))
    assert result["orphaned_versions"] == []
    assert result["missing_content"] == [
        {"key": seeded.object_key, "version_id": seeded.object_version_id}
    ]
