"""Read verification (M6 phase 3): a version re-hashes its stored object and verifies its
manifest signature with the public key of its kid; a tampered object or a wrong kid is shown
(`snapshot_ok` / `signature_valid` false), audited, and the content is refused."""

import base64
import hashlib
import io
import json
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cyberlab_jobs.report import (
    REPORT_SCHEMA,
    Manifest,
    Profile,
    canonical_json,
    manifest_bytes,
    section_counts,
)
from sqlalchemy import select, update

from app.core.clients import get_minio
from app.core.signing import sign
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.reports.models import Report, ReportVersion
from tests.integration.seed import Tenant
from tests.report_helpers import (
    SigningKeys,
    fake_snapshot,
    new_signing_keys,
    purge_reports_test_bucket,
    reports_test_bucket,
    seed_report,
    seed_version,
    use_signing_keys,
)
from tests.security.idor_cases_reports import API, owner_case


@pytest.fixture
def keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SigningKeys]:
    yield use_signing_keys(monkeypatch, tmp_path)
    purge_reports_test_bucket()


async def tampered_version(t: Tenant, report_id: uuid.UUID, keys: SigningKeys) -> int:
    """A version whose row records the sha256 of the original bytes while the recorded
    object version holds other bytes (as if the stored object had been replaced)."""
    snapshot = fake_snapshot()
    data = canonical_json(snapshot)
    sha = hashlib.sha256(data).hexdigest()
    evil = data.replace(b"Suspicious beaconing", b"Harmless printer ok")
    async with tenant_session(t.org_id, t.owner_id) as s:
        report = await s.get(Report, report_id, with_for_update=True)
        assert report is not None
        number = report.latest_version + 1
        key = f"{t.org_id}/{report_id}/{number}/snapshot.json"
        put = get_minio().put_object(
            reports_test_bucket(), key, io.BytesIO(evil), len(evil), content_type="application/json"
        )
        now = datetime.now(UTC)
        manifest = Manifest(
            report_id=report_id,
            version=number,
            org_id=t.org_id,
            snapshot_sha256=sha,
            snapshot_bytes=len(data),
            tlp="amber",
            profile=Profile.INTERNAL,
            finalized_at=now,
            finalized_by=t.owner_id,
            kid=keys.kid,
        )
        raw = manifest_bytes(manifest)
        s.add(
            ReportVersion(
                organization_id=t.org_id,
                report_id=report_id,
                version=number,
                schema_version=REPORT_SCHEMA,
                tlp="amber",
                profile="internal",
                snapshot_sha256=sha,
                snapshot_bytes=len(data),
                object_key=key,
                object_version_id=str(put.version_id),
                manifest=json.loads(raw),
                signature=sign(raw, keys.kid, keys.keys),
                kid=keys.kid,
                section_counts=section_counts(snapshot),
                finalized_by=t.owner_id,
                finalized_at=now,
            )
        )
        await s.execute(
            update(Report)
            .where(Report.id == report_id)
            .values(latest_version=number, revision=Report.revision + 1)
        )
    return number


async def _audited(t: Tenant, action: str) -> int:
    async with tenant_session(t.org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog).where(AuditLog.organization_id == t.org_id, AuditLog.action == action)
        )
        return len(list(rows))


async def test_a_valid_version_verifies(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    report_id = await seed_report(t)
    seeded = await seed_version(t, report_id, keys)
    base = f"{API}/{reg.org_id}/reports/{report_id}/versions/{seeded.version}"
    detail = (await reg.client.get(base)).json()
    assert detail["snapshot_ok"] is True and detail["signature_valid"] is True
    assert detail["alg"] == "Ed25519"
    assert detail["section_counts"]["findings"] == {"included": 1, "total": 1}
    signature = await reg.client.get(f"{base}/signature")
    assert signature.status_code == 200
    assert ".sig.json" in signature.headers["content-disposition"]
    body = signature.json()
    assert body["kid"] == keys.kid and body["alg"] == "Ed25519"
    # Offline: the canonical manifest bytes verify with the published key.
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(keys.public_b64))
    raw = json.dumps(body["manifest"], sort_keys=True, separators=(",", ":")).encode()
    public.verify(base64.b64decode(body["signature"]), raw)
    assert body["manifest"]["snapshot_sha256"] == seeded.sha256
    assert await _audited(t, "report.integrity_failed") == 0


async def test_a_tampered_object_is_shown_audited_and_refused(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    report_id = await seed_report(t)
    number = await tampered_version(t, report_id, keys)
    base = f"{API}/{reg.org_id}/reports/{report_id}/versions/{number}"
    detail = (await reg.client.get(base)).json()
    assert detail["snapshot_ok"] is False
    assert detail["signature_valid"] is True  # the manifest itself is intact
    content = await reg.client.get(f"{base}/content")
    assert content.status_code == 409
    assert content.json()["error"]["code"] == "integrity_failed"
    download = await reg.client.get(f"{base}/snapshot")
    assert download.status_code == 409
    assert await _audited(t, "report.integrity_failed") == 3


async def test_a_wrong_kid_is_invalid(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    report_id = await seed_report(t)
    other = new_signing_keys("other-kid-1")
    seeded = await seed_version(t, report_id, other)
    detail = (await reg.client.get(f"{API}/{reg.org_id}/reports/{report_id}/versions/1")).json()
    assert detail["snapshot_ok"] is True
    assert detail["signature_valid"] is False
    assert detail["version"]["kid"] == other.kid
    # The same key under the active kid: the signature does not verify either.
    impostor = SigningKeys(keys.kid, other.private)
    await seed_version(t, report_id, impostor)
    second = (await reg.client.get(f"{API}/{reg.org_id}/reports/{report_id}/versions/2")).json()
    assert second["signature_valid"] is False
    assert seeded.version == 1
    assert await _audited(t, "report.integrity_failed") == 2


async def test_unknown_versions_and_reports_are_404(keys: SigningKeys) -> None:
    reg, t = await owner_case()
    report_id = await seed_report(t)
    base = f"{API}/{reg.org_id}/reports"
    assert (await reg.client.get(f"{base}/{report_id}/versions/1")).status_code == 404
    assert (await reg.client.get(f"{base}/{uuid.uuid4()}/versions")).status_code == 404
    assert (await reg.client.get(f"{base}/{report_id}/versions/1/signature")).status_code == 404
