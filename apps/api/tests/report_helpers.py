"""Report seeding and doubles for the M6 tests (phase 1, FROZEN for group B).

- `new_signing_keys()` / `use_signing_keys(monkeypatch, tmp_path)`: a fresh Ed25519 pair
  installed as the api's REPORT_SIGNING_* settings (api-test holds no signing key file).
- `fake_snapshot(**sections)`: the golden fixture as a `ReportSnapshot`, optionally with
  replaced top-level sections.
- `seed_report`, `seed_version` (the snapshot object put in `reports-test`, a signed
  manifest), `seed_render` (with its token and index row).
- `purge_reports_test_bucket()`: removes this process's object versions of `reports-test`
  (its orgs' keys and its lane prefix, never another lane's, M7 phase 11) with the root
  credentials (governance bypass); call it from a test's teardown.
"""

import base64
import hashlib
import io
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cyberlab_jobs.report import (
    REPORT_SCHEMA,
    Manifest,
    Profile,
    ReportSnapshot,
    canonical_json,
    manifest_bytes,
    section_counts,
)
from sqlalchemy import update

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.signing import public_key_b64, sign
from app.core.tenancy import tenant_session
from app.modules.reports import signing as report_signing
from app.modules.reports.models import (
    Report,
    ReportRender,
    ReportRenderIndex,
    ReportVersion,
)
from tests.integration.seed import Tenant
from tests.storage_helpers import purge_owned

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "report"
REPORTS_TEST_BUCKET = "reports-test"


@dataclass(frozen=True)
class SigningKeys:
    kid: str
    private: Ed25519PrivateKey

    @property
    def public_b64(self) -> str:
        return public_key_b64(self.private)

    @property
    def private_b64(self) -> str:
        return base64.b64encode(
            self.private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode()

    @property
    def keys(self) -> dict[str, Ed25519PrivateKey]:
        return {self.kid: self.private}

    def write(self, path: Path) -> Path:
        path.write_text(json.dumps({self.kid: self.private_b64}), encoding="utf-8")
        return path


def new_signing_keys(kid: str = "test-report-1") -> SigningKeys:
    return SigningKeys(kid, Ed25519PrivateKey.generate())


def use_signing_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keys: SigningKeys | None = None
) -> SigningKeys:
    """Install a key pair as the api's signing settings for one test."""
    keys = keys or new_signing_keys()
    settings = get_settings()
    path = keys.write(tmp_path / "report_signing_private.json")
    monkeypatch.setattr(settings, "report_signing_keys_file", str(path))
    monkeypatch.setattr(settings, "report_signing_active_kid", keys.kid)
    monkeypatch.setattr(settings, "report_signing_public_keys", {keys.kid: keys.public_b64})
    # The wrapper's cached loader is replaced for this test only (no cache leaks across).
    monkeypatch.setattr(report_signing, "_private_keys", lambda: keys.keys)
    return keys


def golden_data() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURES / "golden_snapshot.json").read_text(encoding="utf-8")
    )
    return data


def fake_snapshot(**sections: Any) -> ReportSnapshot:
    """The golden snapshot, with top-level sections replaced (`report=...`, `case=...`)."""
    data = golden_data()
    for name, value in sections.items():
        data[name] = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    return ReportSnapshot.model_validate(data)


def hostile_snapshot() -> ReportSnapshot:
    return ReportSnapshot.model_validate_json((FIXTURES / "hostile_snapshot.json").read_bytes())


def reports_test_bucket() -> str:
    bucket = get_settings().reports_bucket
    if bucket != REPORTS_TEST_BUCKET:
        raise RuntimeError(f"refusing to touch bucket {bucket!r} in tests")
    return bucket


def purge_reports_test_bucket() -> None:
    purge_owned([reports_test_bucket()])


async def seed_report(
    t: Tenant,
    investigation_id: uuid.UUID | None = None,
    *,
    title: str = "Incident report",
    tlp: str = "amber",
    profile: str = "internal",
    draft: dict[str, Any] | None = None,
    distribution: str | None = None,
) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        report = Report(
            organization_id=t.org_id,
            investigation_id=investigation_id or t.investigation_id,
            title=title,
            tlp=tlp,
            profile=profile,
            draft=draft or {},
            distribution=distribution,
            created_by=t.owner_id,
        )
        s.add(report)
    return report.id


@dataclass(frozen=True)
class SeededVersion:
    version_id: uuid.UUID
    version: int
    snapshot: bytes
    sha256: str
    object_key: str
    object_version_id: str
    manifest: bytes
    signature: str
    kid: str


async def seed_version(
    t: Tenant,
    report_id: uuid.UUID,
    keys: SigningKeys,
    *,
    snapshot: ReportSnapshot | None = None,
    tlp: str = "amber",
    profile: str = "internal",
    store: bool = True,
    change_note: str | None = None,
) -> SeededVersion:
    """The next version of a report: canonical bytes in `reports-test` (unless
    `store=False`, then a fake version id), a signed manifest, the `report_versions` row
    and `reports.latest_version` bumped (with the +1 revision the guard requires)."""
    snapshot = snapshot or fake_snapshot()
    data = canonical_json(snapshot)
    sha = hashlib.sha256(data).hexdigest()
    async with tenant_session(t.org_id, t.owner_id) as s:
        report = await s.get(Report, report_id, with_for_update=True)
        assert report is not None
        number = report.latest_version + 1
        key = f"{t.org_id}/{report_id}/{number}/snapshot.json"
        if store:
            put = get_minio().put_object(
                reports_test_bucket(),
                key,
                io.BytesIO(data),
                len(data),
                content_type="application/json",
            )
            object_version = str(put.version_id)
        else:
            object_version = f"fake-{secrets.token_hex(8)}"
        finalized_at = datetime.now(UTC)
        manifest = Manifest(
            report_id=report_id,
            version=number,
            org_id=t.org_id,
            snapshot_sha256=sha,
            snapshot_bytes=len(data),
            tlp=tlp,
            profile=Profile(profile),
            finalized_at=finalized_at,
            finalized_by=t.owner_id,
            kid=keys.kid,
        )
        raw_manifest = manifest_bytes(manifest)
        signature = sign(raw_manifest, keys.kid, keys.keys)
        version = ReportVersion(
            organization_id=t.org_id,
            report_id=report_id,
            version=number,
            schema_version=REPORT_SCHEMA,
            tlp=tlp,
            profile=profile,
            snapshot_sha256=sha,
            snapshot_bytes=len(data),
            object_key=key,
            object_version_id=object_version,
            manifest=json.loads(raw_manifest),
            signature=signature,
            kid=keys.kid,
            section_counts=section_counts(snapshot),
            change_note=change_note,
            finalized_by=t.owner_id,
            finalized_at=finalized_at,
        )
        s.add(version)
        await s.execute(
            update(Report)
            .where(Report.id == report_id)
            .values(latest_version=number, revision=Report.revision + 1)
        )
    return SeededVersion(
        version.id, number, data, sha, key, object_version, raw_manifest, signature, keys.kid
    )


async def seed_render(
    t: Tenant,
    version_id: uuid.UUID,
    *,
    fmt: str = "pdf",
    status: str = "queued",
    deadline_s: int = 600,
) -> tuple[uuid.UUID, str]:
    """A render with its index row; returns (render_id, token)."""
    token = secrets.token_urlsafe(32)
    async with tenant_session(t.org_id, t.owner_id) as s:
        render = ReportRender(
            organization_id=t.org_id,
            version_id=version_id,
            format=fmt,
            status=status,
            token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            requested_by=t.owner_id,
        )
        s.add(render)
        await s.flush()
        s.add(
            ReportRenderIndex(
                render_id=render.id,
                organization_id=t.org_id,
                status=status,
                dispatched_at=datetime.now(UTC),
                deadline_at=datetime.now(UTC) + timedelta(seconds=deadline_s),
            )
        )
    return render.id, token
