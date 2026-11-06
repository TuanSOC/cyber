import hashlib
import os
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from minio.error import S3Error
from sqlalchemy import select

from app.core import storage
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.tenancy import tenant_session
from app.core.upload_slots import slot_key
from app.main import app
from app.modules.audit.models import AuditLog
from app.modules.evidence import locking, uploads
from app.modules.evidence.models import Evidence, EvidenceHash, HashAlgorithm
from app.modules.retention.models import LegalHold
from tests.factories import Registered, csrf, register
from tests.integration.test_orgs_members import org_with_roles
from tests.storage_helpers import all_entries, overwrite, versions

# Built at runtime: the repository never contains the EICAR string or real malware.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


def _hashes(data: bytes) -> dict[str, str]:
    return {name: hashlib.new(name, data).hexdigest() for name in ("md5", "sha1", "sha256")}


async def _new_case(reg: Registered) -> str:
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Evidence case", "severity": "high"},
        headers=csrf(reg.client),
    )
    return str(response.json()["id"])


async def _upload(
    client: AsyncClient,
    org_id: uuid.UUID,
    case_id: str,
    content: bytes | AsyncIterator[bytes],
    filename: str = "capture.pcap",
    **params: str,
) -> Any:
    return await client.post(
        f"/api/v1/orgs/{org_id}/investigations/{case_id}/evidence",
        params={"filename": filename, **params},
        content=content,
        headers={"Content-Type": "application/octet-stream", **csrf(client)},
    )


async def _evidence_rows(org_id: uuid.UUID) -> list[Evidence]:
    async with tenant_session(org_id, None) as s:  # RLS: evidence is only visible per org
        return list((await s.execute(select(Evidence))).scalars())


def _tmp_files() -> list[Path]:
    return list(Path(get_settings().upload_tmp_dir).glob("evidence-*.part"))


async def test_upload_hashes_stores_and_records_custody() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    data = os.urandom(5 * 1024 * 1024 + 3)
    response = await _upload(reg.client, reg.org_id, case_id, data, description="DC memory")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["hashes"] == _hashes(data)
    assert body["size_bytes"] == len(data)
    assert body["description"] == "DC memory"
    assert "storage_key" not in body and "storage_version_id" not in body

    [row] = await _evidence_rows(reg.org_id)
    assert row.storage_version_id and row.storage_key.startswith(f"{reg.org_id}/")
    assert versions(prefix=row.storage_key) == [(row.storage_key, row.storage_version_id)]
    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{body['id']}/custody")
    ).json()
    # Any non-empty upload within the static cap is queued for an AV scan after it commits.
    assert [e["action"] for e in custody["items"]] == ["uploaded", "analysis_requested"]
    assert _tmp_files() == []

    case = (await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}")).json()
    assert case["evidence_count"] == 1


async def test_oversize_stream_is_rejected_without_leftovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "max_evidence_bytes", 1024 * 1024)
    reg = await register()
    case_id = await _new_case(reg)

    async def chunked() -> AsyncIterator[bytes]:  # no Content-Length: limit enforced mid-stream
        for _ in range(32):
            yield os.urandom(64 * 1024)

    response = await _upload(reg.client, reg.org_id, case_id, chunked())
    assert (response.status_code, response.json()["error"]["code"]) == (413, "payload_too_large")
    assert await get_redis().zcard(slot_key("upload", reg.user_id)) == 0
    assert await _evidence_rows(reg.org_id) == []
    assert versions(prefix=f"{reg.org_id}/") == []
    assert _tmp_files() == []


async def test_declared_oversize_is_rejected_before_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "max_evidence_bytes", 1000)
    reg = await register()
    case_id = await _new_case(reg)
    response = await _upload(reg.client, reg.org_id, case_id, b"x" * 2000)
    assert response.status_code == 413


async def test_db_failure_after_store_deletes_the_version(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register()
    case_id = await _new_case(reg)

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(uploads, "record_event", boom)
    # Return the 500 response instead of re-raising the app exception into the test.
    client = AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False, client=("10.0.0.1", 40000)),
        base_url=str(reg.client.base_url),
        cookies=reg.client.cookies,
    )
    response = await _upload(client, reg.org_id, case_id, b"evidence bytes")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert await get_redis().zcard(slot_key("upload", reg.user_id)) == 0
    assert await _evidence_rows(reg.org_id) == []
    # Exact version removed, not merely hidden behind a delete marker.
    assert all_entries(prefix=f"{reg.org_id}/") == []
    assert _tmp_files() == []


@pytest.mark.parametrize("scope", ["investigation", "org"])
async def test_db_failure_under_a_legal_hold_keeps_the_version(
    monkeypatch: pytest.MonkeyPatch, scope: str
) -> None:
    """M7 phase 11 (RT5): the api's only evidence delete (failed-upload cleanup) checks the
    legal holds first and keeps the version under a case or an org hold."""
    reg = await register()
    case_id = await _new_case(reg)
    async with tenant_session(reg.org_id, reg.user_id) as s:
        s.add(
            LegalHold(
                organization_id=reg.org_id,
                scope=scope,
                investigation_id=uuid.UUID(case_id) if scope == "investigation" else None,
                reason="Preservation",
                placed_by=reg.user_id,
            )
        )

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(uploads, "record_event", boom)
    client = AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False, client=("10.0.0.1", 40000)),
        base_url=str(reg.client.base_url),
        cookies=reg.client.cookies,
    )
    response = await _upload(client, reg.org_id, case_id, b"held evidence bytes")
    assert response.status_code == 500
    assert await _evidence_rows(reg.org_id) == []
    # Kept (an orphan `reconcile_orphans.py` reports), never deleted under a hold.
    assert [marker for _, _, marker in all_entries(prefix=f"{reg.org_id}/")] == [False]


async def test_discard_never_removes_a_recorded_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "evidence_lock_days", 0)  # no GOVERNANCE lock at all
    reg = await register()
    case_id = await _new_case(reg)
    assert (await _upload(reg.client, reg.org_id, case_id, b"committed")).status_code == 201
    [row] = await _evidence_rows(reg.org_id)
    user = CurrentUser(
        id=reg.user_id,
        email="x@example.com",
        display_name="x",
        jti="t",
        family_id=uuid.uuid4(),
        token_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    await locking.discard_version(
        reg.org_id, user, uuid.UUID(case_id), row.storage_key, row.storage_version_id
    )
    assert versions(row.storage_key) == [(row.storage_key, row.storage_version_id)]


async def test_concurrent_upload_slots_are_bounded() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    limit = get_settings().max_concurrent_uploads_per_user
    key = slot_key("upload", reg.user_id)
    now = time.time()
    await get_redis().zadd(key, {f"busy-{i}": now for i in range(limit)})  # all slots busy
    response = await _upload(reg.client, reg.org_id, case_id, b"data")
    assert response.status_code == 429
    await get_redis().delete(key)
    assert (await _upload(reg.client, reg.org_id, case_id, b"data")).status_code == 201
    assert await get_redis().zcard(key) == 0  # slot released


async def test_overwrite_attack_does_not_change_served_or_verified_bytes() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    original = os.urandom(10_000)
    evidence = (await _upload(reg.client, reg.org_id, case_id, original)).json()
    [row] = await _evidence_rows(reg.org_id)
    overwrite(row.storage_key, b"forged content")  # attacker with storage creds

    download = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/download")
    assert download.content == original
    verify = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/verify", headers=csrf(reg.client)
    )
    assert verify.json()["result"] == "ok"


async def _evidence_with_wrong_hash(reg: Registered, case_id: str, tmp_path: Path) -> uuid.UUID:
    path = tmp_path / "real.bin"
    path.write_bytes(b"real stored bytes")
    key = f"{reg.org_id}/{uuid.uuid4()}"
    version_id = await storage.put_file(key, path)
    async with tenant_session(reg.org_id, reg.user_id) as s:
        evidence = Evidence(
            organization_id=reg.org_id,
            investigation_id=uuid.UUID(case_id),
            original_filename="real.bin",
            detected_mime="application/octet-stream",
            detected_description="data",
            size_bytes=17,
            storage_bucket=storage.bucket(),
            storage_key=key,
            storage_version_id=version_id,
            uploaded_by=reg.user_id,
        )
        s.add(evidence)
        await s.flush()
        for algo in HashAlgorithm:
            s.add(
                EvidenceHash(
                    organization_id=reg.org_id,
                    evidence_id=evidence.id,
                    algorithm=algo,
                    value="0" * 64,
                )
            )
    return evidence.id


async def test_verify_detects_mismatch_and_records_custody(tmp_path: Path) -> None:
    reg = await register()
    case_id = await _new_case(reg)
    evidence_id = await _evidence_with_wrong_hash(reg, case_id, tmp_path)
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}"
    result = (await reg.client.post(f"{url}/verify", headers=csrf(reg.client))).json()
    assert result["result"] == "mismatch"
    assert result["actual"] == _hashes(b"real stored bytes")
    custody = (await reg.client.get(f"{url}/custody")).json()["items"]
    assert custody[-1]["action"] == "verified_mismatch"
    assert custody[-1]["details"]["reason"] == "hash"


async def test_verify_and_download_report_missing_content() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    evidence = (await _upload(reg.client, reg.org_id, case_id, b"to be lost")).json()
    [row] = await _evidence_rows(reg.org_id)
    await storage.delete_version(row.storage_bucket, row.storage_key, row.storage_version_id)
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}"
    verify = (await reg.client.post(f"{url}/verify", headers=csrf(reg.client))).json()
    assert verify["result"] == "missing" and verify["actual"] is None
    download = await reg.client.get(f"{url}/download")
    assert (download.status_code, download.json()["error"]["code"]) == (
        409,
        "evidence_content_missing",
    )


async def test_download_headers_body_and_custody() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    data = os.urandom(300_000)
    evidence = (
        await _upload(reg.client, reg.org_id, case_id, data, filename="báo cáo<script>.pdf")
    ).json()
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}"
    async with reg.client.stream("GET", f"{url}/download") as streamed:
        assert streamed.status_code == 200
        # Custody is already committed before any body byte has been read.
        early = (await reg.client.get(f"{url}/custody")).json()["items"]
        assert [e["action"] for e in early] == ["uploaded", "analysis_requested", "downloaded"]
        await streamed.aread()
    response = await reg.client.get(f"{url}/download")
    assert response.content == data
    h = response.headers
    assert h["content-type"] == "application/octet-stream"
    assert h["x-content-type-options"] == "nosniff"
    assert h["cache-control"] == "no-store"
    assert h["content-security-policy"] == "sandbox"
    assert h["content-length"] == str(len(data))
    assert h["content-disposition"].startswith("attachment;")
    assert "filename*=UTF-8''b%C3%A1o%20c%C3%A1o%3Cscript%3E.pdf" in h["content-disposition"]
    custody = (await reg.client.get(f"{url}/custody")).json()["items"]
    assert [e["action"] for e in custody] == [
        "uploaded",
        "analysis_requested",
        "downloaded",
        "downloaded",
    ]


async def test_eicar_is_stored_inert_with_detected_type() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    response = await _upload(reg.client, reg.org_id, case_id, EICAR, filename="eicar.com")
    assert response.status_code == 201
    body = response.json()
    assert body["hashes"]["sha256"] == hashlib.sha256(EICAR).hexdigest()
    assert body["detected_mime"]  # recorded, never used to reject
    download = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{body['id']}/download")
    assert download.content == EICAR


async def test_archive_and_archived_case_rules() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    evidence = (await _upload(reg.client, reg.org_id, case_id, b"abc")).json()
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}"
    archived = await reg.client.post(f"{url}/archive", headers=csrf(reg.client))
    assert archived.json()["status"] == "archived"
    again = await reg.client.post(f"{url}/archive", headers=csrf(reg.client))
    assert (again.status_code, again.json()["error"]["code"]) == (409, "evidence_archived")
    assert (await reg.client.get(f"{url}/download")).status_code == 200  # still readable

    for step in ("closed", "archived"):
        changed = await reg.client.patch(
            f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
            json={"status": step, "status_reason": "Status change for the test"},
            headers=csrf(reg.client),
        )
        assert changed.status_code == 200, changed.text
    blocked = await _upload(reg.client, reg.org_id, case_id, b"late")
    assert (blocked.status_code, blocked.json()["error"]["code"]) == (409, "investigation_archived")


async def test_list_evidence_paginated() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    for i in range(3):
        await _upload(reg.client, reg.org_id, case_id, f"file {i}".encode(), filename=f"f{i}.bin")
    url = f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}/evidence"
    page = (await reg.client.get(url, params={"limit": 2})).json()
    assert page["total"] == 3 and len(page["items"]) == 2
    assert page["items"][0]["original_filename"] == "f2.bin"  # newest first
    missing = await reg.client.get(
        f"/api/v1/orgs/{reg.org_id}/investigations/{uuid.uuid4()}/evidence"
    )
    assert missing.status_code == 404


async def test_permissions_and_tenant_isolation() -> None:
    org = await org_with_roles()
    analyst, viewer = org.clients["analyst"], org.clients["viewer"]
    case = await analyst.post(
        f"/api/v1/orgs/{org.org_id}/investigations",
        json={"title": "Shared case", "severity": "low"},
        headers=csrf(analyst),
    )
    case_id = case.json()["id"]
    evidence = (await _upload(analyst, org.org_id, case_id, b"secret")).json()
    url = f"/api/v1/orgs/{org.org_id}/evidence/{evidence['id']}"

    assert (await _upload(viewer, org.org_id, case_id, b"nope")).status_code == 403
    assert (await viewer.post(f"{url}/verify", headers=csrf(viewer))).status_code == 403
    assert (await viewer.post(f"{url}/archive", headers=csrf(viewer))).status_code == 403
    assert (await viewer.get(f"{url}/download")).content == b"secret"  # viewers may read

    other = await register()
    for path in ("", "/download", "/custody"):
        assert (await other.client.get(f"{url}{path}")).status_code == 404
        foreign = f"/api/v1/orgs/{other.org_id}/evidence/{evidence['id']}{path}"
        assert (await other.client.get(foreign)).status_code == 404
    assert (await _upload(other.client, org.org_id, case_id, b"x")).status_code == 404

    anonymous = AsyncClient(transport=analyst._transport, base_url=str(analyst.base_url))
    assert (await anonymous.get(f"{url}/download")).status_code == 401


async def test_upload_and_verify_are_audited() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    evidence = (await _upload(reg.client, reg.org_id, case_id, b"audit me")).json()
    await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/verify", headers=csrf(reg.client)
    )
    async with tenant_session(reg.org_id, reg.user_id) as s:
        actions = set((await s.execute(select(AuditLog.action))).scalars())
    assert {"evidence.uploaded", "evidence.verified"} <= actions


async def test_uploaded_version_is_retention_locked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "evidence_lock_days", 1)
    reg = await register()
    case_id = await _new_case(reg)
    assert (await _upload(reg.client, reg.org_id, case_id, b"locked bytes")).status_code == 201
    [row] = await _evidence_rows(reg.org_id)
    until = await storage.get_retention_until(
        row.storage_bucket, row.storage_key, row.storage_version_id
    )
    assert until is not None and until > datetime.now(UTC) + timedelta(hours=23)
    with pytest.raises(S3Error):  # the API credential cannot remove it
        await storage.delete_version(row.storage_bucket, row.storage_key, row.storage_version_id)


async def test_lock_failure_is_audited_but_upload_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "evidence_lock_days", 1)

    async def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("retention unavailable")

    monkeypatch.setattr(storage, "set_retention", broken)
    reg = await register()
    case_id = await _new_case(reg)
    response = await _upload(reg.client, reg.org_id, case_id, b"unlocked")
    assert response.status_code == 201
    async with tenant_session(reg.org_id, reg.user_id) as s:
        actions = set((await s.execute(select(AuditLog.action))).scalars())
    assert "evidence.lock_failed" in actions


async def test_upload_requires_octet_stream() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}/evidence",
        params={"filename": "x.bin"},
        files={"file": ("x.bin", b"multipart body")},
        headers=csrf(reg.client),
    )
    assert (response.status_code, response.json()["error"]["code"]) == (
        415,
        "unsupported_media_type",
    )


async def test_cannot_archive_evidence_in_archived_case() -> None:
    reg = await register()
    case_id = await _new_case(reg)
    evidence = (await _upload(reg.client, reg.org_id, case_id, b"abc")).json()
    for step in ("closed", "archived"):
        changed = await reg.client.patch(
            f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
            json={"status": step, "status_reason": "Status change for the test"},
            headers=csrf(reg.client),
        )
        assert changed.status_code == 200, changed.text
    response = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/archive", headers=csrf(reg.client)
    )
    assert (response.status_code, response.json()["error"]["code"]) == (
        409,
        "investigation_archived",
    )


async def test_verify_reports_size_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register()
    case_id = await _new_case(reg)
    data = b"exact"
    evidence = (await _upload(reg.client, reg.org_id, case_id, data)).json()

    async def same_hashes_other_size(*args: object) -> tuple[int, dict[str, str]]:
        return len(data) + 1, _hashes(data)

    monkeypatch.setattr(storage, "hash_version", same_hashes_other_size)
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}"
    assert (await reg.client.post(f"{url}/verify", headers=csrf(reg.client))).json()[
        "result"
    ] == "mismatch"
    custody = (await reg.client.get(f"{url}/custody")).json()["items"]
    assert custody[-1]["details"]["reason"] == "size"
