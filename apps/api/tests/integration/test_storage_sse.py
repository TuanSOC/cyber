"""SSE-S3 at rest on every app path (M7 phase 6; SSE configured by phase 1's minio-init).

The test buckets (`evidence-test`, `results-test`, `reports-test`) carry the SSE-S3 bucket
default (`mc encrypt set sse-s3`, MINIO_SSE_ENABLED=true). Proven here, on the three write
paths the platform uses:
- a new evidence upload (API, multipart `fput_object`);
- an analyzer's result object written through the presigned POST of the pcap job message
  (`analysis.dispatch.build_message`: key + `content-length-range` conditions), and the
  renderer's presigned POST into the locked reports bucket (key + Content-Type conditions);
- a report snapshot (`reports.storage.put_snapshot`).
And: the analyzers' presigned GET of an encrypted evidence version returns the plaintext, and
no path needs `Content-MD5` (the reports bucket has no default retention on purpose, M6 RT6).
"""

import hashlib
import io
import os
import secrets
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from minio.datatypes import PostPolicy
from minio.deleteobjects import DeleteObject

from app.core.clients import get_minio
from app.core.config import get_settings
from app.modules.analysis import dispatch
from app.modules.reports import storage as report_storage
from tests.factories import csrf, register
from tests.storage_helpers import evidence_test_bucket, root_minio

SSE_HEADER = "x-amz-server-side-encryption"


def _sse(bucket: str, key: str, version_id: str | None = None) -> str | None:
    stat = root_minio().stat_object(bucket, key, version_id=version_id)
    return stat.metadata.get(SSE_HEADER)


def _test_bucket(name: str) -> str:
    if not name.endswith("-test"):
        raise RuntimeError(f"refusing to touch bucket {name!r} in tests")
    return name


@pytest.fixture
def cleanup() -> Iterator[list[tuple[str, str, str | None]]]:
    """Objects written to the results / reports test buckets, removed with bypass after."""
    created: list[tuple[str, str, str | None]] = []
    yield created
    for bucket, key, version_id in created:
        errors = list(
            root_minio().remove_objects(
                _test_bucket(bucket),
                [DeleteObject(key, version_id)],
                bypass_governance_mode=True,
            )
        )
        assert not errors, errors


@pytest.mark.parametrize(
    "bucket_attr", ["minio_bucket", "results_bucket", "reports_bucket"], ids=str
)
def test_test_buckets_have_the_sse_s3_default(bucket_attr: str) -> None:
    bucket = _test_bucket(getattr(get_settings(), bucket_attr))
    config = root_minio().get_bucket_encryption(bucket)
    assert config is not None, f"{bucket}: no default encryption (MINIO_SSE_ENABLED?)"
    assert config.rule.sse_algorithm == "AES256"


async def test_new_evidence_upload_is_encrypted_and_presigned_get_works() -> None:
    reg = await register()
    case = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "SSE case", "severity": "low"},
        headers=csrf(reg.client),
    )
    data = os.urandom(300_000)
    upload = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case.json()['id']}/evidence",
        params={"filename": "blob.bin"},
        content=data,
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )
    assert upload.status_code == 201, upload.text
    bucket = evidence_test_bucket()
    [obj] = list(
        root_minio().list_objects(
            bucket, prefix=f"{reg.org_id}/", recursive=True, include_version=True
        )
    )
    assert _sse(bucket, obj.object_name, obj.version_id) == "AES256"
    # The analyzer path: a presigned GET of the exact (encrypted) version, no credentials.
    message = dispatch.build_message(
        dispatch.DispatchInput(
            job_id=uuid.uuid4(),
            organization_id=reg.org_id,
            evidence_id=uuid.UUID(upload.json()["id"]),
            storage_bucket=bucket,
            storage_key=obj.object_name,
            storage_version_id=str(obj.version_id),
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            ingest_token=secrets.token_urlsafe(32),
        )
    )
    fetched = httpx.get(str(message.evidence_url), timeout=30)
    assert fetched.status_code == 200
    assert fetched.content == data
    # The API's own download decrypts too (custody path).
    download = await reg.client.get(
        f"/api/v1/orgs/{reg.org_id}/evidence/{upload.json()['id']}/download"
    )
    assert download.content == data


def test_analyzer_result_presigned_post_is_encrypted_without_content_md5(
    cleanup: list[tuple[str, str, str | None]],
) -> None:
    org_id, job_id = uuid.uuid4(), uuid.uuid4()
    message = dispatch.build_message(
        dispatch.DispatchInput(
            job_id=job_id,
            organization_id=org_id,
            evidence_id=uuid.uuid4(),
            storage_bucket=evidence_test_bucket(),
            storage_key=f"{org_id}/unused",
            storage_version_id="unused",
            sha256="0" * 64,
            size_bytes=1,
            ingest_token=secrets.token_urlsafe(32),
        )
    )
    post = message.result_post
    body = os.urandom(4096)
    # Exactly what the analyzers send: the fields verbatim plus the file; no Content-MD5.
    response = httpx.post(
        str(post.url), data=dict(post.fields), files={"file": ("result", body)}, timeout=30
    )
    assert response.status_code == 204, response.text
    version_id = response.headers.get("x-amz-version-id")
    assert version_id
    bucket = _test_bucket(get_settings().results_bucket)
    key = dispatch.result_key(org_id, job_id)
    cleanup.append((bucket, key, version_id))
    assert _sse(bucket, key, version_id) == "AES256"
    got = get_minio().get_object(bucket, key, version_id=version_id)
    try:
        assert got.read() == body
    finally:
        got.close()
        got.release_conn()


def test_render_presigned_post_into_locked_reports_bucket_is_encrypted(
    cleanup: list[tuple[str, str, str | None]],
) -> None:
    """The renderer's policy shape (reports.dispatch.build_message): key, Content-Type and a
    1..max length range, into the object-locked reports bucket without a default retention."""
    settings = get_settings()
    bucket = _test_bucket(settings.reports_bucket)
    key = f"{uuid.uuid4()}/{uuid.uuid4()}/1/{uuid.uuid4()}.pdf"
    policy = PostPolicy(bucket, datetime.now(UTC) + timedelta(minutes=5))
    policy.add_equals_condition("key", key)
    policy.add_equals_condition("Content-Type", "application/pdf")
    policy.add_content_length_range_condition(1, settings.report_max_artifact_bytes)
    fields = {
        **get_minio().presigned_post_policy(policy),
        "key": key,
        "Content-Type": "application/pdf",
    }
    scheme = "https" if settings.minio_secure else "http"
    url = f"{scheme}://{settings.need('minio_endpoint')}/{bucket}"
    response = httpx.post(
        url, data=fields, files={"file": ("r.pdf", b"%PDF-1.7 render")}, timeout=30
    )
    assert response.status_code == 204, response.text
    version_id = response.headers["x-amz-version-id"]
    cleanup.append((bucket, key, version_id))
    assert _sse(bucket, key, version_id) == "AES256"


async def test_report_snapshot_is_encrypted_and_readable(
    cleanup: list[tuple[str, str, str | None]],
) -> None:
    key = report_storage.snapshot_key(uuid.uuid4(), uuid.uuid4(), 1)
    data = b'{"snapshot": true}'
    version_id = await report_storage.put_snapshot(key, data)
    bucket = _test_bucket(report_storage.bucket())
    cleanup.append((bucket, key, version_id))
    assert _sse(bucket, key, version_id) == "AES256"
    assert await report_storage.read_snapshot(key, version_id) == data
    # The renderer reads the snapshot through a presigned GET of that version.
    url = get_minio().presigned_get_object(
        bucket, key, expires=timedelta(minutes=5), version_id=version_id
    )
    assert httpx.get(url, timeout=30).content == data


def test_plain_put_without_sse_headers_is_encrypted_by_the_bucket_default(
    cleanup: list[tuple[str, str, str | None]],
) -> None:
    """The bucket default, not a client header, encrypts: the api client never sends one."""
    bucket = _test_bucket(get_settings().results_bucket)
    key = f"results/{uuid.uuid4()}/plain.bin"
    result = get_minio().put_object(bucket, key, io.BytesIO(b"plain"), 5)
    cleanup.append((bucket, key, result.version_id))
    assert _sse(bucket, key, result.version_id) == "AES256"
