"""Object-store conformance suite (M7 phase 6): what CyberLab needs from its S3 store.

Runs against the configured store (`MINIO_ENDPOINT`, root keys `TEST_MINIO_ROOT_USER` /
`TEST_MINIO_ROOT_PASSWORD`), and also against a throwaway candidate image when
`OBJECT_STORE_CANDIDATE_URL` (e.g. `http://objstore-candidate:9000`) with
`OBJECT_STORE_CANDIDATE_ROOT_USER` / `OBJECT_STORE_CANDIDATE_ROOT_PASSWORD` is set (test-only
env; the candidate runs in its own compose project,
`infra/minio/image/docker-compose.candidate.yml`, which documents the commands).

Every run creates fresh buckets (`conf-<run>-evidence` / `-reports` object-locked,
`conf-<run>-results` versioned), its own api and purge users with the policies of
`infra/minio/{api,purge}-policy.template.json` rendered for those buckets, and removes all of
it afterwards. Only root uses the admin API (setup); every app path below is plain S3, so the
app never needs `mc admin` (asserted: the api user's admin calls are refused).

RT7 (restart under the KMS key) needs a container restart, which a test cannot do. Two
steps: `OBJECT_STORE_RESTART_PHASE=prepare` leaves a sentinel user, policy and SSE object;
restart the store; `OBJECT_STORE_RESTART_PHASE=verify` checks them and removes them.
`OBJECT_STORE_EXPECT_SSE=false` skips the SSE checks (a store without a KMS key).
"""

import hashlib
import io
import json
import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest
from minio import Minio
from minio.commonconfig import ENABLED, GOVERNANCE
from minio.credentials import StaticProvider
from minio.datatypes import PostPolicy
from minio.deleteobjects import DeleteObject
from minio.error import MinioAdminException, S3Error
from minio.minioadmin import MinioAdmin
from minio.retention import Retention
from minio.sse import SseS3
from minio.sseconfig import Rule, SSEConfig
from minio.versioningconfig import VersioningConfig

from app.core.config import get_settings

SSE_HEADER = "x-amz-server-side-encryption"
SENTINEL = "conformance-sentinel"
# A refused delete / retention change of a WORM-protected version: MinIO answers
# `AccessDenied` (policy) or `InvalidRequest` / `ObjectLocked` ("Object is WORM protected").
LOCKED_CODES = {"AccessDenied", "InvalidRequest", "ObjectLocked"}


# --- targets --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    label: str
    endpoint: str  # host:port
    secure: bool
    root_user: str
    root_password: str

    def client(self, access_key: str, secret_key: str) -> Minio:
        return Minio(
            self.endpoint, access_key=access_key, secret_key=secret_key, secure=self.secure
        )

    def root(self) -> Minio:
        return self.client(self.root_user, self.root_password)

    def admin(self, access_key: str | None = None, secret_key: str | None = None) -> MinioAdmin:
        return MinioAdmin(
            endpoint=self.endpoint,
            credentials=StaticProvider(
                access_key or self.root_user, secret_key or self.root_password
            ),
            secure=self.secure,
        )

    def url(self, bucket: str) -> str:
        return f"{'https' if self.secure else 'http'}://{self.endpoint}/{bucket}"


def _targets() -> list[Target]:
    s = get_settings()
    found = [
        Target(
            "current",
            s.need("minio_endpoint"),
            s.minio_secure,
            os.environ["TEST_MINIO_ROOT_USER"],
            os.environ["TEST_MINIO_ROOT_PASSWORD"],
        )
    ]
    candidate = os.environ.get("OBJECT_STORE_CANDIDATE_URL")
    if candidate:
        parsed = urlparse(candidate)
        found.append(
            Target(
                "candidate",
                parsed.netloc,
                parsed.scheme == "https",
                os.environ["OBJECT_STORE_CANDIDATE_ROOT_USER"],
                os.environ["OBJECT_STORE_CANDIDATE_ROOT_PASSWORD"],
            )
        )
    return found


EXPECT_SSE = os.environ.get("OBJECT_STORE_EXPECT_SSE", "true").lower() != "false"


# --- policies (the shape of infra/minio/*-policy.template.json, for the fresh buckets) ------


def _arn(bucket: str, path: str = "") -> str:
    return f"arn:aws:s3:::{bucket}{path}"


def api_policy(evidence: str, results: str, reports: str) -> dict[str, object]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket",
                    "s3:ListBucketVersions",
                    "s3:GetBucketLocation",
                    "s3:GetBucketObjectLockConfiguration",
                    "s3:ListBucketMultipartUploads",
                ],
                "Resource": [_arn(evidence), _arn(results), _arn(reports)],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:PutObjectRetention",
                    "s3:GetObjectRetention",
                    "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts",
                ],
                "Resource": [_arn(evidence, "/*")],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"],
                "Resource": [_arn(results, "/*")],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:PutObjectRetention",
                    "s3:GetObjectRetention",
                ],
                "Resource": [_arn(reports, "/*")],
            },
        ],
    }


def purge_policy(evidence: str, results: str, reports: str) -> dict[str, object]:
    buckets = (evidence, results, reports)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket",
                    "s3:ListBucketVersions",
                    "s3:GetBucketLocation",
                    "s3:GetBucketObjectLockConfiguration",
                ],
                "Resource": [_arn(b) for b in buckets],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectVersion",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                    "s3:GetObjectRetention",
                    "s3:GetObjectLegalHold",
                    "s3:PutObjectLegalHold",
                ],
                "Resource": [_arn(b, "/*") for b in buckets],
            },
            {
                "Effect": "Deny",
                "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
                "Resource": [_arn(reports, "/*/snapshot.json")],
            },
        ],
    }


# --- the store under test -------------------------------------------------------------------


@dataclass
class Store:
    target: Target
    root: Minio
    api: Minio
    purge: Minio
    api_keys: tuple[str, str]
    evidence: str
    results: str
    reports: str

    def put(self, bucket: str, key: str, data: bytes, client: Minio | None = None) -> str:
        result = (client or self.api).put_object(bucket, key, io.BytesIO(data), len(data))
        assert result.version_id, f"{bucket} is not versioned"
        return str(result.version_id)

    def read(self, bucket: str, key: str, version_id: str, client: Minio | None = None) -> bytes:
        response = (client or self.api).get_object(bucket, key, version_id=version_id)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def versions(self, bucket: str, prefix: str, client: Minio | None = None) -> list[tuple]:
        objects = (client or self.api).list_objects(
            bucket, prefix=prefix, recursive=True, include_version=True
        )
        return [(o.object_name, o.version_id, o.is_delete_marker) for o in objects]

    def bypass_delete(self, bucket: str, key: str, version_id: str) -> list[Any]:
        return list(
            self.root.remove_objects(
                bucket, [DeleteObject(key, version_id)], bypass_governance_mode=True
            )
        )


def _empty_and_remove(root: Minio, bucket: str) -> None:
    if not root.bucket_exists(bucket):
        return
    entries = list(root.list_objects(bucket, recursive=True, include_version=True))
    for entry in entries:
        try:
            root.disable_object_legal_hold(bucket, entry.object_name, entry.version_id)
        except S3Error:
            pass  # not locked / no hold
    targets = [DeleteObject(e.object_name, e.version_id) for e in entries]
    if targets:
        errors = list(root.remove_objects(bucket, targets, bypass_governance_mode=True))
        assert not errors, errors
    root.remove_bucket(bucket)


def _create_user(
    admin: MinioAdmin, name: str, policy: dict[str, object], secret: str | None = None
) -> str:
    secret = secret or uuid.uuid4().hex
    admin.policy_add(name, policy=policy)
    admin.user_add(name, secret)
    admin.attach_policy([name], user=name)
    return secret


@pytest.fixture(params=_targets(), ids=lambda t: t.label, scope="module")
def store(request: pytest.FixtureRequest) -> Iterator[Store]:
    target: Target = request.param
    root, admin = target.root(), target.admin()
    run = uuid.uuid4().hex[:8]
    evidence, results, reports = (f"conf-{run}-{n}" for n in ("evidence", "results", "reports"))
    api_name, purge_name = f"conf-{run}-api", f"conf-{run}-purge"
    try:
        root.make_bucket(evidence, object_lock=True)
        root.make_bucket(reports, object_lock=True)
        root.make_bucket(results)
        root.set_bucket_versioning(results, VersioningConfig(ENABLED))
        if EXPECT_SSE:
            for bucket in (evidence, results, reports):
                root.set_bucket_encryption(bucket, SSEConfig(Rule.new_sse_s3_rule()))
        api_secret = _create_user(admin, api_name, api_policy(evidence, results, reports))
        purge_secret = _create_user(admin, purge_name, purge_policy(evidence, results, reports))
        yield Store(
            target=target,
            root=root,
            api=target.client(api_name, api_secret),
            purge=target.client(purge_name, purge_secret),
            api_keys=(api_name, api_secret),
            evidence=evidence,
            results=results,
            reports=reports,
        )
    finally:
        for bucket in (evidence, results, reports):
            _empty_and_remove(root, bucket)
        for name in (api_name, purge_name):
            for remove in (admin.user_remove, admin.policy_remove):
                try:
                    remove(name)
                except MinioAdminException:
                    pass


def _key() -> str:
    return f"{uuid.uuid4()}/{uuid.uuid4()}"


def _soon(**delta: float) -> datetime:
    # S3 retention dates have second precision; strip microseconds for exact comparisons.
    return (datetime.now(UTC) + timedelta(**delta)).replace(microsecond=0)


# --- versioning, lock configuration, exact versions -----------------------------------------


def test_buckets_are_versioned_and_locked_without_default_retention(store: Store) -> None:
    for bucket in (store.evidence, store.reports, store.results):
        assert store.root.get_bucket_versioning(bucket).status == ENABLED
    for bucket in (store.evidence, store.reports):
        config = store.api.get_object_lock_config(bucket)  # an app call (lock check)
        assert config.mode is None and config.duration is None  # per-object retention only
    with pytest.raises(S3Error):
        store.api.get_object_lock_config(store.results)


def test_versions_exact_get_and_list_object_versions(store: Store) -> None:
    key = _key()
    first = store.put(store.evidence, key, b"original evidence")
    second = store.put(store.evidence, key, b"forged overwrite")
    assert first != second
    assert store.read(store.evidence, key, first) == b"original evidence"
    assert store.read(store.evidence, key, second) == b"forged overwrite"
    listed = store.versions(store.evidence, key)
    assert {(k, v) for k, v, marker in listed if not marker} == {(key, first), (key, second)}
    # A delete without a version id only adds a marker: both versions stay readable.
    store.api.remove_object(store.evidence, key)
    after = store.versions(store.evidence, key)
    assert sum(1 for *_, marker in after if marker) == 1
    assert store.read(store.evidence, key, first) == b"original evidence"
    with pytest.raises(S3Error) as missing:
        store.read(store.evidence, key, "00000000-0000-0000-0000-000000000000")
    assert missing.value.code in {"NoSuchVersion", "NoSuchKey", "InvalidArgument"}


# --- GOVERNANCE retention -------------------------------------------------------------------


def test_governance_retention_set_extend_and_refuse_shorten(store: Store) -> None:
    key = _key()
    version = store.put(store.evidence, key, b"locked")
    until = _soon(days=1)
    store.api.set_object_retention(store.evidence, key, Retention(GOVERNANCE, until), version)
    got = store.api.get_object_retention(store.evidence, key, version)
    assert got.mode == GOVERNANCE and got.retain_until_date == until
    extended = _soon(days=2)
    store.api.set_object_retention(store.evidence, key, Retention(GOVERNANCE, extended), version)
    assert (
        store.api.get_object_retention(store.evidence, key, version).retain_until_date == extended
    )
    # Shortening needs s3:BypassGovernanceRetention + the bypass header: refused.
    with pytest.raises(S3Error) as refused:
        store.api.set_object_retention(
            store.evidence, key, Retention(GOVERNANCE, _soon(hours=1)), version
        )
    assert refused.value.code in LOCKED_CODES
    assert (
        store.api.get_object_retention(store.evidence, key, version).retain_until_date == extended
    )
    # Report snapshots use the same per-object retention in the reports bucket.
    snap = f"{_key()}/1/snapshot.json"
    snap_version = store.put(store.reports, snap, b"{}")
    store.api.set_object_retention(store.reports, snap, Retention(GOVERNANCE, until), snap_version)
    assert store.api.get_object_retention(store.reports, snap, snap_version).mode == GOVERNANCE


def test_locked_version_delete_refused_except_root_with_bypass(store: Store) -> None:
    key = _key()
    version = store.put(store.evidence, key, b"locked")
    store.api.set_object_retention(
        store.evidence, key, Retention(GOVERNANCE, _soon(days=1)), version
    )
    for client in (store.api, store.purge, store.root):  # root without the bypass header too
        with pytest.raises(S3Error) as refused:
            client.remove_object(store.evidence, key, version_id=version)
        assert refused.value.code in LOCKED_CODES
    # Batch delete with bypass by a user without s3:BypassGovernanceRetention: refused.
    errors = list(
        store.purge.remove_objects(
            store.evidence, [DeleteObject(key, version)], bypass_governance_mode=True
        )
    )
    assert errors and errors[0].code in LOCKED_CODES
    assert (key, version, False) in store.versions(store.evidence, key)
    assert store.bypass_delete(store.evidence, key, version) == []
    assert store.versions(store.evidence, key) == []


# --- the purge user (retention worker, RT5) -------------------------------------------------


def test_purge_user_deletes_an_unlocked_version_for_real(store: Store) -> None:
    key = _key()
    keep = store.put(store.evidence, key, b"keep")
    gone = store.put(store.evidence, key, b"purge me")
    store.purge.remove_object(store.evidence, key, version_id=gone)
    remaining = store.versions(store.evidence, key)
    assert remaining == [(key, keep, False)]  # removed, not hidden behind a marker
    # The purge user holds no PutObject and no PutObjectRetention.
    with pytest.raises(S3Error):
        store.put(store.evidence, _key(), b"x", client=store.purge)
    with pytest.raises(S3Error):
        store.purge.set_object_retention(
            store.evidence, key, Retention(GOVERNANCE, _soon(days=1)), keep
        )


def test_snapshot_json_explicit_deny_applies_to_versioned_deletes(store: Store) -> None:
    prefix = _key()
    snapshot = f"{prefix}/1/snapshot.json"
    artifact = f"{prefix}/1/{uuid.uuid4()}.pdf"
    snap_version = store.put(store.reports, snapshot, b"{}")
    artifact_version = store.put(store.reports, artifact, b"%PDF")
    with pytest.raises(S3Error) as denied:
        store.purge.remove_object(store.reports, snapshot, version_id=snap_version)
    assert denied.value.code == "AccessDenied"
    errors = list(store.purge.remove_objects(store.reports, [DeleteObject(snapshot, snap_version)]))
    assert errors and errors[0].code == "AccessDenied"
    store.purge.remove_object(store.reports, artifact, version_id=artifact_version)
    assert store.versions(store.reports, prefix, client=store.root) == [
        (snapshot, snap_version, False)
    ]
    # The api user never deletes in the reports bucket at all.
    with pytest.raises(S3Error):
        store.api.remove_object(store.reports, snapshot, version_id=snap_version)


def test_legal_hold_by_purge_user_only_and_blocks_every_delete(store: Store) -> None:
    key = _key()
    version = store.put(store.evidence, key, b"held")
    # RT5: the api user has no legal-hold action.
    with pytest.raises(S3Error) as refused:
        store.api.enable_object_legal_hold(store.evidence, key, version)
    assert refused.value.code == "AccessDenied"
    store.purge.enable_object_legal_hold(store.evidence, key, version)
    assert store.purge.is_object_legal_hold_enabled(store.evidence, key, version) is True
    with pytest.raises(S3Error):
        store.api.disable_object_legal_hold(store.evidence, key, version)
    for client in (store.api, store.purge):
        with pytest.raises(S3Error) as blocked:
            client.remove_object(store.evidence, key, version_id=version)
        assert blocked.value.code in LOCKED_CODES
    # Governance bypass does not lift a legal hold, even for root.
    errors = store.bypass_delete(store.evidence, key, version)
    assert errors and errors[0].code in LOCKED_CODES
    store.purge.disable_object_legal_hold(store.evidence, key, version)
    assert store.purge.is_object_legal_hold_enabled(store.evidence, key, version) is False
    store.purge.remove_object(store.evidence, key, version_id=version)
    assert store.versions(store.evidence, key) == []


# --- presigned POST / GET (analyzers and renderer hold no credentials) ----------------------


def _post_policy(store: Store, bucket: str, key: str, max_bytes: int, **equals: str) -> dict:
    policy = PostPolicy(bucket, datetime.now(UTC) + timedelta(minutes=10))
    policy.add_equals_condition("key", key)
    for field, value in equals.items():
        policy.add_equals_condition(field, value)
    policy.add_content_length_range_condition(0 if not equals else 1, max_bytes)
    return {**store.api.presigned_post_policy(policy), "key": key, **equals}


def test_presigned_post_with_key_and_length_conditions(store: Store) -> None:
    key = f"results/{uuid.uuid4()}/{uuid.uuid4()}.ndjson.gz"
    fields = _post_policy(store, store.results, key, 1024)
    url = store.target.url(store.results)
    ok = httpx.post(url, data=fields, files={"file": ("r", b"x" * 1000)}, timeout=30)
    assert ok.status_code == 204, ok.text
    version = ok.headers.get("x-amz-version-id")
    assert version and store.read(store.results, key, version) == b"x" * 1000
    too_big = httpx.post(url, data=fields, files={"file": ("r", b"x" * 1025)}, timeout=30)
    assert too_big.status_code in {400, 403}, too_big.text
    other_key = {**fields, "key": f"{key}.other"}
    wrong = httpx.post(url, data=other_key, files={"file": ("r", b"x")}, timeout=30)
    assert wrong.status_code == 403, wrong.text
    assert [v for _, v, _ in store.versions(store.results, key)] == [version]


def test_presigned_post_into_a_locked_bucket_needs_no_content_md5(store: Store) -> None:
    key = f"{_key()}/1/{uuid.uuid4()}.pdf"
    fields = _post_policy(store, store.reports, key, 1 << 20, **{"Content-Type": "application/pdf"})
    response = httpx.post(
        store.target.url(store.reports), data=fields, files={"file": ("r.pdf", b"%PDF")}, timeout=30
    )
    assert response.status_code == 204, response.text
    wrong_type = {**fields, "Content-Type": "text/html"}
    refused = httpx.post(
        store.target.url(store.reports), data=wrong_type, files={"file": ("r", b"<x>")}, timeout=30
    )
    assert refused.status_code == 403


def test_presigned_get_of_an_exact_version(store: Store) -> None:
    key = _key()
    first = store.put(store.evidence, key, b"first")
    store.put(store.evidence, key, b"second")
    url = store.api.presigned_get_object(
        store.evidence, key, expires=timedelta(minutes=5), version_id=first
    )
    response = httpx.get(url, timeout=30)
    assert (response.status_code, response.content) == (200, b"first")
    tampered = httpx.get(url.replace(first, "00000000-0000-0000-0000-000000000000"), timeout=30)
    assert tampered.status_code == 403  # the version id is signed


# --- SSE-S3 ---------------------------------------------------------------------------------


@pytest.mark.skipif(not EXPECT_SSE, reason="OBJECT_STORE_EXPECT_SSE=false")
def test_sse_s3_bucket_default_encrypts_every_new_object(store: Store) -> None:
    for bucket in (store.evidence, store.results, store.reports):
        config = store.root.get_bucket_encryption(bucket)
        assert config is not None and config.rule.sse_algorithm == "AES256"
    key = _key()
    version = store.put(store.evidence, key, b"secret bytes")
    stat = store.root.stat_object(store.evidence, key, version_id=version)
    assert stat.metadata.get(SSE_HEADER) == "AES256"
    assert store.read(store.evidence, key, version) == b"secret bytes"
    # A client that asks for SSE-S3 explicitly gets the same (no Content-MD5 needed).
    explicit = store.api.put_object(
        store.results, f"results/{uuid.uuid4()}", io.BytesIO(b"e"), 1, sse=SseS3()
    )
    stat = store.root.stat_object(
        store.results, explicit.object_name, version_id=explicit.version_id
    )
    assert stat.metadata.get(SSE_HEADER) == "AES256"
    # Presigned GET of an encrypted version decrypts transparently (analyzer path).
    url = store.api.presigned_get_object(
        store.evidence, key, expires=timedelta(minutes=5), version_id=version
    )
    assert httpx.get(url, timeout=30).content == b"secret bytes"


@pytest.mark.skipif(not EXPECT_SSE, reason="OBJECT_STORE_EXPECT_SSE=false")
def test_kms_key_is_usable(store: Store) -> None:
    status = json.loads(store.target.admin().kms_key_status())
    assert status.get("key-id"), status
    assert not status.get("encryption-error"), status
    assert not status.get("decryption-error"), status


# --- no admin rights on the app paths -------------------------------------------------------


def test_app_users_hold_no_admin_rights(store: Store) -> None:
    admin_as_api = store.target.admin(*store.api_keys)
    for call in (admin_as_api.user_list, admin_as_api.kms_key_status):
        with pytest.raises(MinioAdminException):
            call()
    with pytest.raises(S3Error):
        store.api.make_bucket(f"conf-{uuid.uuid4().hex[:8]}-rogue")
    with pytest.raises(S3Error):
        store.api.set_bucket_encryption(store.evidence, SSEConfig(Rule.new_sse_s3_rule()))


# --- RT7: users, policies and SSE objects survive a restart under the KMS key -------------


RESTART_PHASE = os.environ.get("OBJECT_STORE_RESTART_PHASE", "")


def _sentinel_secret(target: Target) -> str:
    # Deterministic (the test containers are --rm, nothing survives between the two runs).
    return hashlib.sha256(f"{SENTINEL}:{target.root_password}".encode()).hexdigest()[:40]


@pytest.mark.skipif(
    RESTART_PHASE not in {"prepare", "verify"},
    reason="needs a store restart between OBJECT_STORE_RESTART_PHASE=prepare and =verify",
)
@pytest.mark.parametrize("target", _targets(), ids=lambda t: t.label)
def test_restart_keeps_users_policies_and_encrypted_objects(target: Target) -> None:
    root, admin = target.root(), target.admin()
    bucket, key, body = f"{SENTINEL}-bucket", "sentinel.bin", b"survives restarts"
    secret = _sentinel_secret(target)
    if RESTART_PHASE == "prepare":
        if not root.bucket_exists(bucket):
            root.make_bucket(bucket, object_lock=True)
        if EXPECT_SSE:
            root.set_bucket_encryption(bucket, SSEConfig(Rule.new_sse_s3_rule()))
        _create_user(admin, SENTINEL, api_policy(bucket, bucket, bucket), secret)
        target.client(SENTINEL, secret).put_object(bucket, key, io.BytesIO(body), len(body))
        pytest.skip("prepared: restart the store, then run with OBJECT_STORE_RESTART_PHASE=verify")
    try:
        assert SENTINEL in json.loads(admin.user_list())
        sentinel = target.client(SENTINEL, secret)  # IAM decrypted under the KMS key
        [version] = [o.version_id for o in sentinel.list_objects(bucket, include_version=True)]
        response = sentinel.get_object(bucket, key, version_id=version)
        try:
            assert response.read() == body
        finally:
            response.close()
            response.release_conn()
        if EXPECT_SSE:
            stat = root.stat_object(bucket, key, version_id=version)
            assert stat.metadata.get(SSE_HEADER) == "AES256"
    finally:
        _empty_and_remove(root, bucket)
        for remove in (admin.user_remove, admin.policy_remove):
            try:
                remove(SENTINEL)
            except MinioAdminException:
                pass
