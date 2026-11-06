"""Test-only MinIO helpers using root credentials (attacker/admin simulation and cleanup).

Lane isolation (M7 phase 11): every test lane (scripts/lane-test.sh) shares the MinIO test
buckets, so cleanup never empties a bucket. It removes only what this test process owns:
- every key under `{org_id}/` of an organization this process inserted (the app keys every
  evidence, result and report object by its org; recorded by an ORM `after_insert` hook);
- every key under `lane_key("")` (`lane-<TEST_LANE>/`), the prefix tests use for the objects
  they write themselves (probes and fixtures outside any org).
A parallel lane's objects (another process's orgs, another lane prefix) are never touched.
"""

import io
import os
from collections.abc import Iterable
from functools import lru_cache
from typing import Any

from minio import Minio
from minio.deleteobjects import DeleteObject
from minio.error import S3Error
from sqlalchemy import event

from app.core.config import get_settings
from app.modules.organizations.models import Organization

_OWNED_ORGS: set[str] = set()


@event.listens_for(Organization, "after_insert")
def _own_org(mapper: Any, connection: Any, target: Organization) -> None:
    _OWNED_ORGS.add(str(target.id))


def own_org(org_id: object) -> None:
    """Record an org inserted outside the ORM (raw SQL) so its objects are cleaned up too."""
    _OWNED_ORGS.add(str(org_id))


def lane() -> str:
    """This process's test lane (scripts/lane-test.sh sets TEST_LANE; the default lane is 1)."""
    return os.environ.get("TEST_LANE") or "1"


def lane_key(name: str) -> str:
    """A key only this lane's cleanup removes, for objects a test writes outside any org."""
    return f"lane-{lane()}/{name}"


@lru_cache
def root_minio() -> Minio:
    s = get_settings()
    return Minio(
        s.minio_endpoint,
        access_key=os.environ["TEST_MINIO_ROOT_USER"],
        secret_key=os.environ["TEST_MINIO_ROOT_PASSWORD"],
        secure=s.minio_secure,
    )


def evidence_test_bucket() -> str:
    bucket = get_settings().minio_bucket
    if bucket != "evidence-test":
        raise RuntimeError(f"refusing to touch bucket {bucket!r} in tests")
    return bucket


def cleanup_buckets() -> list[str]:
    """The evidence, results and reports test buckets (refusing any non-test name)."""
    s = get_settings()
    out = [evidence_test_bucket()]
    for bucket in (s.results_bucket, s.reports_bucket):
        if not bucket.endswith("-test"):
            raise RuntimeError(f"refusing to touch bucket {bucket!r} in tests")
        out.append(bucket)
    return out


def owned_prefixes() -> list[str]:
    return [f"{org}/" for org in sorted(_OWNED_ORGS)] + [lane_key("")]


def versions(prefix: str = "") -> list[tuple[str, str]]:
    objects = root_minio().list_objects(
        evidence_test_bucket(), prefix=prefix, recursive=True, include_version=True
    )
    return [(o.object_name, o.version_id) for o in objects if not o.is_delete_marker]


def all_entries(prefix: str = "") -> list[tuple[str, str, bool]]:
    objects = root_minio().list_objects(
        evidence_test_bucket(), prefix=prefix, recursive=True, include_version=True
    )
    return [(o.object_name, o.version_id, o.is_delete_marker) for o in objects]


def overwrite(key: str, data: bytes) -> str:
    result = root_minio().put_object(evidence_test_bucket(), key, io.BytesIO(data), len(data))
    return str(result.version_id)


def _entries(bucket: str, prefixes: Iterable[str]) -> list[Any]:
    client = root_minio()
    return [
        o
        for prefix in prefixes
        for o in client.list_objects(bucket, prefix=prefix, recursive=True, include_version=True)
        if o.object_name
    ]


def release_owned_holds(buckets: Iterable[str] | None = None) -> None:
    """Root: turn this process's S3 legal holds off (a held version cannot be removed, even
    with governance bypass). The results bucket has no object lock: nothing to release."""
    client = root_minio()
    s = get_settings()
    for bucket in buckets or cleanup_buckets():
        if bucket == s.results_bucket:
            continue
        for o in _entries(bucket, owned_prefixes()):
            if o.is_delete_marker:
                continue
            try:
                if client.is_object_legal_hold_enabled(bucket, o.object_name, o.version_id):
                    client.disable_object_legal_hold(bucket, o.object_name, o.version_id)
            except S3Error:
                continue  # gone meanwhile


def purge_owned(buckets: Iterable[str] | None = None) -> None:
    """Remove every version this process owns (incl. retention-locked and held ones)."""
    selected = list(buckets or cleanup_buckets())
    release_owned_holds(selected)
    client = root_minio()
    for bucket in selected:
        targets = [
            DeleteObject(o.object_name, o.version_id) for o in _entries(bucket, owned_prefixes())
        ]
        if not targets:
            continue
        errors = list(client.remove_objects(bucket, targets, bypass_governance_mode=True))
        if errors:
            raise RuntimeError(f"could not purge {bucket}: {errors[:3]}")


def forget_owned_orgs() -> None:
    """After a purge of every bucket: the orgs are truncated, their objects are gone."""
    _OWNED_ORGS.clear()


def purge_test_bucket() -> None:
    """Remove this process's versions from the evidence test bucket (lane-safe)."""
    purge_owned([evidence_test_bucket()])
