"""Test-only MinIO helpers using root credentials (attacker/admin simulation and cleanup)."""

import io
import os
from functools import lru_cache

from minio import Minio
from minio.deleteobjects import DeleteObject

from app.core.config import get_settings


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


def purge_test_bucket() -> None:
    """Remove every version (incl. retention-locked ones) from the test bucket."""
    targets = [DeleteObject(name, version_id) for name, version_id, _ in all_entries()]
    if not targets:
        return
    errors = list(
        root_minio().remove_objects(evidence_test_bucket(), targets, bypass_governance_mode=True)
    )
    if errors:
        raise RuntimeError(f"could not purge test bucket: {errors[:3]}")
