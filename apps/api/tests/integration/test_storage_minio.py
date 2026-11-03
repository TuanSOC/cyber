import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from minio.error import S3Error

from app.core import storage
from tests.storage_helpers import evidence_test_bucket, overwrite, root_minio, versions


async def _read(key: str, version_id: str) -> bytes:
    return b"".join(
        [chunk async for chunk in storage.iter_version(storage.bucket(), key, version_id)]
    )


@pytest.fixture
def sample(tmp_path: Path) -> tuple[Path, bytes]:
    data = os.urandom(70_000)
    path = tmp_path / "sample.bin"
    path.write_bytes(data)
    return path, data


async def test_put_returns_version_and_reads_back(sample: tuple[Path, bytes]) -> None:
    path, data = sample
    key = f"test/{uuid.uuid4()}"
    version_id = await storage.put_file(key, path)
    assert version_id
    assert await _read(key, version_id) == data


async def test_overwrite_creates_new_version_original_still_served(
    sample: tuple[Path, bytes],
) -> None:
    path, data = sample
    key = f"test/{uuid.uuid4()}"
    version_id = await storage.put_file(key, path)
    forged = overwrite(key, b"forged bytes")
    assert forged != version_id
    assert await _read(key, version_id) == data  # pinned version is unaffected


async def test_missing_version_raises(sample: tuple[Path, bytes]) -> None:
    path, _ = sample
    key = f"test/{uuid.uuid4()}"
    await storage.put_file(key, path)
    with pytest.raises(storage.ObjectMissing):
        await _read(key, "00000000-0000-0000-0000-000000000000")


async def test_delete_version_removes_bytes_not_just_marker(sample: tuple[Path, bytes]) -> None:
    path, _ = sample
    key = f"test/{uuid.uuid4()}"
    version_id = await storage.put_file(key, path)
    await storage.delete_version(storage.bucket(), key, version_id)
    assert versions(prefix=key) == []


async def test_api_user_cannot_delete_retained_version(sample: tuple[Path, bytes]) -> None:
    path, _ = sample
    key = f"test/{uuid.uuid4()}"
    version_id = await storage.put_file(key, path)
    await storage.set_retention(
        storage.bucket(), key, version_id, datetime.now(UTC) + timedelta(days=1)
    )
    with pytest.raises(S3Error):
        await storage.delete_version(storage.bucket(), key, version_id)
    # Without governance bypass even root cannot delete it.
    with pytest.raises(S3Error):
        root_minio().remove_object(evidence_test_bucket(), key, version_id=version_id)
    assert versions(prefix=key) == [(key, version_id)]


async def test_hash_version_matches_content(sample: tuple[Path, bytes]) -> None:
    path, data = sample
    key = f"test/{uuid.uuid4()}"
    version_id = await storage.put_file(key, path)
    size, hashes = await storage.hash_version(storage.bucket(), key, version_id)
    assert size == len(data)
    assert hashes["sha256"] == hashlib.sha256(data).hexdigest()
