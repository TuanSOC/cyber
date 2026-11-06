"""M9 phase 7: the segment-set rules of a disk analysis request, without a database.

Every refusal reason (`first_segment`, `too_many`, `duplicate`, `not_found`,
`other_investigation`, `purged`, `archived`, `empty`) and both size limits; a valid set keeps
the analyst's order.
"""

import uuid
from typing import Any

import pytest

from app.core.config import Settings
from app.core.errors import AppError
from app.modules.disk_forensics import segments
from app.modules.disk_forensics.errors import (
    DiskImageSetTooLarge,
    DiskImageTooLarge,
    DiskSegmentsInvalid,
)

BASE: dict[str, Any] = {
    "database_url": "postgresql+asyncpg://cyberlab_app:s3cret@postgres/cyberlab",
    "redis_url": "redis://redis:6379/0",
    "jwt_secret": "x" * 48,
    "minio_endpoint": "minio:9000",
    "minio_access_key": "cyberlab-api",
    "minio_secret_key": "s3cret-minio",
    "broker_url": "redis://api:x@redis-broker:6379/0",
}
MIB = 1024**2
CASE = uuid.uuid4()


def _settings(**overrides: Any) -> Settings:
    return Settings(**{**BASE, **overrides})


def _stored(**over: Any) -> segments.Stored:
    values: dict[str, Any] = {
        "investigation_id": CASE,
        "archived": False,
        "purged": False,
        "size_bytes": MIB,
        "sha256": "a" * 64,
        "storage_bucket": "evidence",
        "storage_key": f"org/{uuid.uuid4()}",
        "storage_version_id": "v1",
        **over,
    }
    return segments.Stored(**values)


def _reason(exc: pytest.ExceptionInfo[AppError]) -> object:
    assert isinstance(exc.value, DiskSegmentsInvalid)
    assert exc.value.code == "disk_segments_invalid" and exc.value.status_code == 422
    return exc.value.extra["reason"]


def test_shape_rules() -> None:
    settings = _settings(disk_max_segments=3)
    a, b, c, d = (uuid.uuid4() for _ in range(4))
    segments.check_shape(a, [a, b, c], settings)
    for ids, reason in (
        ([b, a], "first_segment"),
        ([a, b, a], "duplicate"),
        ([a, b, c, d], "too_many"),
        ([], "first_segment"),
    ):
        with pytest.raises(AppError) as caught:
            segments.check_shape(a, ids, settings)
        assert _reason(caught) == reason, ids


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (None, "not_found"),
        ({"sha256": None}, "not_found"),
        ({"investigation_id": uuid.uuid4()}, "other_investigation"),
        ({"purged": True}, "purged"),
        ({"archived": True}, "archived"),
        ({"size_bytes": 0}, "empty"),
    ],
)
def test_every_refusal_reason_names_the_segment(row: dict[str, Any] | None, reason: str) -> None:
    first, second = uuid.uuid4(), uuid.uuid4()
    stored = {first: _stored()}
    if row is not None:
        stored[second] = _stored(**row)
    with pytest.raises(AppError) as caught:
        segments.check_rows([first, second], CASE, stored, _settings())
    assert _reason(caught) == reason
    assert caught.value.extra["ordinal"] == 1


def test_size_limits() -> None:
    settings = _settings(disk_max_upload_bytes=4 * MIB, disk_max_image_bytes=6 * MIB)
    ids = [uuid.uuid4() for _ in range(3)]
    with pytest.raises(DiskImageTooLarge):
        segments.check_rows(ids[:1], CASE, {ids[0]: _stored(size_bytes=5 * MIB)}, settings)
    stored = {i: _stored(size_bytes=3 * MIB) for i in ids}
    assert len(segments.check_rows(ids[:2], CASE, stored, settings)) == 2
    with pytest.raises(DiskImageSetTooLarge):
        segments.check_rows(ids, CASE, stored, settings)


def test_a_valid_set_keeps_the_analysts_order() -> None:
    ids = [uuid.uuid4() for _ in range(4)]
    stored = {i: _stored(sha256=f"{n:x}" * 64) for n, i in enumerate(ids)}
    out = segments.check_rows(list(reversed(ids)), CASE, stored, _settings())
    assert [s.evidence_id for s in out] == list(reversed(ids))
    assert [s.ordinal for s in out] == [0, 1, 2, 3]
    assert out[0].sha256 == stored[ids[-1]].sha256
