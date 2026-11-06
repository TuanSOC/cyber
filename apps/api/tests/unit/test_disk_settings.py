"""M9 phase 1: the disk settings and their bounds (RT6, RT9, RT21)."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import Settings

BASE: dict[str, Any] = {
    "database_url": "postgresql+asyncpg://cyberlab_app:s3cret@postgres/cyberlab",
    "redis_url": "redis://redis:6379/0",
    "jwt_secret": "x" * 48,
    "minio_endpoint": "minio:9000",
    "minio_access_key": "cyberlab-api",
    "minio_secret_key": "s3cret-minio",
    "broker_url": "redis://api:x@redis-broker:6379/0",
}
GIB = 1024**3
MIB = 1024**2


def _settings(**overrides: Any) -> Settings:
    return Settings(**{**BASE, **overrides})


def test_defaults_match_the_plan() -> None:
    s = _settings()
    assert (s.disk_max_upload_bytes, s.disk_max_image_bytes) == (8 * GIB, 16 * GIB)
    assert s.disk_max_media_bytes == 2 * 1024**4
    assert s.disk_max_segments == 64
    assert s.disk_max_result_bytes == 256 * MIB
    assert s.disk_max_result_decompressed_bytes == 3 * GIB // 2
    assert (s.analysis_disk_timeout_s, s.disk_ingest_timeout_s) == (14_400, 1_800)
    assert (s.disk_max_active_per_org, s.disk_max_active_total) == (1, 1)
    assert (s.disk_export_max_bytes, s.disk_export_max_files) == (64 * MIB, 20)
    assert s.disk_export_ttl_s == 7 * 86_400
    caps = (128, 500_000, 250_000, 5_000, 20_000, 5_000)
    assert s.disk_max_result_lines() == 3 + sum(caps)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("disk_max_upload_bytes", 16 * GIB + 1),
        ("disk_max_image_bytes", 64 * GIB + 1),
        ("disk_max_segments", 65),
        ("disk_max_result_bytes", 256 * MIB + 1),
        ("disk_max_result_decompressed_bytes", 3 * GIB // 2 + 1),
        ("analysis_disk_timeout_s", 21_601),
        ("disk_max_files", 2_000_001),
        ("disk_max_partitions", 129),
        ("disk_max_timeline", 5_001),
        ("disk_export_max_files", 21),
        ("disk_export_max_bytes", 64 * MIB + 1),
    ],
)
def test_caps_cannot_exceed_the_contract(name: str, value: int) -> None:
    with pytest.raises(ValidationError):
        _settings(**{name: value})


def test_cross_field_rules() -> None:
    with pytest.raises(ValidationError):  # one upload larger than a whole set
        _settings(disk_max_upload_bytes=8 * GIB, disk_max_image_bytes=4 * GIB)
    with pytest.raises(ValidationError):  # an export the static analyzer would refuse
        _settings(disk_export_max_bytes=64 * MIB, static_max_bytes=32 * MIB)
    with pytest.raises(ValidationError):
        _settings(disk_max_events=1_000, disk_max_events_read=999)
    with pytest.raises(ValidationError):
        _settings(analysis_disk_timeout_s=1_800, disk_ingest_timeout_s=1_800)
    small = _settings(disk_max_upload_bytes=64 * MIB, disk_max_image_bytes=256 * MIB)
    assert small.disk_max_image_bytes == 256 * MIB
