"""M8 phase 1: the memory settings and their bounds (RT9, RT14), and the `MemoryLimits` the
dispatch builds from them."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.memory_analysis.dispatch import memory_limits

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


def _settings(**overrides: Any) -> Settings:
    return Settings(**{**BASE, **overrides})


def test_defaults_match_the_plan() -> None:
    s = _settings(memory_max_bytes=8 * GIB)
    assert s.memory_max_bytes == 8 * GIB
    assert s.memory_max_result_bytes == 256 * 1024**2
    assert s.memory_max_result_decompressed_bytes == GIB
    assert (s.analysis_memory_timeout_s, s.analysis_memory_plugin_timeout_s) == (5400, 1200)
    assert (s.memory_max_active_per_org, s.memory_max_active_total) == (1, 2)
    caps = (20_000, 50_000, 5_000, 50_000, 5_000, 20_000, 5_000)
    assert s.memory_max_result_lines() == 3 + sum(caps)


def test_the_image_cap_is_at_most_16_gib() -> None:
    _settings(memory_max_bytes=16 * GIB)
    with pytest.raises(ValidationError):
        _settings(memory_max_bytes=16 * GIB + 1)


def test_result_caps_cannot_exceed_the_contract() -> None:
    for name, value in (
        ("memory_max_result_bytes", 256 * 1024**2 + 1),
        ("memory_max_result_decompressed_bytes", GIB + 1),
        ("memory_max_artifacts", 50_001),
        ("memory_max_timeline", 5_001),
    ):
        with pytest.raises(ValidationError):
            _settings(**{name: value})


def test_plugin_and_identify_timeouts_fit_the_job_timeout() -> None:
    with pytest.raises(ValidationError, match="ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S"):
        _settings(analysis_memory_timeout_s=600, analysis_memory_plugin_timeout_s=600)
    with pytest.raises(ValidationError, match="ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S"):
        _settings(analysis_memory_timeout_s=900, analysis_memory_identify_timeout_s=900)
    with pytest.raises(ValidationError):
        _settings(analysis_memory_timeout_s=21_601)


def test_memory_limits_validate_against_the_contract() -> None:
    limits = memory_limits(_settings(memory_max_bytes=8 * GIB))
    assert limits.max_bytes == 8 * GIB
    assert limits.tool_timeout_s < limits.timeout_s
    assert limits.max_lines() == _settings().memory_max_result_lines()
