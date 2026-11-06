"""M10 phase 1: the reverse-engineering settings, their bounds and order, the heavy-analysis
cap (RT2) and the RE job limits built from them."""

from typing import Any

import pytest
from cyberlab_jobs.reverse import ReLimits
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
    assert s.re_max_bytes == 16 * MIB
    assert (s.re_max_result_bytes, s.re_max_result_decompressed_bytes) == (256 * MIB, 768 * MIB)
    assert (s.analysis_re_timeout_s, s.re_analysis_timeout_s, s.re_decompile_timeout_s) == (
        3_600,
        1_500,
        30,
    )
    assert (s.re_quick_timeout_s, s.re_max_decompiled, s.re_max_work_bytes) == (300, 300, 2 * GIB)
    assert (s.re_max_active_per_org, s.analysis_heavy_max_active) == (1, 1)
    assert s.re_quick_enabled is False
    assert s.ai_max_code_chars == 12_000
    caps = (20_000, 100_000, 10_000, 50_000, 20_000, 50_000, 300, 2_000, 10_000)
    assert s.re_max_result_lines() == 3 + sum(caps)


@pytest.mark.parametrize(
    ("overrides"),
    [
        {"re_max_bytes": 64 * MIB + 1},
        {"re_max_bytes": 32 * MIB, "static_max_bytes": 16 * MIB},  # RE_MAX_BYTES <= STATIC
        {"re_decompile_timeout_s": 1_500},  # not below the analysis timeout
        {"re_analysis_timeout_s": 3_600},  # not below the job timeout
        {"re_quick_timeout_s": 3_600},
        {"analysis_re_timeout_s": 21_601},
        {"re_max_decompiled": 2_001},
        {"re_max_functions": 20_001},
        {"re_max_result_decompressed_bytes": 768 * MIB + 1},
        {"analysis_heavy_max_active": 0},
        {"ai_max_code_chars": 12_001},
    ],
)
def test_bounds_and_order(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


def test_re_limits_from_settings_are_valid() -> None:
    from app.modules.reverse_engineering.dispatch import re_limits

    limits = re_limits(_settings())
    assert isinstance(limits, ReLimits)
    assert limits.decompile_timeout_s < limits.tool_timeout_s < limits.timeout_s
    assert limits.max_lines() == _settings().re_max_result_lines()
    # The smallest legal job still nests the stage timeout inside it.
    tight = re_limits(
        _settings(
            analysis_re_timeout_s=120,
            re_analysis_timeout_s=100,
            re_decompile_timeout_s=10,
            re_quick_timeout_s=60,
        )
    )
    assert tight.tool_timeout_s < tight.timeout_s
