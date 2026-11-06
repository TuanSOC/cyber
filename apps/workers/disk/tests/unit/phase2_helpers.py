"""Shared helpers of the M9 phase-2 unit tests (pure: no sandbox import)."""

from typing import Any

from cyberlab_jobs.disk import (
    PROFILE_BUDGETS,
    DiskLimits,
    DiskProfile,
    default_stage_limits,
    split_event_quotas,
)


def limits_dict(**overrides: Any) -> dict[str, Any]:
    budgets = dict(PROFILE_BUDGETS[DiskProfile.TRIAGE])
    stages = default_stage_limits(budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"])
    data: dict[str, Any] = {
        "max_image_bytes": 16 * 1024**3,
        "max_media_bytes": 2 * 1024**4,
        "timeout_s": 14_400,
        "stages": {k: v.model_dump() for k, v in stages.items()},
        **budgets,
        "max_partitions": 128,
        "max_filesystems": 32,
        "max_files": 500_000,
        "max_streams_per_file": 16,
        "max_events_stored": 250_000,
        "max_events_read": 20_000_000,
        "max_findings": 5_000,
        "max_iocs": 20_000,
        "max_timeline": 5_000,
        "max_result_bytes": 256 * 1024**2,
        "event_quotas": {k.value: v for k, v in split_event_quotas(250_000).items()},
    }
    data.update(overrides)
    return data


def limits(**overrides: Any) -> DiskLimits:
    return DiskLimits.model_validate(limits_dict(**overrides))


class ListWriter:
    """A `RowWriter` stand-in that keeps rows in memory (row cap only)."""

    def __init__(self, max_rows: int = 10**9) -> None:
        self.items: list[dict[str, Any]] = []
        self.max_rows = max_rows
        self.truncated = False

    @property
    def rows(self) -> int:
        return len(self.items)

    def write(self, row: dict[str, Any]) -> bool:
        if self.truncated or len(self.items) >= self.max_rows:
            self.truncated = True
            return False
        self.items.append(dict(row))
        return True
