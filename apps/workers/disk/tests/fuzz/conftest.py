"""Fuzz-lite (M9 phase 13): writes the outcome counts at the end of the session.

The report goes to `DISK_FUZZ_REPORT` (default `/work/fuzz-outcomes.json`, the test tmpfs; the
metric harness copies the counts into the metric report). Nothing is written when no fuzz case
ran (the modules skip unless `DISK_FUZZ=1`).
"""

from typing import Any

import pytest

from tests.fuzz import harness


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    doc: dict[str, Any] | None = harness.write_report()
    if doc is None:
        return
    for group, data in doc["groups"].items():
        print(
            f"\nfuzz-lite {group}: {data['clean']}/{data['total']} clean; "
            f"by outcome {data['by_outcome']}"
        )
    print(f"fuzz-lite report: {harness.REPORT}")
