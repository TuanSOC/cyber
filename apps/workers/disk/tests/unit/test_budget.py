"""The deadline budget (M9 phase 2, RT5). Pure: runs anywhere."""

from datetime import UTC, datetime, timedelta

from disk_worker.budget import Budget
from tests.unit.phase2_helpers import limits


def _budget(minutes_left: float) -> Budget:
    return Budget(datetime.now(UTC) + timedelta(minutes=minutes_left), limits())


def test_a_stage_gets_its_cap_when_time_is_plentiful() -> None:
    b = _budget(240)
    assert b.timeout("walk") == 3600
    assert b.timeout("layout") == 600


def test_a_stage_never_runs_past_the_deadline_minus_the_reserve() -> None:
    b = _budget(30)  # 1 800 s left - 900 s reserve = 900 s
    assert 880 < b.timeout("walk") <= 900


def test_with_20_minutes_left_a_stage_whose_cap_cannot_fit_is_skipped() -> None:
    b = _budget(20)  # 300 s usable
    assert b.timeout("log2timeline") <= 0  # needs at least 600 s
    assert 0 < b.timeout("layout") <= 300


def test_past_the_deadline_everything_is_skipped() -> None:
    b = _budget(10)  # 600 s left < the 900 s reserve
    for stage in ("verify", "layout", "walk", "collect", "scan", "extract"):
        assert b.timeout(stage) <= 0  # type: ignore[arg-type]


def test_verify_scales_with_the_media_size() -> None:
    b = _budget(240)
    base = b.timeout("verify")
    b.set_media_size(200 * 10**9)  # 200 GB at 100 MB/s: + 2 000 s
    assert b.timeout("verify") == base + 2000


def test_the_stage_sum_never_passes_the_deadline() -> None:
    b = _budget(60)
    spent = 0.0
    for stage in ("layout", "verify", "walk", "walk", "collect", "scan", "log2timeline"):
        t = b.timeout(stage)  # type: ignore[arg-type]
        if t > 0:
            spent += t
            b.deadline_at -= timedelta(seconds=t)  # the stage used all of it
    assert spent <= 60 * 60 - 900
