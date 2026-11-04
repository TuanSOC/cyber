"""Enrich-worker slice robustness (phase-2 review fixes folded into phase 4).

- an unexpected failure handling one item is contained: an `internal_error` row is recorded
  and the lane goes on; if even recording fails the slice halts (items stay pending);
- a lane that raises cancels its siblings (TaskGroup), so nothing outlives the slice on the
  worker's persistent event loop;
- the lease renewer never raises out of the slice.
"""

import asyncio
import time
import uuid
from typing import Any

import pytest

from app.core.config import get_settings
from app.modules.threat_intel.catalog import ProviderLimits
from app.modules.threat_intel.providers.base import IocRef, IocType, ProviderName
from app.workers import enrich


def _slice() -> enrich._Slice:
    deps = enrich.Deps(
        settings=get_settings(),
        limiter=None,  # type: ignore[arg-type]  # never reached: _process is replaced
        private_keys={},
    )
    return enrich._Slice(deps, uuid.uuid4(), uuid.uuid4(), "token", time.time() + 600)


def _lane(n: int = 3) -> enrich._Lane:
    lane = enrich._Lane(provider=ProviderName.MISP, config=None, limits=ProviderLimits(60, None))
    for seq in range(n):
        ioc = IocRef.of(IocType.DOMAIN, f"d{seq}.acme-corp.net")
        lane.items.append(enrich._Item(ProviderName.MISP, ioc, seq))
    return lane


async def test_an_item_failure_is_recorded_and_the_lane_goes_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work, lane = _slice(), _lane()
    recorded: list[tuple[int, str | None]] = []

    async def boom(_lane: Any, _item: Any) -> bool:
        raise TimeoutError("pool exhausted")

    async def record(item: Any, result: Any, latency: int) -> None:
        recorded.append((item.seq, result.error_code))

    monkeypatch.setattr(work, "_process", boom)
    monkeypatch.setattr(work, "_record", record)
    await work._lane_worker(lane)
    assert recorded == [(0, "internal_error"), (1, "internal_error"), (2, "internal_error")]
    assert not work.halted and not lane.items


async def test_a_failure_that_cannot_be_recorded_halts_the_slice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work, lane = _slice(), _lane()

    async def boom(_lane: Any, _item: Any) -> bool:
        raise RuntimeError("db down")

    monkeypatch.setattr(work, "_process", boom)
    monkeypatch.setattr(work, "_record", boom)
    await work._lane_worker(lane)
    assert work.halted
    assert [i.seq for i in lane.items] == [1, 2]  # still pending for a later slice


async def test_a_raising_lane_cancels_its_siblings(monkeypatch: pytest.MonkeyPatch) -> None:
    work = _slice()
    bad, good = _lane(1), _lane(1)
    cancelled = asyncio.Event()

    async def run_lane(lane: Any) -> None:
        if lane is bad:
            await asyncio.sleep(0)
            raise RuntimeError("lane bug")
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(work, "_run_lane", run_lane)
    async with asyncio.timeout(5):
        await work.run_lanes([bad, good])
    assert cancelled.is_set() and work.halted


async def test_the_lease_renewer_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    work = _slice()

    def broken_session(*_: Any) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(enrich, "LEASE_RENEW_S", 0.0)
    monkeypatch.setattr(enrich, "tenant_session", broken_session)
    async with asyncio.timeout(5):
        await work.renew_forever()  # returns (stops renewing) instead of raising
    assert not work.lease_lost
