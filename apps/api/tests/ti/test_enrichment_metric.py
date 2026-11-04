"""Metric "IOC enrichment success" (M4 phase 7, RT24): resilience under synthetic faults.

600 lookups (100 per real adapter) run through the real enrich worker slices, broker limiter,
retries and resume logic, over fixture-backed transports with seeded faults and a virtual
clock (see `metric_harness`). Floors: success >= 0.95 per provider, and no ineligible value
ever reaches a transport. A second pass measures the cache.

Run it with `scripts/ti_eval.py` (prints the table), or:
`docker compose --profile test run --rm api-test uv run pytest -q -s -m metric tests/ti`.
"""

import asyncio
import time

import pytest

from app.workers import enrich
from tests.ti.metric_harness import LOOKUPS_PER_PROVIDER, PROVIDERS, Simulation, render

BEGIN = "=== TI METRIC BEGIN ==="
END = "=== TI METRIC END ==="
SUCCESS_FLOOR = 0.95
REAL_TIMEOUT_S = 900


@pytest.mark.metric
async def test_ioc_enrichment_success(monkeypatch: pytest.MonkeyPatch) -> None:
    started = time.perf_counter()
    sim = await Simulation.create()
    monkeypatch.setattr(enrich, "time", sim.clock.module())
    async with asyncio.timeout(REAL_TIMEOUT_S), sim.running():
        await sim.run_pass(1)
        await sim.run_pass(2)
    first, second = await sim.stats(1), await sim.stats(2)
    table = render(sim, first, second)
    runtime = time.perf_counter() - started
    print(f"\n{BEGIN}\n{table}\n- Real runtime: {runtime:.0f} s.\n{END}")

    assert sim.violations == []
    for provider in PROVIDERS:
        one, two = first[provider.value], second[provider.value]
        assert one.planned == two.planned == LOOKUPS_PER_PROVIDER, provider
        assert one.cached == 0 and one.reached > 0, provider
        assert one.success >= SUCCESS_FLOOR, (provider, one.success)
        # Every pass-1 ok / not_found answer is served from the cache on the immediate repeat;
        # errors are never cached.
        assert two.cached == one.ok + one.not_found, provider
