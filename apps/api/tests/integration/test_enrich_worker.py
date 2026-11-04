"""The enrich worker's time-sliced run loop, in process (M4 phase 2).

Each test plans a run through `runs.create_run`, seals the key through the real `seal()`, and
runs `handle_enrich` with the real `mock` adapter over a MockTransport (`SafeTransport`, which
asserts that every IOC reaching it is eligible). The broker limiter is real (test db, `test.`
prefix); re-publishing is captured instead of sent.
"""

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import func, select, update

from app.core.config import Settings, get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.threat_intel import runs
from app.modules.threat_intel.messages import TiRunMessage
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.ratelimit import Limiter, broker_redis
from app.workers import enrich, reaper
from tests.integration.seed import Tenant, seed_tenant
from tests.ti_helpers import (
    SENTINEL_KEY,
    MockSink,
    SafeTransport,
    SealKeys,
    assert_key_absent,
    new_seal_keys,
    seal_config,
)


@dataclass
class World:
    t: Tenant
    keys: SealKeys
    sink: MockSink
    transport: SafeTransport
    deps: enrich.Deps
    published: list[TiRunMessage] = field(default_factory=list)

    async def run(self, *values: str | runs.LookupValue) -> uuid.UUID:
        async with tenant_session(self.t.org_id, self.t.owner_id) as s:
            created = await runs.create_run(
                s,
                self.t.org_id,
                "manual",
                values=list(values),
                providers=["mock"],
                requested_by=self.t.owner_id,
            )
        assert created.run_id is not None
        return created.run_id

    async def slice(self, run_id: uuid.UUID) -> None:
        await enrich.handle_enrich({"run_id": str(run_id), "org_id": str(self.t.org_id)}, self.deps)

    async def state(self, run_id: uuid.UUID) -> tuple[str, str, dict[str, Any]]:
        async with tenant_session(self.t.org_id, self.t.owner_id) as s:
            run = await s.get(TiEnrichmentRun, run_id)
            index = await s.get(TiRunIndex, run_id)
            assert run is not None and index is not None
            return run.status, index.status, run.summary

    async def items(self, run_id: uuid.UUID) -> dict[str, tuple[str, str | None, uuid.UUID | None]]:
        async with tenant_session(self.t.org_id, self.t.owner_id) as s:
            rows = await s.execute(
                select(
                    TiRunItem.value_norm, TiRunItem.state, TiRunItem.reason, TiRunItem.result_id
                ).where(TiRunItem.run_id == run_id)
            )
            return {value: (state, reason, rid) for value, state, reason, rid in rows}

    async def results(self, run_id: uuid.UUID) -> dict[str, TiResult]:
        async with tenant_session(self.t.org_id, self.t.owner_id) as s:
            rows = (await s.scalars(select(TiResult).where(TiResult.run_id == run_id))).all()
            return {row.value_norm: row for row in rows}

    async def index(self, run_id: uuid.UUID) -> TiRunIndex:
        async with tenant_session(None, None) as s:
            index = await s.get(TiRunIndex, run_id)
            assert index is not None
            return index


def _deps(
    settings: Settings, keys: SealKeys, transport: SafeTransport, published: list[TiRunMessage]
) -> enrich.Deps:
    async def publish(message: TiRunMessage) -> None:
        published.append(message)

    async def no_sleep(_: float) -> None:
        return None

    return enrich.Deps(
        settings=settings,
        limiter=Limiter(broker_redis(settings.broker_url), settings.queue_prefix),
        private_keys=keys.private_keys,
        publish=publish,
        transport=transport,
        sleep=no_sleep,
        jitter=lambda: 0.0,
    )


async def _world(
    *,
    settings: Settings | None = None,
    key: str = SENTINEL_KEY,
    sink: MockSink | None = None,
    **config: Any,
) -> World:
    t = await seed_tenant(f"org{uuid.uuid4().hex[:8]}")
    keys = new_seal_keys()
    await seal_config(t, keys, key=key, **config)
    sink = sink or MockSink()
    transport = SafeTransport(sink)
    published: list[TiRunMessage] = []
    # The test key pair is the active one (else the worker lazily re-seals under dev-1).
    settings = (settings or get_settings()).model_copy(
        update={"ti_seal_active_kid": keys.kid, "ti_seal_public_keys": {keys.kid: keys.public_b64}}
    )
    deps = _deps(settings, keys, transport, published)
    return World(t, keys, sink, transport, deps, published)


@pytest_asyncio.fixture(loop_scope="session")
async def world() -> AsyncIterator[World]:
    w = await _world()
    yield w
    await w.deps.limiter._redis.aclose()  # noqa: SLF001


async def test_hit_and_not_found_complete(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    run_id = await world.run("hit.example.com", "notfound.example.com", "8.8.8.8")
    await world.slice(run_id)
    status, index_status, summary = await world.state(run_id)
    assert (status, index_status) == ("completed", "completed")
    items = await world.items(run_id)
    assert {v: s for v, (s, _, _) in items.items()} == {
        "hit.example.com": "done",
        "notfound.example.com": "done",
        "8.8.8.8": "done",
    }
    results = await world.results(run_id)
    hit = results["hit.example.com"]
    assert (hit.status, hit.found, hit.score, hit.score_scale) == ("ok", True, 3.0, "mock_hits")
    assert hit.summary == {
        "provider": "mock",
        "behaviour": "hit",
        "label": "test-hit",
        "hits": 3,
        "tags": ["mock"],
    }
    assert hit.expires_at is not None and hit.latency_ms is not None
    assert items["hit.example.com"][2] == hit.id
    assert results["notfound.example.com"].status == "not_found"
    mock = summary["providers"]["mock"]
    assert (mock["planned"], mock["ok"], mock["not_found"]) == (3, 1, 2)
    assert mock["latency_p50_ms"] is not None and summary["latency_p95_ms"] is not None
    index = await world.index(run_id)
    assert index.lease_until is None and index.lease_owner is None
    # The key travelled only in the auth header; never in rows, logs or messages.
    assert all(r.headers["X-Mock-Key"] == SENTINEL_KEY for r in world.transport.requests)
    assert SENTINEL_KEY not in caplog.text
    await assert_key_absent(world.t, SENTINEL_KEY)


async def test_redelivery_and_concurrent_duplicates_make_no_extra_calls(world: World) -> None:
    run_id = await world.run("hit.example.com", "notfound.example.com", "1.1.1.1", "9.9.9.9")
    await asyncio.gather(*(world.slice(run_id) for _ in range(4)))
    assert (await world.state(run_id))[0] == "completed"
    calls = dict(world.sink.calls)
    assert calls == {"hit.example.com": 1, "notfound.example.com": 1, "1.1.1.1": 1, "9.9.9.9": 1}
    await world.slice(run_id)  # redelivered after the end
    assert dict(world.sink.calls) == calls
    assert len(await world.results(run_id)) == 4


async def test_org_mismatch_and_bad_messages_are_dropped(world: World) -> None:
    other = await seed_tenant(f"org{uuid.uuid4().hex[:8]}")
    run_id = await world.run("hit.example.com")
    for message in (
        {"run_id": str(run_id), "org_id": str(other.org_id)},
        {"run_id": str(uuid.uuid4()), "org_id": str(world.t.org_id)},
        {"run_id": "not-a-uuid", "org_id": str(world.t.org_id)},
        {"run_id": str(run_id), "org_id": str(world.t.org_id), "values": ["x"]},
    ):
        await enrich.handle_enrich(message, world.deps)
    assert (await world.state(run_id))[:2] == ("queued", "queued")
    assert not world.sink.calls


async def test_cache_hit_on_repeat(world: World) -> None:
    first = await world.run("hit.example.com", "err500.example.com")
    await world.slice(first)
    assert (await world.state(first))[0] == "partial"  # the error item
    second = await world.run("hit.example.com", "err500.example.com")
    await world.slice(second)
    items = await world.items(second)
    hit_row = (await world.results(first))["hit.example.com"]
    assert items["hit.example.com"] == ("cached", None, hit_row.id)
    assert items["err500.example.com"][0] == "done"  # errors are never served from the cache
    assert world.sink.calls["hit.example.com"] == 1
    assert world.sink.calls["err500.example.com"] == 6  # 3 attempts per run
    summary = (await world.state(second))[2]
    assert summary["providers"]["mock"]["cached"] == 1
    third = await world.run("hit.example.com")
    await world.slice(third)
    assert (await world.state(third))[0] == "completed"  # every item cached


@pytest.mark.parametrize(
    ("value", "code", "calls"),
    [
        ("err500.example.com", "http_5xx", 3),
        ("slow.example.com", "timeout", 3),
        ("big.example.com", "oversize", 1),
        ("redirect.example.com", "redirect", 1),
        ("badjson.example.com", "bad_json", 1),
        ("deep.example.com", "bad_json", 1),
    ],
)
async def test_provider_faults_become_error_rows(
    world: World, value: str, code: str, calls: int
) -> None:
    run_id = await world.run(value, "hit.example.com")
    await world.slice(run_id)
    status, _, summary = await world.state(run_id)
    assert status == "partial"
    row = (await world.results(run_id))[value]
    assert (row.status, row.error_code, row.expires_at, row.summary) == ("error", code, None, None)
    assert world.sink.calls[value] == calls
    assert summary["providers"]["mock"]["error"] == 1


async def test_slice_budget_republishes_to_the_tail() -> None:
    settings = get_settings().model_copy(update={"ti_slice_s": 1})
    w = await _world(settings=settings, sink=MockSink(delay_s=0.3))
    values = [f"{n}.{n}.{n}.{n}" for n in range(11, 31)]
    run_id = await w.run(*values)
    await w.slice(run_id)
    status, index_status, _ = await w.state(run_id)
    assert (status, index_status) == ("running", "running")
    assert w.published == [TiRunMessage(run_id=run_id, org_id=w.t.org_id)]
    index = await w.index(run_id)
    assert index.lease_owner is None and index.dispatched_at is not None
    done = sum(1 for s, _, _ in (await w.items(run_id)).values() if s == "done")
    assert 0 < done < len(values)
    while (await w.state(run_id))[0] != "completed":
        await w.slice(run_id)
    assert sum(w.sink.calls.values()) == len(values)


async def test_token_far_away_waits_and_resumes() -> None:
    w = await _world(limits={"per_minute": 1})
    run_id = await w.run("hit.example.com", "notfound.example.com")
    await w.slice(run_id)
    status, index_status, _ = await w.state(run_id)
    assert (status, index_status) == ("waiting", "waiting")
    index = await w.index(run_id)
    assert index.resume_at is not None and index.lease_owner is None
    assert w.published == []
    # Not due yet: ti.resume leaves it alone.
    assert await enrich.handle_resume({}, w.deps) == 0
    async with tenant_session(None, None) as s:
        await s.execute(
            update(TiRunIndex)
            .where(TiRunIndex.run_id == run_id)
            .values(
                resume_at=func.now() - timedelta(seconds=1),
                dispatched_at=func.now() - timedelta(seconds=10),
            )
        )
    assert await enrich.handle_resume({}, w.deps) == 1
    assert w.published == [TiRunMessage(run_id=run_id, org_id=w.t.org_id)]
    assert await enrich.handle_resume({}, w.deps) == 0  # sent once, then throttled


async def test_resume_does_not_resend_recent_queued_runs(world: World) -> None:
    run_id = await world.run("hit.example.com")
    assert await enrich.handle_resume({}, world.deps) == 0  # dispatched just now
    async with tenant_session(None, None) as s:
        await s.execute(
            update(TiRunIndex)
            .where(TiRunIndex.run_id == run_id)
            .values(dispatched_at=func.now() - timedelta(minutes=3))
        )
    assert await enrich.handle_resume({}, world.deps) == 1
    assert await enrich.handle_resume({}, world.deps) == 0
    # A held lease is never re-sent either (a slice is running it).
    async with tenant_session(None, None) as s:
        await s.execute(
            update(TiRunIndex)
            .where(TiRunIndex.run_id == run_id)
            .values(
                dispatched_at=func.now() - timedelta(minutes=3),
                lease_until=func.now() + timedelta(seconds=30),
                lease_owner="other",
            )
        )
    assert await enrich.handle_resume({}, world.deps) == 0


async def _expire_deadline(run_id: uuid.UUID, org_id: uuid.UUID, ago: timedelta) -> None:
    async with tenant_session(org_id, None) as s:
        await s.execute(
            update(TiEnrichmentRun)
            .where(TiEnrichmentRun.id == run_id)
            .values(deadline_at=func.now() - ago)
        )
        await s.execute(
            update(TiRunIndex)
            .where(TiRunIndex.run_id == run_id)
            .values(deadline_at=func.now() - ago)
        )


async def test_deadline_ends_partial(world: World) -> None:
    run_id = await world.run("hit.example.com", "ratelimit.example.com")
    await world.slice(run_id)  # 429 (Retry-After 600) -> waiting
    assert (await world.state(run_id))[0] == "waiting"
    await _expire_deadline(run_id, world.t.org_id, timedelta(seconds=1))
    await world.slice(run_id)
    status, index_status, summary = await world.state(run_id)
    assert (status, index_status) == ("partial", "partial")
    items = await world.items(run_id)
    assert items["ratelimit.example.com"][:2] == ("abandoned", "deadline")
    assert summary["providers"]["mock"]["abandoned_deadline"] == 1
    assert summary["ended_by"] == "deadline"
    assert "ratelimit.example.com" not in await world.results(run_id)  # no row for 429s


async def test_deadline_with_nothing_attempted_fails(world: World) -> None:
    run_id = await world.run("hit.example.com")
    await _expire_deadline(run_id, world.t.org_id, timedelta(seconds=1))
    await world.slice(run_id)
    assert (await world.state(run_id))[:2] == ("failed", "failed")
    assert not world.sink.calls


async def test_429_past_the_deadline_abandons_rate_limited(world: World) -> None:
    run_id = await world.run("hit.example.com", "ratelimit-long.example.com")
    await world.slice(run_id)  # Retry-After 3600 > the 30-minute deadline
    status, _, summary = await world.state(run_id)
    assert status == "partial"
    assert (await world.items(run_id))["ratelimit-long.example.com"][:2] == (
        "abandoned",
        "rate_limited",
    )
    assert summary["providers"]["mock"]["abandoned_rate_limited"] == 1


async def test_fallback_reaper() -> None:
    w = await _world()
    stuck = await w.run("hit.example.com")
    recent = await w.run("notfound.example.com")
    # A lease that expired long ago (worker died mid-slice).
    async with tenant_session(None, None) as s:
        await s.execute(
            update(TiRunIndex)
            .where(TiRunIndex.run_id == stuck)
            .values(lease_until=func.now() - timedelta(minutes=20), lease_owner="dead")
        )
    await _expire_deadline(stuck, w.t.org_id, timedelta(minutes=11))
    await _expire_deadline(recent, w.t.org_id, timedelta(minutes=5))  # within the grace
    assert await reaper.reap_ti_runs() == 1
    assert (await w.state(stuck))[:2] == ("failed", "failed")
    assert (await w.items(stuck))["hit.example.com"][:2] == ("abandoned", "deadline")
    assert (await w.state(recent))[0] == "queued"
    assert await w.results(stuck) == {}  # the reaper writes no result rows
    async with tenant_session(w.t.org_id, w.t.owner_id) as s:
        actions = (await s.scalars(select(AuditLog.action))).all()
    assert actions == ["ti.run_deadline"]
    # The worker arriving afterwards is a no-op.
    await w.slice(stuck)
    assert not w.sink.calls
    assert await reaper.reap_ti_runs() == 0


async def test_401_with_failing_verify_marks_invalid() -> None:
    w = await _world(key="WRONG-KEY-123456", verify_status="valid")
    run_id = await w.run("hit.example.com", "notfound.example.com", "8.8.8.8")
    await w.slice(run_id)
    status, _, summary = await w.state(run_id)
    assert status == "partial"
    states = sorted(s for s, _, _ in (await w.items(run_id)).values())
    results = await w.results(run_id)
    assert any(r.status == "auth_failed" and r.error_code == "auth_401" for r in results.values())
    assert states.count("abandoned") == 3 - len(results)
    assert w.sink.calls["verify"] == 1
    async with tenant_session(w.t.org_id, w.t.owner_id) as s:
        config = (await s.scalars(select(TiProviderConfig))).one()
        assert (config.verify_status, config.last_error_code) == ("invalid", "auth")
        audit = (await s.scalars(select(AuditLog))).one()
        assert (audit.action, audit.actor_id) == ("integration.verify_failed", None)
    assert summary["providers"]["mock"]["auth_failed"] == len(results)


async def test_403_with_passing_verify_stays_valid() -> None:
    w = await _world(sink=MockSink(lookup_status=403), verify_status="valid")
    run_id = await w.run("hit.example.com", "notfound.example.com")
    await w.slice(run_id)
    results = await w.results(run_id)
    assert {r.status for r in results.values()} == {"auth_failed"}
    assert {r.error_code for r in results.values()} == {"auth_403"}
    async with tenant_session(w.t.org_id, w.t.owner_id) as s:
        config = (await s.scalars(select(TiProviderConfig))).one()
        assert config.verify_status == "valid"
    assert w.sink.calls["verify"] == 1


async def test_daily_quota_abandons_quota_exhausted() -> None:
    w = await _world(limits={"per_day": 1})
    run_id = await w.run("hit.example.com", "notfound.example.com", "8.8.8.8")
    await w.slice(run_id)
    status, _, summary = await w.state(run_id)
    assert status == "partial"
    states = sorted((s, r) for s, r, _ in (await w.items(run_id)).values())
    assert states == [("abandoned", "quota_exhausted")] * 2 + [("done", None)]
    assert summary["providers"]["mock"]["abandoned_quota_exhausted"] == 2
    cool = w.deps.limiter.keys(enrich.ProviderName.MOCK, w.t.org_id)[2]
    assert await w.deps.limiter._redis.pttl(cool) > 0  # noqa: SLF001  cooldown to midnight


async def test_limiter_outage_fails_closed() -> None:
    w = await _world()
    w.deps.limiter = Limiter(broker_redis("redis://127.0.0.1:1/1"), "test.")
    run_id = await w.run("hit.example.com")
    await w.slice(run_id)
    assert (await w.state(run_id))[:2] == ("waiting", "waiting")
    index = await w.index(run_id)
    assert index.resume_at is not None
    assert not w.sink.calls


async def test_lazy_reseal_under_the_active_kid() -> None:
    old = new_seal_keys("old-1")
    new = new_seal_keys("new-1")
    settings = get_settings().model_copy(
        update={"ti_seal_active_kid": "new-1", "ti_seal_public_keys": {"new-1": new.public_b64}}
    )
    t = await seed_tenant(f"org{uuid.uuid4().hex[:8]}")
    await seal_config(t, old)
    sink = MockSink()
    transport = SafeTransport(sink)
    published: list[TiRunMessage] = []
    deps = _deps(settings, old, transport, published)
    deps.private_keys = {**old.private_keys, **new.private_keys}
    w = World(t, old, sink, transport, deps, published)
    run_id = await w.run("hit.example.com")
    await w.slice(run_id)
    assert (await w.state(run_id))[0] == "completed"
    async with tenant_session(t.org_id, t.owner_id) as s:
        config = (await s.scalars(select(TiProviderConfig))).one()
        assert (config.key_kid, config.key_version) == ("new-1", 1)
    # The re-sealed key opens with the new kid only.
    deps.private_keys = new.private_keys
    second = await w.run("notfound.example.com")
    await w.slice(second)
    assert (await w.state(second))[0] == "completed"


async def test_disabled_provider_abandons_its_items(world: World) -> None:
    run_id = await world.run("hit.example.com")
    async with tenant_session(world.t.org_id, world.t.owner_id) as s:
        await s.execute(update(TiProviderConfig).values(enabled=False))
    await world.slice(run_id)
    assert (await world.state(run_id))[0] == "failed"
    assert (await world.items(run_id))["hit.example.com"][:2] == ("abandoned", "auth_failed")
    assert not world.sink.calls


async def test_verify_task(world: World) -> None:
    await enrich.handle_verify({"org_id": str(world.t.org_id), "provider": "mock"}, world.deps)
    async with tenant_session(world.t.org_id, world.t.owner_id) as s:
        config = (await s.scalars(select(TiProviderConfig))).one()
        assert (config.verify_status, config.last_error_code) == ("valid", None)
        assert config.verified_at is not None
        assert (await s.scalars(select(AuditLog.action))).all() == ["integration.verified"]
    # Unknown provider / no config / malformed: dropped.
    for message in (
        {"org_id": str(world.t.org_id), "provider": "nope"},
        {"org_id": str(uuid.uuid4()), "provider": "mock"},
        {"org_id": "x"},
    ):
        await enrich.handle_verify(message, world.deps)
    assert world.sink.calls["verify"] == 1
