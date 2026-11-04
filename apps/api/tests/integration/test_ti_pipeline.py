"""The real enrichment pipeline (M4 phase 2): API-side run creation (`runs.create_run` +
`runs.dispatch`) -> broker (`test.enrich`) -> `enrich-worker-test` (ACL user `enrich`, the dev
seal key pair, its own broker limiter) -> the `mock` adapter over the `egress` network ->
`ti-mock` -> `ti_results` rows.

No test beat runs, so the tests send `ti.resume` themselves. Values are made unique per test
(`hit-<uuid>.example.com`) because `ti-mock` keeps per-value state for `ratelimit-ra*`.
"""

import asyncio
import base64
import contextlib
import json
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

import pytest
import redis
from cyberlab_jobs import TI_ENRICH, TI_RESUME, TI_VERIFY, Queues
from sqlalchemy import func, select, update

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.threat_intel import runs, service_integrations
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.providers.base import ProviderName
from tests.integration.seed import Tenant, seed_tenant
from tests.ti_helpers import PublicSealKey, assert_key_absent, seal_config

MOCK_KEY = os.environ.get("TEST_TI_MOCK_EXPECTED_KEY", "cyberlab-ti-mock-key")
FINAL = ("completed", "partial", "failed")


def _send(task: str, message: dict[str, Any]) -> None:
    from app.workers.celery_app import celery_app  # broker client only

    celery_app.send_task(
        task, kwargs={"message": message}, queue=Queues(get_settings().queue_prefix).enrich
    )


async def _tenant(key: str = MOCK_KEY) -> Tenant:
    settings = get_settings()
    kid = settings.ti_seal_active_kid
    assert kid is not None
    t = await seed_tenant(f"org{uuid.uuid4().hex[:8]}")
    # Sealed with the API's public key only; enrich-worker-test holds the private key.
    await seal_config(t, PublicSealKey(kid, settings.ti_seal_public_keys[kid]), key=key)
    return t


async def _start(t: Tenant, *values: str) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        created = await runs.create_run(
            s,
            t.org_id,
            "manual",
            values=list(values),
            providers=["mock"],
            requested_by=t.owner_id,
        )
    assert created.run_id is not None
    assert await runs.dispatch(created.run_id, t.org_id)
    return created.run_id


async def _status(t: Tenant, run_id: uuid.UUID) -> str:
    async with tenant_session(t.org_id, t.owner_id) as s:
        run = await s.get(TiEnrichmentRun, run_id)
        assert run is not None
        return run.status


async def _until(check: Callable[[], Awaitable[bool]], timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if await check():
            return
        await asyncio.sleep(0.25)
    raise AssertionError("enrich-worker-test did not get there in time")


async def _final(t: Tenant, run_id: uuid.UUID, timeout_s: float = 60) -> str:
    async def done() -> bool:
        return await _status(t, run_id) in FINAL

    await _until(done, timeout_s)
    return await _status(t, run_id)


async def _items(t: Tenant, run_id: uuid.UUID) -> dict[str, tuple[str, str | None]]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = await s.execute(
            select(TiRunItem.value_norm, TiRunItem.state, TiRunItem.reason).where(
                TiRunItem.run_id == run_id
            )
        )
        return {value: (state, reason) for value, state, reason in rows}


async def _results(t: Tenant, run_id: uuid.UUID) -> dict[str, TiResult]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = (await s.scalars(select(TiResult).where(TiResult.run_id == run_id))).all()
        return {row.value_norm: row for row in rows}


def _name(label: str) -> str:
    return f"{label}-{uuid.uuid4().hex[:12]}.example.com"


async def test_hit_not_found_outage_and_cache() -> None:
    t = await _tenant()
    hit, missing, outage = _name("hit"), _name("notfound"), _name("err500")
    run_id = await _start(t, hit, missing, outage)
    assert await _final(t, run_id) == "partial"
    results = await _results(t, run_id)
    assert (results[hit].status, results[hit].found) == ("ok", True)
    assert results[hit].summary == {
        "provider": "mock",
        "behaviour": "hit",
        "label": "test-hit",
        "hits": 3,
        "tags": ["mock"],
    }
    assert results[missing].status == "not_found"
    assert (results[outage].status, results[outage].error_code) == ("error", "http_5xx")

    # A repeat inside the TTL is served from the org's cache (the error is asked again).
    again = await _start(t, hit, missing)
    assert await _final(t, again) == "completed"
    assert await _items(t, again) == {hit: ("cached", None), missing: ("cached", None)}
    assert await _results(t, again) == {}
    async with tenant_session(t.org_id, t.owner_id) as s:
        run = await s.get(TiEnrichmentRun, again)
        assert run is not None and run.summary["providers"]["mock"]["cached"] == 2
    await assert_key_absent(t, MOCK_KEY)


async def test_429_waits_then_resumes() -> None:
    t = await _tenant()
    limited, hit = _name("ratelimit-ra"), _name("hit")
    run_id = await _start(t, limited, hit)

    async def waiting() -> bool:
        return await _status(t, run_id) == "waiting"

    await _until(waiting)  # Retry-After: 5 -> waiting, no Celery ETA
    async with tenant_session(None, None) as s:
        index = await s.get(TiRunIndex, run_id)
        assert index is not None and index.resume_at is not None and index.lease_owner is None
        resume_in = (index.resume_at.timestamp() - time.time()) + 0.5
    await asyncio.sleep(max(0.0, resume_in))
    _send(TI_RESUME, {})
    assert await _final(t, run_id) == "completed"
    results = await _results(t, run_id)
    assert results[limited].status == "ok"
    assert results[limited].summary is not None
    assert results[limited].summary["behaviour"] == "after-retry"
    await assert_key_absent(t, MOCK_KEY)


async def test_deadline_ends_partial() -> None:
    t = await _tenant()
    limited, hit = _name("ratelimit"), _name("hit")
    run_id = await _start(t, limited, hit)

    async def hit_done_and_waiting() -> bool:
        items = await _items(t, run_id)
        return items[hit][0] == "done" and await _status(t, run_id) == "waiting"

    await _until(hit_done_and_waiting)
    async with tenant_session(t.org_id, t.owner_id) as s:
        past = func.now() - timedelta(seconds=1)
        await s.execute(
            update(TiEnrichmentRun).where(TiEnrichmentRun.id == run_id).values(deadline_at=past)
        )
        await s.execute(
            update(TiRunIndex).where(TiRunIndex.run_id == run_id).values(deadline_at=past)
        )
    _send(TI_ENRICH, {"run_id": str(run_id), "org_id": str(t.org_id)})
    assert await _final(t, run_id) == "partial"
    assert (await _items(t, run_id))[limited] == ("abandoned", "deadline")
    assert limited not in await _results(t, run_id)  # 429s are item states, never rows


async def test_wrong_key_is_auth_failed_and_invalid() -> None:
    t = await _tenant(key="definitely-not-the-mock-key")
    hit = _name("hit")
    run_id = await _start(t, hit)
    assert await _final(t, run_id) == "partial"
    result = (await _results(t, run_id))[hit]
    assert (result.status, result.error_code, result.expires_at) == (
        "auth_failed",
        "auth_401",
        None,
    )
    async with tenant_session(t.org_id, t.owner_id) as s:
        config = (await s.scalars(select(TiProviderConfig))).one()
        assert (config.verify_status, config.last_error_code) == ("invalid", "auth")
    await assert_key_absent(t, "definitely-not-the-mock-key")


async def test_verify_task() -> None:
    t = await _tenant()
    _send(TI_VERIFY, {"org_id": str(t.org_id), "provider": "mock"})

    async def verified() -> bool:
        async with tenant_session(t.org_id, t.owner_id) as s:
            config = (await s.scalars(select(TiProviderConfig))).one()
            return config.verify_status == "valid"

    await _until(verified, 45)
    await assert_key_absent(t, MOCK_KEY)


# --- key-leak suite (phase 7) ------------------------------------------------------------


async def test_a_401_that_echoes_the_key_is_stored_without_it() -> None:
    """`echo401*`: ti-mock answers 401 with the (valid) key it received in the body. The
    worker records `auth_failed`, re-verifies (still valid) and keeps the key out of every
    row; `scripts/check-ti-key-leak.mjs` scans the worker logs for it afterwards."""
    t = await _tenant()
    echo, hit = _name("echo401"), _name("hit")
    run_id = await _start(t, echo, hit)
    assert await _final(t, run_id) == "partial"
    results = await _results(t, run_id)
    assert (results[echo].status, results[echo].error_code) == ("auth_failed", "auth_401")
    assert results[echo].summary is None
    async with tenant_session(t.org_id, t.owner_id) as s:
        config = (await s.scalars(select(TiProviderConfig))).one()
        # The re-check passed (the key itself is fine): never marked invalid.
        assert config.verify_status != "invalid"
    await assert_key_absent(t, MOCK_KEY)


def _broker_dump(client: Any, keys: list[str]) -> list[bytes]:
    """Every value under `keys`, read as the api broker user (inspection is denied to the
    enrich user itself). Hashes, lists, sets and sorted sets are read whole."""
    found: list[bytes] = []
    for key in keys:
        kind = client.type(key)
        if kind == b"string":
            found.append(client.get(key))
        elif kind == b"list":
            found.extend(client.lrange(key, 0, -1))
        elif kind == b"hash":
            for field, value in client.hgetall(key).items():
                found.extend((field, value))
        elif kind == b"set":
            found.extend(client.smembers(key))
        elif kind == b"zset":
            found.extend(member for member, _ in client.zrange(key, 0, -1, withscores=True))
    return found


def _decoded(raw: bytes) -> str:
    """A kombu envelope with its (base64) body decoded, as text."""
    text = raw.decode(errors="replace")
    try:
        envelope = json.loads(text)
    except ValueError:
        return text
    body = envelope.get("body") if isinstance(envelope, dict) else None
    if isinstance(body, str):
        with contextlib.suppress(ValueError):
            text += base64.b64decode(body).decode(errors="replace")
    return text


async def test_broker_holds_no_key_while_a_run_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    """The broker only ever carries ids: while a run waits on a 429, every enrich key the
    worker and the API use (queue, unacked bookkeeping, limiter state, verify dedupe) and a
    copy of each published message (`ti.enrich`, `ti.verify`, sent through the real
    publish code to a probe queue nobody consumes) is free of the key."""
    t = await _tenant()
    limited = _name("ratelimit-ra")
    run_id = await _start(t, limited, _name("hit"))
    _send(TI_VERIFY, {"org_id": str(t.org_id), "provider": "mock"})

    async def waiting() -> bool:
        return await _status(t, run_id) == "waiting"

    await _until(waiting)
    prefix = get_settings().queue_prefix
    enrich_q = Queues(prefix).enrich
    probe = f"{enrich_q}.leak-probe-{uuid.uuid4().hex[:8]}"

    class ProbeQueues:
        def __init__(self, _: str) -> None:
            self.enrich = probe

    monkeypatch.setattr(runs, "Queues", ProbeQueues)
    monkeypatch.setattr(service_integrations, "Queues", ProbeQueues)
    assert await runs.dispatch(run_id, t.org_id)
    assert await service_integrations.send_verify(t.org_id, ProviderName.MOCK)

    client = redis.Redis.from_url(os.environ["TEST_BROKER_API_URL"], socket_timeout=3)
    org = str(t.org_id)
    today = time.strftime("%Y%m%d", time.gmtime())
    keys = [
        enrich_q,
        f"{enrich_q}.unacked",
        f"{enrich_q}.unacked_index",
        f"_kombu.binding.{enrich_q}",
        probe,
        f"_kombu.binding.{probe}",
        f"{enrich_q}.ti:rl:mock:{org}",
        f"{enrich_q}.ti:day:mock:{org}:{today}",
        f"{enrich_q}.ti:cool:mock:{org}",
        f"{enrich_q}.ti:strikes:mock:{org}",
        f"{enrich_q}.ti:verify:{org}:mock:1",
    ]
    try:
        values = _broker_dump(client, keys)
        published = client.lrange(probe, 0, -1)
    finally:
        client.delete(probe, f"_kombu.binding.{probe}")
        client.close()
    assert len(published) == 2  # the probe really captured both messages
    texts = [_decoded(v) for v in values]
    bodies = [_decoded(m) for m in published]
    assert any(str(run_id) in b for b in bodies) and all(org in b for b in bodies)
    for text in texts + bodies:
        assert MOCK_KEY not in text
        assert MOCK_KEY.encode().hex() not in text
        assert base64.b64encode(MOCK_KEY.encode()).decode() not in text
    # The run still finishes once resumed.
    async with tenant_session(None, None) as s:
        index = await s.get(TiRunIndex, run_id)
        assert index is not None and index.resume_at is not None
        resume_in = (index.resume_at.timestamp() - time.time()) + 0.5
    await asyncio.sleep(max(0.0, resume_in))
    _send(TI_RESUME, {})
    assert await _final(t, run_id) == "completed"
    await assert_key_absent(t, MOCK_KEY)
