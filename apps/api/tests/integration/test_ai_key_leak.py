"""Key-leak suite of the AI analyst (M5 phase 11): an AI provider key set through the API
must be absent from every API response that carries AI data, `audit_logs.details`, the AI
tables, the broker while a run waits, and the reprs of providers and errors.

The key is the one `ai-mock` expects (`TEST_AI_MOCK_EXPECTED_KEY`), so the real worker
unseals it, sends it, and `ai-mock:401` echoes it back in a 401 body. `scripts/check-ai-key-
leak.mjs` runs this module with a fresh random key and then scans every container's log for
it (tests cannot read `docker logs`). Default test lane only (the worker serves it).
"""

import asyncio
import base64
import time
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.ai.budget import Budget
from app.modules.ai.contracts import ProviderError, ProviderErrorKind
from app.modules.ai.providers.registry import build_provider
from app.modules.ai.ratelimit import AiLimiter
from tests.ai_api_helpers import API
from tests.analysis_helpers import SentJobs
from tests.integration.test_ai_pipeline import (
    MOCK_KEY,
    _detail,
    _pcap_job,
    _ready,
    _run,
    _settle,
    records,
)
from tests.integration.test_ai_pipeline import pytestmark as pipeline_mark
from tests.integration.test_ai_pipeline import sent as sent  # noqa: F401 (fixture)

pytestmark = pipeline_mark
TABLES = (
    "ai_runs",
    "ai_run_index",
    "ai_run_inputs",
    "ai_context_refs",
    "ai_outputs",
    "ai_citations",
    "ai_provider_configs",
    "ai_org_settings",
)


def needles(key: str = MOCK_KEY) -> list[str]:
    raw = key.encode()
    return [key, base64.b64encode(raw).decode(), raw.hex()]


def assert_absent(where: str, value: str) -> None:
    """Fails naming the location only: the sentinel and the value are never echoed."""
    leaked = any(needle in value for needle in needles())
    assert not leaked, f"{where} contains the sentinel"


@pytest.fixture
def broker() -> Iterator[Redis]:
    yield Redis.from_url(get_settings().broker_url)


async def _broker_values(broker: Redis, org_id: uuid.UUID, run_ids: list[uuid.UUID]) -> str:
    """Everything the analyst keeps on the broker for this org (SCAN/KEYS are ACL-denied):
    the queue and its unacked bookkeeping, the limiter, budget and repair keys."""
    prefix = get_settings().queue_prefix
    queue = f"{prefix}analyst"
    limiter, budget = AiLimiter(broker, prefix), Budget(broker, prefix)
    out: list[Any] = [
        await broker.lrange(queue, 0, -1),  # type: ignore[misc]
        await broker.hgetall(f"{queue}.unacked"),  # type: ignore[misc]
        await broker.zrange(f"{queue}.unacked_index", 0, -1),
    ]
    for key in (*limiter.keys("mock", org_id), budget.day_key(org_id)):
        kind = (await broker.type(key)).decode()
        if kind == "string":
            out.append(await broker.get(key))
        elif kind == "hash":
            out.append(await broker.hgetall(key))  # type: ignore[misc]
    for run_id in run_ids:
        out.append(await broker.get(limiter.repair_key(run_id)))
        out.append(await broker.get(budget.tree_key(run_id)))
    return repr(out)


async def test_the_key_never_leaves_its_sealed_columns(sent: SentJobs, broker: Redis) -> None:
    reg = await _ready()
    job = await _pcap_job(reg, records())
    done = await _run(reg, task="summarize_pcap", job_id=str(job))
    assert (await _settle(reg, done))["status"] == "completed"
    # The mock answers 401 and echoes the key it received in the body; the inline key check
    # then finds the key valid, so the run ends as a provider error.
    echo_job = await _pcap_job(reg, records("ai-mock:401"))
    echoed = await _run(reg, task="summarize_pcap", job_id=str(echo_job))
    assert (await _settle(reg, echoed))["error_code"] == "provider_error"
    # A run parked on a rate limit: the broker holds its state meanwhile.
    wait_job = await _pcap_job(reg, records("ai-mock:429-nora"))
    waiting = await _run(reg, task="summarize_pcap", job_id=str(wait_job))
    deadline = time.monotonic() + 30
    while (await _detail(reg.client, reg.org_id, waiting))["status"] != "waiting":
        assert time.monotonic() < deadline
        await asyncio.sleep(0.5)
    runs = [done, echoed, waiting]
    assert_absent("the broker", await _broker_values(broker, reg.org_id, runs))

    # Every API response that carries AI data (the verify check re-sealed nothing).
    base = f"{API}/{reg.org_id}"
    urls = [
        f"{base}/ai/providers",
        f"{base}/ai/settings",
        f"{base}/ai/usage",
        f"{base}/ai/runs",
        f"{base}/ai/runs?job_id={job}",
        f"{base}/audit-logs?limit=100",
        f"{base}/investigations",
    ]
    for run_id in runs:
        urls += [
            f"{base}/ai/runs/{run_id}",
            f"{base}/ai/runs/{run_id}?pseudonyms=keep",
            f"{base}/ai/runs/{run_id}/context?reveal=true",
        ]
    for url in urls:
        response = await reg.client.get(url)
        assert response.status_code == 200, (url, response.status_code)
        assert_absent(url, response.text)
    providers = (await reg.client.get(f"{base}/ai/providers")).json()["items"]
    mock = next(p for p in providers if p["name"] == "mock")
    assert mock["configured"] is True and mock["key_last4"] == MOCK_KEY[-4:]

    # Audit details and every AI row of the org, as text.
    async with tenant_session(reg.org_id, None) as s:
        audit = (
            await s.execute(
                text("select details::text from audit_logs where organization_id = :org"),
                {"org": reg.org_id},
            )
        ).scalars()
        assert_absent("audit_logs.details", "\n".join(audit))
        for table in TABLES:
            rows = (
                await s.execute(
                    text(f"select t::text from {table} t where organization_id = :org"),  # noqa: S608
                    {"org": reg.org_id},
                )
            ).scalars()
            assert_absent(table, "\n".join(rows))


async def test_providers_and_errors_never_print_the_key() -> None:
    settings = get_settings()
    provider = build_provider(
        "mock", api_key=SecretStr(MOCK_KEY), model="mock-1", settings=settings, org_options={}
    )
    try:
        client = getattr(provider, "_client", None)
        for value in (repr(provider), str(provider), repr(client)):
            assert_absent("a provider or client repr", value)
        error = ProviderError(ProviderErrorKind.AUTH_FAILED, http_status=401, request_sent=True)
        assert_absent("an error repr", f"{error!r} {error}")
    finally:
        await provider.aclose()
