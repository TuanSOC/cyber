"""Key-leak suite (M4 phase 7): a sentinel key set through the API never comes back out.

- every API response: a crawl of every route of the IDOR enumerator (all TI routes and the
  generic routes that embed TI data, `iocs?include=enrichment` included) plus the routes
  outside an org, replayed by the owner after the key is stored;
- the error envelopes of failed PUTs;
- `audit_logs.details`, `ti_results.summary` and every other TI row (`assert_key_absent`);
- a MISP key sealed for one `base_url` is unusable once the stored URL is swapped in the
  database (the AAD binds it: RT1), so nothing is sent to the new host.

The real-worker parts (broker message bodies while a run waits, a 401 body echoing the key)
are in `test_ti_pipeline.py`; `scripts/check-ti-key-leak.mjs` scans the container logs.
"""

import base64
import uuid
from typing import Any

import pytest
from sqlalchemy import select, update

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.main import app
from app.modules.reports import dispatch
from app.modules.reports import signing as report_signing
from app.modules.threat_intel import runs
from app.modules.threat_intel.models import TiProviderConfig, TiRunItem
from app.modules.threat_intel.ratelimit import Limiter, broker_redis
from app.modules.threat_intel.unseal import UnsealError, open_sealed
from app.workers import enrich
from tests.factories import csrf, register
from tests.integration.seed import Tenant
from tests.security.test_idor_routes import ROUTE_CASES, _url, _victim
from tests.ti_api_helpers import API, add_result, capture_sends, put_integration
from tests.ti_helpers import SENTINEL_KEY, MockSink, SafeTransport, assert_key_absent, new_seal_keys

# Routes outside an org: none takes a resource id.
GLOBAL_GETS = (
    "/api/v1/auth/me",
    "/api/v1/orgs",
    "/api/v1/attack/techniques",
    "/api/v1/health",
    "/api/v1/report-signing-keys",  # M6: public keys only, unauthenticated
    "/internal/metrics",  # M7: outside /api, bearer token (404 while unset), no tenant data
)


@pytest.fixture(autouse=True)
def _no_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    capture_sends(monkeypatch, analyses=False)


async def _ciphertexts(org_id: uuid.UUID, provider: str = "mock") -> list[str]:
    async with tenant_session(org_id, None) as s:
        row = await s.scalar(select(TiProviderConfig).where(TiProviderConfig.provider == provider))
    assert row is not None and row.key_ct is not None
    return [row.key_ct.hex(), base64.b64encode(row.key_ct).decode()]


def _assert_clean(text: str, where: str, ciphertexts: list[str]) -> None:
    """Fails naming the location only: the sentinel, ciphertexts and text are never echoed."""
    leaked = any(n in text for n in (SENTINEL_KEY, SENTINEL_KEY[:12], "TEST-SENTINEL-KEY"))
    assert not leaked, f"{where} contains the sentinel"
    sealed = any(ct in text for ct in ciphertexts)
    assert not sealed, f"{where} contains a key ciphertext"


def test_the_crawl_covers_every_route_outside_an_org() -> None:
    """Org-scoped routes are pinned by the IDOR enumerator; this pins the others."""
    paths = app.openapi()["paths"]
    gets = {p for p, item in paths.items() if "{org_id}" not in p and "get" in item}
    assert gets == set(GLOBAL_GETS)


@pytest.fixture(autouse=True)
def _restore_report_stand_ins(monkeypatch: pytest.MonkeyPatch) -> None:
    """`_victim` (the IDOR enumerator's) installs the M6 report stand-ins by plain assignment
    (the signing key loader, the render dispatch, the published key); registering the real
    objects first restores them after each test, as `test_idor_routes._no_publish` does, so
    no stand-in outlives this module (it broke `unit/test_signing.py` later in the run)."""
    settings = get_settings()
    monkeypatch.setattr(settings, "report_signing_public_keys", settings.report_signing_public_keys)
    monkeypatch.setattr(report_signing, "_private_keys", report_signing._private_keys)
    monkeypatch.setattr(dispatch, "create_render", dispatch.create_render)
    monkeypatch.setattr(dispatch, "dispatch_render", dispatch.dispatch_render)


async def test_no_api_response_carries_the_key() -> None:
    owner, victim = await _victim()  # mock enabled with SENTINEL_KEY, a run and a result
    c = owner.client
    # The job's own IOC gets a TI answer too, so `iocs?include=enrichment` embeds TI data.
    await add_result(owner.org_id, victim.run_id, value_norm="example.com", complete_item=False)
    ciphertexts = await _ciphertexts(owner.org_id)
    seen: list[tuple[str, int]] = []

    async def call(method: str, url: str, request: dict[str, Any]) -> None:
        response = await c.request(
            method,
            url,
            json=request.get("json"),
            content=request.get("content"),
            params=request.get("params"),
            headers={**csrf(c), **request.get("headers", {})},
        )
        _assert_clean(response.text + str(response.headers), f"{method} {url}", ciphertexts)
        seen.append((f"{method} {url}", response.status_code))

    # Reads first (while everything exists), then every write, the key removal last.
    ordered = sorted(ROUTE_CASES, key=lambda r: (r[0] != "GET", "/key" in r[1], r))
    for method, template in ordered:
        await call(
            method, _url(template, owner.org_id, victim), ROUTE_CASES[(method, template)](victim)
        )
    base = f"{API}/{owner.org_id}"
    history = f"{base}/ti/results/lookup"
    extra: list[tuple[str, str, dict[str, Any]]] = [
        ("GET", f"{base}/analyses/{victim.job_id}/iocs", {"params": {"include": "enrichment"}}),
        ("POST", history, {"json": {"value": "example.com"}}),
        ("POST", history, {"json": {"value": "hit.example.com", "provider": "mock"}}),
        ("GET", f"{base}/ti/runs/{victim.run_id}", {}),
        ("GET", f"{base}/integrations", {}),
        ("GET", f"{base}/audit-logs", {"params": {"limit": 100}}),
    ]
    for method, url, request in extra:
        await call(method, url, request)
    for url in GLOBAL_GETS:
        await call("GET", url, {})

    statuses = dict(seen)
    assert statuses[f"GET {base}/analyses/{victim.job_id}/iocs"] == 200
    assert all(status < 500 for status in statuses.values()), statuses
    # The crawl reached the TI data it is meant to scan (not a vacuous pass).
    iocs = await c.get(f"{base}/analyses/{victim.job_id}/iocs", params={"include": "enrichment"})
    assert any(item.get("enrichment") for item in iocs.json()["items"])
    await assert_key_absent(Tenant(owner.org_id, owner.user_id, uuid.uuid4()), SENTINEL_KEY)


async def test_failed_puts_never_echo_the_key() -> None:
    owner = await register()
    stored = await put_integration(
        owner.client, owner.org_id, api_key=SENTINEL_KEY, enabled=True, acknowledge_terms=True
    )
    assert stored.status_code == 200
    ciphertexts = await _ciphertexts(owner.org_id)
    bodies: list[dict[str, Any]] = [
        {"api_key": SENTINEL_KEY, "unexpected": SENTINEL_KEY},  # extra field
        {"api_key": [SENTINEL_KEY]},  # wrong type
        {"api_key": {"value": SENTINEL_KEY}},
        {"api_key": SENTINEL_KEY, "enabled": "maybe"},
        {"api_key": SENTINEL_KEY, "limits": {"per_minute": 0}},
        {"api_key": SENTINEL_KEY, "limits": {"per_minute": 10**9}},
        {"api_key": SENTINEL_KEY, "base_url": "https://misp.acme-corp.net"},  # not MISP
        {"api_key": f"{SENTINEL_KEY}\x00"},
        {"api_key": SENTINEL_KEY * 8},
    ]
    for n, body in enumerate(bodies):
        response = await put_integration(owner.client, owner.org_id, **body)
        assert response.status_code in (400, 409, 422), (f"body #{n}", response.status_code)
        _assert_clean(response.text, f"the answer to body #{n}", ciphertexts)
    for provider, body in (
        ("misp", {"api_key": SENTINEL_KEY, "base_url": f"https://u:{SENTINEL_KEY}@misp.x.net"}),
        ("misp", {"api_key": SENTINEL_KEY, "base_url": f"https://misp.x.net/?k={SENTINEL_KEY}"}),
        ("misp", {"api_key": SENTINEL_KEY}),
        ("nope", {"api_key": SENTINEL_KEY}),
    ):
        response = await put_integration(owner.client, owner.org_id, provider, **body)
        assert response.status_code == 422, (provider, response.status_code)
        _assert_clean(response.text, provider, ciphertexts)
    # Malformed JSON with the key in it.
    raw = await owner.client.put(
        f"{API}/{owner.org_id}/integrations/mock",
        content=f'{{"api_key": "{SENTINEL_KEY}", '.encode(),
        headers={**csrf(owner.client), "Content-Type": "application/json"},
    )
    assert raw.status_code == 422
    _assert_clean(raw.text, "malformed json", ciphertexts)
    await assert_key_absent(Tenant(owner.org_id, owner.user_id, uuid.uuid4()), SENTINEL_KEY)


# --- the MISP URL binding at the database level (RT1) ---------------------------------------

MISP_URL = "https://misp.acme-corp.net"
EVIL_URL = "https://misp.attacker-owned.net"


async def test_a_misp_key_does_not_follow_a_swapped_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Someone with write access to `ti_provider_configs` (but not the sealing private key)
    points the stored MISP URL at a host they control: the worker cannot unseal the key for
    that URL, so it never sends the key (or any IOC) there."""
    keys = new_seal_keys("test-swap")
    monkeypatch.setattr(get_settings(), "ti_seal_public_keys", {keys.kid: keys.public_b64})
    monkeypatch.setattr(get_settings(), "ti_seal_active_kid", keys.kid)
    owner = await register()
    saved = await put_integration(
        owner.client,
        owner.org_id,
        "misp",
        api_key=SENTINEL_KEY,
        base_url=MISP_URL,
        enabled=True,
        acknowledge_terms=True,
    )
    assert saved.status_code == 200, saved.text

    async with tenant_session(owner.org_id, None) as s:
        row = await s.scalar(select(TiProviderConfig).where(TiProviderConfig.provider == "misp"))
        assert row is not None
        sealed = enrich._Config.of(row).sealed  # noqa: SLF001
        assert sealed is not None
        # Positive control: the stored key opens for the URL it was sealed for.
        opened = open_sealed(sealed, owner.org_id, "misp", MISP_URL, keys.private_keys)
        assert opened.get_secret_value() == SENTINEL_KEY
        await s.execute(
            update(TiProviderConfig)
            .where(TiProviderConfig.provider == "misp")
            .values(base_url=EVIL_URL, verify_status="valid")
        )

    sink = MockSink()
    transport = SafeTransport(sink)
    settings = get_settings().model_copy(
        update={"ti_seal_active_kid": keys.kid, "ti_seal_public_keys": {keys.kid: keys.public_b64}}
    )
    limiter = Limiter(broker_redis(settings.broker_url), settings.queue_prefix)

    async def publish(_: object) -> None:
        return None

    deps = enrich.Deps(
        settings=settings,
        limiter=limiter,
        private_keys=keys.private_keys,
        publish=publish,
        transport=transport,
    )
    try:
        async with tenant_session(owner.org_id, None) as s:
            row = await s.scalar(
                select(TiProviderConfig).where(TiProviderConfig.provider == "misp")
            )
            assert row is not None and row.base_url == EVIL_URL
            config = enrich._Config.of(row)  # noqa: SLF001
        with pytest.raises(UnsealError):
            await enrich._open_provider(deps, owner.org_id, config)  # noqa: SLF001

        # The full paths too: a verify and an enrichment run, through the real handlers.
        await enrich.handle_verify({"org_id": str(owner.org_id), "provider": "misp"}, deps)
        async with tenant_session(owner.org_id, owner.user_id) as s:
            created = await runs.create_run(
                s,
                owner.org_id,
                "manual",
                values=["8.8.8.8"],
                providers=["misp"],
                requested_by=owner.user_id,
            )
        assert created.run_id is not None
        await enrich.handle_enrich(
            {"run_id": str(created.run_id), "org_id": str(owner.org_id)}, deps
        )
    finally:
        await limiter._redis.aclose()  # noqa: SLF001

    assert transport.requests == [] and not sink.calls  # nothing left the worker
    async with tenant_session(owner.org_id, None) as s:
        row = await s.scalar(select(TiProviderConfig).where(TiProviderConfig.provider == "misp"))
        assert row is not None and row.verify_status != "valid"
        states = (
            await s.execute(
                select(TiRunItem.state, TiRunItem.reason).where(TiRunItem.run_id == created.run_id)
            )
        ).all()
    assert [tuple(r) for r in states] == [("abandoned", "auth_failed")]
    await assert_key_absent(Tenant(owner.org_id, owner.user_id, uuid.uuid4()), SENTINEL_KEY)
