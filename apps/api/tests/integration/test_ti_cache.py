"""The per-org result cache = the newest unexpired ok / not_found history row."""

import uuid
from datetime import timedelta

from sqlalchemy import text

from app.core.tenancy import tenant_session
from app.modules.threat_intel import cache
from app.modules.threat_intel.models import TiResult
from app.modules.threat_intel.providers.base import IocType, ProviderName, ResultStatus
from tests.integration.seed import Tenant, seed_tenant
from tests.ti_helpers import DOMAIN, DOMAIN_KEY, seed_run

H = timedelta(hours=1)


def test_ttl_table() -> None:
    ok, nf, err = ResultStatus.OK, ResultStatus.NOT_FOUND, ResultStatus.ERROR
    vt, abuse = ProviderName.VIRUSTOTAL, ProviderName.ABUSEIPDB
    assert cache.ttl(vt, IocType.SHA256, ok) == 72 * H
    assert cache.ttl(vt, IocType.SHA256, nf) == 6 * H  # a quarter, at most 6 h for hashes
    assert cache.ttl(vt, IocType.IPV4, ok) == 12 * H
    assert cache.ttl(abuse, IocType.IPV4, ok) == 6 * H
    assert cache.ttl(abuse, IocType.IPV6, nf) == 1.5 * H
    assert cache.ttl(vt, IocType.DOMAIN, ok) == 24 * H
    assert cache.ttl(vt, IocType.DOMAIN, nf) == 6 * H
    assert cache.ttl(vt, IocType.URL, ok) == 12 * H
    assert cache.ttl(ProviderName.MISP, IocType.SHA256, ok) == H
    assert cache.ttl(ProviderName.MISP, IocType.EMAIL, nf) == H / 4
    assert cache.ttl(vt, IocType.URL, err) is None
    assert cache.ttl(vt, IocType.URL, ResultStatus.AUTH_FAILED) is None


async def _result(
    t: Tenant, run_id: uuid.UUID, *, status: str, expires_in: timedelta | None, age_s: int = 0
) -> uuid.UUID:
    result_id = uuid.uuid4()
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            text(
                "INSERT INTO ti_results (id, organization_id, run_id, provider, ioc_type, "
                "value_norm, ioc_key, status, found, fetched_at, expires_at) VALUES "
                "(:id, :org, :run, 'mock', 'domain', :value, :key, :status, false, "
                "now() - make_interval(secs => :age), now() + :ttl)"
            ),
            {
                "id": result_id,
                "org": t.org_id,
                "run": run_id,
                "value": DOMAIN,
                "key": DOMAIN_KEY,
                "status": status,
                "age": age_s,
                "ttl": expires_in,
            },
        )
    return result_id


async def _fresh(t: Tenant) -> uuid.UUID | None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return await cache.fresh_result(s, t.org_id, ProviderName.MOCK, DOMAIN_KEY)


async def test_fresh_result_rules() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    assert await _fresh(a) is None
    # Errors and auth failures are never hits; neither are expired rows.
    for status in ("error", "auth_failed"):
        await _result(a, await seed_run(a), status=status, expires_in=None)
    await _result(a, await seed_run(a), status="ok", expires_in=-H)
    assert await _fresh(a) is None
    older = await _result(a, await seed_run(a), status="ok", expires_in=H, age_s=60)
    assert await _fresh(a) == older
    newer = await _result(a, await seed_run(a), status="not_found", expires_in=H)
    assert await _fresh(a) == newer
    # Never another org's row (RLS and an explicit org filter).
    assert await _fresh(b) is None
    async with tenant_session(b.org_id, b.owner_id) as s:
        assert await cache.fresh_result(s, a.org_id, ProviderName.MOCK, DOMAIN_KEY) is None
    async with tenant_session(a.org_id, a.owner_id) as s:
        assert await cache.fresh_result(s, a.org_id, ProviderName.OTX, DOMAIN_KEY) is None
        assert (await s.get(TiResult, newer)) is not None
