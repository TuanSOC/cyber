"""Helpers for the threat intel API tests (M4 phase 5): captured publishes, configured
providers, a succeeded analysis job with IOCs, and result rows "written by the worker"."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import update

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch as analysis_dispatch
from app.modules.threat_intel import runs, service_integrations
from app.modules.threat_intel.models import TiResult, TiRunItem
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key
from tests.analysis_helpers import new_case, upload
from tests.factories import Registered, csrf
from tests.pcap_results import seed_results
from tests.ti_helpers import SENTINEL_KEY

API = "/api/v1/orgs"


@dataclass
class Sent:
    """Publishes captured instead of sent (no live enrich worker in API tests)."""

    runs: list[tuple[uuid.UUID, uuid.UUID]] = field(default_factory=list)
    verifies: list[tuple[uuid.UUID, str]] = field(default_factory=list)
    analyses: list[Any] = field(default_factory=list)


def capture_sends(monkeypatch: pytest.MonkeyPatch, *, analyses: bool = True) -> Sent:
    """Capture `ti.enrich` / `ti.verify` publishes (and analysis dispatches, unless the
    caller wants those queued for real)."""
    sent = Sent()

    async def dispatch(run_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        sent.runs.append((run_id, org_id))
        return True

    async def send_verify(org_id: uuid.UUID, provider: Any) -> bool:
        sent.verifies.append((org_id, str(provider)))
        return True

    async def send_analysis(item: Any) -> None:
        sent.analyses.append(item)

    monkeypatch.setattr(runs, "dispatch", dispatch)
    monkeypatch.setattr(service_integrations, "send_verify", send_verify)
    if analyses:
        monkeypatch.setattr(analysis_dispatch, "send", send_analysis)
    return sent


async def put_integration(
    client: AsyncClient, org_id: uuid.UUID, provider: str = "mock", **body: Any
) -> Response:
    return await client.put(
        f"{API}/{org_id}/integrations/{provider}", json=body, headers=csrf(client)
    )


async def enable(
    client: AsyncClient, org_id: uuid.UUID, provider: str = "mock", key: str = SENTINEL_KEY
) -> dict[str, Any]:
    response = await put_integration(
        client, org_id, provider, api_key=key, enabled=True, acknowledge_terms=True
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


async def lookup(
    client: AsyncClient, org_id: uuid.UUID, *values: str | dict[str, str], **body: Any
) -> Response:
    payload = [v if isinstance(v, dict) else {"value": v} for v in values]
    return await client.post(
        f"{API}/{org_id}/ti/lookups", json={"values": payload, **body}, headers=csrf(client)
    )


async def enrich_job(
    client: AsyncClient, org_id: uuid.UUID, job_id: uuid.UUID | str, **body: Any
) -> Response:
    return await client.post(
        f"{API}/{org_id}/analyses/{job_id}/enrichments", json=body, headers=csrf(client)
    )


async def succeeded_job(reg: Registered) -> uuid.UUID:
    """A pcap job with persisted results: IOCs `192.0.2.1` (ip) and `example.com` (domain)."""
    case_id = await new_case(reg)
    evidence = await upload(reg.client, reg.org_id, case_id, b"ti evidence", "ti.bin")
    job = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )
    assert job.status_code == 201, job.text
    job_id = uuid.UUID(job.json()["id"])
    await seed_results(reg.org_id, job_id)
    return job_id


async def queued_job(reg: Registered) -> uuid.UUID:
    case_id = await new_case(reg)
    evidence = await upload(reg.client, reg.org_id, case_id, b"queued evidence", "q.bin")
    job = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "pcap"},
        headers=csrf(reg.client),
    )
    assert job.status_code == 201, job.text
    return uuid.UUID(job.json()["id"])


def key_of(ioc_type: str, value_norm: str) -> str:
    return compute_ioc_key(IocType(ioc_type), value_norm)


async def add_result(
    org_id: uuid.UUID,
    run_id: uuid.UUID | str,
    *,
    provider: str = "mock",
    ioc_type: str = "domain",
    value_norm: str = "hit.example.com",
    status: str = "ok",
    fetched_at: datetime | None = None,
    expires_in: timedelta | None = timedelta(hours=1),
    summary: dict[str, Any] | None = None,
    complete_item: bool = True,
) -> uuid.UUID:
    """One provider answer as the worker writes it, plus (optionally) its item `done`."""
    fetched = fetched_at or datetime.now(UTC)
    cacheable = status in ("ok", "not_found")
    async with tenant_session(org_id, None) as s:
        row = TiResult(
            organization_id=org_id,
            run_id=uuid.UUID(str(run_id)),
            provider=provider,
            ioc_type=ioc_type,
            value_norm=value_norm,
            ioc_key=key_of(ioc_type, value_norm),
            status=status,
            found=status == "ok",
            score=3.0 if status == "ok" else None,
            score_scale="mock_hits" if status == "ok" else None,
            tags=["mock"] if status == "ok" else [],
            summary=summary
            if summary is not None
            else ({"provider": provider, "label": "test-hit", "hits": 3} if cacheable else None),
            permalink="https://ti-mock.example/x" if cacheable else None,
            error_code=None if cacheable else "http_5xx",
            fetched_at=fetched,
            expires_at=(fetched + expires_in) if cacheable and expires_in is not None else None,
        )
        if cacheable and expires_in is None:
            row.expires_at = fetched - timedelta(seconds=1)
        s.add(row)
        await s.flush()
        if complete_item:
            await s.execute(
                update(TiRunItem)
                .where(
                    TiRunItem.run_id == uuid.UUID(str(run_id)),
                    TiRunItem.provider == provider,
                    TiRunItem.ioc_key == row.ioc_key,
                )
                .values(state="done", result_id=row.id)
            )
    return row.id


async def mark_cached(
    org_id: uuid.UUID, run_id: uuid.UUID | str, result_id: uuid.UUID, provider: str = "mock"
) -> None:
    async with tenant_session(org_id, None) as s:
        await s.execute(
            update(TiRunItem)
            .where(TiRunItem.run_id == uuid.UUID(str(run_id)), TiRunItem.provider == provider)
            .values(state="cached", result_id=result_id)
        )
