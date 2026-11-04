"""Run creation (`threat_intel.runs`, API side): the frozen plan of a run (RT9)."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.evidence.models import Evidence
from app.modules.pcap_analysis.models import Ioc
from app.modules.static_analysis.models import MalwareSample
from app.modules.threat_intel import runs
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiOrgSettings,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.providers.base import IocType, ProviderName, compute_ioc_key
from tests.integration.seed import Tenant, seed_tenant
from tests.ti_helpers import new_seal_keys, seal_config

SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


async def _tenant(*providers: str) -> Tenant:
    t = await seed_tenant(f"org{uuid.uuid4().hex[:8]}")
    keys = new_seal_keys()
    for provider in providers or ("mock",):
        await seal_config(t, keys, provider=provider)
    return t


async def _create(t: Tenant, scope: str = "manual", **kwargs: object) -> runs.RunCreated:
    kwargs.setdefault("providers", ["mock"])
    async with tenant_session(t.org_id, t.owner_id) as s:
        return await runs.create_run(
            s,
            t.org_id,
            scope,
            requested_by=t.owner_id,
            **kwargs,  # type: ignore[arg-type]
        )


async def _items(t: Tenant, run_id: uuid.UUID) -> list[tuple[int, str, str, str]]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = await s.execute(
            select(TiRunItem.seq, TiRunItem.provider, TiRunItem.ioc_type, TiRunItem.value_norm)
            .where(TiRunItem.run_id == run_id)
            .order_by(TiRunItem.seq)
        )
        return [tuple(row) for row in rows]  # type: ignore[misc]


async def test_manual_lookup_plan_and_report() -> None:
    t = await _tenant("mock", "virustotal")
    created = await _create(
        t,
        providers=["virustotal", "mock"],
        values=[
            "8.8.8.8",
            runs.LookupValue("hit.example.com", "domain"),
            "10.0.0.1",
            "https://login.acme-corp.net/reset?token=s3cr3t#x",
            "5.1.168.192.in-addr.arpa",
            "alice@acme-corp.net",
            "8.8.8.8",
            runs.LookupValue("x", "registry_key"),
        ],
    )
    assert created.run_id is not None
    items = await _items(t, created.run_id)
    assert items == [
        (0, "virustotal", "ipv4", "8.8.8.8"),
        (1, "mock", "ipv4", "8.8.8.8"),
        (2, "mock", "domain", "hit.example.com"),
        (3, "virustotal", "url", "https://login.acme-corp.net/reset"),
        (4, "mock", "url", "https://login.acme-corp.net/reset"),
        (5, "mock", "email", "alice@acme-corp.net"),
    ]
    report = {r.index: r for r in created.report}
    assert report[1].provider_skips == {"virustotal": "special_use_name"}
    assert report[2].skipped == "not_global_ip"
    assert report[3].notes == ("query_removed",)
    assert report[3].value_norm == "https://login.acme-corp.net/reset"
    assert report[3].ioc_key == compute_ioc_key(IocType.URL, "https://login.acme-corp.net/reset")
    assert report[4].skipped == "special_use_name"
    assert report[5].providers == ("mock",)
    assert report[5].provider_skips == {"virustotal": "unsupported_type"}
    assert report[6].providers == ()  # a duplicate of value 0
    assert report[7].skipped == "unsupported_type"
    summary = created.summary
    assert summary["planned_values"] == 4
    assert summary["items"] == 6
    assert summary["duplicates"] == 1
    assert summary["skipped"] == {
        "not_global_ip": 1,
        "special_use_name": 1,
        "unsupported_type": 1,
    }
    assert summary["providers"]["virustotal"]["planned"] == 2
    assert summary["providers"]["virustotal"]["skipped_special_use_name"] == 2
    async with tenant_session(t.org_id, t.owner_id) as s:
        run = await s.get(TiEnrichmentRun, created.run_id)
        index = await s.get(TiRunIndex, created.run_id)
        assert run is not None and index is not None
        assert (run.status, run.scope, run.providers) == (
            "queued",
            "manual",
            ["virustotal", "mock"],
        )
        assert (index.status, index.organization_id) == ("queued", t.org_id)
        assert index.dispatched_at is not None
        assert index.deadline_at == run.deadline_at
        assert run.summary == summary
    # Nothing sensitive was planned: no private IP, internal/.arpa name or query string.
    planned = " ".join(row[3] for row in items)
    for forbidden in ("10.0.0.1", "arpa", "token", "s3cr3t", "?", "#"):
        assert forbidden not in planned


async def test_nothing_eligible_creates_no_run() -> None:
    t = await _tenant()
    created = await _create(t, values=["10.0.0.1", "printer.local", "x.example.org"])
    assert created.run_id is None
    assert [r.skipped for r in created.report] == [
        "not_global_ip",
        "special_use_name",
        "special_use_name",
    ]
    async with tenant_session(t.org_id, t.owner_id) as s:
        assert (await s.execute(select(TiEnrichmentRun))).first() is None
        assert (await s.execute(select(TiRunItem))).first() is None


async def test_excluded_suffixes() -> None:
    t = await _tenant()
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(TiOrgSettings(organization_id=t.org_id, excluded_suffixes=["corp.acme-corp.net"]))
    created = await _create(
        t, values=["fs.corp.acme-corp.net", "https://wiki.corp.acme-corp.net/a", "acme-corp.net"]
    )
    assert created.run_id is not None
    assert [r.skipped for r in created.report] == ["excluded_suffix", "excluded_suffix", None]
    assert [row[3] for row in await _items(t, created.run_id)] == ["acme-corp.net"]


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"values": ["8.8.8.8"] * 21}, "too_many_values"),
        ({"values": []}, "no_values"),
        ({"values": ["8.8.8.8"], "providers": ["virustotal"]}, "provider_not_enabled"),
        ({"values": ["8.8.8.8"], "providers": ["nope"]}, "unknown_provider"),
        ({"values": ["8.8.8.8"], "providers": []}, "no_provider_enabled"),
        ({"values": ["8.8.8.8"], "job_id": uuid.uuid4()}, "bad_scope"),
    ],
)
async def test_refusals(kwargs: dict[str, object], code: str) -> None:
    t = await _tenant()
    with pytest.raises(runs.RunError) as caught:
        await _create(t, **kwargs)
    assert caught.value.code == code


async def test_disabled_provider_is_refused() -> None:
    t = await seed_tenant("alpha")
    await seal_config(t, new_seal_keys(), enabled=False)
    with pytest.raises(runs.RunError, match="provider_not_enabled"):
        await _create(t, values=["8.8.8.8"])


async def test_mock_is_unavailable_in_prod() -> None:
    t = await _tenant()
    prod = get_settings().model_copy(update={"env": "prod"})
    with pytest.raises(runs.RunError) as caught:
        await _create(t, values=["8.8.8.8"], settings=prod)
    assert caught.value.code == "provider_unavailable"
    off = get_settings().model_copy(update={"ti_mock_enabled": False})
    with pytest.raises(runs.RunError):
        await _create(t, values=["8.8.8.8"], settings=off)


async def _seed_job(t: Tenant, iocs: list[tuple[str, str, int]], *, sample: bool) -> uuid.UUID:
    now = datetime.now(UTC)
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=t.investigation_id,
            original_filename="sample.bin",
            detected_mime="application/octet-stream",
            detected_description="data",
            size_bytes=1,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
        await s.flush()
        job_id = (
            await s.execute(
                text(
                    "INSERT INTO analysis_jobs (organization_id, evidence_id, analyzer, "
                    "requested_by, ingest_token_sha256) VALUES (:org, :evidence, "
                    "CAST('pcap' AS analyzer), :user, :digest) RETURNING id"
                ),
                {"org": t.org_id, "evidence": evidence.id, "user": t.owner_id, "digest": "0" * 64},
            )
        ).scalar_one()
        for ioc_type, value, count in iocs:
            s.add(
                Ioc(
                    organization_id=t.org_id,
                    job_id=job_id,
                    type=ioc_type,
                    value=value,
                    first_seen=now,
                    last_seen=now,
                    count=count,
                    source="test",
                )
            )
        if sample:
            s.add(
                MalwareSample(
                    organization_id=t.org_id,
                    job_id=job_id,
                    size=1,
                    md5=MD5,
                    sha1=SHA1,
                    sha256=SHA256,
                    entropy=0.0,
                    file_format="other",
                )
            )
    return uuid.UUID(str(job_id))


async def test_job_plan_order_and_cap() -> None:
    t = await _tenant()
    job_id = await _seed_job(
        t,
        [
            ("domain", "rare.acme-corp.net", 1),
            ("ip", "10.0.0.7", 900),  # most frequent, but never sent
            ("domain", "frequent.acme-corp.net", 500),
            ("url", "http://mid.acme-corp.net/x?session=1", 50),
            ("ja3", "771,4865-4866,0-23,29-23,0", 400),
            ("email", "bob@acme-corp.net", 40),
        ],
        sample=True,
    )
    capped = get_settings().model_copy(update={"ti_max_iocs_per_run": 5})
    created = await _create(t, "job", job_id=job_id, settings=capped)
    assert created.run_id is not None
    values = [(row[2], row[3]) for row in await _items(t, created.run_id)]
    assert values == [
        ("sha256", SHA256),
        ("sha1", SHA1),
        ("md5", MD5),
        ("domain", "frequent.acme-corp.net"),
        ("url", "http://mid.acme-corp.net/x"),
    ]
    summary = created.summary
    assert summary["truncated"] is True
    assert summary["skipped"] == {"not_global_ip": 1, "unsupported_type": 1}
    async with tenant_session(t.org_id, t.owner_id) as s:
        run = await s.get(TiEnrichmentRun, created.run_id)
        assert run is not None and (run.scope, run.job_id) == ("job", job_id)

    # Without a cap problem: everything eligible, not truncated; a pcap job has no sample.
    job2 = await _seed_job(
        t, [("domain", "a.acme-corp.net", 3), ("ip", "8.8.4.4", 2)], sample=False
    )
    created2 = await _create(t, "job", job_id=job2)
    assert created2.summary["truncated"] is False
    assert [row[3] for row in await _items(t, created2.run_id or uuid.uuid4())] == [
        "a.acme-corp.net",
        "8.8.4.4",
    ]


async def test_job_of_another_org_is_not_found() -> None:
    a = await _tenant()
    b = await _tenant()
    job_id = await _seed_job(a, [("domain", "a.acme-corp.net", 1)], sample=False)
    with pytest.raises(runs.RunError, match="job_not_found"):
        await _create(b, "job", job_id=job_id)


async def test_dispatch_publishes_ids_only(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[object] = []
    monkeypatch.setattr(runs, "_send_sync", lambda message: sent.append(message))
    run_id, org_id = uuid.uuid4(), uuid.uuid4()
    assert await runs.dispatch(run_id, org_id) is True
    assert [m.model_dump(mode="json") for m in sent] == [  # type: ignore[attr-defined]
        {"run_id": str(run_id), "org_id": str(org_id)}
    ]

    def boom(_: object) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(runs, "_send_sync", boom)
    assert await runs.dispatch(run_id, org_id) is False  # logged; ti.resume retries


def test_lookup_values_carry_their_type() -> None:
    assert runs.LookupValue("8.8.8.8").type_hint is None
    assert ProviderName("mock") is ProviderName.MOCK
