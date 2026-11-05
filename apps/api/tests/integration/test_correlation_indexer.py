"""The correlation indexer (M7 phase 4): every succeeded job is indexed once, idempotently,
within the per-tick bounds (RT19), with the per-job cap; keys are M6 `normalize_item` keys
(RT8) and never cross an org.

The module also holds the correlation test helpers (`index_rows`, `seed_indexed`,
`member_client`, `extra_job`) used by the read and related-case tests.
"""

import secrets
import uuid
from collections.abc import Coroutine, Iterable
from datetime import timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex, AnalysisStatus, Analyzer
from app.modules.correlation import indexer
from app.modules.correlation.models import CorrelationJobState, CorrelationKey
from app.modules.correlation.normalize import correlation_key
from app.modules.evidence.models import Evidence, EvidenceHash, HashAlgorithm
from app.modules.organizations.models import MemberRole
from app.modules.pcap_analysis.models import Ioc
from app.modules.static_analysis.models import MalwareSample
from app.workers import tasks
from app.workers.celery_app import celery_app
from tests.case_helpers import seed_job_on
from tests.factories import add_member, login, make_user, unique_email
from tests.integration.seed import Tenant
from tests.ops_helpers import SHARED_IOCS, CorrelatedSeed, _job_with_iocs, now, seed_correlated_jobs

# --- helpers (shared with test_correlation_reads / _related / test_search) -------------------


async def index_rows(
    t: Tenant,
    job_ids: Iterable[uuid.UUID],
    *,
    status: AnalysisStatus = AnalysisStatus.SUCCEEDED,
    analyzer: Analyzer = Analyzer.PCAP,
) -> None:
    """The `analysis_job_index` rows the API writes with every job (the seed helpers insert
    jobs directly, without them)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        for job_id in job_ids:
            s.add(
                AnalysisJobIndex(
                    job_id=job_id,
                    organization_id=t.org_id,
                    analyzer=analyzer,
                    status=status,
                    deadline_at=now() + timedelta(hours=1),
                )
            )


async def seed_indexed() -> CorrelatedSeed:
    """`seed_correlated_jobs` with every job indexed."""
    seed = await seed_correlated_jobs()
    await index_rows(seed.org_a, (seed.job_a1, seed.job_a2))
    await index_rows(seed.org_b, (seed.job_b,))
    assert await indexer.index_pending(10) == 3
    return seed


async def extra_job(t: Tenant, case_id: uuid.UUID, *, index: bool = True) -> uuid.UUID:
    """One more succeeded pcap job carrying every SHARED_IOCS value (and its index row)."""
    job_id = await _job_with_iocs(t, case_id)
    await index_rows(t, (job_id,))
    if index:
        assert await indexer.index_job(t.org_id, job_id)
    return job_id


async def job_with_iocs(
    t: Tenant,
    case_id: uuid.UUID,
    iocs: Iterable[tuple[str, str]],
    *,
    filename: str = "other.pcap",
    index: bool = True,
) -> uuid.UUID:
    """A succeeded pcap job on new evidence of the case carrying exactly `iocs`."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=case_id,
            original_filename=filename,
            detected_mime="application/vnd.tcpdump.pcap",
            detected_description="pcap capture file",
            size_bytes=1024,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
    job_id = await seed_job_on(t, evidence.id, "pcap")
    async with tenant_session(t.org_id, t.owner_id) as s:
        for ioc_type, value in iocs:
            s.add(
                Ioc(
                    organization_id=t.org_id,
                    job_id=job_id,
                    type=ioc_type,
                    value=value,
                    first_seen=now(),
                    last_seen=now(),
                    count=1,
                    source="zeek",
                )
            )
    await index_rows(t, (job_id,))
    if index:
        assert await indexer.index_job(t.org_id, job_id)
    return job_id


async def member_client(org_id: uuid.UUID, role: MemberRole = MemberRole.ANALYST) -> AsyncClient:
    """A logged-in member of a seeded org (seeded owners have no usable password)."""
    email = unique_email("corr")
    user_id = await make_user(email)
    await add_member(org_id, user_id, role)
    return await login(email)


async def keys_of(t: Tenant, job_id: uuid.UUID) -> list[CorrelationKey]:
    async with tenant_session(t.org_id, None) as s:
        rows = await s.execute(
            select(CorrelationKey)
            .where(CorrelationKey.job_id == job_id)
            .order_by(CorrelationKey.kind)
        )
        return list(rows.scalars())


async def state_of(t: Tenant, job_id: uuid.UUID) -> CorrelationJobState | None:
    async with tenant_session(t.org_id, None) as s:
        return await s.get(CorrelationJobState, job_id)


def expected_shared() -> set[tuple[str, str, str]]:
    out = set()
    for ioc_type, value in SHARED_IOCS:
        key = correlation_key(ioc_type, value)
        assert key is not None
        out.add(key)
    return out


# --- tests -----------------------------------------------------------------------------------


async def test_every_succeeded_job_is_indexed_with_m6_keys() -> None:
    seed = await seed_indexed()
    for t, job_id, case_id in (
        (seed.org_a, seed.job_a1, seed.case_a1),
        (seed.org_a, seed.job_a2, seed.case_a2),
        (seed.org_b, seed.job_b, seed.case_b),
    ):
        keys = await keys_of(t, job_id)
        assert {(k.kind, k.key, k.value_norm) for k in keys} == expected_shared()
        assert {k.kind for k in keys} == {"ipv4", "domain", "sha256", "ja3"}
        assert all(k.source_table == "iocs" and k.organization_id == t.org_id for k in keys)
        assert all(k.investigation_id == case_id for k in keys)
        assert all(k.first_seen is not None and k.last_seen is not None for k in keys)
        state = await state_of(t, job_id)
        assert state is not None and (state.keys, state.truncated) == (4, False)


async def test_indexing_is_idempotent_and_restart_safe() -> None:
    seed = await seed_indexed()
    assert await indexer.index_pending(10) == 0  # nothing pending
    assert not await indexer.index_job(seed.org_a.org_id, seed.job_a1)  # already indexed
    assert len(await keys_of(seed.org_a, seed.job_a1)) == 4
    # A crash after the keys but before the state row cannot happen (one transaction); a
    # re-run over existing keys (a concurrent backfill) inserts nothing twice either.
    job_id = await extra_job(seed.org_a, seed.case_a1, index=False)
    assert await indexer.index_job(seed.org_a.org_id, job_id)
    assert not await indexer.index_job(seed.org_a.org_id, job_id)
    assert len(await keys_of(seed.org_a, job_id)) == 4


async def test_the_per_job_cap_keeps_hashes_and_ja3_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "correlation_max_keys_per_job", 2)
    seed = await seed_indexed()
    keys = await keys_of(seed.org_a, seed.job_a1)
    assert {k.kind for k in keys} == {"sha256", "ja3"}
    state = await state_of(seed.org_a, seed.job_a1)
    assert state is not None and (state.keys, state.truncated) == (2, True)


async def test_failed_and_running_jobs_are_not_indexed() -> None:
    seed = await seed_correlated_jobs()
    t = seed.org_a
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=await _evidence_of(t, seed.job_a1),
            analyzer=Analyzer.PCAP,
            status=AnalysisStatus.FAILED,
            error_code="invalid_result",
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(job)
    failed = job.id
    await index_rows(seed.org_a, (failed,), status=AnalysisStatus.FAILED)
    # The index says running while the job row is succeeded: the index decides discovery.
    await index_rows(seed.org_a, (seed.job_a1,), status=AnalysisStatus.RUNNING)
    assert await indexer.index_pending(10) == 0
    assert await state_of(seed.org_a, failed) is None
    assert not await indexer.index_job(seed.org_a.org_id, failed)  # the job row is checked too
    assert await keys_of(seed.org_a, failed) == []


async def test_a_tick_is_bounded_by_the_limit_and_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = await seed_correlated_jobs()
    await index_rows(seed.org_a, (seed.job_a1, seed.job_a2))
    await index_rows(seed.org_b, (seed.job_b,))
    assert await indexer.index_pending(1) == 1
    # A spent budget still indexes one job per tick (a slow job never stalls the backlog).
    monkeypatch.setattr(get_settings(), "correlation_index_budget_s", 1e-9)
    assert await indexer.index_pending(10) == 1
    assert await indexer.index_pending(10) == 1
    assert await indexer.index_pending(10) == 0


async def test_a_static_job_indexes_its_sample_and_evidence_hashes() -> None:
    seed = await seed_correlated_jobs()
    t = seed.org_a
    sha256, sha1, md5 = secrets.token_hex(32), secrets.token_hex(20), secrets.token_hex(16)
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=seed.case_a1,
            original_filename="dropper.exe",
            detected_mime="application/x-dosexec",
            detected_description="PE32 executable",
            size_bytes=2048,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
        await s.flush()
        s.add(
            EvidenceHash(
                organization_id=t.org_id,
                evidence_id=evidence.id,
                algorithm=HashAlgorithm.SHA256,
                value=sha256,
            )
        )
        s.add(
            EvidenceHash(
                organization_id=t.org_id,
                evidence_id=evidence.id,
                algorithm=HashAlgorithm.MD5,
                value=md5,
            )
        )
    job_id = await seed_job_on(t, evidence.id, "static")
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            MalwareSample(
                organization_id=t.org_id,
                job_id=job_id,
                size=2048,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                entropy=6.1,
                file_format="pe",
            )
        )
        # An IOC repeating the sample hash, a registry key and an invalid IP: one key, two
        # skipped values (counted, never raised).
        for ioc_type, value in (
            ("file_sha256", sha256.upper()),
            ("registry_key", r"HKLM\Software\Run\evil"),
            ("ip", "999.1.1.1"),
        ):
            s.add(
                Ioc(
                    organization_id=t.org_id,
                    job_id=job_id,
                    type=ioc_type,
                    value=value,
                    first_seen=now(),
                    last_seen=now(),
                    count=1,
                    source="static",
                )
            )
    await index_rows(t, (job_id,), analyzer=Analyzer.STATIC)
    assert await indexer.index_pending(1) == 1
    keys = {k.kind: k for k in await keys_of(t, job_id)}
    assert set(keys) == {"sha256", "sha1", "md5"}
    # The evidence sha256 comes first; the sample and the IOC carry the same key.
    assert keys["sha256"].source_table == "evidence_hashes"
    assert keys["sha256"].value_norm == sha256
    assert keys["sha1"].source_table == keys["md5"].source_table == "malware_samples"
    assert all(k.evidence_id == evidence.id for k in keys.values())
    state = await state_of(t, job_id)
    assert state is not None and (state.keys, state.truncated) == (3, False)


async def test_keys_stay_inside_their_org() -> None:
    seed = await seed_indexed()
    async with tenant_session(seed.org_a.org_id, None) as s:
        orgs = await s.execute(text("SELECT DISTINCT organization_id FROM correlation_keys"))
        assert [r[0] for r in orgs] == [seed.org_a.org_id]
        jobs = await s.execute(text("SELECT count(*) FROM correlation_job_state"))
        assert jobs.scalar_one() == 2


async def test_the_beat_task_runs_the_indexer_with_the_batch_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = celery_app.conf.beat_schedule["index-correlation-keys"]
    assert entry["task"] == "correlation.index_pending" and entry["schedule"] == 60.0
    seed = await seed_correlated_jobs()
    await index_rows(seed.org_a, (seed.job_a1, seed.job_a2))
    await index_rows(seed.org_b, (seed.job_b,))
    monkeypatch.setattr(get_settings(), "correlation_index_batch_jobs", 2)
    # The task's sync bridge owns its own loop: hand the coroutine to the test loop instead.
    captured: list[Coroutine[Any, Any, int]] = []
    monkeypatch.setattr(tasks, "run", lambda coro: captured.append(coro) or 0)
    tasks.correlation_index_pending({})
    [coro] = captured
    assert await coro == 2  # the batch setting bounds the tick
    assert await indexer.index_pending(10) == 1


async def _evidence_of(t: Tenant, job_id: uuid.UUID) -> uuid.UUID:
    async with tenant_session(t.org_id, None) as s:
        row = await s.execute(
            text("SELECT evidence_id FROM analysis_jobs WHERE id = :j"), {"j": job_id}
        )
        return uuid.UUID(str(row.scalar_one()))
