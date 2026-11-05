"""Row seeding for the M7 platform-operations tests (phase 1, FROZEN for group B).

Rows go straight into tenant sessions (no routes), so phases 3-5 can seed:
- a retention policy (and backdate when its pending values / enforce switch take effect, RT1);
- legal holds, active or released N days ago (a released hold still protects for the delay);
- an aged, closed case with purgeable data: a pcap and a static job with bulk rows and
  results objects, evidence bytes in `evidence-test` (lock 0 in tests), a succeeded render
  with its object in `reports-test`, a backdated closing status event, TI results reused by
  a later `cached` run item, and an AI run tree (parent + child);
- correlated jobs (two cases and two orgs sharing an IP, a domain, a sha256 and a JA3, all as
  `iocs` rows, RT8);
- `job_outcomes` rows;
and open a tenant session as `cyberlab_retention` (`retention_session`). Phases add their own
helpers in their own modules; nobody edits `tests/conftest.py`.
"""

import hashlib
import io
import os
import secrets
import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from minio import Minio
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.ai.contracts import AiRunStatus, AiTask
from app.modules.ai.models import AiRun
from app.modules.analysis.dispatch import result_key
from app.modules.analysis.models import AnalysisJobIndex, AnalysisStatus, Analyzer
from app.modules.evidence.models import Evidence, EvidenceHash, HashAlgorithm
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.pcap_analysis.models import Ioc
from app.modules.reports.models import ReportRender
from app.modules.retention.models import LegalHold, OrgRetentionPolicy, RetentionPolicyIndex
from app.modules.threat_intel.models import TiEnrichmentRun, TiResult, TiRunItem
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key
from tests import pcap_results, static_results
from tests.ai_helpers import seed_ai_run
from tests.analysis_helpers import pe_bytes, tiny_pcap
from tests.case_helpers import seed_case, seed_job_on
from tests.conftest import assert_test_database
from tests.integration.seed import Tenant, seed_tenant
from tests.report_helpers import new_signing_keys, reports_test_bucket, seed_render, seed_report
from tests.report_helpers import seed_version as seed_report_version
from tests.storage_helpers import evidence_test_bucket, root_minio

DAY = timedelta(days=1)


def now() -> datetime:
    return datetime.now(UTC)


def days_ago(days: float) -> datetime:
    return now() - timedelta(days=days)


# --- the retention role ----------------------------------------------------------------------


@lru_cache
def _retention_engine() -> AsyncEngine:
    url = os.environ["RETENTION_TEST_DATABASE_URL"]
    assert_test_database(url)
    return create_async_engine(url, poolclass=NullPool)


@lru_cache
def retention_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(_retention_engine(), expire_on_commit=False)


@asynccontextmanager
async def retention_session(
    org_id: uuid.UUID | None, user_id: uuid.UUID | None = None
) -> AsyncIterator[AsyncSession]:
    """A `tenant_session` as `cyberlab_retention` (NOBYPASSRLS): what the worker opens."""
    async with tenant_session(org_id, user_id, sessionmaker=retention_sessionmaker()) as s:
        yield s


@lru_cache
def purge_minio() -> Minio:
    """The `cyberlab-purge` MinIO user (test env names, RT27)."""
    s = get_settings()
    return Minio(
        s.need("minio_endpoint"),
        access_key=os.environ["TEST_MINIO_PURGE_ACCESS_KEY"],
        secret_key=os.environ["TEST_MINIO_PURGE_SECRET_KEY"],
        secure=s.minio_secure,
    )


# --- policies and holds ------------------------------------------------------------------


async def seed_retention_policy(
    t: Tenant,
    *,
    ti_results_days: int | None = None,
    ai_runs_days: int | None = None,
    closed_case_days: int | None = None,
    enforce: bool = False,
    pending: dict[str, int] | None = None,
    effective_at: datetime | None = None,
    pending_enforce: bool = False,
    enforce_effective_at: datetime | None = None,
) -> None:
    """The org's policy row and its `retention_policy_index` row (RT3). `pending` maps
    `ti_results_days` / `ai_runs_days` / `closed_case_days` to a lowered value waiting for
    `effective_at` (default: now + 7 days)."""
    pending = pending or {}
    if pending and effective_at is None:
        effective_at = now() + 7 * DAY
    if pending_enforce and enforce_effective_at is None:
        enforce_effective_at = now() + 7 * DAY
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            OrgRetentionPolicy(
                organization_id=t.org_id,
                ti_results_days=ti_results_days,
                ai_runs_days=ai_runs_days,
                closed_case_days=closed_case_days,
                pending_ti_results_days=pending.get("ti_results_days"),
                pending_ai_runs_days=pending.get("ai_runs_days"),
                pending_closed_case_days=pending.get("closed_case_days"),
                effective_at=effective_at if pending else None,
                enforce=enforce,
                pending_enforce=pending_enforce,
                enforce_effective_at=enforce_effective_at if pending_enforce else None,
                updated_by=t.owner_id,
            )
        )
        s.add(RetentionPolicyIndex(organization_id=t.org_id))


async def backdate_policy(
    t: Tenant,
    *,
    effective_days_ago: float | None = None,
    enforce_days_ago: float | None = None,
) -> None:
    """Move the pending values' / the enforce switch's effective time into the past."""
    values: dict[str, Any] = {}
    if effective_days_ago is not None:
        values["effective_at"] = days_ago(effective_days_ago)
    if enforce_days_ago is not None:
        values["enforce_effective_at"] = days_ago(enforce_days_ago)
    if not values:
        return
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(OrgRetentionPolicy)
            .where(OrgRetentionPolicy.organization_id == t.org_id)
            .values(**values)
        )


async def seed_hold(
    t: Tenant, *, investigation_id: uuid.UUID | None = None, reason: str = "Litigation hold"
) -> uuid.UUID:
    """An active hold: org scope without `investigation_id`, else case scope."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        hold = LegalHold(
            organization_id=t.org_id,
            scope="org" if investigation_id is None else "investigation",
            investigation_id=investigation_id,
            reason=reason,
            placed_by=t.owner_id,
        )
        s.add(hold)
    return hold.id


async def seed_released_hold(
    t: Tenant,
    released_days_ago: float,
    *,
    investigation_id: uuid.UUID | None = None,
    reason: str = "Litigation hold",
) -> uuid.UUID:
    """A hold placed earlier and released `released_days_ago` days ago (RT1)."""
    released_at = days_ago(released_days_ago)
    async with tenant_session(t.org_id, t.owner_id) as s:
        hold = LegalHold(
            organization_id=t.org_id,
            scope="org" if investigation_id is None else "investigation",
            investigation_id=investigation_id,
            reason=reason,
            placed_by=t.owner_id,
            placed_at=released_at - 30 * DAY,
            released_by=t.owner_id,
            released_at=released_at,
            release_reason="Matter closed",
        )
        s.add(hold)
    return hold.id


# --- an aged, closed case with purgeable data ----------------------------------------------


@dataclass(frozen=True)
class AgedCase:
    investigation_id: uuid.UUID
    pcap_evidence_id: uuid.UUID
    static_evidence_id: uuid.UUID
    pcap_job_id: uuid.UUID
    static_job_id: uuid.UUID
    report_id: uuid.UUID
    version_id: uuid.UUID
    render_id: uuid.UUID
    ti_old_run_id: uuid.UUID
    ti_new_run_id: uuid.UUID
    ti_result_id: uuid.UUID
    ai_parent_run_id: uuid.UUID
    ai_child_run_id: uuid.UUID
    # (bucket, key, version id) of every object the case owns.
    objects: tuple[tuple[str, str, str], ...]


async def _stored_evidence(
    t: Tenant, investigation_id: uuid.UUID, data: bytes, filename: str
) -> tuple[uuid.UUID, tuple[str, str, str]]:
    """An evidence row whose bytes really are in `evidence-test`, with its three hashes."""
    bucket = evidence_test_bucket()
    key = f"{t.org_id}/{uuid.uuid4()}"
    stored = root_minio().put_object(bucket, key, io.BytesIO(data), len(data))
    version_id = str(stored.version_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=investigation_id,
            original_filename=filename,
            detected_mime="application/octet-stream",
            detected_description="data",
            size_bytes=len(data),
            storage_bucket=bucket,
            storage_key=key,
            storage_version_id=version_id,
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
        await s.flush()
        for algorithm, digest in (
            (HashAlgorithm.MD5, hashlib.md5(data).hexdigest()),  # noqa: S324 (identity only)
            (HashAlgorithm.SHA1, hashlib.sha1(data).hexdigest()),  # noqa: S324
            (HashAlgorithm.SHA256, hashlib.sha256(data).hexdigest()),
        ):
            s.add(
                EvidenceHash(
                    organization_id=t.org_id,
                    evidence_id=evidence.id,
                    algorithm=algorithm,
                    value=digest,
                )
            )
    return evidence.id, (bucket, key, version_id)


async def _queued_job(t: Tenant, evidence_id: uuid.UUID, analyzer: str) -> uuid.UUID:
    """A queued job with its index row, so the real ingest can finish it."""
    job_id = await seed_job_on(t, evidence_id, analyzer, status="queued")
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            AnalysisJobIndex(
                job_id=job_id,
                organization_id=t.org_id,
                analyzer=Analyzer(analyzer),
                status=AnalysisStatus.QUEUED,
                deadline_at=now() + timedelta(hours=1),
            )
        )
    return job_id


async def _close_case(t: Tenant, investigation_id: uuid.UUID, closed_at: datetime) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(status=InvestigationStatus.CLOSED)
        )
        await s.execute(
            text(
                "INSERT INTO investigation_status_events (organization_id, investigation_id, "
                "from_status, to_status, reason, actor_id, occurred_at) VALUES "
                "(:o, :i, 'open', 'closed', 'Case closed', :a, :at)"
            ),
            {"o": t.org_id, "i": investigation_id, "a": t.owner_id, "at": closed_at},
        )


async def _succeeded_render(
    t: Tenant, version_id: uuid.UUID
) -> tuple[uuid.UUID, tuple[str, str, str]]:
    bucket = reports_test_bucket()
    data = b"%PDF-1.7 aged rendition\n"
    key = f"{t.org_id}/renders/{uuid.uuid4()}.pdf"
    stored = root_minio().put_object(bucket, key, io.BytesIO(data), len(data))
    version = str(stored.version_id)
    render_id, _ = await seed_render(t, version_id)
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(status="running", started_at=days_ago(400))
        )
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(
                status="succeeded",
                sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data),
                pages=1,
                object_version_id=version,
                finished_at=days_ago(400),
            )
        )
    return render_id, (bucket, key, version)


async def _ti_reuse(t: Tenant, *, aged_days: float) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """An old completed run whose answer a later run reuses as `cached` (RT10)."""
    value = "aged.example.com"
    key = compute_ioc_key(IocType.DOMAIN, value)
    old_run, new_run = uuid.uuid4(), uuid.uuid4()
    async with tenant_session(t.org_id, t.owner_id) as s:
        for run_id, finished in ((old_run, days_ago(aged_days)), (new_run, days_ago(1))):
            s.add(
                TiEnrichmentRun(
                    id=run_id,
                    organization_id=t.org_id,
                    scope="manual",
                    requested_by=t.owner_id,
                    providers=["mock"],
                    status="completed",
                    deadline_at=finished + timedelta(minutes=30),
                    started_at=finished - timedelta(minutes=1),
                    finished_at=finished,
                )
            )
        await s.flush()
        result = TiResult(
            organization_id=t.org_id,
            run_id=old_run,
            provider="mock",
            ioc_type="domain",
            value_norm=value,
            ioc_key=key,
            status="ok",
            found=True,
            summary={"provider": "mock", "label": "aged"},
            fetched_at=days_ago(aged_days),
            # An `ok` answer is cacheable, so it carries an expiry (long past by now).
            expires_at=days_ago(aged_days) + timedelta(hours=1),
        )
        s.add(result)
        await s.flush()
        for run_id, state in ((old_run, "done"), (new_run, "cached")):
            s.add(
                TiRunItem(
                    run_id=run_id,
                    organization_id=t.org_id,
                    seq=0,
                    provider="mock",
                    ioc_type="domain",
                    value_norm=value,
                    ioc_key=key,
                    state=state,
                    result_id=result.id,
                )
            )
    return old_run, new_run, result.id


async def _finish_ai_run(t: Tenant, run_id: uuid.UUID, finished_at: datetime) -> None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(AiRun)
            .where(AiRun.id == run_id)
            .values(status=AiRunStatus.RUNNING, started_at=finished_at - timedelta(minutes=1))
        )
        await s.execute(
            update(AiRun)
            .where(AiRun.id == run_id)
            .values(status=AiRunStatus.COMPLETED, finished_at=finished_at)
        )


async def seed_aged_closed_case(
    t: Tenant, *, closed_days_ago: float = 400, aged_days: float = 400
) -> AgedCase:
    """A case closed `closed_days_ago` days ago (status event backdated) with every
    category's purgeable data aged `aged_days` days (created rows keep their insert time
    where the schema makes it immutable)."""
    case_id = await seed_case(t, title="Aged closed case")
    pcap_evidence, pcap_object = await _stored_evidence(t, case_id, tiny_pcap(), "aged.pcap")
    static_evidence, static_object = await _stored_evidence(t, case_id, pe_bytes(), "aged.exe")
    pcap_job = await _queued_job(t, pcap_evidence, "pcap")
    await pcap_results.seed_results(t.org_id, pcap_job)
    static_job = await _queued_job(t, static_evidence, "static")
    await static_results.seed_results(t.org_id, static_job)

    report_id = await seed_report(t, case_id)
    version = await seed_report_version(t, report_id, new_signing_keys())
    render_id, render_object = await _succeeded_render(t, version.version_id)

    ti_old, ti_new, ti_result = await _ti_reuse(t, aged_days=aged_days)
    case = Tenant(t.org_id, t.owner_id, case_id)
    parent = await seed_ai_run(case, job_id=pcap_job)
    # Children of a tree are `job_digest` runs (the incident pattern, M5).
    child = await seed_ai_run(case, job_id=pcap_job, task=AiTask.JOB_DIGEST, parent_run_id=parent)
    for run_id in (parent, child):
        await _finish_ai_run(t, run_id, days_ago(aged_days))

    await _close_case(t, case_id, days_ago(closed_days_ago))
    bucket = get_settings().results_bucket
    results = tuple(
        (bucket, o.object_name, str(o.version_id))
        for job_id in (pcap_job, static_job)
        for o in root_minio().list_objects(
            bucket, prefix=result_key(t.org_id, job_id), include_version=True
        )
        if not o.is_delete_marker
    )
    return AgedCase(
        investigation_id=case_id,
        pcap_evidence_id=pcap_evidence,
        static_evidence_id=static_evidence,
        pcap_job_id=pcap_job,
        static_job_id=static_job,
        report_id=report_id,
        version_id=version.version_id,
        render_id=render_id,
        ti_old_run_id=ti_old,
        ti_new_run_id=ti_new,
        ti_result_id=ti_result,
        ai_parent_run_id=parent,
        ai_child_run_id=child,
        objects=(pcap_object, static_object, render_object, *results),
    )


# --- correlation ---------------------------------------------------------------------------

# Shared observables as `iocs` rows (the pcap IocType names, RT8).
SHARED_IOCS: tuple[tuple[str, str], ...] = (
    ("ip", "203.0.113.77"),
    ("domain", "c2.shared-example.net"),
    ("file_sha256", "a" * 64),
    ("ja3", "771,4865-4866-4867,0-23-65281,29-23-24,0"),
)


@dataclass(frozen=True)
class CorrelatedSeed:
    org_a: Tenant
    org_b: Tenant
    # Two cases of org A and one of org B, each with one succeeded pcap job carrying every
    # SHARED_IOCS value.
    case_a1: uuid.UUID
    case_a2: uuid.UUID
    case_b: uuid.UUID
    job_a1: uuid.UUID
    job_a2: uuid.UUID
    job_b: uuid.UUID


async def _job_with_iocs(t: Tenant, case_id: uuid.UUID) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=case_id,
            original_filename="shared.pcap",
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
    seen = days_ago(2)
    async with tenant_session(t.org_id, t.owner_id) as s:
        for ioc_type, value in SHARED_IOCS:
            s.add(
                Ioc(
                    organization_id=t.org_id,
                    job_id=job_id,
                    type=ioc_type,
                    value=value,
                    first_seen=seen,
                    last_seen=seen + timedelta(minutes=5),
                    count=3,
                    source="zeek",
                )
            )
    return job_id


async def seed_correlated_jobs() -> CorrelatedSeed:
    a = await seed_tenant(f"corr-a-{secrets.token_hex(3)}")
    b = await seed_tenant(f"corr-b-{secrets.token_hex(3)}")
    case_a1 = await seed_case(a, title="Correlated case A1")
    case_a2 = await seed_case(a, title="Correlated case A2")
    case_b = await seed_case(b, title="Other org case")
    return CorrelatedSeed(
        org_a=a,
        org_b=b,
        case_a1=case_a1,
        case_a2=case_a2,
        case_b=case_b,
        job_a1=await _job_with_iocs(a, case_a1),
        job_a2=await _job_with_iocs(a, case_a2),
        job_b=await _job_with_iocs(b, case_b),
    )


# --- runtime metrics -----------------------------------------------------------------------


async def seed_job_outcomes(owner_engine: AsyncEngine, rows: Sequence[dict[str, Any]]) -> None:
    """Insert `job_outcomes` rows as the owner (the app role may only read them). Each row:
    kind, status, and optionally subkind, error_code, queue_ms, run_ms, finished_at."""
    async with owner_engine.begin() as conn:
        for row in rows:
            await conn.execute(
                text(
                    "INSERT INTO job_outcomes (kind, subkind, status, error_code, queue_ms, "
                    "run_ms, finished_at) VALUES (:kind, :subkind, :status, :error_code, "
                    ":queue_ms, :run_ms, :finished_at)"
                ),
                {
                    "kind": row["kind"],
                    "subkind": row.get("subkind"),
                    "status": row["status"],
                    "error_code": row.get("error_code"),
                    "queue_ms": row.get("queue_ms"),
                    "run_ms": row.get("run_ms"),
                    "finished_at": row.get("finished_at") or now(),
                },
            )
