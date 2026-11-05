"""The `job_outcomes` triggers of migration 0014 (M7 phase 5 owns the full test).

Every terminal transition of an analysis job, TI run, AI run or report render writes exactly
one tenant-free row, through the normal lifecycle paths and through the reaper fail paths; a
non-terminal change writes none; a purge (`succeeded -> purged`) writes none; the app role
cannot write the table; and the trigger never blocks the status change it observes (a NULL
`started_at` gives NULL durations; an error inside it is a WARNING). Q6: the cost of the
trigger under a bulk reaper fail of 500 jobs is measured and must stay under 20 %.
"""

import secrets
import time
import uuid
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cyberlab_jobs.static import Profile
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.tenancy import tenant_session
from app.modules.ai import lifecycle as ai_lifecycle
from app.modules.ai.contracts import AiErrorCode, AiRunStatus
from app.modules.ai.models import AiRun, AiRunIndex
from app.modules.analysis import lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.models import (
    ACTIVE,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
    Analyzer,
)
from app.modules.evidence.models import Evidence
from app.modules.reports.models import ReportRender, ReportRenderIndex
from app.modules.threat_intel.lifecycle import finalize_run
from app.modules.threat_intel.models import TiEnrichmentRun, TiRunIndex, TiRunItem
from app.workers import reaper
from tests.ai_helpers import seed_ai_run, seed_job
from tests.integration.seed import Tenant, seed_tenant
from tests.ops_helpers import retention_session
from tests.report_helpers import new_signing_keys, seed_render, seed_report, seed_version
from tests.ti_helpers import seed_result, seed_run

OUTCOME_COLUMNS = {
    "id",
    "kind",
    "subkind",
    "status",
    "error_code",
    "queue_ms",
    "run_ms",
    "finished_at",
}
Row = tuple[str, str | None, str, str | None]


def now() -> datetime:
    return datetime.now(UTC)


async def outcomes() -> list[dict[str, Any]]:
    async with tenant_session(None, None) as s:
        rows = await s.execute(text("SELECT * FROM job_outcomes ORDER BY finished_at, id"))
        return [dict(r) for r in rows.mappings()]


async def outcome_keys() -> Counter[Row]:
    return Counter(
        (r["kind"], r["subkind"], r["status"], r["error_code"]) for r in await outcomes()
    )


# --- analysis jobs ------------------------------------------------------------------------


def _evidence(t: Tenant, analyzer: Analyzer) -> Evidence:
    return Evidence(
        id=uuid.uuid4(),
        organization_id=t.org_id,
        investigation_id=t.investigation_id,
        original_filename="capture.pcap" if analyzer is Analyzer.PCAP else "sample.bin",
        detected_mime="application/octet-stream",
        detected_description="data",
        size_bytes=1024,
        storage_bucket="evidence-test",
        storage_key=f"{t.org_id}/{uuid.uuid4()}",
        storage_version_id="v1",
        uploaded_by=t.owner_id,
    )


async def seed_jobs(
    t: Tenant,
    analyzer: str = "pcap",
    *,
    n: int = 1,
    status: AnalysisStatus = AnalysisStatus.QUEUED,
    deadline_s: int = 600,
) -> list[uuid.UUID]:
    """`n` jobs (each on its own evidence: one active job per evidence) with their index
    rows, as the upload path creates them. `running` jobs get a `started_at`."""
    kind = Analyzer(analyzer)
    deadline = now() + timedelta(seconds=deadline_s)
    ids = []
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = [_evidence(t, kind) for _ in range(n)]
        s.add_all(evidence)
        await s.flush()
        jobs = [
            AnalysisJob(
                id=uuid.uuid4(),
                organization_id=t.org_id,
                evidence_id=e.id,
                analyzer=kind,
                profile=Profile.FULL if kind is Analyzer.STATIC else None,
                status=status,
                requested_by=t.owner_id,
                ingest_token_sha256=secrets.token_hex(32),
                started_at=now() if status is AnalysisStatus.RUNNING else None,
            )
            for e in evidence
        ]
        s.add_all(jobs)
        await s.flush()
        s.add_all(
            AnalysisJobIndex(
                job_id=j.id,
                organization_id=t.org_id,
                analyzer=kind,
                status=status,
                deadline_at=deadline,
            )
            for j in jobs
        )
        ids = [j.id for j in jobs]
    return ids


async def move(t: Tenant, job_id: uuid.UUID, to: AnalysisStatus, code: str | None = None) -> None:
    """The lifecycle path the API, the ingest worker and the reaper share."""
    async with tenant_session(t.org_id, None) as s:
        job = await repo.get_for_update(s, t.org_id, job_id)
        assert job is not None
        allowed = (AnalysisStatus.QUEUED,) if to is AnalysisStatus.RUNNING else ACTIVE
        assert await lifecycle.transition(s, job, to, allowed_from=allowed, error_code=code)


@pytest.mark.parametrize(("analyzer", "subkind"), [("pcap", None), ("static", "full")])
async def test_analysis_lifecycle_writes_one_row_per_terminal_transition(
    analyzer: str, subkind: str | None
) -> None:
    t = await seed_tenant(f"ops-{analyzer}")
    ok, bad = await seed_jobs(t, analyzer, n=2)
    for job in (ok, bad):
        await move(t, job, AnalysisStatus.RUNNING)
    assert await outcomes() == []  # queued -> running is not terminal
    await move(t, ok, AnalysisStatus.SUCCEEDED)
    await move(t, bad, AnalysisStatus.FAILED, "unparseable_capture")
    assert await outcome_keys() == Counter(
        {
            (analyzer, subkind, "succeeded", None): 1,
            (analyzer, subkind, "failed", "unparseable_capture"): 1,
        }
    )
    for row in await outcomes():
        assert row["queue_ms"] is not None and row["queue_ms"] >= 0
        assert row["run_ms"] is not None and row["run_ms"] >= 0


async def test_the_analysis_reaper_fail_paths_write_one_row_each() -> None:
    t = await seed_tenant("ops-reaper")
    [queued] = await seed_jobs(t, "pcap", deadline_s=-5)
    [running] = await seed_jobs(t, "static", status=AnalysisStatus.RUNNING, deadline_s=-5)
    [alive] = await seed_jobs(t, "pcap")
    assert await reaper.reap() == 2
    assert await reaper.reap() == 0
    rows = {r["error_code"]: r for r in await outcomes()}
    assert set(rows) == {"never_started", "timed_out"}
    # Never started: NULL started_at gives NULL durations, never an error.
    assert (rows["never_started"]["queue_ms"], rows["never_started"]["run_ms"]) == (None, None)
    assert rows["never_started"]["kind"] == "pcap"
    assert rows["timed_out"]["kind"] == "static" and rows["timed_out"]["run_ms"] is not None
    async with tenant_session(t.org_id, None) as s:
        job = await s.get(AnalysisJob, alive)
        assert job is not None and job.status is AnalysisStatus.QUEUED
        assert (await s.get(AnalysisJob, queued)).status is AnalysisStatus.FAILED  # type: ignore[union-attr]
        assert (await s.get(AnalysisJob, running)).status is AnalysisStatus.FAILED  # type: ignore[union-attr]


# --- threat intel runs ----------------------------------------------------------------------


async def test_ti_runs_write_one_row_per_final_status() -> None:
    t = await seed_tenant("ops-ti")
    done = await seed_run(t)
    result = await seed_result(t, done)
    async with tenant_session(t.org_id, None) as s:
        await s.execute(
            update(TiRunItem)
            .where(TiRunItem.run_id == done)
            .values(state="cached", result_id=result)
        )
    waiting = await seed_run(t)
    async with tenant_session(t.org_id, None) as s:
        for status in ("running", "waiting"):  # not terminal: no row
            await s.execute(
                update(TiEnrichmentRun).where(TiEnrichmentRun.id == waiting).values(status=status)
            )
            await s.flush()
    assert await outcomes() == []
    async with tenant_session(t.org_id, None) as s:
        assert await finalize_run(s, t.org_id, done) == "completed"
    # The fallback reaper: deadline more than 10 minutes ago, no lease -> abandoned -> failed.
    stale = now() - timedelta(minutes=11)
    async with tenant_session(t.org_id, None) as s:
        await s.execute(
            update(TiEnrichmentRun).where(TiEnrichmentRun.id == waiting).values(deadline_at=stale)
        )
        await s.execute(
            update(TiRunIndex)
            .where(TiRunIndex.run_id == waiting)
            .values(deadline_at=stale, status="waiting")
        )
    assert await reaper.reap_ti_runs() == 1
    assert await outcome_keys() == Counter(
        {("ti", "mock", "completed", None): 1, ("ti", "mock", "failed", None): 1}
    )
    async with tenant_session(t.org_id, None) as s:  # a final run: finalize is a no-op
        assert await finalize_run(s, t.org_id, done) is None
    assert len(await outcomes()) == 2


async def test_a_multi_provider_run_is_recorded_as_multi() -> None:
    t = await seed_tenant("ops-ti-multi")
    run = uuid.uuid4()
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            TiEnrichmentRun(
                id=run,
                organization_id=t.org_id,
                scope="manual",
                requested_by=t.owner_id,
                providers=["mock", "otx"],
                status="queued",
                deadline_at=now() + timedelta(minutes=30),
            )
        )
    async with tenant_session(t.org_id, None) as s:
        assert await finalize_run(s, t.org_id, run, abandon_reason="deadline") == "failed"
    assert await outcome_keys() == Counter({("ti", "multi", "failed", None): 1})


# --- AI runs -------------------------------------------------------------------------------


async def test_ai_runs_write_one_row_per_final_status() -> None:
    t = await seed_tenant("ops-ai")
    job = await seed_job(t)
    finals = [
        (AiRunStatus.COMPLETED, None),
        (AiRunStatus.FAILED, AiErrorCode.INVALID_OUTPUT),
        (AiRunStatus.FAILED, AiErrorCode.POLICY_BLOCKED),
        (AiRunStatus.REFUSED, AiErrorCode.REFUSED),
    ]
    runs = [await seed_ai_run(t, job_id=job) for _ in finals]
    async with tenant_session(t.org_id, None) as s:
        assert await ai_lifecycle.mark_running(s, runs[0]) is not None  # not terminal
    assert await outcomes() == []
    for run, (status, code) in zip(runs, finals, strict=True):
        async with tenant_session(t.org_id, None) as s:
            assert await ai_lifecycle.finalize(s, run, status, code) == status
    # The fallback reaper: deadline more than 10 minutes ago and no live lease.
    stale = await seed_ai_run(t, job_id=job, deadline_s=-700)
    assert await reaper.reap_ai_runs() == 1
    assert await outcome_keys() == Counter(
        {
            ("ai", "mock", "completed", None): 1,
            ("ai", "mock", "failed", "invalid_output"): 1,
            ("ai", "mock", "failed", "policy_blocked"): 1,
            ("ai", "mock", "refused", "refused"): 1,
            ("ai", "mock", "failed", "deadline"): 1,
        }
    )
    async with tenant_session(t.org_id, None) as s:
        reaped = await s.get(AiRun, stale)
        index = await s.get(AiRunIndex, stale)
        assert reaped is not None and index is not None and reaped.status == "failed"


# --- report renders ------------------------------------------------------------------------


async def _renders(t: Tenant, *formats: str, deadline_s: int = 600) -> list[uuid.UUID]:
    report = await seed_report(t)
    version = await seed_version(t, report, new_signing_keys(), store=False)
    return [
        (await seed_render(t, version.version_id, fmt=fmt, deadline_s=deadline_s))[0]
        for fmt in formats
    ]


async def _set_render(t: Tenant, render_id: uuid.UUID, **values: Any) -> None:
    async with tenant_session(t.org_id, None) as s:
        await s.execute(update(ReportRender).where(ReportRender.id == render_id).values(**values))
        if "status" in values:
            await s.execute(
                update(ReportRenderIndex)
                .where(ReportRenderIndex.render_id == render_id)
                .values(status=values["status"])
            )


async def test_renders_write_one_row_per_final_status_and_none_on_purge() -> None:
    t = await seed_tenant("ops-render")
    ok, bad = await _renders(t, "pdf", "html")
    for render in (ok, bad):
        await _set_render(t, render, status="running", started_at=now())
    assert await outcomes() == []
    await _set_render(
        t,
        ok,
        status="succeeded",
        sha256="a" * 64,
        bytes=10,
        object_version_id="v1",
        finished_at=now(),
    )
    await _set_render(t, bad, status="failed", error_code="oom", finished_at=now())
    [expired] = await _renders(t, "md", deadline_s=-5)
    assert await reaper.reap_report_renders() == 1  # the reaper: failed / timeout
    expected = Counter(
        {
            ("report", "pdf", "succeeded", None): 1,
            ("report", "html", "failed", "oom"): 1,
            ("report", "md", "failed", "timeout"): 1,
        }
    )
    assert await outcome_keys() == expected
    # Retention purges the rendition: `succeeded -> purged` is not a new outcome.
    async with retention_session(t.org_id) as s:
        await s.execute(update(ReportRender).where(ReportRender.id == ok).values(status="purged"))
    async with tenant_session(t.org_id, None) as s:
        assert (await s.get(ReportRender, ok)).status == "purged"  # type: ignore[union-attr]
        assert (await s.get(ReportRender, expired)).error_code == "timeout"  # type: ignore[union-attr]
    assert await outcome_keys() == expected


# --- the table itself ------------------------------------------------------------------------


async def test_rows_hold_no_tenant_data(owner_engine: AsyncEngine) -> None:
    t = await seed_tenant("ops-tenant-secret-name")
    [job] = await seed_jobs(t, "pcap")
    await move(t, job, AnalysisStatus.RUNNING)
    await move(t, job, AnalysisStatus.FAILED, "zeek_failed")
    async with owner_engine.connect() as conn:
        columns = set(
            (
                await conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = 'job_outcomes'"
                    )
                )
            ).scalars()
        )
    assert columns == OUTCOME_COLUMNS
    [row] = await outcomes()
    dumped = repr(row)
    for secret in (
        str(t.org_id),
        str(t.owner_id),
        str(t.investigation_id),
        str(job),
        "ops-tenant-secret-name",
    ):
        assert secret not in dumped


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO job_outcomes (kind, status) VALUES ('pcap', 'succeeded')",
        "UPDATE job_outcomes SET status = 'failed'",
        "DELETE FROM job_outcomes",
    ],
)
async def test_the_app_role_cannot_write_job_outcomes(
    owner_engine: AsyncEngine, statement: str
) -> None:
    async with owner_engine.begin() as conn:
        await conn.execute(text("INSERT INTO job_outcomes (kind, status) VALUES ('ai', 'failed')"))
    with pytest.raises(DBAPIError, match="permission denied"):
        async with tenant_session(None, None) as s:
            await s.execute(text(statement))
    assert len(await outcomes()) == 1


@asynccontextmanager
async def _broken_outcomes(owner_engine: AsyncEngine) -> AsyncIterator[None]:
    """Make every INSERT into job_outcomes fail (lane test DB only; restored after)."""
    async with owner_engine.begin() as conn:
        await conn.execute(
            text(
                "ALTER TABLE job_outcomes ADD CONSTRAINT ck_ops_test_broken CHECK (false) NOT VALID"
            )
        )
    try:
        yield
    finally:
        async with owner_engine.begin() as conn:
            await conn.execute(
                text("ALTER TABLE job_outcomes DROP CONSTRAINT IF EXISTS ck_ops_test_broken")
            )


async def test_the_trigger_never_blocks_the_transition(owner_engine: AsyncEngine) -> None:
    t = await seed_tenant("ops-never-blocks")
    [job] = await seed_jobs(t, "pcap")
    async with _broken_outcomes(owner_engine):
        await move(t, job, AnalysisStatus.RUNNING)
        await move(t, job, AnalysisStatus.SUCCEEDED)  # the INSERT fails inside: a WARNING
    async with tenant_session(t.org_id, None) as s:
        row = await s.scalar(select(AnalysisJob.status).where(AnalysisJob.id == job))
    assert row is AnalysisStatus.SUCCEEDED
    assert await outcomes() == []


async def test_bad_codes_and_subkinds_are_sanitized(owner_engine: AsyncEngine) -> None:
    t = await seed_tenant("ops-sanitize")
    [job] = await seed_jobs(t, "pcap")
    await move(t, job, AnalysisStatus.RUNNING)
    await move(t, job, AnalysisStatus.FAILED, "Bad Code; org=secret")
    [row] = await outcomes()
    assert row["error_code"] == "other"


# --- Q6: the cost under a bulk reaper fail ------------------------------------------------------

BULK = 500


async def _timed_reap(t: Tenant) -> float:
    await seed_jobs(t, "pcap", n=BULK, deadline_s=-5)
    started = time.perf_counter()
    reaped = 0
    while n := await reaper.reap():
        reaped += n
    elapsed = time.perf_counter() - started
    assert reaped == BULK
    return elapsed


async def _set_trigger(owner_engine: AsyncEngine, enabled: bool) -> None:
    action = "ENABLE" if enabled else "DISABLE"
    async with owner_engine.begin() as conn:
        await conn.execute(
            text(f"ALTER TABLE analysis_jobs {action} TRIGGER analysis_jobs_job_outcome")
        )


async def test_bulk_reaper_fail_cost_of_the_trigger(owner_engine: AsyncEngine) -> None:
    """Q6: reap 500 stale jobs with the trigger disabled and enabled (two rounds each,
    interleaved; the minimum of each is compared). The trigger adds < 20 %."""
    t = await seed_tenant("ops-bulk")
    timings: dict[bool, list[float]] = {False: [], True: []}
    try:
        for enabled in (False, True, False, True):
            await _set_trigger(owner_engine, enabled)
            timings[enabled].append(await _timed_reap(t))
    finally:
        await _set_trigger(owner_engine, True)
    without, with_trigger = min(timings[False]), min(timings[True])
    overhead = (with_trigger - without) / without
    print(
        f"\nQ6 bulk reaper fail of {BULK} jobs: without trigger {timings[False]} s, "
        f"with trigger {timings[True]} s, overhead {overhead:+.1%}"
    )
    assert len(await outcomes()) == 2 * BULK  # one row per job reaped with the trigger on
    assert overhead < 0.20
