"""Trusted handling of analyzer messages.

Nothing in a message is trusted beyond what it can prove: the job is located through the
non-tenant index (the org in the message must match), the per-job token must hash to the
stored digest, and only state-valid transitions apply.

A success report is only accepted with its result: the exact reported version is
downloaded, fully validated outside any transaction, then written together with the final
state in one transaction (all rows or none). What "validated" and "written" mean depends on
the job's analyzer (one ingester per analyzer, see SUCCESS_INGESTERS).

M8: a memory job may also report `failed` / `symbols_missing` WITH a result version: its
diagnostic stream (the symbols it needs) goes to DIAGNOSTIC_INGESTERS; a failed report of any
other analyzer, or with another code, never has its result read: carrying a result version
anyway fails the job `invalid_result`.
"""

import errno
import hashlib
import hmac
import logging
import shutil
import tempfile
from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import anyio
import urllib3
from asyncpg.exceptions._base import DataError as ArgumentDataError
from cyberlab_jobs import IngestEvent, IngestMessageV1, Outcome
from minio.error import S3Error
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients import get_minio
from app.core.config import Settings, get_settings
from app.core.tenancy import tenant_session
from app.core.threads import evidence_io_limiter
from app.modules.analysis import analyzers, lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.dispatch import result_key
from app.modules.analysis.models import (
    ACTIVE,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
    Analyzer,
    JobProfile,
)
from app.modules.analysis.result_stream import InvalidResult
from app.modules.audit import service as audit
from app.modules.disk_forensics import handoff as disk_handoff
from app.modules.disk_forensics import ingest as disk_ingest
from app.modules.disk_forensics import ingest_export as disk_ingest_export
from app.modules.evidence.models import (
    CustodyAction,
    Evidence,
    EvidenceCustodyEvent,
    EvidenceHash,
)
from app.modules.memory_analysis import ingest as memory_ingest
from app.modules.pcap_analysis import ingest as pcap_ingest
from app.modules.pcap_analysis import stream
from app.modules.static_analysis import ingest as static_ingest
from app.modules.static_analysis import stream as static_stream

log = logging.getLogger(__name__)

# Time the worker gets after reporting `started` before the reaper fails the job.
RUNNING_GRACE_S = 120
DOWNLOAD_CHUNK = 1024**2
# Every scratch dir is created with this prefix, so a restart can sweep what a crash left.
TMP_PREFIX = "ingest-"


class ResultMissing(Exception):
    """The reported result version does not exist (never uploaded, or a forged version id)."""


class ResultTooLarge(Exception):
    pass


class ScratchSpaceExhausted(Exception):
    """No room on the scratch volume for this result now: transient, the task retries."""


def prepare_scratch(settings: Settings) -> None:
    """Ingest worker start-up: require a scratch dir outside tests and sweep its leftovers.

    Assumes one consumer per scratch volume (the compose service has its own volume), so a
    leftover `ingest-*` dir can only belong to a run that died with the previous process.
    """
    if settings.ingest_tmp_dir is None:
        if settings.env == "test":
            return
        raise RuntimeError("INGEST_TMP_DIR must be set for the ingest worker")
    root = Path(settings.ingest_tmp_dir)
    if not root.is_absolute() or not root.is_dir():
        raise RuntimeError(f"INGEST_TMP_DIR {root} is not an absolute path to a directory")
    for leftover in root.glob(f"{TMP_PREFIX}*"):
        log.warning("removing leftover ingest scratch dir %s", leftover)
        if leftover.is_dir() and not leftover.is_symlink():
            shutil.rmtree(leftover)
        else:
            leftover.unlink()


def _token_ok(job: AnalysisJob, token: str) -> bool:
    digest = hashlib.sha256(token.encode()).hexdigest()
    return hmac.compare_digest(digest, job.ingest_token_sha256)


def _download_sync(
    bucket: str, key: str, version_id: str, dest: Path, max_bytes: int, reserve_bytes: int
) -> None:
    try:
        response = get_minio().get_object(bucket, key, version_id=version_id)
    except S3Error as exc:
        if exc.code in {"NoSuchKey", "NoSuchVersion", "InvalidArgument", "BadRequest"}:
            raise ResultMissing(exc.code) from exc
        raise
    written = 0
    try:
        length = response.headers.get("Content-Length")
        size = int(length) if length and length.isdigit() else max_bytes
        if size > max_bytes:
            raise ResultTooLarge()
        if shutil.disk_usage(dest.parent).free < size + reserve_bytes:
            raise ScratchSpaceExhausted(f"{size} bytes needed in {dest.parent}")
        with open(dest, "xb") as out:
            for chunk in response.stream(DOWNLOAD_CHUNK):
                written += len(chunk)
                if written > max_bytes:
                    raise ResultTooLarge()
                out.write(chunk)
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise ScratchSpaceExhausted(str(dest.parent)) from exc
        raise
    finally:
        response.close()
        response.release_conn()


async def _download_result(job: AnalysisJob, version_id: str, dest: Path) -> None:
    """Copy the exact result version the analyzer reported (key re-derived) to `dest`."""
    settings = get_settings()
    await anyio.to_thread.run_sync(
        _download_sync,
        settings.results_bucket,
        result_key(job.organization_id, job.id),
        version_id,
        dest,
        analyzers.max_result_bytes(settings, job.analyzer),
        settings.ingest_min_free_bytes,
        limiter=evidence_io_limiter(),
    )


def _refused_by_database(exc: DBAPIError) -> bool:
    """A value the database will not store: SQLSTATE class 22 (data exception) or 23
    (integrity violation), or asyncpg's client-side check of a query argument (e.g. an
    integer outside int64), which SQLAlchemy reports as an InterfaceError.

    Validation should make this unreachable; if a gap remains, the result is still the
    analyzer's fault (invalid_result), never a retryable infrastructure error.
    """
    seen: BaseException | None = exc.orig
    for _ in range(4):  # DBAPIError -> adapted driver error -> asyncpg error
        if seen is None:
            break
        if isinstance(seen, ArgumentDataError):
            return True
        state = getattr(seen, "sqlstate", None)
        if isinstance(state, str) and state[:2] in {"22", "23"}:
            return True
        seen = seen.__cause__
    return False


def _audit(session: AsyncSession, job: AnalysisJob, action: str, **details: Any) -> None:
    audit.record(
        session,
        action=action,
        org_id=job.organization_id,
        actor_id=None,
        target_type="analysis_job",
        target_id=job.id,
        details={"evidence_id": str(job.evidence_id), **details},
    )


async def _apply(session: AsyncSession, job: AnalysisJob, msg: IngestMessageV1) -> None:
    """`started` and failed `finished` reports (successes go through ingest_success)."""
    settings = get_settings()
    if msg.event == IngestEvent.STARTED:
        if await lifecycle.transition(
            session,
            job,
            AnalysisStatus.RUNNING,
            allowed_from=(AnalysisStatus.QUEUED,),
            deadline_at=lifecycle.now()
            + timedelta(seconds=analyzers.timeout_s(settings, job.analyzer) + RUNNING_GRACE_S),
        ):
            job.worker_version = msg.worker_version
        return
    await _fail(session, job, msg.error_code or "analyzer_failed")


async def _fail(session: AsyncSession, job: AnalysisJob, code: str) -> None:
    if await lifecycle.transition(
        session,
        job,
        AnalysisStatus.FAILED,
        allowed_from=(AnalysisStatus.QUEUED, AnalysisStatus.RUNNING),
        error_code=code,
    ):
        _audit(session, job, "analysis.failed", error_code=code)


async def _fail_job(job: AnalysisJob, code: str) -> None:
    async with tenant_session(job.organization_id, None) as session:
        locked = await repo.get_for_update(session, job.organization_id, job.id)
        if locked is not None:
            await _fail(session, locked, code)


async def _record_success(
    session: AsyncSession, locked: AnalysisJob, msg: IngestMessageV1, summary: dict[str, Any]
) -> None:
    """Final state, result version, summary, `analyzed` custody event and audit entry.

    `locked` is the job loaded FOR UPDATE in `session`, still active.
    """
    if not await lifecycle.transition(
        session, locked, AnalysisStatus.SUCCEEDED, allowed_from=ACTIVE
    ):
        raise RuntimeError("job left the active states under its row lock")
    locked.result_version_id = msg.result_version_id
    locked.worker_version = msg.worker_version
    locked.summary = summary
    custody: dict[str, Any] = {
        "job_id": str(locked.id),
        "system": True,
        "worker": msg.worker_version,
    }
    if "tool_versions" in summary:
        custody["tool_versions"] = summary["tool_versions"]
    session.add(
        EvidenceCustodyEvent(
            organization_id=locked.organization_id,
            evidence_id=locked.evidence_id,
            action=CustodyAction.ANALYZED,
            # The requester is accountable for the run; the worker acted for them.
            actor_id=locked.requested_by,
            details=custody,
        )
    )
    _audit(
        session,
        locked,
        "analysis.succeeded",
        worker=msg.worker_version,
        counts=summary.get("counts", {}),
    )


async def _limit_transaction(session: AsyncSession, settings: Settings) -> None:
    # Transaction-local (SET LOCAL): both revert to the role defaults at commit/rollback.
    await session.execute(
        text(
            "SELECT set_config('statement_timeout', :statement, true), "
            "set_config('idle_in_transaction_session_timeout', :idle, true)"
        ),
        {
            "statement": f"{settings.ingest_statement_timeout_s}s",
            "idle": f"{settings.ingest_idle_in_transaction_timeout_s}s",
        },
    )


# Writes a validated result's rows in the persist transaction; returns the job summary.
Writer = Callable[[AsyncSession], Awaitable[dict[str, Any]]]


async def _persist(job: AnalysisJob, msg: IngestMessageV1, write: Writer) -> None:
    """One transaction: rows, summary, final state, custody and audit, or nothing at all."""
    settings = get_settings()
    async with tenant_session(job.organization_id, None) as session:
        await _limit_transaction(session, settings)
        # The guard runs under the row lock in this same transaction, so a redelivered
        # report after success (or after the reaper) can never insert a second copy.
        locked = await repo.get_for_update(session, job.organization_id, job.id)
        if locked is None or locked.status not in ACTIVE:
            return
        summary = await write(session)
        await _record_success(session, locked, msg, summary)


def _check_written(written: Counter[str], validated: Counter[str], *, skip: str = "") -> None:
    expected = +validated
    expected.pop(skip, None)
    if written != expected:
        raise RuntimeError(f"ingest wrote {dict(written)}, validated {dict(expected)}")


async def _refuse(job: AnalysisJob, exc: InvalidResult) -> None:
    log.warning("refusing the result of analysis job %s: %s", job.id, exc.reason)
    await _fail_job(job, "invalid_result")


async def _ingest_pcap(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """`pcap.v1`: validate the whole stream (worker thread), then write it in one transaction."""
    caps = stream.Caps.from_settings(get_settings())
    try:
        result = await anyio.to_thread.run_sync(stream.validate, path, job.id, caps)
    except InvalidResult as exc:
        await _refuse(job, exc)
        return

    async def write(session: AsyncSession) -> dict[str, Any]:
        written = await pcap_ingest.insert_rows(session, job.organization_id, job.id, path, caps)
        _check_written(written, result.counts, skip="stats")
        return pcap_ingest.build_summary(result, written)

    await _persist(job, msg, write)


async def _evidence_facts(job: AnalysisJob) -> static_stream.Expected:
    """The trusted record of the analyzed evidence (size + hashes computed at upload)."""
    async with tenant_session(job.organization_id, None) as session:
        size = await session.scalar(
            select(Evidence.size_bytes).where(
                Evidence.id == job.evidence_id, Evidence.organization_id == job.organization_id
            )
        )
        rows = await session.execute(
            select(EvidenceHash.algorithm, EvidenceHash.value).where(
                EvidenceHash.evidence_id == job.evidence_id,
                EvidenceHash.organization_id == job.organization_id,
            )
        )
        hashes = {algorithm.value: value for algorithm, value in rows}
    if size is None or "sha256" not in hashes:
        raise RuntimeError(f"evidence record of analysis job {job.id} is incomplete")
    return static_stream.Expected(
        sha256=hashes["sha256"], size=size, md5=hashes.get("md5"), sha1=hashes.get("sha1")
    )


async def _ingest_static(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """`static.v1`: validate the whole stream, incl. the sample against the evidence record
    (worker thread), then write it in one transaction."""
    caps = static_stream.Caps.from_settings(get_settings())
    expected = await _evidence_facts(job)
    try:
        result = await anyio.to_thread.run_sync(
            static_stream.validate, path, job.id, expected, caps
        )
    except InvalidResult as exc:
        await _refuse(job, exc)
        return

    async def write(session: AsyncSession) -> dict[str, Any]:
        written = await static_ingest.insert_rows(
            session, job.organization_id, job.id, path, result, caps
        )
        _check_written(written, result.counts)
        return static_ingest.build_summary(result, written, expected)

    await _persist(job, msg, write)


# One success handler per analyzer: (job, report, downloaded result file) -> None.
Ingester = Callable[[AnalysisJob, IngestMessageV1, Path], Awaitable[None]]
SUCCESS_INGESTERS: dict[Analyzer, Ingester] = {
    Analyzer.PCAP: _ingest_pcap,
    Analyzer.STATIC: _ingest_static,
    Analyzer.MEMORY: memory_ingest.ingest_memory,
    # M9: run by the disk ingest worker (task `disk.ingest`, queue `ingest_disk`; RT9), never
    # by this one: `handle_event` hands every disk result off first.
    Analyzer.DISK: disk_ingest.ingest_disk,
}
# M8: failed reports that carry a diagnostic result (memory `symbols_missing`; M9: disk
# `no_supported_filesystem` / `unsupported_disk_format`, on the disk ingest worker).
DIAGNOSTIC_INGESTERS: dict[Analyzer, Ingester] = {
    Analyzer.MEMORY: memory_ingest.ingest_memory_diagnostic,
    Analyzer.DISK: disk_ingest.ingest_disk_diagnostic,
}
DIAGNOSTIC_CODES_BY_ANALYZER: dict[Analyzer, frozenset[str]] = {
    Analyzer.MEMORY: frozenset({"symbols_missing"}),
    Analyzer.DISK: frozenset({"no_supported_filesystem", "unsupported_disk_format"}),
}
DIAGNOSTIC_CODES: frozenset[str] = frozenset().union(*DIAGNOSTIC_CODES_BY_ANALYZER.values())


async def ingest_success(job: AnalysisJob, msg: IngestMessageV1) -> None:
    """Download the exact reported result (no transaction open), then hand it to the
    analyzer's ingester, which validates and persists it.

    `job` must already be authenticated for `msg`. Any defect in the result (including a
    value the database refuses despite validation) fails the job with `invalid_result` and
    writes no rows.
    """
    if job.status not in ACTIVE or not msg.result_version_id:
        return  # already final (unlocked read; ingesters re-check under the row lock)
    await _ingest_result(job, msg, SUCCESS_INGESTERS[job.analyzer])


def is_diagnostic(job: AnalysisJob, msg: IngestMessageV1) -> bool:
    """A failed report whose result must be read (M8: memory `symbols_missing`)."""
    return (
        msg.outcome == Outcome.FAILED
        and msg.result_version_id is not None
        and job.analyzer in DIAGNOSTIC_INGESTERS
        and msg.error_code in DIAGNOSTIC_CODES_BY_ANALYZER.get(job.analyzer, frozenset())
    )


async def ingest_diagnostic(job: AnalysisJob, msg: IngestMessageV1) -> None:
    """The diagnostic stream of a failed memory job (phase-6 body in memory_analysis)."""
    if job.status not in ACTIVE or not msg.result_version_id:
        return
    await _ingest_result(job, msg, DIAGNOSTIC_INGESTERS[job.analyzer])


async def _ingest_result(job: AnalysisJob, msg: IngestMessageV1, ingester: Ingester) -> None:
    assert msg.result_version_id is not None  # noqa: S101 - checked by both callers
    settings = get_settings()
    with tempfile.TemporaryDirectory(prefix=TMP_PREFIX, dir=settings.ingest_tmp_dir) as tmp:
        path = Path(tmp) / "result.ndjson.gz"
        try:
            await _download_result(job, msg.result_version_id, path)
        except (ResultMissing, ResultTooLarge) as exc:
            log.warning("refusing the result of analysis job %s: %s", job.id, type(exc).__name__)
            await _fail_job(job, "invalid_result")
            return
        try:
            await ingester(job, msg, path)
        except DBAPIError as exc:
            if not _refused_by_database(exc):
                raise
            # The transaction rolled back as a whole: no rows, the job is still active.
            log.warning("database refused the result of analysis job %s: %s", job.id, exc.orig)
            await _fail_job(job, "invalid_result")


# Worth retrying (the task redelivers): infrastructure hiccups, never logic errors.
TRANSIENT_ERRORS: tuple[type[BaseException], ...] = (
    OperationalError,
    InterfaceError,
    ConnectionError,
    TimeoutError,
    urllib3.exceptions.HTTPError,
    ScratchSpaceExhausted,
)


async def _authenticated_job(msg: IngestMessageV1) -> AnalysisJob | None:
    """The job a message may act on, or None (dropped). Takes no row locks."""
    async with tenant_session(None, None) as session:
        index = await session.get(AnalysisJobIndex, msg.job_id)
        org_id = index.organization_id if index else None
    if org_id is None or org_id != msg.organization_id:
        log.warning("dropping ingest message for unknown job %s", msg.job_id)
        return None
    # The org comes from our own index row, never from the message alone.
    async with tenant_session(org_id, None) as session:
        job = await session.get(AnalysisJob, msg.job_id)
    if job is None:
        return None
    if not _token_ok(job, msg.ingest_token):
        log.warning("dropping ingest message with a bad token for job %s", job.id)
        return None
    return job


def _carries_disk_result(job: AnalysisJob, msg: IngestMessageV1) -> bool:
    """A disk report the disk ingest worker reads: success (`disk.v1`, or `disk-export.v1`
    for an `extract` job) or a diagnostic failure."""
    if msg.result_version_id is None:
        return False
    return msg.outcome == Outcome.SUCCEEDED or is_diagnostic(job, msg)


async def handle_disk_ingest(raw: dict[str, Any]) -> None:
    """The task `disk.ingest` (disk ingest worker, M9 RT9): the report handed off by
    `handle_event`, re-authenticated here (token and org from our own index), then one of
    three schema branches: `disk-export.v1` (an `extract` job, phase 10), `disk.v1` (a
    success, phase 7), or the diagnostic stream (phase 7). A permanent failure is recorded on
    the job (`ingest_error`); transient ones are retried by the task."""
    try:
        msg = IngestMessageV1.model_validate(raw)
    except ValidationError:
        log.warning("dropping invalid disk ingest message")
        return
    job = await _authenticated_job(msg)
    if job is None or job.analyzer != Analyzer.DISK or job.status not in ACTIVE:
        return
    if not _carries_disk_result(job, msg):
        return
    org_id = job.organization_id
    try:
        if job.profile == JobProfile.EXTRACT:
            await _ingest_result(job, msg, disk_ingest_export.ingest_disk_export)
        elif msg.outcome == Outcome.SUCCEEDED:
            await _ingest_result(job, msg, SUCCESS_INGESTERS[Analyzer.DISK])
        else:
            await _ingest_result(job, msg, DIAGNOSTIC_INGESTERS[Analyzer.DISK])
    except TRANSIENT_ERRORS:
        raise
    except Exception:
        log.exception("disk ingest failed for analysis job %s", msg.job_id)
        async with tenant_session(org_id, None) as session:
            locked = await repo.get_for_update(session, org_id, msg.job_id)
            if locked is not None:
                await _fail(session, locked, "ingest_error")


async def handle_event(raw: dict[str, Any]) -> None:
    try:
        msg = IngestMessageV1.model_validate(raw)
    except ValidationError:
        log.warning("dropping invalid ingest message")
        return

    job = await _authenticated_job(msg)
    if job is None:
        return
    org_id = job.organization_id
    try:
        if job.analyzer == Analyzer.DISK and _carries_disk_result(job, msg):
            # M9 (RT9): validated here, ingested by the disk ingest worker (`disk.ingest` on
            # `ingest_disk`); the hand-off moves the deadline by DISK_INGEST_TIMEOUT_S.
            if job.status in ACTIVE:
                await disk_handoff.hand_off(job, msg)
            return
        if msg.outcome == Outcome.SUCCEEDED:
            await ingest_success(job, msg)
            return
        if is_diagnostic(job, msg):
            await ingest_diagnostic(job, msg)
            return
        if msg.outcome == Outcome.FAILED and msg.result_version_id is not None:
            # M8: only a memory `symbols_missing` report may carry a result. Any other
            # failed report with one (another analyzer, another code) is refused unread.
            log.warning("refusing a failed report with a result for analysis job %s", job.id)
            await _fail_job(job, "invalid_result")
            return
        async with tenant_session(org_id, None) as session:
            locked = await repo.get_for_update(session, org_id, msg.job_id)
            if locked is not None:
                await _apply(session, locked, msg)
    except TRANSIENT_ERRORS:
        raise
    except Exception:
        # A permanent failure must not be retried into silence: record it on the job.
        log.exception("ingest failed for analysis job %s", msg.job_id)
        async with tenant_session(org_id, None) as session:
            locked = await repo.get_for_update(session, org_id, msg.job_id)
            if locked is not None:
                await _fail(session, locked, "ingest_error")
