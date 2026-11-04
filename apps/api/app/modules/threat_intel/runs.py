"""Enrichment run creation (API side; no HTTP, no provider, no DNS).

Phase 5's routes call `create_run` inside their request transaction and `dispatch` after the
commit. The run's plan is frozen at creation (RT9): one `ti_run_items` row per eligible
(IOC, provider) pair, in `seq` order (job: sample hashes first, then the job's IOCs by
occurrence count). Nothing ineligible is ever planned, so nothing ineligible can reach the
worker or a transport.

The run summary written here (later completed by the worker):
    {"planned_values": n, "items": m, "truncated": bool, "duplicates": d,
     "skipped": {reason: n},               # values no requested provider may receive
     "providers": {provider: {"planned": k, "skipped_<reason>": n, ...}}}
"""

import logging
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
from cyberlab_jobs import TI_ENRICH, Queues
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.threads import broker_limiter
from app.modules.analysis.models import AnalysisJob
from app.modules.pcap_analysis.models import Ioc
from app.modules.static_analysis.models import MalwareSample
from app.modules.threat_intel.availability import provider_available
from app.modules.threat_intel.messages import TiRunMessage
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiOrgSettings,
    TiProviderConfig,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.normalize import Normalized, Skip, eligible, normalize
from app.modules.threat_intel.providers.base import ProviderName

log = logging.getLogger(__name__)

# How many job IOC rows are examined to fill the per-run cap (most frequent first).
SCAN_FACTOR = 10
MIN_SCAN = 2000
SEND_TIMEOUT_S = 15


class RunError(Exception):
    """A refused run request; `code` is a fixed string for the API's error envelope."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LookupValue:
    value: str
    type_hint: str | None = None


@dataclass(frozen=True)
class ValueReport:
    """The normalization outcome of one manual lookup value (for the UI)."""

    index: int
    ioc_type: str | None
    value_norm: str | None
    ioc_key: str | None
    notes: tuple[str, ...]
    # Set when no requested provider may receive the value (nothing is sent).
    skipped: str | None
    providers: tuple[str, ...]
    provider_skips: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RunCreated:
    run_id: uuid.UUID | None  # None: nothing eligible, no run created
    items: int
    summary: dict[str, Any]
    report: tuple[ValueReport, ...] = ()
    deadline_at: datetime | None = None


@dataclass
class _Plan:
    providers: tuple[ProviderName, ...]
    excluded: tuple[str, ...]
    cap: int
    values: list[tuple[Normalized, list[ProviderName]]] = field(default_factory=list)
    keys: set[str] = field(default_factory=set)
    skipped: Counter[str] = field(default_factory=Counter)
    provider_skips: dict[str, Counter[str]] = field(default_factory=dict)
    duplicates: int = 0
    truncated: bool = False

    def add(self, type_hint: str | None, raw: str) -> ValueReport | None:
        outcome = normalize(type_hint, raw)
        targets: list[ProviderName] = []
        skips: dict[str, str] = {}
        chosen: Normalized | None = None
        for provider in self.providers:
            verdict = eligible(outcome, provider, self.excluded)
            if isinstance(verdict, Normalized):
                targets.append(provider)
                chosen = chosen or verdict
            else:
                skips[provider.value] = verdict.reason.value
        base = outcome if isinstance(outcome, Normalized) else chosen
        notes = tuple(n.value for n in (base.notes if base else outcome.notes))
        ioc_type = base.ioc_type.value if base else _skip_type(outcome)
        value_norm = base.value_norm if base else _skip_value(outcome)

        if chosen is None:
            reason = outcome.reason.value if isinstance(outcome, Skip) else _first(skips)
            self.skipped[reason] += 1
            self._count_provider_skips(skips)
            return ValueReport(-1, ioc_type, value_norm, None, notes, reason, (), skips)
        if chosen.ioc_key in self.keys:
            self.duplicates += 1
            return ValueReport(-1, ioc_type, value_norm, chosen.ioc_key, notes, None, (), {})
        if len(self.values) >= self.cap:
            self.truncated = True
            return None
        self.keys.add(chosen.ioc_key)
        self.values.append((chosen, targets))
        self._count_provider_skips(skips)
        report_targets = tuple(p.value for p in targets)
        return ValueReport(
            -1, ioc_type, value_norm, chosen.ioc_key, notes, None, report_targets, skips
        )

    def _count_provider_skips(self, skips: dict[str, str]) -> None:
        for provider, reason in skips.items():
            self.provider_skips.setdefault(provider, Counter())[f"skipped_{reason}"] += 1

    def summary(self) -> dict[str, Any]:
        planned: Counter[str] = Counter(p.value for _, targets in self.values for p in targets)
        providers: dict[str, dict[str, int]] = {}
        for provider in self.providers:
            counts: dict[str, int] = {"planned": planned[provider.value]}
            counts.update(self.provider_skips.get(provider.value, {}))
            providers[provider.value] = counts
        return {
            "planned_values": len(self.values),
            "items": sum(planned.values()),
            "truncated": self.truncated,
            "duplicates": self.duplicates,
            "skipped": dict(self.skipped),
            "providers": providers,
        }


def _first(skips: dict[str, str]) -> str:
    return next(iter(skips.values()), "unsupported_type")


def _skip_type(outcome: Normalized | Skip) -> str | None:
    if isinstance(outcome, Skip) and outcome.ioc_type is not None:
        return outcome.ioc_type.value
    return None


def _skip_value(outcome: Normalized | Skip) -> str | None:
    return outcome.value_norm if isinstance(outcome, Skip) else None


def _providers(
    providers: Sequence[ProviderName | str], settings: Settings
) -> tuple[ProviderName, ...]:
    names: list[ProviderName] = []
    for raw in providers:
        try:
            name = ProviderName(raw)
        except ValueError:
            raise RunError("unknown_provider") from None
        if not provider_available(name, settings):
            raise RunError("provider_unavailable", name.value)
        if name not in names:
            names.append(name)
    if not names:
        raise RunError("no_provider_enabled")
    return tuple(names)


async def _check_enabled(
    session: AsyncSession, org_id: uuid.UUID, providers: tuple[ProviderName, ...]
) -> None:
    enabled = set(
        (
            await session.scalars(
                select(TiProviderConfig.provider).where(
                    TiProviderConfig.organization_id == org_id,
                    TiProviderConfig.provider.in_([p.value for p in providers]),
                    TiProviderConfig.enabled.is_(True),
                    TiProviderConfig.key_ct.is_not(None),
                )
            )
        ).all()
    )
    missing = [p.value for p in providers if p.value not in enabled]
    if missing:
        raise RunError("provider_not_enabled", ",".join(missing))


async def _excluded_suffixes(session: AsyncSession, org_id: uuid.UUID) -> tuple[str, ...]:
    settings_row = await session.get(TiOrgSettings, org_id)
    if settings_row is None:
        return ()
    return tuple(s for s in settings_row.excluded_suffixes if isinstance(s, str) and s)


async def _plan_job(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, plan: _Plan
) -> None:
    job = await session.scalar(
        select(AnalysisJob.id).where(
            AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id
        )
    )
    if job is None:
        raise RunError("job_not_found")
    # The analyzed file's trusted hashes first (a sample is only ever sent as its hashes).
    sample = (
        await session.execute(
            select(MalwareSample.sha256, MalwareSample.sha1, MalwareSample.md5).where(
                MalwareSample.organization_id == org_id, MalwareSample.job_id == job_id
            )
        )
    ).first()
    if sample is not None:
        for hint, value in zip(("file_sha256", "file_sha1", "file_md5"), sample, strict=True):
            plan.add(hint, value)
    scan = max(plan.cap * SCAN_FACTOR, MIN_SCAN)
    rows = await session.execute(
        select(Ioc.type, Ioc.value)
        .where(Ioc.organization_id == org_id, Ioc.job_id == job_id)
        .order_by(Ioc.count.desc(), Ioc.first_seen, Ioc.id)
        .limit(scan + 1)
    )
    for n, (ioc_type, value) in enumerate(rows):
        if n == scan:
            plan.truncated = True  # more IOCs than examined
            break
        plan.add(ioc_type, value)
        if plan.truncated:
            break


async def create_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    scope: str,
    *,
    job_id: uuid.UUID | None = None,
    values: Sequence[LookupValue | str] | None = None,
    providers: Sequence[ProviderName | str],
    requested_by: uuid.UUID,
    settings: Settings | None = None,
) -> RunCreated:
    """Plan and insert a run in the caller's transaction (tenant session of `org_id`).

    Raises `RunError` (`unknown_provider`, `provider_unavailable`, `no_provider_enabled`,
    `provider_not_enabled`, `job_not_found`, `no_values`, `too_many_values`, `bad_scope`).
    With nothing eligible, no row is written and `run_id` is None.
    """
    settings = settings or get_settings()
    if not settings.ti_enabled:
        raise RunError("provider_unavailable")
    names = _providers(providers, settings)
    await _check_enabled(session, org_id, names)
    plan = _Plan(names, await _excluded_suffixes(session, org_id), settings.ti_max_iocs_per_run)

    reports: list[ValueReport] = []
    if scope == "job":
        if job_id is None or values is not None:
            raise RunError("bad_scope")
        await _plan_job(session, org_id, job_id, plan)
    elif scope == "manual":
        if job_id is not None or not values:
            raise RunError("no_values" if not values else "bad_scope")
        if len(values) > settings.ti_max_lookup_values:
            raise RunError("too_many_values")
        for index, item in enumerate(values):
            lookup = item if isinstance(item, LookupValue) else LookupValue(item)
            report = plan.add(lookup.type_hint, lookup.value)
            if report is not None:
                reports.append(_with_index(report, index))
    else:
        raise RunError("bad_scope")

    summary = plan.summary()
    if not plan.values:
        return RunCreated(None, 0, summary, tuple(reports))

    run_id = uuid.uuid4()
    deadline = datetime.now(UTC) + timedelta(seconds=settings.ti_run_deadline_s)
    session.add(
        TiEnrichmentRun(
            id=run_id,
            organization_id=org_id,
            scope=scope,
            job_id=job_id,
            requested_by=requested_by,
            providers=[p.value for p in names],
            status="queued",
            summary=summary,
            deadline_at=deadline,
        )
    )
    await session.flush()
    session.add(
        TiRunIndex(
            run_id=run_id,
            organization_id=org_id,
            status="queued",
            deadline_at=deadline,
            dispatched_at=datetime.now(UTC),
        )
    )
    rows: list[dict[str, Any]] = []
    for normalized, targets in plan.values:
        for provider in targets:
            rows.append(
                {
                    "run_id": run_id,
                    "organization_id": org_id,
                    "seq": len(rows),
                    "provider": provider.value,
                    "ioc_type": normalized.ioc_type.value,
                    "value_norm": normalized.value_norm,
                    "ioc_key": normalized.ioc_key,
                    "state": "pending",
                }
            )
    await session.flush()
    await session.execute(insert(TiRunItem), rows)
    return RunCreated(run_id, len(rows), summary, tuple(reports), deadline)


def _with_index(report: ValueReport, index: int) -> ValueReport:
    return ValueReport(
        index,
        report.ioc_type,
        report.value_norm,
        report.ioc_key,
        report.notes,
        report.skipped,
        report.providers,
        report.provider_skips,
    )


def _send_sync(message: TiRunMessage) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    celery_app.send_task(
        TI_ENRICH,
        kwargs={"message": message.model_dump(mode="json")},
        queue=Queues(get_settings().queue_prefix).enrich,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def dispatch(run_id: uuid.UUID, org_id: uuid.UUID) -> bool:
    """Publish `ti.enrich` after the commit, bounded like `analysis.dispatch.send`. A failure
    is logged and left to `ti.resume` (the run stays queued with its `dispatched_at`)."""
    message = TiRunMessage(run_id=run_id, org_id=org_id)
    try:
        with anyio.fail_after(SEND_TIMEOUT_S):
            await anyio.to_thread.run_sync(
                _send_sync, message, limiter=broker_limiter(), abandon_on_cancel=True
            )
    except Exception as exc:  # noqa: BLE001 - any broker failure is left to ti.resume
        log.warning("ti.enrich publish failed for run %s (%s)", run_id, type(exc).__name__)
        return False
    return True


__all__ = ["LookupValue", "RunCreated", "RunError", "ValueReport", "create_run", "dispatch"]
