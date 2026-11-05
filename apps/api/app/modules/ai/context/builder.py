"""Context builder entry points (signatures FROZEN in phase 1; bodies M5 phase 4).

Both run inside the caller's `require()` tenant session: they never open their own session
and never bypass RLS (every query also filters on the org explicitly). Errors are
`contracts.ContextBuildError(code)`:
- `target_not_found`: the job / investigation is not in the org, or the explain target is
  not a row of the job;
- `job_not_ready`: the job has not succeeded;
- `task_not_applicable`: the task needs another analyzer (`summarize_pcap` / `explain_alert`
  need a pcap job, `explain_static` a static one);
- `context_empty`: nothing to analyze (no succeeded job in an investigation, no IOC for
  `ioc_correlation`, no finding / capability / signature / alert for `attack_mapping`, or a
  budget too small for the first item).

Selection order = output order = budget priority (labels are per-kind counters in this
order, so the same DB state always gives the same labels, bytes and sha256):

| Task | Order |
|---|---|
| `summarize_pcap`, pcap `job_digest` | J, F, A (by sid), I, T, E, N, R |
| `explain_static`, static `job_digest` | J, M, P, F, S, C, I, T, X (opt-in) |
| `explain_finding` | target F, J, related A, C (static), I, T, N, R |
| `explain_alert` | target A, J, related F, I, N, R |
| `ioc_correlation` | J…, I, T, F and A mentioning the IOCs |
| `attack_mapping` | J…, F, C, S, A (by sid) |
| `incident_summary` (root) | V, K, J1…Jn (one per child, in child order), E (merged) |

T items appear only with `include_ti`, X only with `include_strings`, V's title and
description only with `include_case_text`. An incident has one `job_digest` child per latest
succeeded job per evidence (newest first, ≤ `AI_MAX_JOBS_PER_INCIDENT`; `children[i]` is
`J{i+1}` in the root and in the reduce); one pseudonymizer serves the children (in order)
and then the root.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.modules.ai.context import select as sel
from app.modules.ai.context.assemble import Selection, assemble
from app.modules.ai.context.estimate import context_budget
from app.modules.ai.context.fields import RawItem
from app.modules.ai.context.pseudonymize import Pseudonymizer
from app.modules.ai.contracts import (
    AiRunRequest,
    AiScope,
    AiTask,
    BuiltRun,
    ContextBuildError,
    FrozenContext,
    RefKind,
    RunScope,
)
from app.modules.ai.labels import format_label
from app.modules.ai.models import AiOrgSettings
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.investigations.models import Investigation
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert

PCAP_TASKS = frozenset({AiTask.SUMMARIZE_PCAP, AiTask.EXPLAIN_ALERT})
STATIC_TASKS = frozenset({AiTask.EXPLAIN_STATIC})


@dataclass(frozen=True)
class Options:
    include_ti: bool
    include_strings: bool
    include_case_text: bool
    budget_tokens: int
    max_jobs: int


def options(settings_row: AiOrgSettings, *, max_input_tokens: int, max_jobs: int) -> Options:
    return Options(
        include_ti=bool(settings_row.include_ti),
        include_strings=bool(settings_row.include_strings),
        include_case_text=bool(settings_row.include_case_text),
        budget_tokens=context_budget(max_input_tokens),
        max_jobs=max_jobs,
    )


def pseudonymizer_for(settings_row: AiOrgSettings) -> Pseudonymizer:
    return Pseudonymizer(
        enabled=bool(settings_row.pseudonymize_internal),
        internal_cidrs=settings_row.internal_cidrs or (),
        internal_suffixes=settings_row.internal_suffixes or (),
    )


async def build_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    settings_row: AiOrgSettings,
) -> BuiltRun:
    """The root context and, for `incident_summary`, one `job_digest` child per job."""
    settings = get_settings()
    opts = options(
        settings_row,
        max_input_tokens=settings.ai_max_input_tokens,
        max_jobs=settings.ai_max_jobs_per_incident,
    )
    return await build(session, org_id, req, settings_row, opts)


async def preview(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    settings_row: AiOrgSettings,
) -> FrozenContext:
    """What `build_run` would send (an incident previews its root, built after its children
    so the pseudonyms match the real run); never persisted."""
    return (await build_run(session, org_id, user_id, req, settings_row)).root


async def build(
    session: AsyncSession,
    org_id: uuid.UUID,
    req: AiRunRequest,
    settings_row: AiOrgSettings,
    opts: Options,
) -> BuiltRun:
    pz = pseudonymizer_for(settings_row)
    if req.task is AiTask.INCIDENT_SUMMARY and req.investigation_id is not None:
        return await _incident(session, org_id, req.investigation_id, opts, pz)
    if req.job_id is not None:
        job = await _ready_job(session, org_id, req.job_id, req.task)
        selections = await _job_selections(session, org_id, job, req.task, req.target_id, opts)
        scope = RunScope(scope=AiScope.JOB, job_ids=(job.id,))
        root = assemble(req.task, scope, selections, pz, budget_tokens=opts.budget_tokens)
        return BuiltRun(root=root)
    if req.investigation_id is None:  # AiRunRequest validates the shape
        raise ContextBuildError("task_not_applicable")
    return await _investigation_task(session, org_id, req.investigation_id, req.task, opts, pz)


# --- validation ----------------------------------------------------------------------------


async def _ready_job(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, task: AiTask
) -> AnalysisJob:
    job = await sel.get_job(session, org_id, job_id)
    if job is None:
        raise ContextBuildError("target_not_found")
    if job.status != AnalysisStatus.SUCCEEDED:
        raise ContextBuildError("job_not_ready")
    if task in PCAP_TASKS and job.analyzer != Analyzer.PCAP:
        raise ContextBuildError("task_not_applicable")
    if task in STATIC_TASKS and job.analyzer != Analyzer.STATIC:
        raise ContextBuildError("task_not_applicable")
    return job


def _require(selections: list[Selection], kinds: set[RefKind]) -> None:
    if not any(s.items for s in selections if s.kind in kinds):
        raise ContextBuildError("context_empty")


# --- job scope -----------------------------------------------------------------------------


def _flow_refs(items: list[RawItem]) -> list[str]:
    refs: list[str] = []
    for item in items:
        row = item.extra.get("row")
        if row is None:
            continue
        refs.extend(r for r in (getattr(row, "evidence_refs", None) or []) if isinstance(r, str))
        if getattr(row, "flow_ref", None):
            refs.append(row.flow_ref)
    return list(dict.fromkeys(refs))


def _haystack(*selections: Selection) -> str:
    parts: list[str] = []
    for selection in selections:
        for item in selection.items:
            parts.extend(str(v) for v in item.fields.values() if isinstance(v, str | int))
            row = item.extra.get("row")
            for column in ("src_ip", "dst_ip"):
                value = getattr(row, column, None) if row is not None else None
                if value is not None:
                    parts.append(str(value))
    return "\n".join(parts)


async def _ti(
    session: AsyncSession, org_id: uuid.UUID, iocs: Selection, opts: Options
) -> Selection:
    """T for the chosen IOCs; their I labels are I1…In (the only I selection of a context)."""
    if not opts.include_ti or not iocs.items:
        return Selection(RefKind.TI_RESULT, [], 0)
    rows = [item.extra["row"] for item in iocs.items]
    labels = [format_label(RefKind.IOC, i) for i in range(1, len(rows) + 1)]
    return await sel.ti_results(session, org_id, rows, labels)


async def _pcap_summary(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, opts: Options
) -> list[Selection]:
    jobs = [job.id]
    findings = await sel.findings(session, org_id, jobs)
    iocs = await sel.iocs(session, org_id, jobs)
    flows = await sel.flows(session, org_id, job.id, named=_flow_refs(findings.items))
    records = await sel.records_on_flows(session, org_id, job.id, [i.ref_id for i in flows.items])
    return [
        await sel.job_items(session, org_id, [job]),
        findings,
        await sel.alert_groups(session, org_id, jobs),
        iocs,
        await _ti(session, org_id, iocs, opts),
        await sel.job_timeline(session, org_id, job.id),
        flows,
        records,
    ]


async def _static_summary(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, opts: Options
) -> list[Selection]:
    jobs = [job.id]
    sample, pe = await sel.sample_items(session, org_id, job.id)
    iocs = await sel.iocs(session, org_id, jobs)
    selections = [
        await sel.job_items(session, org_id, [job]),
        sample,
        pe,
        await sel.findings(session, org_id, jobs),
        await sel.signatures(session, org_id, jobs),
        await sel.capabilities(session, org_id, jobs),
        iocs,
        await _ti(session, org_id, iocs, opts),
    ]
    if opts.include_strings:
        selections.append(await sel.floss_strings(session, org_id, job.id))
    return selections


async def _explain_finding(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, target_id: uuid.UUID, opts: Options
) -> list[Selection]:
    rows = await sel.finding_rows(
        session, org_id, [job.id], limit=1, where=[AnalysisFinding.id == target_id]
    )
    if not rows:
        raise ContextBuildError("target_not_found")
    target = Selection(RefKind.FINDING, [sel.finding_item(rows[0])], 1)
    row = rows[0]
    flows = await sel.flows(
        session,
        org_id,
        job.id,
        named=_flow_refs(target.items),
        top=0,
        pair=(row.src_ip, row.dst_ip),
    )
    flow_refs = [i.ref_id for i in flows.items]
    records = await sel.records_on_flows(session, org_id, job.id, flow_refs)
    alerts = await sel.related_alerts(
        session, org_id, job.id, flow_refs=flow_refs, src=row.src_ip, dst=row.dst_ip
    )
    iocs = await sel.iocs_mentioned(session, org_id, [job.id], _haystack(target, records))
    selections = [target, await sel.job_items(session, org_id, [job]), alerts]
    if job.analyzer == Analyzer.STATIC:
        selections.append(await sel.capabilities(session, org_id, [job.id]))
    selections += [iocs, await _ti(session, org_id, iocs, opts), flows, records]
    return selections


async def _explain_alert(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, target_id: uuid.UUID, opts: Options
) -> list[Selection]:
    rows = await sel.alert_rows(
        session, org_id, [job.id], limit=1, where=[NetworkAlert.id == target_id]
    )
    if not rows:
        raise ContextBuildError("target_not_found")
    row = rows[0]
    same_sid = await sel.alert_rows(
        session,
        org_id,
        [job.id],
        limit=sel.SCAN_LIMIT,
        where=[NetworkAlert.signature_id == row.signature_id],
    )
    first = min((r.ts for r in same_sid), default=row.ts)
    last = max((r.ts for r in same_sid), default=row.ts)
    target = Selection(
        RefKind.ALERT, [sel.alert_item(row, count=len(same_sid), first=first, last=last)], 1
    )
    flows = await sel.flows(
        session,
        org_id,
        job.id,
        named=[row.flow_ref] if row.flow_ref else [],
        top=0,
        pair=(row.src_ip, row.dst_ip),
    )
    records = await sel.records_on_flows(session, org_id, job.id, [i.ref_id for i in flows.items])
    findings = await sel.related_findings(
        session, org_id, job.id, flow_ref=row.flow_ref, src=row.src_ip, dst=row.dst_ip
    )
    iocs = await sel.iocs_mentioned(session, org_id, [job.id], _haystack(target, records))
    return [target, await sel.job_items(session, org_id, [job]), findings, iocs, flows, records]


async def _correlation(
    session: AsyncSession, org_id: uuid.UUID, jobs: list[AnalysisJob], opts: Options
) -> list[Selection]:
    ids = [j.id for j in jobs]
    iocs = await sel.iocs(session, org_id, ids)
    _require([iocs], {RefKind.IOC})
    values = [item.extra["row"].value.lower() for item in iocs.items]

    def mentions(selection: Selection, cap: int) -> Selection:
        kept = [
            item
            for item in selection.items
            if any(
                sel.mentions(v, _haystack(Selection(item.kind, [item], 1)).lower()) for v in values
            )
        ]
        return Selection(selection.kind, kept[:cap], len(kept))

    findings = await sel.findings(session, org_id, ids, cap=sel.SCAN_LIMIT)
    alerts = await sel.alert_groups(session, org_id, ids, cap=sel.SCAN_LIMIT)
    return [
        await sel.job_items(session, org_id, jobs),
        iocs,
        await _ti(session, org_id, iocs, opts),
        mentions(findings, sel.CAP_FINDINGS),
        mentions(alerts, sel.CAP_ALERT_GROUPS),
    ]


async def _attack_mapping(
    session: AsyncSession, org_id: uuid.UUID, jobs: list[AnalysisJob]
) -> list[Selection]:
    ids = [j.id for j in jobs]
    selections = [
        await sel.findings(session, org_id, ids),
        await sel.capabilities(session, org_id, ids),
        await sel.signatures(session, org_id, ids),
        await sel.alert_groups(session, org_id, ids),
    ]
    _require(selections, {RefKind.FINDING, RefKind.CAPABILITY, RefKind.SIGNATURE, RefKind.ALERT})
    return [await sel.job_items(session, org_id, jobs), *selections]


async def _digest_selections(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, opts: Options
) -> list[Selection]:
    if job.analyzer == Analyzer.STATIC:
        return await _static_summary(session, org_id, job, opts)
    return await _pcap_summary(session, org_id, job, opts)


async def _job_selections(
    session: AsyncSession,
    org_id: uuid.UUID,
    job: AnalysisJob,
    task: AiTask,
    target_id: uuid.UUID | None,
    opts: Options,
) -> list[Selection]:
    if task is AiTask.EXPLAIN_FINDING and target_id is not None:
        return await _explain_finding(session, org_id, job, target_id, opts)
    if task is AiTask.EXPLAIN_ALERT and target_id is not None:
        return await _explain_alert(session, org_id, job, target_id, opts)
    if task is AiTask.SUMMARIZE_PCAP:
        return await _pcap_summary(session, org_id, job, opts)
    if task is AiTask.EXPLAIN_STATIC:
        return await _static_summary(session, org_id, job, opts)
    if task is AiTask.IOC_CORRELATION:
        return await _correlation(session, org_id, [job], opts)
    if task is AiTask.ATTACK_MAPPING:
        return await _attack_mapping(session, org_id, [job])
    raise ContextBuildError("task_not_applicable")


# --- investigation scope -------------------------------------------------------------------


async def _case_jobs(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, opts: Options
) -> tuple[Investigation, list[AnalysisJob], int, RunScope]:
    investigation = await sel.get_investigation(session, org_id, investigation_id)
    if investigation is None:
        raise ContextBuildError("target_not_found")
    jobs = await sel.latest_succeeded_jobs(session, org_id, investigation_id)
    if not jobs:
        raise ContextBuildError("context_empty")
    omitted = max(len(jobs) - opts.max_jobs, 0)
    jobs = jobs[: opts.max_jobs]
    scope = RunScope(
        scope=AiScope.INVESTIGATION,
        job_ids=tuple(j.id for j in jobs),
        investigation_id=investigation_id,
        evidence_ids=tuple(await sel.evidence_ids(session, org_id, investigation_id)),
    )
    return investigation, jobs, omitted, scope


async def _investigation_task(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    task: AiTask,
    opts: Options,
    pz: Pseudonymizer,
) -> BuiltRun:
    _, jobs, omitted, scope = await _case_jobs(session, org_id, investigation_id, opts)
    if task is AiTask.IOC_CORRELATION:
        selections = await _correlation(session, org_id, jobs, opts)
    elif task is AiTask.ATTACK_MAPPING:
        selections = await _attack_mapping(session, org_id, jobs)
    else:
        raise ContextBuildError("task_not_applicable")
    root = assemble(
        task, scope, selections, pz, budget_tokens=opts.budget_tokens, jobs_omitted=omitted
    )
    return BuiltRun(root=root)


async def _incident(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    opts: Options,
    pz: Pseudonymizer,
) -> BuiltRun:
    investigation, jobs, omitted, scope = await _case_jobs(session, org_id, investigation_id, opts)
    children = []
    for job in jobs:
        selections = await _digest_selections(session, org_id, job, opts)
        child_scope = RunScope(scope=AiScope.JOB, job_ids=(job.id,))
        children.append(
            assemble(
                AiTask.JOB_DIGEST, child_scope, selections, pz, budget_tokens=opts.budget_tokens
            )
        )
    root_selections = [
        sel.investigation_item(investigation, include_text=opts.include_case_text),
        await sel.evidence_items(session, org_id, investigation_id),
        await sel.job_items(session, org_id, jobs),
        await sel.case_timeline_items(session, org_id, investigation_id),
    ]
    root = assemble(
        AiTask.INCIDENT_SUMMARY,
        scope,
        root_selections,
        pz,
        budget_tokens=opts.budget_tokens,
        jobs_omitted=omitted,
    )
    return BuiltRun(root=root, children=tuple(children))
