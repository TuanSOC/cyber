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
| `explain_function` (M10) | target G, its Q, J, C linked to it, F citing it, I, ≤ 10 callee G |

`explain_function` needs a succeeded `reverse` job; its scope also holds the job's source
static job (the linked C rows live there). It is the only task that reads decompiled code.

T items appear only with `include_ti`, X only with `include_strings`, V's title and
description only with `include_case_text`. An incident has one `job_digest` child per latest
succeeded job per evidence (newest first, ≤ `AI_MAX_JOBS_PER_INCIDENT`; `children[i]` is
`J{i+1}` in the root and in the reduce); one pseudonymizer serves the children (in order)
and then the root.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.modules.ai.context import select as sel
from app.modules.ai.context.assemble import Selection, assemble
from app.modules.ai.context.estimate import context_budget
from app.modules.ai.context.fields import RawItem
from app.modules.ai.context.pseudonymize import Pseudonymizer
from app.modules.ai.context.transform import MAX_CODE_CHARS
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
from app.modules.disk_forensics.models import AnalysisJobSegment
from app.modules.investigations import policy
from app.modules.investigations.models import Investigation
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert

PCAP_TASKS = frozenset({AiTask.SUMMARIZE_PCAP, AiTask.EXPLAIN_ALERT})
STATIC_TASKS = frozenset({AiTask.EXPLAIN_STATIC})
RE_TASKS = frozenset({AiTask.EXPLAIN_FUNCTION})


@dataclass(frozen=True)
class Options:
    include_ti: bool
    include_strings: bool
    include_case_text: bool
    budget_tokens: int
    max_jobs: int
    max_code_chars: int = MAX_CODE_CHARS  # M10: the `Q.code` cap (AI_MAX_CODE_CHARS)


def options(
    settings_row: AiOrgSettings,
    *,
    max_input_tokens: int,
    max_jobs: int,
    max_code_chars: int = MAX_CODE_CHARS,
) -> Options:
    return Options(
        include_ti=bool(settings_row.include_ti),
        include_strings=bool(settings_row.include_strings),
        include_case_text=bool(settings_row.include_case_text),
        budget_tokens=context_budget(max_input_tokens),
        max_jobs=max_jobs,
        max_code_chars=max_code_chars,
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
        max_code_chars=settings.ai_max_code_chars,
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
        root = assemble(
            req.task,
            _job_scope(job, req.task),
            selections,
            pz,
            budget_tokens=opts.budget_tokens,
            max_code_chars=opts.max_code_chars,
        )
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
    if task in RE_TASKS and job.analyzer != Analyzer.REVERSE:
        raise ContextBuildError("task_not_applicable")
    return job


def _job_scope(job: AnalysisJob, task: AiTask) -> RunScope:
    """The rows a job-scope run may cite: its job, plus (M10, `explain_function`) the RE
    job's source static job, whose capability rows the function's C items are. Both are the
    same evidence (the 0018 trigger), so the share policy check of the job covers them."""
    jobs = [job.id]
    if task in RE_TASKS and job.source_job_id is not None:
        jobs.append(job.source_job_id)
    return RunScope(scope=AiScope.JOB, job_ids=tuple(jobs))


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


async def _memory_digest(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, opts: Options
) -> list[Selection]:
    """M8 phase 8: a memory job's digest is its findings and IOCs only (with the TI answers
    of those IOCs when asked), never a pcap summary (RT1). Finding text and IOC context carry
    masked secrets (phase 3, RT13); process lists, raw command lines and artifacts never
    enter a context. The job only gets here once the evidence is no longer AI-excluded
    (an admin released it and the flags were cleared): the case builder skips excluded
    evidence and the run request refuses it (`409 policy_blocked`)."""
    jobs = [job.id]
    iocs = await sel.iocs(session, org_id, jobs)
    return [await sel.findings(session, org_id, jobs), iocs, await _ti(session, org_id, iocs, opts)]


async def _disk_digest(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, opts: Options
) -> list[Selection]:
    """M9 phase 9: a disk job's digest is its findings and IOCs only (with the TI answers of
    those IOCs when asked), like the memory arm and never a pcap summary (RT1). Quoted text
    in findings and IOC context is masked by the worker (`cyberlab_worker.mask`); file
    listings (`disk_files`), events (`disk_events`), partitions and shell history never enter
    a context, and there is no disk-specific AI task (`JOB_TASKS.disk = []`). The job only
    gets here once every segment is no longer AI-excluded (released, then the flags cleared):
    the case builder skips a disk job with an excluded segment and the run request refuses
    it (`409 policy_blocked`)."""
    jobs = [job.id]
    iocs = await sel.iocs(session, org_id, jobs)
    return [await sel.findings(session, org_id, jobs), iocs, await _ti(session, org_id, iocs, opts)]


async def _re_digest(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, opts: Options
) -> list[Selection]:
    """M10: a reverse-engineering job's digest is its program summary (the J item: engine,
    code kind, arch, bits, format), its findings and IOCs (with the TI answers of those IOCs
    when asked), never a pcap summary (RT1). Functions, strings and decompiled code never
    enter a job digest, so an incident never sends code: code reaches the AI only through
    `explain_function` (phase 9, `G` / `Q` items)."""
    jobs = [job.id]
    iocs = await sel.iocs(session, org_id, jobs)
    return [
        await sel.job_items(session, org_id, [job]),
        await sel.findings(session, org_id, jobs),
        iocs,
        await _ti(session, org_id, iocs, opts),
    ]


async def _digest_selections(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, opts: Options
) -> list[Selection]:
    if job.analyzer == Analyzer.MEMORY:
        return await _memory_digest(session, org_id, job, opts)
    if job.analyzer == Analyzer.DISK:
        return await _disk_digest(session, org_id, job, opts)
    if job.analyzer == Analyzer.REVERSE:
        return await _re_digest(session, org_id, job, opts)
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
    if task is AiTask.EXPLAIN_FUNCTION and target_id is not None:
        return await sel.select_function_items(session, org_id, job, target_id)
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


@dataclass(frozen=True)
class _Case:
    investigation: Investigation
    jobs: list[AnalysisJob]
    omitted: int
    scope: RunScope
    # M6: evidence AI-excluded by the share policy (skipped, counted in `policy_excluded`).
    excluded: frozenset[uuid.UUID]


async def _case_jobs(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, opts: Options
) -> _Case:
    investigation = await sel.get_investigation(session, org_id, investigation_id)
    if investigation is None:
        raise ContextBuildError("target_not_found")
    found = await policy.load_policy(session, org_id, investigation_id=investigation_id)
    excluded = found.excluded_evidence_ids
    latest = await sel.latest_succeeded_jobs(session, org_id, investigation_id)
    blocked = await _excluded_segment_jobs(session, org_id, latest, excluded)
    jobs = [j for j in latest if j.evidence_id not in excluded and j.id not in blocked]
    if not jobs:
        raise ContextBuildError("context_empty")
    omitted = max(len(jobs) - opts.max_jobs, 0)
    jobs = jobs[: opts.max_jobs]
    evidence_ids = await sel.evidence_ids(session, org_id, investigation_id)
    scope = RunScope(
        scope=AiScope.INVESTIGATION,
        job_ids=tuple(j.id for j in jobs),
        investigation_id=investigation_id,
        evidence_ids=tuple(e for e in evidence_ids if e not in excluded),
    )
    return _Case(investigation, jobs, omitted, scope, excluded)


async def _excluded_segment_jobs(
    session: AsyncSession,
    org_id: uuid.UUID,
    jobs: list[AnalysisJob],
    excluded: frozenset[uuid.UUID],
) -> set[uuid.UUID]:
    """M9: the disk jobs with an AI-excluded segment beyond ordinal 0 (the job's own
    `evidence_id`); the builder skips them like a job of excluded evidence."""
    disk = [j.id for j in jobs if j.analyzer == Analyzer.DISK]
    if not disk or not excluded:
        return set()
    seg = AnalysisJobSegment
    rows = await session.scalars(
        select(seg.job_id).where(
            seg.organization_id == org_id,
            seg.job_id.in_(disk),
            seg.evidence_id.in_(list(excluded)),
        )
    )
    return set(rows)


def _with_policy_count(ctx: FrozenContext, excluded: frozenset[uuid.UUID]) -> FrozenContext:
    """`context_stats.policy_excluded` (stored, never rendered: the sha256 covers only the
    items, and `prompt` has no phrase for it, so the pinned digests are unchanged)."""
    if not excluded:
        return ctx
    stats = ctx.stats.model_copy(update={"policy_excluded": len(excluded)})
    return ctx.model_copy(update={"stats": stats})


async def _investigation_task(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    task: AiTask,
    opts: Options,
    pz: Pseudonymizer,
) -> BuiltRun:
    case = await _case_jobs(session, org_id, investigation_id, opts)
    if task is AiTask.IOC_CORRELATION:
        selections = await _correlation(session, org_id, case.jobs, opts)
    elif task is AiTask.ATTACK_MAPPING:
        selections = await _attack_mapping(session, org_id, case.jobs)
    else:
        raise ContextBuildError("task_not_applicable")
    root = assemble(
        task,
        case.scope,
        selections,
        pz,
        budget_tokens=opts.budget_tokens,
        jobs_omitted=case.omitted,
    )
    return BuiltRun(root=_with_policy_count(root, case.excluded))


async def _incident(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    opts: Options,
    pz: Pseudonymizer,
) -> BuiltRun:
    case = await _case_jobs(session, org_id, investigation_id, opts)
    jobs = case.jobs
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
        sel.investigation_item(case.investigation, include_text=opts.include_case_text),
        await sel.evidence_items(session, org_id, investigation_id, exclude=case.excluded),
        await sel.job_items(session, org_id, jobs),
        await sel.case_timeline_items(
            session, org_id, investigation_id, exclude_evidence=case.excluded
        ),
    ]
    root = assemble(
        AiTask.INCIDENT_SUMMARY,
        case.scope,
        root_selections,
        pz,
        budget_tokens=opts.budget_tokens,
        jobs_omitted=case.omitted,
    )
    return BuiltRun(root=_with_policy_count(root, case.excluded), children=tuple(children))
