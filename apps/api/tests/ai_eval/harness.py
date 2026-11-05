"""The evaluation harness (M5 phase 6): case -> context builder -> prompt -> provider -> verifier.

It drives the real pipeline functions through their frozen signatures (`real_pipeline`):
`context.builder.build_run`, `prompt.render`, `verify.verify_output` and, for an incident,
`context.reduce.build_reduce_context`. Each case is seeded into a fresh org (`cases.seed_case`)
with AI enabled and every disclosure toggle on (strings, TI, case text), so injected text from
every carrier reaches the context. `doubles_pipeline` swaps in a reference context built
straight from the case rows plus the phase-1 doubles; it exists so the harness and the floors
can be exercised before group B is merged, and so a test can prove the floors catch a
permissive verifier.

Canary and delimiter are derived from (case, task, stage), so a replayed run sees the same
canary as the recorded one and scores identically.
"""

import hashlib
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tenancy import tenant_session
from app.modules.ai.contracts import (
    TARGETED_TASKS,
    AiRunRequest,
    AiScope,
    AiTask,
    BuiltRun,
    ContextItem,
    ContextRef,
    DigestInput,
    FieldValue,
    FrozenContext,
    LlmProvider,
    PromptParts,
    ProviderError,
    ProviderErrorKind,
    ProviderRequest,
    RefKind,
    RunScope,
    ValidationFailed,
    VerifiedOutput,
)
from app.modules.ai.labels import format_label
from app.modules.ai.models import AiOrgSettings
from app.modules.ai.output_schema import provider_json_schema
from app.modules.ai.providers.fake import FakeProvider
from app.modules.ai.text import defang
from tests.ai_doubles import PassThroughVerifier, fields_sha256, passthrough_reduce, trivial_render
from tests.ai_eval import scoring
from tests.ai_eval.cases import TI_TABLE, Case, RowRef, SeededCase, load_case, seed_case
from tests.ai_eval.golden import Golden, load_golden
from tests.ai_eval.providers import (
    CassetteMiss,
    EvalHints,
    HostileProvider,
    Quotable,
    quotables,
)
from tests.ai_helpers import seed_ai_settings
from tests.integration.seed import Tenant, seed_tenant

MAX_OUTPUT_TOKENS = 16_000


class PipelineNotReady(Exception):
    """A pipeline entry point is still the phase-1 stub (group B not merged)."""


BuildRun = Callable[
    [AsyncSession, uuid.UUID, uuid.UUID, AiRunRequest, AiOrgSettings], Awaitable[BuiltRun]
]
Render = Callable[..., PromptParts]
Verify = Callable[..., Awaitable[VerifiedOutput]]
Reduce = Callable[[FrozenContext, list[DigestInput]], FrozenContext]


@dataclass
class Pipeline:
    build_run: BuildRun
    render: Render
    verify: Verify
    reduce: Reduce
    label: str
    prompt_version: str


def real_pipeline() -> Pipeline:
    """The merged group-B functions, looked up at call time (monkeypatching still works)."""
    from app.modules.ai import prompt, verify
    from app.modules.ai.context import builder, reduce

    async def build_run(*args: Any) -> BuiltRun:
        return await builder.build_run(*args)

    async def verify_output(*args: Any) -> VerifiedOutput:
        return await verify.verify_output(*args)

    def render(*args: Any, **kwargs: Any) -> PromptParts:
        return prompt.render(*args, **kwargs)

    def build_reduce(base: FrozenContext, digests: list[DigestInput]) -> FrozenContext:
        return reduce.build_reduce_context(base, digests)

    return Pipeline(build_run, render, verify_output, build_reduce, "real", prompt.PROMPT_VERSION)


# --- reference context (doubles only) ----------------------------------------------------------

_REFERENCE: dict[uuid.UUID, SeededCase] = {}
_KIND_TABLES: tuple[tuple[RefKind, str, tuple[str, ...]], ...] = (
    (RefKind.SAMPLE, "malware_samples", ("sha256", "file_type", "file_format")),
    (RefKind.FINDING, "analysis_findings", ("type", "title", "severity", "description")),
    (RefKind.ALERT, "network_alerts", ("signature", "signature_id", "severity")),
    (RefKind.SIGNATURE, "malware_signature_matches", ("engine", "name")),
    (RefKind.CAPABILITY, "malware_capabilities", ("name", "namespace", "attack")),
    (RefKind.IOC, "iocs", ("type", "value", "count")),
    (RefKind.TIMELINE, "analysis_timeline", ("event", "title", "ts")),
    (RefKind.RECORD, "network_records", ("kind", "summary")),
    (RefKind.STRING, "malware_strings", ("value", "encoding")),
    (RefKind.FLOW, "network_flows", ("src_ip", "dst_ip", "dst_port", "proto")),
)


def _field(value: Any) -> FieldValue:
    """Lists joined, URLs and domains defanged (as the builder sends them)."""
    if isinstance(value, list):
        return defang(", ".join(str(v) for v in value))
    if isinstance(value, str):
        return defang(value)
    if value is None or isinstance(value, int | float | bool):
        return value
    return defang(str(value))


def reference_context(seeded: SeededCase, task: AiTask, job_keys: Sequence[str]) -> FrozenContext:
    """A plain context from the case rows (no caps, no pseudonyms): doubles only."""
    case = seeded.case
    items: list[ContextItem] = []
    refs: list[ContextRef] = []
    counters: dict[RefKind, int] = {}

    def add(kind: RefKind, fields: dict[str, FieldValue], ref: RowRef) -> None:
        counters[kind] = counters.get(kind, 0) + 1
        label = format_label(kind, counters[kind])
        items.append(ContextItem(label=label, kind=kind, fields=fields))
        refs.append(
            ContextRef(
                label=label,
                kind=kind,
                ref_table=ref.table,
                ref_id=ref.ref_id,
                job_id=ref.job_id,
                fields_sha256=fields_sha256(fields),
            )
        )

    for key in job_keys:
        job = case.job(key)
        job_id = seeded.job_ids[key]
        add(
            RefKind.JOB,
            {"analyzer": job["analyzer"], "file": job["evidence"]["filename"]},
            RowRef("analysis_jobs", str(job_id), job_id),
        )
        for kind, table, names in _KIND_TABLES:
            for index, row in enumerate(case.rows(key, table)[:25]):
                fields = {n: _field(row.get(n)) for n in names if row.get(n) is not None}
                if kind is RefKind.RECORD and isinstance(row.get("details"), dict):
                    for name in ("query", "host", "uri", "user_agent", "server_name"):
                        if row["details"].get(name):
                            fields[name] = _field(row["details"][name])
                add(kind, fields, seeded._ref(key, table, index))
    first = seeded.job_ids[case.jobs[0]["key"]]
    for n, row in enumerate(case.ti):
        ref = seeded.find(TI_TABLE, {"provider": row["provider"], "ioc.value": row["ioc"]["value"]})
        summary = row.get("summary") or {}
        text = "; ".join(str(s) for s in scoring.strings_of(summary) if s != row["provider"])
        add(
            RefKind.TI_RESULT,
            {"provider": row["provider"], "value": row["ioc"]["value"], "summary": text[:256]},
            ref[0] if ref else RowRef(TI_TABLE, str(n), first),
        )
    job_ids = tuple(seeded.job_ids[k] for k in job_keys)
    if task is AiTask.INCIDENT_SUMMARY:
        scope = RunScope(
            scope=AiScope.INVESTIGATION, job_ids=job_ids, investigation_id=seeded.investigation_id
        )
    else:
        scope = RunScope(scope=AiScope.JOB, job_ids=job_ids)
    return FrozenContext(task=task, scope=scope, items=tuple(items), refs=tuple(refs))


async def reference_build_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    settings_row: AiOrgSettings,
) -> BuiltRun:
    seeded = _REFERENCE[org_id]
    keys = [j["key"] for j in seeded.case.jobs]
    if req.task is AiTask.INCIDENT_SUMMARY:
        children = tuple(reference_context(seeded, AiTask.JOB_DIGEST, [k]) for k in keys)
        root = reference_context(seeded, req.task, [])
        root = root.model_copy(
            update={
                "scope": RunScope(
                    scope=AiScope.INVESTIGATION,
                    job_ids=tuple(seeded.job_ids[k] for k in keys),
                    investigation_id=seeded.investigation_id,
                )
            }
        )
        return BuiltRun(root=root, children=children)
    return BuiltRun(root=reference_context(seeded, req.task, keys[:1]))


def doubles_pipeline() -> Pipeline:
    verifier = PassThroughVerifier()

    async def verify(*args: Any) -> VerifiedOutput:
        return await verifier(*args)

    return Pipeline(
        reference_build_run, trivial_render, verify, passthrough_reduce, "doubles", "doubles"
    )


# --- one case ----------------------------------------------------------------------------------


@dataclass
class Prepared:
    case: Case
    golden: Golden
    seeded: SeededCase
    built: dict[str, BuiltRun] = field(default_factory=dict)
    foreign: dict[str, FrozenContext] = field(default_factory=dict)


def derive(case: str, task: str, stage: str, what: str, n: int) -> str:
    return hashlib.sha256(f"{case}|{task}|{stage}|{what}".encode()).hexdigest()[:n]


def canary_for(case: str, task: str, stage: str) -> str:
    return "CANARY-" + derive(case, task, stage, "canary", 24).upper()


def request_for(task: AiTask, prepared: Prepared) -> AiRunRequest:
    seeded = prepared.seeded
    if task is AiTask.INCIDENT_SUMMARY:
        return AiRunRequest(task=task, investigation_id=seeded.investigation_id)
    first = prepared.case.jobs[0]["key"]
    job_id = seeded.job_ids[first]
    target: uuid.UUID | None = None
    if task in TARGETED_TASKS:
        table = "analysis_findings" if task is AiTask.EXPLAIN_FINDING else "network_alerts"
        must = [m for m in prepared.golden.must_mention if m.table == table]
        if must:
            ref = seeded.resolve(table, must[0].where, must[0].job)
        else:
            ref = seeded._ref(first, table, 0)
        target = uuid.UUID(ref.ref_id)
    return AiRunRequest(task=task, job_id=job_id, target_id=target)


async def _tenant() -> Tenant:
    tenant = await seed_tenant(f"eval{uuid.uuid4().hex[:12]}")
    await seed_ai_settings(tenant, enabled=True, include_strings=True, include_case_text=True)
    return tenant


async def _build(pipeline: Pipeline, seeded: SeededCase, req: AiRunRequest) -> BuiltRun:
    _REFERENCE[seeded.org_id] = seeded
    async with tenant_session(seeded.org_id, seeded.owner_id) as s:
        settings_row = await s.get(AiOrgSettings, seeded.org_id)
        assert settings_row is not None
        try:
            return await pipeline.build_run(s, seeded.org_id, seeded.owner_id, req, settings_row)
        except NotImplementedError as exc:
            raise PipelineNotReady(f"build_run: {exc}") from None


async def prepare(case_name: str, pipeline: Pipeline, *, foreign: bool = False) -> Prepared:
    """Seed the case into a fresh org and build every task's context (and, with `foreign`,
    a second org seeded with the same case for the cross-org poisoning)."""
    case = load_case(case_name)
    golden = load_golden(case.base)
    seeded = await seed_case(case, await _tenant())
    prepared = Prepared(case=case, golden=golden, seeded=seeded)
    for task in case.tasks:
        prepared.built[task] = await _build(pipeline, seeded, request_for(AiTask(task), prepared))
    if foreign:
        other = await seed_case(case, await _tenant())
        shadow = Prepared(case=case, golden=golden, seeded=other)
        for task in case.tasks:
            built = await _build(pipeline, other, request_for(AiTask(task), shadow))
            prepared.foreign[task] = built.root
    return prepared


def poison(ctx: FrozenContext, foreign: FrozenContext) -> tuple[FrozenContext, str | None]:
    """Add one item of another org's context under a fresh label whose ref points at that
    org's row but claims this run's job (only the verifier's org-scoped re-query can catch it)."""
    by_label = {r.label: r for r in foreign.refs}
    pick: Quotable | None = None
    for q in quotables(foreign):
        ref = by_label.get(q.label)
        if ref is not None and ref.ref_table != "network_flows" and q.item.kind is not RefKind.JOB:
            pick = q
            break
    if pick is None:
        return ctx, None
    kind = pick.item.kind
    label = format_label(kind, 900)
    ref = by_label[pick.label]
    job = ctx.scope.job_ids[0] if ctx.scope.job_ids else ref.job_id
    item = ContextItem(label=label, kind=kind, fields=dict(pick.item.fields))
    forged = ref.model_copy(update={"label": label, "job_id": job})
    return ctx.model_copy(update={"items": (*ctx.items, item), "refs": (*ctx.refs, forged)}), label


def _labels_for(ctx: FrozenContext, refs: Sequence[RowRef]) -> set[str]:
    out = set()
    for row in refs:
        for r in ctx.refs:
            if r.ref_table == row.table and r.ref_id == row.ref_id:
                if r.job_id is None or r.job_id == row.job_id or row.table == TI_TABLE:
                    out.add(r.label)
    return out


def must_labels(prepared: Prepared, ctx: FrozenContext) -> dict[str, set[str]]:
    return {
        m.id: _labels_for(ctx, [prepared.seeded.resolve(m.table, m.where, m.job)])
        for m in prepared.golden.must_mention
    }


@dataclass
class CallSpec:
    provider: LlmProvider
    provider_name: str
    model: str
    run: int = 0
    script: str | None = None
    schema_provider: str = "mock"


async def stage(
    prepared: Prepared,
    pipeline: Pipeline,
    spec: CallSpec,
    ctx: FrozenContext,
    task: AiTask,
    stage_name: str,
    *,
    final: bool,
    foreign_label: str | None = None,
) -> scoring.RunRecord:
    case = prepared.case
    canary = canary_for(case.name, task.value, stage_name)
    record = scoring.RunRecord(
        case=case.name,
        base=case.base,
        injected=case.injected,
        task=task.value,
        stage=stage_name,
        provider=spec.provider_name,
        model=spec.model,
        run=spec.run,
        ctx=ctx,
        canary=canary,
        golden=prepared.golden,
        final=final,
        script=spec.script,
        stored_severity=case.max_severity(),
        replayed=bool(getattr(spec.provider, "replayed", False)),
    )
    if final:
        record.must = must_labels(prepared, ctx)
    if case.injected:
        record.planted = _labels_for(ctx, prepared.seeded.planted_refs())
    try:
        parts = pipeline.render(
            ctx,
            task,
            delimiter=derive(case.name, task.value, stage_name, "delim", 32),
            canary=canary,
        )
    except NotImplementedError as exc:
        raise PipelineNotReady(f"render: {exc}") from None
    set_hints = getattr(spec.provider, "set_hints", None)
    if callable(set_hints):
        set_hints(
            EvalHints(
                canary=canary,
                case=case.name,
                stage=stage_name,
                task=task.value,
                run=spec.run,
                foreign_label=foreign_label,
            )
        )
    request = ProviderRequest(
        model=spec.model,
        system=parts.system,
        user=parts.user,
        output_schema=provider_json_schema(spec.schema_provider),
        max_output_tokens=MAX_OUTPUT_TOKENS,
        context=ctx,
    )
    try:
        result = await spec.provider.analyze(request)
    except CassetteMiss as exc:
        record.outcome, record.error = "pending", str(exc)
        return record
    except ProviderError as exc:
        record.outcome = "refused" if exc.kind is ProviderErrorKind.REFUSED else "error"
        record.error, record.refusal_category = exc.kind.value, exc.category
        return record
    record.parsed = result.parsed
    record.refusal_category = result.refusal_category
    if isinstance(spec.provider, HostileProvider) and spec.provider.expectations:
        record.expect = spec.provider.expectations[-1]
    seeded = prepared.seeded
    try:
        async with tenant_session(seeded.org_id, seeded.owner_id) as s:
            record.verified = await pipeline.verify(
                s, seeded.org_id, ctx.scope, ctx, ctx.refs, result.parsed, canary
            )
    except ValidationFailed as exc:
        record.outcome, record.error = "invalid_output", ";".join(exc.errors)[:500]
    except NotImplementedError as exc:
        raise PipelineNotReady(f"verify_output: {exc}") from None
    return record


def _digest(child: FrozenContext, index: int, verified: VerifiedOutput) -> DigestInput:
    return DigestInput(
        run_id=uuid.uuid5(uuid.NAMESPACE_URL, f"ai-eval:{child.sha256}"),
        job_id=child.scope.job_ids[0],
        job_label=f"J{index + 1}",
        context=child,
        body=verified.body,
        claims=verified.claims,
        citations=verified.citations,
        flags=verified.flags,
    )


async def run_task(
    prepared: Prepared,
    pipeline: Pipeline,
    task_name: str,
    spec: CallSpec,
    *,
    child_spec: CallSpec | None = None,
    hostile_children: bool = False,
) -> list[scoring.RunRecord]:
    """Every stage of one task: one call, or an incident's children + reduce."""
    task = AiTask(task_name)
    built = prepared.built[task_name]
    poisoned: str | None = None
    root = built.root
    if spec.script in ("cross_org", "hostile_refs") and task_name in prepared.foreign:
        root, poisoned = poison(root, prepared.foreign[task_name])
    if not built.children:
        return [
            await stage(
                prepared, pipeline, spec, root, task, "base", final=True, foreign_label=poisoned
            )
        ]
    records: list[scoring.RunRecord] = []
    digests: list[DigestInput] = []
    for n, child in enumerate(built.children):
        name = f"child:{n + 1}"
        if hostile_children:
            records.append(
                await stage(prepared, pipeline, spec, child, AiTask.JOB_DIGEST, name, final=False)
            )
        rec = await stage(
            prepared, pipeline, child_spec or spec, child, AiTask.JOB_DIGEST, name, final=False
        )
        if child_spec is None:
            records.append(rec)
        if rec.outcome == "pending":
            return records  # the reduce needs every child
        if rec.verified is not None:
            digests.append(_digest(child, n, rec.verified))
    try:
        reduced = pipeline.reduce(built.root, digests)
    except NotImplementedError as exc:
        raise PipelineNotReady(f"build_reduce_context: {exc}") from None
    if spec.script in ("cross_org", "hostile_refs") and task_name in prepared.foreign:
        reduced, poisoned = poison(reduced, prepared.foreign[task_name])
    records.append(
        await stage(
            prepared, pipeline, spec, reduced, task, "reduce", final=True, foreign_label=poisoned
        )
    )
    return records


async def run_fake(case_name: str, pipeline: Pipeline) -> list[scoring.RunRecord]:
    prepared = await prepare(case_name, pipeline)
    records = []
    for task in prepared.case.tasks:
        spec = CallSpec(FakeProvider(), "fake", "fake-1")
        records += await run_task(prepared, pipeline, task, spec)
    return records


async def run_hostile(
    case_name: str, pipeline: Pipeline, scripts: Sequence[str]
) -> list[scoring.RunRecord]:
    prepared = await prepare(case_name, pipeline, foreign=True)
    records = []
    for task in prepared.case.tasks:
        for script in scripts:
            spec = CallSpec(HostileProvider(script), "hostile", "hostile-1", script=script)
            honest = CallSpec(FakeProvider(), "fake", "fake-1")
            records += await run_task(
                prepared, pipeline, task, spec, child_spec=honest, hostile_children=True
            )
    return records


async def run_provider(
    case_name: str,
    pipeline: Pipeline,
    make: Callable[[int], CallSpec],
    runs: int = 1,
) -> list[scoring.RunRecord]:
    """Any provider (replay, live recorder) over every task, `runs` times."""
    prepared = await prepare(case_name, pipeline)
    records = []
    for run in range(runs):
        for task in prepared.case.tasks:
            records += await run_task(prepared, pipeline, task, make(run))
    return records


BEGIN = "=== AI EVAL TABLE BEGIN ==="
END = "=== AI EVAL TABLE END ==="


def report(title: str, scores: Sequence[scoring.RunScore], *, detail: int = 40) -> str:
    """The metric table (printed between markers for `scripts/ai_eval.py`)."""
    aggregates = scoring.aggregate(scores)
    lines = [BEGIN, f"### {title}", "", scoring.table(aggregates), ""]
    for agg in aggregates:
        if agg.asr_reasons:
            reasons = ", ".join(f"{k} {v}" for k, v in sorted(agg.asr_reasons.items()))
            lines.append(f"- {agg.provider} ASR reasons: {reasons}")
        if agg.violations:
            kinds = ", ".join(f"{k} {v}" for k, v in sorted(agg.violations.items()))
            lines.append(f"- {agg.provider} violations: {kinds}")
    lines += [f"  - {v}" for v in scoring.violation_lines(scores, detail)]
    lines.append(END)
    return "\n".join(lines)
