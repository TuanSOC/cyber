"""Report drafts, preview, finalize and version reads (M6 phase 3).

**Finalize** runs in three steps and holds no transaction across the build, the put or the
signing (RT14):
1. *read*: one `org_session(..., snapshot_read=True)` (REPEATABLE READ READ ONLY): the
   revision, the archived case, the TLP rule against the **current** case TLP (RT7), the
   profile rules (RT8), build, redact, the size and render-budget checks (RT1), canonical
   bytes and sha256; the `revision` and `latest_version` read are recorded;
2. *outside any transaction*: the manifest is signed with the active kid, then the snapshot is
   put in the object-locked bucket and its exact version gets a GOVERNANCE retention (RT6);
3. *write*: one short tenant transaction under a per-report advisory lock re-checks the
   revision, `latest_version` and the TLP rule, inserts the version and its citations, bumps
   `latest_version`, queues the PDF render (`dispatch.create_render`, PDF only, RT5), audits
   `report.finalized`, commits, then `dispatch.dispatch_render`.

A stored object whose write step fails is an orphan: logged, listed by the reconcile script,
never served. A dispatch failure still answers 201 (the reaper recovers the render).

**Version reads** re-hash the stored object and verify the signature with the public key of
the version's kid; a mismatch is shown (`snapshot_ok` / `signature_valid` false), never
hidden, and audited as `report.integrity_failed`. The content and snapshot routes serve
the bytes only when both hold (`409 integrity_failed` otherwise).
"""

import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import anyio
from cyberlab_jobs.report import (
    TLP,
    Manifest,
    Profile,
    ReportSnapshot,
    canonical_json,
    manifest_bytes,
    parse_snapshot,
    render_units,
    section_counts,
    section_units,
)
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.rbac import (
    OrgContext,
    Permission,
    org_session,
)
from app.core.signing import SigningError
from app.modules.ai.models import AiOutput, AiRun
from app.modules.ai.service_outputs import has_canary_leak
from app.modules.analysis.models import AnalysisJob
from app.modules.audit import service as audit
from app.modules.evidence.models import Evidence
from app.modules.investigations import policy
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.investigations.schemas import case_ref
from app.modules.ioc_collections.models import IocCollection
from app.modules.notes.models import AnalystNote
from app.modules.reports import dispatch, redact
from app.modules.reports import repository as repo
from app.modules.reports import signing as report_signing
from app.modules.reports import storage as report_storage
from app.modules.reports.citations import CaseScope
from app.modules.reports.models import Report, ReportCitation, ReportRender, ReportVersion
from app.modules.reports.schemas import (
    RenderOut,
    ReportCreate,
    ReportDetail,
    ReportDraft,
    ReportFinalize,
    ReportOut,
    ReportPage,
    ReportPreviewOut,
    ReportSignatureOut,
    ReportUpdate,
    ReportVersionDetail,
    ReportVersionList,
    ReportVersionSummary,
    SectionCount,
)
from app.modules.reports.snapshot import BuiltSnapshot, CitationRow, build_snapshot
from app.modules.reports.snapshot_sections import AI_FINAL

log = logging.getLogger(__name__)

WINDOW_S = 600
STRICT_DISTRIBUTION = (TLP.RED.value, TLP.AMBER_STRICT.value)


class Unprocessable(AppError):
    status_code = 422
    code = "unprocessable"
    message = "The request cannot be processed"


class StaleDraft(Conflict):
    code = "stale_draft"
    message = "The draft changed since it was read; reload it"


class SigningUnavailable(AppError):
    status_code = 503
    code = "signing_unavailable"
    message = "Report signing is not available"


class IntegrityFailed(Conflict):
    code = "integrity_failed"
    message = "The stored snapshot does not match its recorded hash"


# --- mapping ------------------------------------------------------------------------------------


def _summary(row: repo.VersionRow) -> ReportVersionSummary:
    v = row.version
    return ReportVersionSummary(
        id=v.id,
        version=v.version,
        tlp=TLP(v.tlp),
        profile=Profile(v.profile),
        snapshot_sha256=v.snapshot_sha256,
        snapshot_bytes=v.snapshot_bytes,
        kid=v.kid,
        change_note=v.change_note,
        finalized_by=v.finalized_by,
        finalized_by_name=row.finalized_by_name,
        finalized_at=v.finalized_at,
    )


def _out(row: repo.ReportRow, latest: repo.VersionRow | None) -> ReportOut:
    r = row.report
    return ReportOut(
        id=r.id,
        investigation_id=r.investigation_id,
        case_ref=case_ref(row.case_number),
        title=r.title,
        template="incident_v1",
        tlp=TLP(r.tlp),
        profile=Profile(r.profile),
        distribution=r.distribution,
        status="discarded" if r.status == "discarded" else "draft",
        revision=r.revision,
        latest_version=r.latest_version,
        latest=_summary(latest) if latest is not None else None,
        created_by=r.created_by,
        created_by_name=row.created_by_name,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _draft(report: Report) -> ReportDraft:
    try:
        return ReportDraft.model_validate(report.draft or {})
    except ValidationError:
        return ReportDraft()


def _render_out(r: ReportRender) -> RenderOut:
    return RenderOut(
        id=r.id,
        version_id=r.version_id,
        format=r.format,
        status=r.status,
        error_code=r.error_code,
        sha256=r.sha256,
        bytes=r.bytes,
        pages=r.pages,
        renderer_version=r.renderer_version,
        requested_by=r.requested_by,
        created_at=r.created_at,
        started_at=r.started_at,
        finished_at=r.finished_at,
    )


async def _page(
    ctx: OrgContext,
    *,
    investigation_id: uuid.UUID | None,
    status: str | None,
    cursor: str | None,
) -> ReportPage:
    after = repo.decode_cursor(cursor) if cursor else None
    rows = await repo.report_rows(
        ctx.session,
        ctx.org_id,
        investigation_id=investigation_id,
        status=status,
        after=after,
        limit=repo.PAGE_SIZE + 1,
    )
    more = len(rows) > repo.PAGE_SIZE
    rows = rows[: repo.PAGE_SIZE]
    latest = await repo.latest_versions(ctx.session, ctx.org_id, [r.report for r in rows])
    next_cursor = (
        repo.encode_cursor(rows[-1].report.updated_at, rows[-1].report.id) if more else None
    )
    return ReportPage(
        items=[_out(r, latest.get(r.report.id)) for r in rows], next_cursor=next_cursor
    )


async def _report_out(session: AsyncSession, org_id: uuid.UUID, report: Report) -> ReportOut:
    rows = await repo.report_rows(session, org_id, report_ids=[report.id], limit=1)
    latest = await repo.latest_versions(session, org_id, [report])
    return _out(rows[0], latest.get(report.id))


async def _detail(session: AsyncSession, org_id: uuid.UUID, report: Report) -> ReportDetail:
    versions = await repo.versions_of(session, org_id, report.id)
    return ReportDetail(
        report=await _report_out(session, org_id, report),
        draft=_draft(report),
        versions=[_summary(v) for v in versions],
    )


# --- rules --------------------------------------------------------------------------------------


def _may(permissions: frozenset[Permission], permission: Permission) -> bool:
    """M11 RT1: the caller's effective permissions (role, or role ∩ API-key scopes)."""
    return permission in permissions


def _tlp_rule(
    permissions: frozenset[Permission], report_tlp: str, case_tlp: str, acknowledged: bool
) -> bool:
    """True when the report TLP is a downgrade from the case TLP that is allowed (audited);
    `409 tlp_below_case` without the acknowledgement, `403` without `org.update`."""
    if not policy.is_downgrade(report_tlp, case_tlp):
        return False
    if not acknowledged:
        raise Conflict(
            "The report TLP is less restrictive than the case TLP",
            code="tlp_below_case",
            extra={"case_tlp": case_tlp},
        )
    if not _may(permissions, Permission.ORG_UPDATE):
        raise Forbidden(
            "Lowering the TLP below the case needs org.update", code="tlp_downgrade_forbidden"
        )
    return True


def _not_archived(case: Investigation) -> None:
    if case.status == InvestigationStatus.ARCHIVED:
        raise Conflict("Archived investigations are read-only", code="investigation_archived")


def _is_draft(report: Report) -> None:
    if report.status != "draft":
        raise Conflict("The report was discarded", code="report_discarded")


async def _case_of(session: AsyncSession, org_id: uuid.UUID, report: Report) -> Investigation:
    case = await repo.get_case(session, org_id, report.investigation_id)
    if case is None:
        raise NotFound()
    return case


def _out_of_scope(field: str) -> Unprocessable:
    return Unprocessable(
        "A selection is not part of this case",
        code="selection_out_of_scope",
        extra={"field": field},
    )


async def validate_selection(
    session: AsyncSession, org_id: uuid.UUID, case: Investigation, draft: ReportDraft
) -> None:
    """Selected AI runs (completed, in the case scope, not canary-leak / refused), notes,
    collections and jobs must all be of this case (`422 selection_out_of_scope`)."""
    inc = draft.include
    if inc.jobs != "latest" and inc.jobs:
        wanted = set(inc.jobs)
        found = set(
            await session.scalars(
                select(AnalysisJob.id)
                .join(
                    Evidence,
                    (Evidence.id == AnalysisJob.evidence_id)
                    & (Evidence.organization_id == AnalysisJob.organization_id),
                )
                .where(
                    AnalysisJob.organization_id == org_id,
                    AnalysisJob.id.in_(list(wanted)),
                    Evidence.investigation_id == case.id,
                )
            )
        )
        if found != wanted:
            raise _out_of_scope("include.jobs")
    if inc.notes:
        wanted = set(inc.notes)
        found = set(
            await session.scalars(
                select(AnalystNote.id).where(
                    AnalystNote.organization_id == org_id,
                    AnalystNote.investigation_id == case.id,
                    AnalystNote.id.in_(list(wanted)),
                    AnalystNote.deleted_at.is_(None),
                )
            )
        )
        if found != wanted:
            raise _out_of_scope("include.notes")
    if inc.iocs.collections:
        wanted = set(inc.iocs.collections)
        found = set(
            await session.scalars(
                select(IocCollection.id).where(
                    IocCollection.organization_id == org_id,
                    IocCollection.investigation_id == case.id,
                    IocCollection.id.in_(list(wanted)),
                )
            )
        )
        if found != wanted:
            raise _out_of_scope("include.iocs.collections")
    if inc.ai_runs:
        scope = await CaseScope.load(session, org_id, case)
        runs = {
            r.id: r
            for r in await session.scalars(
                select(AiRun).where(
                    AiRun.organization_id == org_id, AiRun.id.in_(list(set(inc.ai_runs)))
                )
            )
        }
        outputs = {
            o.run_id: o
            for o in await session.scalars(
                select(AiOutput).where(
                    AiOutput.organization_id == org_id, AiOutput.run_id.in_(list(runs))
                )
            )
        }
        for run_id in set(inc.ai_runs):
            run = runs.get(run_id)
            output = outputs.get(run_id)
            if (
                run is None
                or run.status not in AI_FINAL
                or run.error_code == "canary_leak"
                or output is None
                or has_canary_leak(output)
                or not _run_scope_ok(run, case, scope)
            ):
                raise _out_of_scope("include.ai_runs")


def _run_scope_ok(run: AiRun, case: Investigation, scope: CaseScope) -> bool:
    if run.scope == "investigation":
        return run.investigation_id == case.id
    return run.job_id is not None and run.job_id in scope.jobs


# --- list, create, read, update, discard --------------------------------------------------------


async def list_reports(
    ctx: OrgContext,
    *,
    investigation_id: uuid.UUID | None,
    status: str | None,
    cursor: str | None,
) -> ReportPage:
    return await _page(ctx, investigation_id=investigation_id, status=status, cursor=cursor)


async def list_case_reports(
    ctx: OrgContext, investigation_id: uuid.UUID, cursor: str | None
) -> ReportPage:
    if await repo.get_case(ctx.session, ctx.org_id, investigation_id) is None:
        raise NotFound()
    return await _page(ctx, investigation_id=investigation_id, status=None, cursor=cursor)


async def create_report(
    ctx: OrgContext, investigation_id: uuid.UUID, body: ReportCreate, request: HTTPConnection
) -> ReportOut:
    case = await repo.get_case(ctx.session, ctx.org_id, investigation_id)
    if case is None:
        raise NotFound()
    _not_archived(case)
    tlp = body.tlp.value if body.tlp is not None else case.tlp
    downgraded = _tlp_rule(ctx.permissions, tlp, case.tlp, body.acknowledge_tlp_downgrade)
    report = Report(
        organization_id=ctx.org_id,
        investigation_id=case.id,
        title=body.title,
        template=body.template,
        tlp=tlp,
        profile=body.profile.value,
        draft=ReportDraft().model_dump(mode="json", by_alias=True),
        created_by=ctx.user.id,
    )
    ctx.session.add(report)
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="report.created",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="report",
        target_id=report.id,
        details={"investigation_id": str(case.id), "tlp": tlp, "profile": report.profile},
        request=request,
    )
    if downgraded:
        _audit_downgrade(ctx, report.id, case.tlp, tlp, request, version=None)
    out = await _report_out(ctx.session, ctx.org_id, report)
    await ctx.session.commit()
    return out


def _audit_downgrade(
    ctx: OrgContext,
    report_id: uuid.UUID,
    case_tlp: str,
    tlp: str,
    request: HTTPConnection | None,
    *,
    version: int | None,
    session: AsyncSession | None = None,
) -> None:
    audit.record(
        session or ctx.session,
        action="report.tlp_downgraded",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="report",
        target_id=report_id,
        details={"case_tlp": case_tlp, "tlp": tlp, "version": version},
        request=request,
    )


async def get_report(ctx: OrgContext, report_id: uuid.UUID) -> ReportDetail:
    report = await repo.get_report(ctx.session, ctx.org_id, report_id)
    if report is None:
        raise NotFound()
    return await _detail(ctx.session, ctx.org_id, report)


async def update_report(
    ctx: OrgContext, report_id: uuid.UUID, body: ReportUpdate, request: HTTPConnection
) -> ReportDetail:
    report = await repo.get_report(ctx.session, ctx.org_id, report_id, for_update=True)
    if report is None:
        raise NotFound()
    _is_draft(report)
    case = await _case_of(ctx.session, ctx.org_id, report)
    _not_archived(case)
    if body.revision != report.revision:
        raise StaleDraft(extra={"revision": report.revision})
    if body.draft is not None:
        # Before any attribute changes: the queries must not autoflush a half-made update.
        await validate_selection(ctx.session, ctx.org_id, case, body.draft)
    changed: list[str] = []
    set_fields = body.model_fields_set
    if body.title is not None and body.title != report.title:
        report.title = body.title
        changed.append("title")
    downgraded = False
    if body.tlp is not None and body.tlp.value != report.tlp:
        downgraded = _tlp_rule(
            ctx.permissions, body.tlp.value, case.tlp, body.acknowledge_tlp_downgrade
        )
        report.tlp = body.tlp.value
        changed.append("tlp")
    if body.profile is not None and body.profile.value != report.profile:
        report.profile = body.profile.value
        changed.append("profile")
    if "distribution" in set_fields:
        distribution = body.distribution or None
        if distribution != report.distribution:
            report.distribution = distribution
            changed.append("distribution")
    if body.draft is not None:
        report.draft = body.draft.model_dump(mode="json", by_alias=True)
        changed.append("draft")
    # Every write is one revision (the `report_guard` trigger requires exactly +1).
    report.revision = report.revision + 1
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="report.updated",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="report",
        target_id=report.id,
        details={"fields": changed, "revision": report.revision},
        request=request,
    )
    if downgraded:
        _audit_downgrade(ctx, report.id, case.tlp, report.tlp, request, version=None)
    detail = await _detail(ctx.session, ctx.org_id, report)
    await ctx.session.commit()
    return detail


async def discard_report(
    ctx: OrgContext, report_id: uuid.UUID, request: HTTPConnection
) -> ReportDetail:
    report = await repo.get_report(ctx.session, ctx.org_id, report_id, for_update=True)
    if report is None:
        raise NotFound()
    _is_draft(report)
    if report.latest_version > 0 or await repo.has_versions(ctx.session, ctx.org_id, report.id):
        raise Conflict("A report with versions cannot be discarded", code="report_has_versions")
    report.status = "discarded"
    report.revision = report.revision + 1
    await ctx.session.flush()
    audit.record(
        ctx.session,
        action="report.discarded",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="report",
        target_id=report.id,
        details={"revision": report.revision},
        request=request,
    )
    detail = await _detail(ctx.session, ctx.org_id, report)
    await ctx.session.commit()
    return detail


# --- build, preview -----------------------------------------------------------------------------


@dataclass(frozen=True)
class _Prepared:
    built: BuiltSnapshot
    snapshot: ReportSnapshot
    data: bytes
    sha256: str
    units: int
    revision: int
    latest_version: int
    case_tlp: str
    tlp_downgraded: bool
    tlp: str
    profile: str


def _budget(snapshot: ReportSnapshot) -> tuple[bytes, int, dict[str, int]]:
    return canonical_json(snapshot), render_units(snapshot), section_units(snapshot)


async def build_redacted(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    report: Report,
    case: Investigation,
    now: datetime,
    change_note: str | None = None,
) -> tuple[BuiltSnapshot, ReportSnapshot]:
    """The snapshot as signed for the report's profile: built from the live rows, then
    redacted. The one code path for preview, finalize and the §14 metric's re-resolution of
    external citations (whose `fields_sha256` is the hash of the redacted copy)."""
    built = await build_snapshot(session, org_id, user_id, report, now=now)
    snapshot = built.snapshot
    if change_note:
        # Part of the signed document (RT23), and redacted with the rest of it.
        dumped = snapshot.model_dump(mode="json")
        dumped["report"]["change_note"] = change_note
        snapshot = ReportSnapshot.model_validate(dumped)
    scope = await CaseScope.load(session, org_id, case)
    redacted = await redact.redact(session, scope, snapshot, built.run_originals)
    return built, redacted


async def _build_redacted(
    session: AsyncSession,
    ctx: OrgContext,
    report: Report,
    case: Investigation,
    now: datetime,
    change_note: str | None = None,
) -> tuple[BuiltSnapshot, ReportSnapshot]:
    return await build_redacted(session, ctx.org_id, ctx.user.id, report, case, now, change_note)


@asynccontextmanager
async def _snapshot_session(ctx: OrgContext, permission: Permission) -> AsyncIterator[AsyncSession]:
    """`org_session` in a REPEATABLE READ READ ONLY transaction (RT14): the membership is
    re-checked inside it, as `org_session` does (`SET TRANSACTION` must come before every
    query, so the request's own session cannot be reused)."""
    async with org_session(ctx.org_id, ctx.user, permission, snapshot_read=True) as snap:
        yield snap.session


async def _release(ctx: OrgContext) -> None:
    """End the request's dependency transaction (membership already checked) before a long
    step: the build opens its own snapshot transaction (RT14)."""
    await ctx.session.commit()


async def preview(ctx: OrgContext, report_id: uuid.UUID) -> ReportPreviewOut:
    settings = get_settings()
    await rate_limit.hit(
        f"report:preview:{ctx.user.id}", settings.report_preview_per_user_10min, WINDOW_S
    )
    if await repo.get_report(ctx.session, ctx.org_id, report_id) is None:
        raise NotFound()
    await _release(ctx)
    now = datetime.now(UTC)
    async with _snapshot_session(ctx, Permission.INVESTIGATION_WRITE) as session:
        report = await repo.get_report(session, ctx.org_id, report_id)
        if report is None:
            raise NotFound()
        _is_draft(report)
        case = await _case_of(session, ctx.org_id, report)
        _, snapshot = await _build_redacted(session, ctx, report, case, now)
    data, units, per_section = _budget(snapshot)
    counts = section_counts(snapshot)
    return ReportPreviewOut(
        snapshot=snapshot.model_dump(mode="json"),
        section_counts={k: SectionCount(**v) for k, v in counts.items()},
        snapshot_bytes=len(data),
        max_snapshot_bytes=settings.report_max_snapshot_bytes,
        render_units=units,
        max_render_units=settings.report_max_render_units,
        section_units=per_section,
        over_budget=units > settings.report_max_render_units
        or len(data) > settings.report_max_snapshot_bytes,
    )


# --- finalize -------------------------------------------------------------------------------------


def _profile_rules(report: Report, body: ReportFinalize) -> None:
    if (report.tlp in STRICT_DISTRIBUTION or report.profile == "external") and not (
        report.distribution or ""
    ).strip():
        raise Unprocessable(
            "This TLP or profile needs a distribution statement", code="distribution_required"
        )
    if report.profile == "external" and not body.acknowledge_external_review:
        raise Unprocessable(
            "An external report needs the external review acknowledgement",
            code="external_review_required",
        )


async def _prepare(
    ctx: OrgContext, report_id: uuid.UUID, body: ReportFinalize, now: datetime
) -> _Prepared:
    settings = get_settings()
    async with _snapshot_session(ctx, Permission.INVESTIGATION_WRITE) as session:
        report = await repo.get_report(session, ctx.org_id, report_id)
        if report is None:
            raise NotFound()
        _is_draft(report)
        if body.revision != report.revision:
            raise StaleDraft(extra={"revision": report.revision})
        case = await _case_of(session, ctx.org_id, report)
        _not_archived(case)
        downgraded = _tlp_rule(
            ctx.permissions, report.tlp, case.tlp, body.acknowledge_tlp_downgrade
        )
        _profile_rules(report, body)
        built, snapshot = await _build_redacted(session, ctx, report, case, now, body.change_note)
        revision, latest, case_tlp = report.revision, report.latest_version, case.tlp
        tlp, profile = report.tlp, report.profile
    data, units, per_section = _budget(snapshot)
    counts = section_counts(snapshot)
    if len(data) > settings.report_max_snapshot_bytes:
        raise Unprocessable(
            "The report is larger than the snapshot limit; narrow the selections",
            code="report_too_large",
            extra={
                "snapshot_bytes": len(data),
                "max_snapshot_bytes": settings.report_max_snapshot_bytes,
                "section_counts": counts,
            },
        )
    if units > settings.report_max_render_units:
        raise Unprocessable(
            "The report is too large to render; narrow the selections",
            code="report_too_large_to_render",
            extra={
                "render_units": units,
                "max_render_units": settings.report_max_render_units,
                "section_units": per_section,
                "section_counts": counts,
            },
        )
    return _Prepared(
        built=built,
        snapshot=snapshot,
        data=data,
        sha256=report_storage.sha256(data),
        units=units,
        revision=revision,
        latest_version=latest,
        case_tlp=case_tlp,
        tlp_downgraded=downgraded,
        tlp=tlp,
        profile=profile,
    )


def _citation_rows(prepared: _Prepared) -> list[CitationRow]:
    """The built rows with the `fields_sha256` of the signed (redacted) copies."""
    signed = {c.cite_no: c.fields_sha256 for c in prepared.snapshot.citations.items}
    return [
        CitationRow(
            cite_no=row.cite_no,
            kind=row.kind,
            ref_table=row.ref_table,
            ref_id=row.ref_id,
            job_id=row.job_id,
            fields_sha256=signed.get(row.cite_no, row.fields_sha256),
            source=row.source,
            ai_citation_id=row.ai_citation_id,
        )
        for row in prepared.built.citations
        if row.cite_no in signed
    ]


async def finalize(
    ctx: OrgContext, report_id: uuid.UUID, body: ReportFinalize, request: HTTPConnection
) -> ReportVersionSummary:
    settings = get_settings()
    await rate_limit.hit(
        f"report:finalize:{ctx.user.id}", settings.report_finalize_per_user_10min, WINDOW_S
    )
    if await repo.get_report(ctx.session, ctx.org_id, report_id) is None:
        raise NotFound()
    org_id, user = ctx.org_id, ctx.user
    await _release(ctx)
    now = datetime.now(UTC)

    # 1. read (one snapshot transaction, RT14)
    prepared = await _prepare(ctx, report_id, body, now)
    number = prepared.latest_version + 1

    # 2. outside any transaction: sign, put, lock
    try:
        kid = report_signing.active_kid()
        manifest = Manifest(
            report_id=report_id,
            version=number,
            org_id=org_id,
            snapshot_sha256=prepared.sha256,
            snapshot_bytes=len(prepared.data),
            tlp=TLP(prepared.tlp),
            profile=Profile(prepared.profile),
            finalized_at=now,
            finalized_by=user.id,
            kid=kid,
        )
        raw_manifest = manifest_bytes(manifest)
        signature, signed_kid = report_signing.sign_manifest(raw_manifest)
    except SigningError as exc:
        log.error("report signing unavailable: %s", exc.code)
        raise SigningUnavailable() from None
    if signed_kid != kid:
        raise SigningUnavailable()
    key = report_storage.snapshot_key(org_id, report_id, number)
    object_version = await report_storage.put_snapshot(key, prepared.data)
    until = report_storage.retention_until(now)
    if until is not None:
        try:
            await report_storage.lock_snapshot(key, object_version, until)
        except Exception:
            report_storage.log_orphan(key, object_version, "retention_failed")
            raise

    # 3. one short write transaction
    rows = _citation_rows(prepared)
    try:
        version, render = await _write(
            org_id,
            user,
            report_id,
            body,
            request,
            prepared,
            number,
            key,
            object_version,
            raw_manifest,
            signature,
            kid,
            rows,
            now,
        )
    except BaseException as exc:
        reason = getattr(exc, "code", None) or type(exc).__name__
        report_storage.log_orphan(key, object_version, str(reason))
        raise
    if render is not None:
        try:
            await dispatch.dispatch_render([render])
        except Exception:
            # The render stays `queued`; the reaper recovers it (phase 4).
            log.exception("could not dispatch the render of report %s v%s", report_id, number)
    return _summary(repo.VersionRow(version, user.display_name))


async def _write(
    org_id: uuid.UUID,
    user: Any,
    report_id: uuid.UUID,
    body: ReportFinalize,
    request: HTTPConnection,
    prepared: _Prepared,
    number: int,
    key: str,
    object_version: str,
    raw_manifest: bytes,
    signature: str,
    kid: str,
    rows: list[CitationRow],
    now: datetime,
) -> tuple[ReportVersion, uuid.UUID | None]:
    async with org_session(org_id, user, Permission.INVESTIGATION_WRITE) as wctx:
        session = wctx.session
        await repo.lock_report(session, report_id)
        report = await repo.get_report(session, org_id, report_id, for_update=True)
        if report is None:
            raise NotFound()
        _is_draft(report)
        if report.revision != prepared.revision or report.latest_version != prepared.latest_version:
            raise StaleDraft(extra={"revision": report.revision})
        case = await _case_of(session, org_id, report)
        _not_archived(case)
        # RT7: the case TLP may have been raised while the snapshot was built and stored.
        downgraded = _tlp_rule(
            wctx.permissions, report.tlp, case.tlp, body.acknowledge_tlp_downgrade
        )
        counts = section_counts(prepared.snapshot)
        version = ReportVersion(
            organization_id=org_id,
            report_id=report_id,
            version=number,
            schema_version=prepared.snapshot.schema_version,
            tlp=prepared.tlp,
            profile=prepared.profile,
            snapshot_sha256=prepared.sha256,
            snapshot_bytes=len(prepared.data),
            object_key=key,
            object_version_id=object_version,
            manifest=json.loads(raw_manifest),
            signature=signature,
            kid=kid,
            section_counts=counts,
            change_note=body.change_note or None,
            finalized_by=user.id,
            finalized_at=now,
        )
        session.add(version)
        await session.flush()
        for row in rows:
            session.add(
                ReportCitation(
                    organization_id=org_id,
                    version_id=version.id,
                    cite_no=row.cite_no,
                    kind=row.kind,
                    ref_table=row.ref_table,
                    ref_id=row.ref_id,
                    job_id=row.job_id,
                    fields_sha256=row.fields_sha256,
                    source=row.source,
                    ai_citation_id=row.ai_citation_id,
                )
            )
        report.latest_version = number
        report.revision = report.revision + 1
        await session.flush()
        render_id: uuid.UUID | None = None
        try:
            async with session.begin_nested():
                render = await dispatch.create_render(session, org_id, user.id, version, "pdf")
                render_id = render.id
        except AppError as exc:
            # A refused render (e.g. `render_busy`) never undoes the signed version: the
            # PDF can be requested again from the viewer.
            log.warning("pdf render not queued for report %s v%s: %s", report_id, number, exc.code)
        audit.record(
            session,
            action="report.finalized",
            org_id=org_id,
            actor_id=user.id,
            target_type="report",
            target_id=report_id,
            details={
                "version": number,
                "version_id": str(version.id),
                "sha256": prepared.sha256,
                "snapshot_bytes": len(prepared.data),
                "render_units": prepared.units,
                "tlp": prepared.tlp,
                "profile": prepared.profile,
                "kid": kid,
                "citations": len(rows),
                "counts": counts,
                "tlp_downgraded": downgraded or prepared.tlp_downgraded,
                "external_review": bool(body.acknowledge_external_review)
                and prepared.profile == "external",
                "render_queued": render_id is not None,
            },
            request=request,
        )
        if downgraded or prepared.tlp_downgraded:
            audit.record(
                session,
                action="report.tlp_downgraded",
                org_id=org_id,
                actor_id=user.id,
                target_type="report",
                target_id=report_id,
                details={"case_tlp": case.tlp, "tlp": report.tlp, "version": number},
                request=request,
            )
        await session.commit()
    return version, render_id


# --- version reads -----------------------------------------------------------------------------


async def _version(ctx: OrgContext, report_id: uuid.UUID, version: int) -> repo.VersionRow:
    if await repo.get_report(ctx.session, ctx.org_id, report_id) is None:
        raise NotFound()
    row = await repo.get_version(ctx.session, ctx.org_id, report_id, version)
    if row is None:
        raise NotFound()
    return row


def manifest_matches(v: ReportVersion) -> bool:
    """The stored manifest names exactly this version, object and kid."""
    m = v.manifest or {}
    return (
        m.get("report_id") == str(v.report_id)
        and m.get("version") == v.version
        and m.get("org_id") == str(v.organization_id)
        and m.get("snapshot_sha256") == v.snapshot_sha256
        and m.get("snapshot_bytes") == v.snapshot_bytes
        and m.get("tlp") == v.tlp
        and m.get("profile") == v.profile
        and m.get("kid") == v.kid
    )


def signature_valid(v: ReportVersion) -> bool:
    return manifest_matches(v) and report_signing.verify_stored(v.manifest, v.signature, v.kid)


async def snapshot_ok(v: ReportVersion) -> bool:
    found = await report_storage.hash_snapshot(v.object_key, v.object_version_id)
    return found is not None and found == (v.snapshot_bytes, v.snapshot_sha256)


async def _audit_integrity(
    ctx: OrgContext, v: ReportVersion, *, snapshot: bool, signature: bool, permission: Permission
) -> None:
    with anyio.CancelScope(shield=True):
        try:
            async with org_session(ctx.org_id, ctx.user, permission) as actx:
                audit.record(
                    actx.session,
                    action="report.integrity_failed",
                    org_id=ctx.org_id,
                    actor_id=ctx.user.id,
                    target_type="report",
                    target_id=v.report_id,
                    details={
                        "version": v.version,
                        "version_id": str(v.id),
                        "snapshot_ok": snapshot,
                        "signature_valid": signature,
                    },
                )
        except Exception:
            log.exception("could not audit an integrity failure of report %s", v.report_id)


async def list_versions(ctx: OrgContext, report_id: uuid.UUID) -> ReportVersionList:
    if await repo.get_report(ctx.session, ctx.org_id, report_id) is None:
        raise NotFound()
    rows = await repo.versions_of(ctx.session, ctx.org_id, report_id)
    return ReportVersionList(items=[_summary(r) for r in rows])


async def get_version(ctx: OrgContext, report_id: uuid.UUID, version: int) -> ReportVersionDetail:
    row = await _version(ctx, report_id, version)
    renders = await repo.renders_of(ctx.session, ctx.org_id, row.version.id)
    await _release(ctx)
    v = row.version
    ok = await snapshot_ok(v)
    valid = signature_valid(v)
    if not (ok and valid):
        await _audit_integrity(
            ctx, v, snapshot=ok, signature=valid, permission=Permission.INVESTIGATION_READ
        )
    return ReportVersionDetail(
        version=_summary(row),
        report_id=v.report_id,
        manifest=v.manifest,
        signature=v.signature,
        signature_valid=valid,
        snapshot_ok=ok,
        section_counts={
            k: SectionCount(included=int(c.get("included", 0)), total=int(c.get("total", 0)))
            for k, c in (v.section_counts or {}).items()
            if isinstance(c, dict)
        },
        renders=[_render_out(r) for r in renders],
    )


async def _verified_bytes(ctx: OrgContext, v: ReportVersion, permission: Permission) -> bytes:
    """The stored bytes, refused (`409 integrity_failed`, audited) unless the version's
    manifest signature verifies, the bytes hash to the sha256 (and size) the signed manifest
    names and they re-serialize to the same canonical bytes."""
    try:
        data = await report_storage.read_snapshot(v.object_key, v.object_version_id)
    except report_storage.SnapshotMissing:
        data = b""
    digest = report_storage.sha256(data)
    signed = v.manifest or {}
    size_ok = len(data) == v.snapshot_bytes == signed.get("snapshot_bytes")
    snapshot = size_ok and digest == v.snapshot_sha256 == signed.get("snapshot_sha256")
    if snapshot:
        try:
            snapshot = canonical_json(parse_snapshot(data)) == data
        except ValidationError:
            snapshot = False
    signature = signature_valid(v)
    if not (snapshot and signature):
        await _audit_integrity(
            ctx, v, snapshot=snapshot, signature=signature, permission=permission
        )
        raise IntegrityFailed()
    return data


async def get_content(ctx: OrgContext, report_id: uuid.UUID, version: int) -> bytes:
    row = await _version(ctx, report_id, version)
    await _release(ctx)
    return await _verified_bytes(ctx, row.version, Permission.EVIDENCE_READ)


async def download_snapshot(
    ctx: OrgContext, report_id: uuid.UUID, version: int, request: HTTPConnection
) -> tuple[bytes, str]:
    row = await _version(ctx, report_id, version)
    v = row.version
    # The download request is recorded (and committed) before the bytes are read.
    audit.record(
        ctx.session,
        action="report.snapshot_downloaded",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="report",
        target_id=report_id,
        details={"version": v.version, "version_id": str(v.id), "sha256": v.snapshot_sha256},
        request=request,
    )
    await ctx.session.commit()
    data = await _verified_bytes(ctx, v, Permission.EVIDENCE_READ)
    return data, f"report-{report_id}-v{v.version}.snapshot.json"


async def get_signature(
    ctx: OrgContext, report_id: uuid.UUID, version: int
) -> tuple[ReportSignatureOut, str]:
    row = await _version(ctx, report_id, version)
    v = row.version
    out = ReportSignatureOut(manifest=v.manifest, signature=v.signature, kid=v.kid)
    return out, f"report-{report_id}-v{v.version}.sig.json"


__all__ = [
    "IntegrityFailed",
    "SigningUnavailable",
    "StaleDraft",
    "Unprocessable",
    "create_report",
    "discard_report",
    "download_snapshot",
    "finalize",
    "get_content",
    "get_report",
    "get_signature",
    "get_version",
    "list_case_reports",
    "list_reports",
    "list_versions",
    "preview",
    "update_report",
    "validate_selection",
]
