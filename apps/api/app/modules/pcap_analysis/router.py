"""Read API over one PCAP analysis job's persisted results (evidence.read)."""

import uuid
from typing import Annotated

from cyberlab_jobs.results import Ip
from fastapi import APIRouter, Depends, Query

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.pcap_analysis import repository as repo
from app.modules.pcap_analysis.schemas import (
    AlertOut,
    AlertPage,
    FindingOut,
    FindingPage,
    FindingSeverity,
    FlowOut,
    FlowPage,
    FlowProto,
    FlowSort,
    IocOut,
    IocPage,
    IocType,
    RecordKind,
    RecordOut,
    RecordPage,
    TimelineOut,
    TimelinePage,
)

router = APIRouter(prefix="/orgs/{org_id}/analyses/{job_id}", tags=["pcap-analysis"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
FindingType = Annotated[str, Query(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
Port = Annotated[int, Query(ge=0, le=65535)]


@router.get("/findings", response_model=FindingPage)
async def list_findings(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    severity: FindingSeverity | None = None,
    type: FindingType | None = None,  # noqa: A002 - public query parameter name
) -> FindingPage:
    await repo.ensure_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.findings(
        ctx.session, ctx.org_id, job_id, page, severity=severity, type_=type
    )
    return FindingPage(items=[FindingOut.model_validate(r) for r in rows], total=total)


@router.get("/flows", response_model=FlowPage)
async def list_flows(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    ip: Annotated[Ip | None, Query()] = None,  # the contract's type: no IPv6 zone ids
    port: Port | None = None,
    proto: FlowProto | None = None,
    sort: FlowSort = FlowSort.BYTES,
) -> FlowPage:
    await repo.ensure_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.flows(
        ctx.session,
        ctx.org_id,
        job_id,
        page,
        ip=None if ip is None else str(ip),
        port=port,
        proto=proto,
        sort=sort,
    )
    return FlowPage(items=[FlowOut.model_validate(r) for r in rows], total=total)


@router.get("/records", response_model=RecordPage)
async def list_records(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    kind: RecordKind | None = None,
    q: Annotated[SearchTerm | None, Query()] = None,
) -> RecordPage:
    await repo.ensure_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.records(ctx.session, ctx.org_id, job_id, page, kind=kind, q=q)
    return RecordPage(items=[RecordOut.model_validate(r) for r in rows], total=total)


@router.get("/alerts", response_model=AlertPage)
async def list_alerts(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    severity: Annotated[int | None, Query(ge=1, le=4)] = None,
) -> AlertPage:
    await repo.ensure_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.alerts(ctx.session, ctx.org_id, job_id, page, severity=severity)
    return AlertPage(items=[AlertOut.model_validate(r) for r in rows], total=total)


@router.get("/iocs", response_model=IocPage)
async def list_iocs(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    type: IocType | None = None,  # noqa: A002 - public query parameter name
    q: Annotated[SearchTerm | None, Query()] = None,
) -> IocPage:
    await repo.ensure_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.iocs(ctx.session, ctx.org_id, job_id, page, type_=type, q=q)
    return IocPage(items=[IocOut.model_validate(r) for r in rows], total=total)


@router.get("/timeline", response_model=TimelinePage)
async def list_timeline(job_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep) -> TimelinePage:
    await repo.ensure_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.timeline(ctx.session, ctx.org_id, job_id, page)
    return TimelinePage(items=[TimelineOut.model_validate(r) for r in rows], total=total)
