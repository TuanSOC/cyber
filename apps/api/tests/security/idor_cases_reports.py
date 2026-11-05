"""IDOR cases owned by M6 phase 3 (report drafts, finalize, versions, citations), plus the
seeding the phase-3 report tests share (a case with pcap / static results, AI runs, the
dispatch and case-IOC stand-ins).

Every report route has a case. The victim extender seeds a report with a finalized version
(its snapshot object in `reports-test`, signed with a test key) and a second report with no
version (the only kind `discard` accepts), and patches the cross-phase stubs this lane runs
against (`dispatch.create_render` / `dispatch_render` of phase 4) and the api's signing key
(api-test holds none), only while they are absent. `{report_id}` is a resource parameter.
"""

import hashlib
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.results import DnsRecord
from cyberlab_jobs.static import StringRecord
from httpx import Response
from pydantic import BaseModel
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.ai.contracts import (
    CitationResult,
    CitationStatus,
    ClaimStatus,
    ClaimVerdict,
    OutputVerification,
    RefKind,
)
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence
from app.modules.ioc_collections import case_iocs as case_iocs_mod
from app.modules.ioc_collections.schemas import CaseIocOut, CaseIocPage
from app.modules.pcap_analysis.models import Ioc
from app.modules.reports import dispatch
from app.modules.reports import signing as report_signing
from app.modules.reports.models import Report, ReportRender, ReportRenderIndex, ReportVersion
from app.workers import ingest
from tests import pcap_results, static_results
from tests.ai_api_helpers import finish_run
from tests.ai_doubles import make_context
from tests.ai_helpers import seed_ai_run
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant
from tests.report_helpers import new_signing_keys, seed_report, seed_version
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

API = "/api/v1/orgs"
_ORG = "/api/v1/orgs/{org_id}"
_REPORT = f"{_ORG}/reports/{{report_id}}"
_VERSION = f"{_REPORT}/versions/{{version}}"


# --- shared seeding for the phase-3 report tests -----------------------------------------------


async def owner_case(org_name: str = "Report Org", **case: Any) -> tuple[Registered, Tenant]:
    """A registered owner and a new case (created through the API)."""
    reg = await register(org_name=org_name)
    created = await reg.client.post(
        f"{API}/{reg.org_id}/investigations",
        json={"title": case.pop("title", "Report case"), "severity": "high", **case},
        headers=csrf(reg.client),
    )
    assert created.status_code == 201, created.text
    return reg, Tenant(reg.org_id, reg.user_id, uuid.UUID(created.json()["id"]))


async def upload(reg: Registered, case_id: uuid.UUID, content: bytes, filename: str) -> uuid.UUID:
    response = await reg.client.post(
        f"{API}/{reg.org_id}/investigations/{case_id}/evidence",
        params={"filename": filename},
        content=content,
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


async def _job_for(reg: Registered, evidence_id: uuid.UUID, analyzer: str) -> uuid.UUID:
    jobs = (await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/analyses")).json()
    found = [j for j in jobs["items"] if j["analyzer"] == analyzer and j["status"] == "queued"]
    if found:
        return uuid.UUID(found[0]["id"])
    created = await reg.client.post(
        f"{API}/{reg.org_id}/evidence/{evidence_id}/analyses",
        json={"analyzer": analyzer},
        headers=csrf(reg.client),
    )
    assert created.status_code in (201, 202), created.text
    return uuid.UUID(created.json()["id"])


async def pcap_job(
    reg: Registered,
    t: Tenant,
    records: Sequence[BaseModel] | None = None,
    *,
    filename: str = "capture.pcap",
) -> tuple[uuid.UUID, uuid.UUID]:
    """Uploaded evidence (real hashes, custody) and a succeeded pcap job with results."""
    evidence_id = await upload(reg, t.investigation_id, secrets.token_bytes(64), filename)
    job_id = await _job_for(reg, evidence_id, "pcap")
    data = pcap_results.stream(job_id, list(records) if records is not None else None)
    await pcap_results.seed_results(t.org_id, job_id, data)
    return evidence_id, job_id


async def static_job(
    reg: Registered,
    t: Tenant,
    extra: Sequence[BaseModel] = (),
    *,
    filename: str = "sample.exe",
) -> tuple[uuid.UUID, uuid.UUID]:
    """Uploaded evidence and a succeeded static job (the sample records plus `extra`)."""
    evidence_id = await upload(reg, t.investigation_id, secrets.token_bytes(96), filename)
    job_id = await _job_for(reg, evidence_id, "static")
    sample = await static_results.evidence_sample(t.org_id, job_id)
    records = [*static_results.sample_records(), *extra]
    data = static_results.stream(job_id, sample, records)
    version_id = pcap_results.put_result(t.org_id, job_id, data)
    async with tenant_session(t.org_id, None) as session:
        job = await session.get(AnalysisJob, job_id)
    assert job is not None
    await ingest.ingest_success(
        job,
        IngestMessageV1(
            job_id=job_id,
            organization_id=t.org_id,
            ingest_token="t" * 43,
            event="finished",
            outcome="succeeded",
            result_version_id=version_id,
            worker_version=static_results.WORKER,
        ),
    )
    return evidence_id, job_id


def dns(query: str, ts: int = 10) -> DnsRecord:
    return DnsRecord(ts=pcap_results.at(ts), query=query, qtype="A", rcode="NOERROR")


def user_string(path: str) -> StringRecord:
    return StringRecord(value=path, encoding="ascii", offset=64)


async def rows_of(t: Tenant, model: Any, job_id: uuid.UUID) -> list[Any]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = await s.scalars(
            select(model).where(model.job_id == job_id).order_by(model.id)  # type: ignore[attr-defined]
        )
        return list(rows)


async def ai_run_on(
    t: Tenant,
    job_id: uuid.UUID,
    *,
    claims: Sequence[tuple[str, str, Sequence[tuple[str, str]]]],
    pseudonym_map: dict[str, str] | None = None,
    unsupported: Sequence[str] = (),
    status: str = "completed",
    flags: Sequence[str] = (),
    next_steps: Sequence[str] = (),
) -> uuid.UUID:
    """A completed job run whose `observed` claims are `(id, text, [(kind, ref_id), ...])`;
    every citation is verified against the given row, every claim supported unless listed
    in `unsupported`."""
    ctx = make_context(job_id=job_id, pseudonym_map=pseudonym_map or {})
    run_id = await seed_ai_run(t, job_id=job_id, ctx=ctx)
    observed = []
    results = []
    verdicts: dict[str, ClaimVerdict] = {}
    for n, (cid, text, cites) in enumerate(claims):
        observed.append(
            {
                "id": cid,
                "text": text,
                "confidence": "high",
                "citations": [{"ref": f"F{m + 1}", "field": "title"} for m in range(len(cites))],
            }
        )
        for m, (kind, ref_id) in enumerate(cites):
            results.append(
                CitationResult(
                    claim_path=f"observed[{n}].citations[{m}]",
                    section="observed",
                    claim_id=cid,
                    label=f"F{m + 1}",
                    kind=RefKind(kind),
                    ref_id=ref_id,
                    job_id=job_id,
                    field="title",
                    status=CitationStatus.VERIFIED,
                )
            )
        status_ = ClaimStatus.UNSUPPORTED if cid in unsupported else ClaimStatus.SUPPORTED
        verdicts[cid] = ClaimVerdict(status=status_)
    body = {
        "observed": observed,
        "hypotheses": [
            {"id": "h1", "text": "Possibly a loader", "confidence": "low"},
        ],
        "overall_confidence": {"level": "medium", "rationale": "Two sources agree"},
        "next_steps": [{"text": s, "rationale": "Containment"} for s in next_steps],
        "limitations": ["One capture only"],
    }
    await finish_run(
        t.org_id,
        run_id,
        status=status,
        body=body,
        citations=results,
        verification=OutputVerification(claims=verdicts),
        flags=flags,
    )
    return run_id


async def api_create(reg: Registered, t: Tenant, **body: Any) -> Response:
    return await reg.client.post(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/reports",
        json={"title": "Incident report", **body},
        headers=csrf(reg.client),
    )


async def api_get(reg: Registered, report_id: str | uuid.UUID) -> dict[str, Any]:
    response = await reg.client.get(f"{API}/{reg.org_id}/reports/{report_id}")
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


async def api_patch(reg: Registered, report_id: str | uuid.UUID, **body: Any) -> Response:
    if "revision" not in body:
        body["revision"] = (await api_get(reg, report_id))["report"]["revision"]
    return await reg.client.patch(
        f"{API}/{reg.org_id}/reports/{report_id}", json=body, headers=csrf(reg.client)
    )


async def api_finalize(reg: Registered, report_id: str | uuid.UUID, **body: Any) -> Response:
    if "revision" not in body:
        body["revision"] = (await api_get(reg, report_id))["report"]["revision"]
    return await reg.client.post(
        f"{API}/{reg.org_id}/reports/{report_id}/finalize", json=body, headers=csrf(reg.client)
    )


async def api_preview(reg: Registered, report_id: str | uuid.UUID) -> Response:
    return await reg.client.post(
        f"{API}/{reg.org_id}/reports/{report_id}/preview", headers=csrf(reg.client)
    )


def draft(**include: Any) -> dict[str, Any]:
    """A draft with the given `include` overrides (case IOCs off unless asked)."""
    sections = include.pop("sections", {})
    base: dict[str, Any] = {"iocs": {"case_iocs": False}}
    base.update(include)
    return {"sections": sections, "include": base}


@dataclass
class Dispatched:
    created: list[tuple[uuid.UUID, str]] = field(default_factory=list)
    sent: list[uuid.UUID] = field(default_factory=list)


async def _fake_create_render(
    session: Any, org_id: uuid.UUID, user_id: uuid.UUID, version: ReportVersion, fmt: str
) -> ReportRender:
    token = secrets.token_urlsafe(32)
    render = ReportRender(
        organization_id=org_id,
        version_id=version.id,
        format=fmt,
        status="queued",
        token_sha256=hashlib.sha256(token.encode()).hexdigest(),
        requested_by=user_id,
    )
    session.add(render)
    await session.flush()
    session.add(
        ReportRenderIndex(
            render_id=render.id,
            organization_id=org_id,
            status="queued",
            deadline_at=datetime.now(UTC) + timedelta(seconds=600),
        )
    )
    return render


def fake_dispatch(monkeypatch: Any) -> Dispatched:
    """Phase 4's `create_render` / `dispatch_render` replaced for one test (recorded)."""
    calls = Dispatched()

    async def create(
        session: Any, org_id: uuid.UUID, user_id: uuid.UUID, version: ReportVersion, fmt: str
    ) -> ReportRender:
        render = await _fake_create_render(session, org_id, user_id, version, fmt)
        calls.created.append((version.id, fmt))
        return render

    async def send(render_ids: Sequence[uuid.UUID]) -> None:
        calls.sent.extend(render_ids)

    monkeypatch.setattr(dispatch, "create_render", create)
    monkeypatch.setattr(dispatch, "dispatch_render", send)
    return calls


def ioc_key(ioc_type: str, value: str) -> str:
    return hashlib.sha256(f"{ioc_type}\x00{value.lower()}".encode()).hexdigest()


async def _fake_case_iocs(
    session: Any,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    types: Sequence[str] | None = None,
    q: str | None = None,
    limit: int,
    cursor: str | None = None,
) -> CaseIocPage:
    """Phase 2's case-wide IOC read, reduced: every IOC of the case's jobs, deduplicated."""
    rows = await session.execute(
        select(Ioc.type, Ioc.value, Ioc.job_id, Ioc.first_seen, Ioc.last_seen)
        .join(AnalysisJob, AnalysisJob.id == Ioc.job_id)
        .join(Evidence, Evidence.id == AnalysisJob.evidence_id)
        .where(Ioc.organization_id == org_id, Evidence.investigation_id == investigation_id)
        .order_by(Ioc.type, Ioc.value, Ioc.job_id)
    )
    merged: dict[tuple[str, str], CaseIocOut] = {}
    for ioc_type, value, job_id, first, last in rows.all():
        found = merged.get((ioc_type, value))
        if found is None:
            merged[(ioc_type, value)] = CaseIocOut(
                ioc_type=ioc_type,
                value=value,
                ioc_key=ioc_key(ioc_type, value),
                count_jobs=1,
                first_seen=first,
                last_seen=last,
                job_ids=[job_id],
                in_collections=[],
            )
        elif job_id not in found.job_ids:
            found.count_jobs += 1
            found.job_ids = [*found.job_ids, job_id][:5]
    items = list(merged.values())
    start = int(cursor or 0)
    page = items[start : start + limit]
    more = start + limit < len(items)
    return CaseIocPage(
        items=page, next_cursor=str(start + limit) if more else None, total=len(items)
    )


def fake_case_iocs(monkeypatch: Any) -> None:
    monkeypatch.setattr(case_iocs_mod, "case_iocs", _fake_case_iocs)


# --- IDOR -------------------------------------------------------------------------------------


async def _is_stub(func: Any, *args: Any) -> bool:
    try:
        await func(*args)
    except NotImplementedError:
        return True
    except Exception:  # noqa: BLE001 - a real implementation refuses the dummy call otherwise
        return False
    return False


async def _install_stand_ins() -> None:
    """Only while the phase-4 dispatch and the api signing key are absent (this lane).
    Plain assignments: `test_idor_routes._no_publish` registers the originals with
    monkeypatch first, so they are restored after each test."""
    if await _is_stub(dispatch.dispatch_render, []):

        async def send(render_ids: Sequence[uuid.UUID]) -> None:
            return None

        dispatch.create_render = _fake_create_render  # type: ignore[assignment]
        dispatch.dispatch_render = send  # type: ignore[assignment]
    if get_settings().report_signing_keys_file is None:
        kid = report_signing.active_kid()
        key = Ed25519PrivateKey.generate()
        report_signing._private_keys = lambda: {kid: key}  # type: ignore[method-assign]


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    await _install_stand_ins()
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    report_id = await seed_report(tenant, title="Victim report", draft=draft())
    await seed_version(tenant, report_id, new_signing_keys())
    discardable = await seed_report(tenant, title="Victim draft", draft=draft())
    async with tenant_session(victim.org_id, owner.user_id) as s:
        revision = await s.scalar(select(Report.revision).where(Report.id == report_id))
    return {
        "report_id": str(report_id),
        "draft_report_id": str(discardable),
        "report_revision": str(revision),
        "version": "1",
        "finding_id": str(uuid.UUID(int=1)),
    }


def _draft_report(victim: Victim) -> dict[str, str]:
    return {"report_id": victim.extra["draft_report_id"]}


async def _report_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    base = f"{API}/{victim.org_id}"
    reports = (await owner.client.get(f"{base}/reports")).json()
    versions = (
        await owner.client.get(f"{base}/reports/{victim.extra['report_id']}/versions")
    ).json()
    return {
        "reports": sorted(
            (r["id"], r["title"], r["status"], r["revision"], r["latest_version"], r["tlp"])
            for r in reports["items"]
        ),
        "report_versions": sorted((v["id"], v["version"]) for v in versions["items"]),
    }


ROUTE_CASES: RouteCases = {
    ("GET", f"{_ORG}/reports"): lambda v: {"params": {"investigation_id": v.investigation_id}},
    ("GET", f"{_ORG}/investigations/{{investigation_id}}/reports"): lambda v: {},
    ("POST", f"{_ORG}/investigations/{{investigation_id}}/reports"): lambda v: {
        "json": {"title": "Injected report"}
    },
    ("GET", _REPORT): lambda v: {},
    ("PATCH", _REPORT): lambda v: {
        "json": {"revision": int(v.extra["report_revision"]), "title": "Hijacked report"}
    },
    ("POST", f"{_REPORT}/discard"): lambda v: {},
    ("POST", f"{_REPORT}/preview"): lambda v: {},
    ("POST", f"{_REPORT}/finalize"): lambda v: {
        "json": {"revision": int(v.extra["report_revision"]), "change_note": "Injected"}
    },
    ("GET", f"{_REPORT}/versions"): lambda v: {},
    ("GET", _VERSION): lambda v: {},
    ("GET", f"{_VERSION}/content"): lambda v: {},
    ("GET", f"{_VERSION}/snapshot"): lambda v: {},
    ("GET", f"{_VERSION}/signature"): lambda v: {},
    ("GET", f"{_ORG}/cited-by"): lambda v: {
        "params": {"kind": "finding", "ref_id": v.extra["finding_id"], "job_id": v.job_id}
    },
}
VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
PATH_OVERRIDES: PathOverrides = {f"{_REPORT}/discard": _draft_report}
RESOURCE_PARAMS: tuple[str, ...] = ("{report_id}",)
STATE_HOOKS: list[StateHook] = [_report_state]
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
