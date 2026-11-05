"""Row seeding for the M6 case-management tests (phase 1, FROZEN for group B).

Rows are inserted directly in tenant sessions (no routes), so every phase can seed a case
with its TLP and share-policy flags, evidence with a share-policy row, status events, notes
with versions, IOC collections with items and ATT&CK mappings. Phases add their own
helpers in their own modules; nobody edits `tests/conftest.py`.
"""

import secrets
import uuid
from datetime import UTC, datetime

from cyberlab_jobs.static import Profile
from sqlalchemy import update

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.case_attack.models import CaseAttackMapping
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import (
    EvidenceSharePolicy,
    Investigation,
    InvestigationStatusEvent,
    Severity,
)
from app.modules.ioc_collections.models import IocCollection, IocCollectionItem
from app.modules.notes.models import AnalystNote, AnalystNoteVersion
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key
from tests.integration.seed import Tenant


async def seed_case(
    t: Tenant,
    *,
    title: str = "M6 case",
    tlp: str = "amber",
    ai_excluded: bool = False,
    ti_excluded: bool = False,
    case_number: int | None = None,
) -> uuid.UUID:
    """A new case of the tenant's org (case numbers from 1000 up unless given)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        case = Investigation(
            organization_id=t.org_id,
            case_number=case_number or 1000 + secrets.randbelow(1_000_000),
            title=title,
            severity=Severity.HIGH,
            created_by=t.owner_id,
            tlp=tlp,
            ai_excluded=ai_excluded,
            ti_excluded=ti_excluded,
        )
        s.add(case)
    return case.id


async def set_case_policy(
    t: Tenant,
    investigation_id: uuid.UUID,
    *,
    tlp: str | None = None,
    ai_excluded: bool | None = None,
    ti_excluded: bool | None = None,
) -> None:
    values: dict[str, object] = {}
    if tlp is not None:
        values["tlp"] = tlp
    if ai_excluded is not None:
        values["ai_excluded"] = ai_excluded
    if ti_excluded is not None:
        values["ti_excluded"] = ti_excluded
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(Investigation).where(Investigation.id == investigation_id).values(**values)
        )


async def seed_evidence(
    t: Tenant, investigation_id: uuid.UUID | None = None, *, filename: str = "capture.pcap"
) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        evidence = Evidence(
            organization_id=t.org_id,
            investigation_id=investigation_id or t.investigation_id,
            original_filename=filename,
            detected_mime="application/octet-stream",
            detected_description="data",
            size_bytes=1024,
            storage_bucket="evidence-test",
            storage_key=f"{t.org_id}/{uuid.uuid4()}",
            storage_version_id="v1",
            uploaded_by=t.owner_id,
        )
        s.add(evidence)
    return evidence.id


async def seed_job_on(
    t: Tenant, evidence_id: uuid.UUID, analyzer: str = "pcap", *, status: str = "succeeded"
) -> uuid.UUID:
    """An analysis job on existing evidence (no results)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        job = AnalysisJob(
            organization_id=t.org_id,
            evidence_id=evidence_id,
            analyzer=Analyzer(analyzer),
            profile=Profile.FULL if analyzer == "static" else None,
            status=AnalysisStatus(status),
            requested_by=t.owner_id,
            ingest_token_sha256=secrets.token_hex(32),
        )
        s.add(job)
    return job.id


async def set_evidence_policy(
    t: Tenant, evidence_id: uuid.UUID, *, ai_excluded: bool = False, ti_excluded: bool = False
) -> None:
    """Insert or replace the evidence's share-policy row."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(EvidenceSharePolicy, evidence_id)
        if row is None:
            s.add(
                EvidenceSharePolicy(
                    evidence_id=evidence_id,
                    organization_id=t.org_id,
                    ai_excluded=ai_excluded,
                    ti_excluded=ti_excluded,
                    updated_by=t.owner_id,
                )
            )
        else:
            row.ai_excluded = ai_excluded
            row.ti_excluded = ti_excluded
            row.updated_by = t.owner_id


async def seed_status_event(
    t: Tenant,
    investigation_id: uuid.UUID | None = None,
    *,
    from_status: str | None = "open",
    to_status: str = "in_progress",
    reason: str | None = None,
) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        event = InvestigationStatusEvent(
            organization_id=t.org_id,
            investigation_id=investigation_id or t.investigation_id,
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            actor_id=t.owner_id,
        )
        s.add(event)
    return event.id


async def seed_note(
    t: Tenant,
    investigation_id: uuid.UUID | None = None,
    *,
    bodies: tuple[str, ...] = ("First note",),
    refs: list[dict[str, str]] | None = None,
    pinned: bool = False,
    include_in_reports: bool = False,
    deleted: bool = False,
) -> uuid.UUID:
    """A note with one version per body (the last one is current)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        note = AnalystNote(
            organization_id=t.org_id,
            investigation_id=investigation_id or t.investigation_id,
            created_by=t.owner_id,
            current_version=len(bodies),
            pinned=pinned,
            include_in_reports=include_in_reports,
            deleted_at=datetime.now(UTC) if deleted else None,
            deleted_by=t.owner_id if deleted else None,
        )
        s.add(note)
        await s.flush()
        for number, body in enumerate(bodies, start=1):
            s.add(
                AnalystNoteVersion(
                    note_id=note.id,
                    version=number,
                    organization_id=t.org_id,
                    body=body,
                    refs=refs or [],
                    author_id=t.owner_id,
                )
            )
    return note.id


async def seed_collection(
    t: Tenant, investigation_id: uuid.UUID | None = None, *, name: str = "Blocklist"
) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        collection = IocCollection(
            organization_id=t.org_id,
            investigation_id=investigation_id or t.investigation_id,
            name=name,
            created_by=t.owner_id,
        )
        s.add(collection)
    return collection.id


async def seed_collection_item(
    t: Tenant,
    collection_id: uuid.UUID,
    *,
    ioc_type: str = "domain",
    value: str = "evil.example",
    job_id: uuid.UUID | None = None,
    ioc_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """A manual item (or a job IOC when `job_id` and `ioc_id` are given)."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        item = IocCollectionItem(
            organization_id=t.org_id,
            collection_id=collection_id,
            ioc_type=ioc_type,
            value_norm=value,
            ioc_key=compute_ioc_key(IocType(ioc_type), value),
            source="job_ioc" if ioc_id is not None else "manual",
            job_id=job_id,
            ioc_id=ioc_id,
            added_by=t.owner_id,
        )
        s.add(item)
    return item.id


async def seed_mapping(
    t: Tenant,
    investigation_id: uuid.UUID | None = None,
    *,
    technique_id: str = "T1071.001",
    status: str = "confirmed",
    rationale: str = "HTTPS beacon",
) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        mapping = CaseAttackMapping(
            organization_id=t.org_id,
            investigation_id=investigation_id or t.investigation_id,
            technique_id=technique_id,
            status=status,
            rationale=rationale,
            sources=[],
            created_by=t.owner_id,
            updated_by=t.owner_id,
        )
        s.add(mapping)
    return mapping.id
