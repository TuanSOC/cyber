"""The ordered segment set of a disk analysis request (M9 phase 7).

A disk job reads 1..`DISK_MAX_SEGMENTS` evidence items in the analyst's order (E01, E02…, or
`.001`, `.002`… of a split raw image); segment 0 is the evidence of the request path. Rules:

- `segments[0]` is the path evidence (`first_segment`), at most `DISK_MAX_SEGMENTS`
  (`too_many`), no id twice (`duplicate`);
- every id is evidence of this org (`not_found`: another org's id is indistinguishable from an
  unknown one, no oracle) in the request's investigation (`other_investigation`), not purged
  by retention (`purged`), not archived (`archived`), not empty (`empty`);
- each segment within `DISK_MAX_UPLOAD_BYTES` (`413 disk_image_too_large`), the sum within
  `DISK_MAX_IMAGE_BYTES` (`413 disk_image_set_too_large`).

Every other refusal is `422 disk_segments_invalid` with `reason` (and the offending `ordinal`)
beside the code. The `analysis_job_segments` trigger re-checks the investigation at insert.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.modules.disk_forensics.errors import (
    DiskImageSetTooLarge,
    DiskImageTooLarge,
    DiskSegmentsInvalid,
)
from app.modules.disk_forensics.models import AnalysisJobSegment
from app.modules.evidence.models import Evidence, EvidenceHash, EvidenceStatus, HashAlgorithm
from app.modules.retention.models import EvidencePurge

REASONS = (
    "first_segment",
    "too_many",
    "duplicate",
    "not_found",
    "other_investigation",
    "purged",
    "archived",
    "empty",
)


@dataclass(frozen=True)
class Segment:
    """One validated segment: what the dispatch needs to presign its exact version."""

    ordinal: int
    evidence_id: uuid.UUID
    storage_bucket: str
    storage_key: str
    storage_version_id: str
    sha256: str
    size_bytes: int


def invalid(reason: str, ordinal: int | None = None) -> DiskSegmentsInvalid:
    extra: dict[str, object] = {"reason": reason}
    if ordinal is not None:
        extra["ordinal"] = ordinal
    return DiskSegmentsInvalid(extra=extra)


def check_shape(evidence_id: uuid.UUID, segment_ids: list[uuid.UUID], settings: Settings) -> None:
    """The rules that need no database (before any transaction)."""
    if len(segment_ids) > settings.disk_max_segments:
        raise invalid("too_many")
    if not segment_ids or segment_ids[0] != evidence_id:
        raise invalid("first_segment", 0)
    seen: set[uuid.UUID] = set()
    for ordinal, segment_id in enumerate(segment_ids):
        if segment_id in seen:
            raise invalid("duplicate", ordinal)
        seen.add(segment_id)


@dataclass(frozen=True)
class Stored:
    """What the database holds about one requested segment (RLS-visible rows only)."""

    investigation_id: uuid.UUID
    archived: bool
    purged: bool
    size_bytes: int
    sha256: str | None
    storage_bucket: str
    storage_key: str
    storage_version_id: str


def check_rows(
    segment_ids: list[uuid.UUID],
    investigation_id: uuid.UUID,
    stored: dict[uuid.UUID, Stored],
    settings: Settings,
) -> list[Segment]:
    """The per-segment and set rules over the stored facts (pure)."""
    out: list[Segment] = []
    total = 0
    for ordinal, segment_id in enumerate(segment_ids):
        row = stored.get(segment_id)
        if row is None or row.sha256 is None:
            raise invalid("not_found", ordinal)
        if row.investigation_id != investigation_id:
            raise invalid("other_investigation", ordinal)
        if row.purged:
            raise invalid("purged", ordinal)
        if row.archived:
            raise invalid("archived", ordinal)
        if row.size_bytes <= 0:
            raise invalid("empty", ordinal)
        if row.size_bytes > settings.disk_max_upload_bytes:
            raise DiskImageTooLarge(extra={"ordinal": ordinal})
        total += row.size_bytes
        out.append(
            Segment(
                ordinal=ordinal,
                evidence_id=segment_id,
                storage_bucket=row.storage_bucket,
                storage_key=row.storage_key,
                storage_version_id=row.storage_version_id,
                sha256=row.sha256,
                size_bytes=row.size_bytes,
            )
        )
    if total > settings.disk_max_image_bytes:
        raise DiskImageSetTooLarge()
    return out


async def load(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    segment_ids: list[uuid.UUID],
    settings: Settings,
) -> list[Segment]:
    """Every segment checked against the stored evidence (tenant session: RLS hides other
    orgs' rows). FOR KEY SHARE on each evidence row until the job's transaction ends."""
    ids = list(segment_ids)
    rows = (
        await session.execute(
            select(Evidence)
            .where(Evidence.organization_id == org_id, Evidence.id.in_(ids))
            .with_for_update(read=True, key_share=True)
        )
    ).scalars()
    evidence = {e.id: e for e in rows}
    purged = set(
        (
            await session.execute(
                select(EvidencePurge.evidence_id).where(
                    EvidencePurge.organization_id == org_id, EvidencePurge.evidence_id.in_(ids)
                )
            )
        ).scalars()
    )
    hashes: dict[uuid.UUID, str] = dict(
        (
            await session.execute(
                select(EvidenceHash.evidence_id, EvidenceHash.value).where(
                    EvidenceHash.organization_id == org_id,
                    EvidenceHash.evidence_id.in_(ids),
                    EvidenceHash.algorithm == HashAlgorithm.SHA256,
                )
            )
        ).tuples()
    )
    stored = {
        e.id: Stored(
            investigation_id=e.investigation_id,
            archived=e.status == EvidenceStatus.ARCHIVED,
            purged=e.id in purged,
            size_bytes=e.size_bytes,
            sha256=hashes.get(e.id),
            storage_bucket=e.storage_bucket,
            storage_key=e.storage_key,
            storage_version_id=e.storage_version_id,
        )
        for e in evidence.values()
    }
    return check_rows(ids, investigation_id, stored, settings)


async def of_job(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> list[Segment]:
    """The stored segment set of a job, in order (re-dispatch, ingest custody, phase 10)."""
    rows = await session.execute(
        select(AnalysisJobSegment.ordinal, Evidence, EvidenceHash.value)
        .join(
            Evidence,
            (Evidence.id == AnalysisJobSegment.evidence_id)
            & (Evidence.organization_id == AnalysisJobSegment.organization_id),
        )
        .join(
            EvidenceHash,
            (EvidenceHash.evidence_id == Evidence.id)
            & (EvidenceHash.algorithm == HashAlgorithm.SHA256),
        )
        .where(AnalysisJobSegment.organization_id == org_id, AnalysisJobSegment.job_id == job_id)
        .order_by(AnalysisJobSegment.ordinal)
    )
    return [
        Segment(
            ordinal=ordinal,
            evidence_id=evidence.id,
            storage_bucket=evidence.storage_bucket,
            storage_key=evidence.storage_key,
            storage_version_id=evidence.storage_version_id,
            sha256=sha256,
            size_bytes=evidence.size_bytes,
        )
        for ordinal, evidence, sha256 in rows.tuples()
    ]
