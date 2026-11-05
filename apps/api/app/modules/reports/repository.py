"""Report rows (M6 phase 3). Every query runs in the caller's tenant session and also filters
on the org explicitly (RLS stays on, defense in depth)."""

import base64
import binascii
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import Select, func, select, text, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.modules.investigations.models import Investigation
from app.modules.organizations.models import OrganizationMember
from app.modules.reports.models import Report, ReportRender, ReportVersion
from app.modules.users.models import User

PAGE_SIZE = 50


class InvalidCursor(AppError):
    status_code = 400
    code = "invalid_cursor"
    message = "The cursor is not valid for this list"


@dataclass(frozen=True)
class ReportRow:
    report: Report
    case_number: int
    created_by_name: str


@dataclass(frozen=True)
class VersionRow:
    version: ReportVersion
    finalized_by_name: str


# --- cursor -----------------------------------------------------------------------------------


def encode_cursor(updated_at: datetime, report_id: uuid.UUID) -> str:
    raw = json.dumps([updated_at.isoformat(), str(report_id)]).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(token: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        ts, rid = json.loads(raw)
        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            raise ValueError("cursor")
        return parsed, uuid.UUID(rid)
    except (ValueError, TypeError, binascii.Error, json.JSONDecodeError):
        raise InvalidCursor() from None


# --- reads ------------------------------------------------------------------------------------


async def get_case(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> Investigation | None:
    stmt = select(Investigation).where(
        Investigation.id == investigation_id, Investigation.organization_id == org_id
    )
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.scalars(stmt)).one_or_none()


async def get_report(
    session: AsyncSession, org_id: uuid.UUID, report_id: uuid.UUID, *, for_update: bool = False
) -> Report | None:
    stmt = select(Report).where(Report.id == report_id, Report.organization_id == org_id)
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.scalars(stmt)).one_or_none()


async def report_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    *,
    investigation_id: uuid.UUID | None = None,
    status: str | None = None,
    after: tuple[datetime, uuid.UUID] | None = None,
    limit: int = PAGE_SIZE,
    report_ids: Sequence[uuid.UUID] | None = None,
) -> list[ReportRow]:
    """Newest change first (updated_at, id); `limit + 1` rows tell the caller if more exist."""
    stmt = (
        select(Report, Investigation.case_number, User.display_name)
        .join(
            Investigation,
            (Investigation.id == Report.investigation_id)
            & (Investigation.organization_id == Report.organization_id),
        )
        .join(User, User.id == Report.created_by)
        .where(Report.organization_id == org_id)
    )
    if investigation_id is not None:
        stmt = stmt.where(Report.investigation_id == investigation_id)
    if status is not None:
        stmt = stmt.where(Report.status == status)
    if report_ids is not None:
        stmt = stmt.where(Report.id.in_(list(report_ids)))
    if after is not None:
        stmt = stmt.where(tuple_(Report.updated_at, Report.id) < tuple_(after[0], after[1]))
    stmt = stmt.order_by(Report.updated_at.desc(), Report.id.desc()).limit(limit)
    rows = (await session.execute(stmt)).all()
    return [ReportRow(r[0], int(r[1]), r[2]) for r in rows]


def _versions_query() -> Select[ReportVersion, str]:
    return select(ReportVersion, User.display_name).join(
        User, User.id == ReportVersion.finalized_by
    )


async def versions_of(
    session: AsyncSession, org_id: uuid.UUID, report_id: uuid.UUID
) -> list[VersionRow]:
    rows = await session.execute(
        _versions_query()
        .where(ReportVersion.organization_id == org_id, ReportVersion.report_id == report_id)
        .order_by(ReportVersion.version)
    )
    return [VersionRow(v, name) for v, name in rows.all()]


async def latest_versions(
    session: AsyncSession, org_id: uuid.UUID, reports: Sequence[Report]
) -> dict[uuid.UUID, VersionRow]:
    """The latest version of each report that has one."""
    wanted = [(r.id, r.latest_version) for r in reports if r.latest_version > 0]
    if not wanted:
        return {}
    rows = await session.execute(
        _versions_query().where(
            ReportVersion.organization_id == org_id,
            tuple_(ReportVersion.report_id, ReportVersion.version).in_(wanted),
        )
    )
    return {v.report_id: VersionRow(v, name) for v, name in rows.all()}


async def get_version(
    session: AsyncSession, org_id: uuid.UUID, report_id: uuid.UUID, version: int
) -> VersionRow | None:
    row = (
        await session.execute(
            _versions_query().where(
                ReportVersion.organization_id == org_id,
                ReportVersion.report_id == report_id,
                ReportVersion.version == version,
            )
        )
    ).one_or_none()
    return VersionRow(row[0], row[1]) if row is not None else None


async def renders_of(
    session: AsyncSession, org_id: uuid.UUID, version_id: uuid.UUID
) -> list[ReportRender]:
    rows = await session.scalars(
        select(ReportRender)
        .where(ReportRender.organization_id == org_id, ReportRender.version_id == version_id)
        .order_by(ReportRender.created_at, ReportRender.id)
    )
    return list(rows)


async def user_name(session: AsyncSession, user_id: uuid.UUID) -> str:
    name = await session.scalar(select(User.display_name).where(User.id == user_id))
    return name or ""


async def user_names(session: AsyncSession, user_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, str]:
    ids = sorted(set(user_ids))
    if not ids:
        return {}
    rows = await session.execute(select(User.id, User.display_name).where(User.id.in_(ids)))
    return {uid: name for uid, name in rows.all()}


async def member_roles(
    session: AsyncSession, org_id: uuid.UUID, user_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, str]:
    ids = sorted(set(user_ids))
    if not ids:
        return {}
    rows = await session.execute(
        select(OrganizationMember.user_id, OrganizationMember.role).where(
            OrganizationMember.organization_id == org_id, OrganizationMember.user_id.in_(ids)
        )
    )
    return {uid: str(getattr(role, "value", role)) for uid, role in rows.all()}


async def has_versions(session: AsyncSession, org_id: uuid.UUID, report_id: uuid.UUID) -> bool:
    found = await session.scalar(
        select(func.count(ReportVersion.id)).where(
            ReportVersion.organization_id == org_id, ReportVersion.report_id == report_id
        )
    )
    return bool(found)


async def lock_report(session: AsyncSession, report_id: uuid.UUID) -> None:
    """A per-report advisory lock for the finalize write (released at commit)."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"report:{report_id}"},
    )
