"""Analyst notes (M6): versioned plain text of a case.

- A note is a logical row (`analyst_notes`) plus append-only versions
  (`analyst_note_versions`). A body or refs edit inserts version n+1 and moves
  `current_version`; flag-only edits (`pinned`, `include_in_reports`) update the note.
- Every edit names the version it was based on (`expected_version`): a stale edit is
  `409 stale_note`. The note row is locked for the edit, so concurrent edits serialize.
- Only the author (the note's creator) or an `org.update` holder edits or deletes. A delete
  sets `deleted_at/by`; the versions stay in the database, but a deleted note's bodies (its
  history included) are readable only by an `org.update` holder: every other reader gets
  the tombstone metadata only.
- Refs are re-checked in the org and case scope on every write (`refs.check_refs`).
- Notes of an archived case are read-only (`409 investigation_archived`).
- Audit details carry ids, versions and counts, never the body.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import ColumnElement, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from starlette.requests import HTTPConnection

from app.core.errors import Conflict, Forbidden, NotFound
from app.core.rbac import OrgContext, Permission
from app.modules.audit import service as audit
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.notes import paging, refs
from app.modules.notes.models import AnalystNote, AnalystNoteVersion
from app.modules.notes.schemas import (
    NoteCreate,
    NoteDetail,
    NoteOut,
    NotePage,
    NoteUpdate,
    NoteVersionOut,
)
from app.modules.users.models import User


@dataclass(frozen=True)
class _Row:
    note: AnalystNote
    version: AnalystNoteVersion
    created_by_name: str
    author_name: str


async def _case(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    lock: bool = False,
) -> Investigation:
    stmt = select(Investigation).where(
        Investigation.id == investigation_id, Investigation.organization_id == org_id
    )
    if lock:
        # FOR SHARE: a concurrent archive waits for this write (and the other way round).
        stmt = stmt.with_for_update(read=True)
    case = await session.scalar(stmt)
    if case is None:
        raise NotFound()
    return case


def _writable(case: Investigation) -> None:
    if case.status == InvestigationStatus.ARCHIVED:
        raise Conflict("Archived investigations are read-only", code="investigation_archived")


async def _rows(
    session: AsyncSession, org_id: uuid.UUID, *where: ColumnElement[bool], limit: int | None = None
) -> list[_Row]:
    n, v = AnalystNote, AnalystNoteVersion
    creator, author = aliased(User), aliased(User)
    stmt = (
        select(n, v, creator.display_name, author.display_name)
        .join(v, (v.note_id == n.id) & (v.version == n.current_version))
        .join(creator, creator.id == n.created_by)
        .join(author, author.id == v.author_id)
        .where(n.organization_id == org_id, *where)
        .order_by(n.created_at.desc(), n.id.desc())
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return [_Row(*row) for row in (await session.execute(stmt)).all()]


def _out(row: _Row) -> NoteOut:
    note, version = row.note, row.version
    deleted = note.deleted_at is not None
    return NoteOut(
        id=note.id,
        investigation_id=note.investigation_id,
        version=note.current_version,
        body=None if deleted else version.body,
        refs=[] if deleted else refs.load(version.refs),
        pinned=note.pinned,
        include_in_reports=note.include_in_reports,
        edited=note.current_version > 1,
        deleted=deleted,
        created_by=note.created_by,
        created_by_name=row.created_by_name,
        author_id=version.author_id,
        author_name=row.author_name,
        created_at=note.created_at,
        updated_at=note.updated_at,
        deleted_at=note.deleted_at,
        deleted_by=note.deleted_by,
    )


async def _one(session: AsyncSession, org_id: uuid.UUID, note_id: uuid.UUID) -> _Row:
    found = await _rows(session, org_id, AnalystNote.id == note_id)
    if not found:
        raise NotFound()
    return found[0]


async def _locked_note(ctx: OrgContext, note_id: uuid.UUID) -> AnalystNote:
    note = await ctx.session.scalar(
        select(AnalystNote)
        .where(AnalystNote.id == note_id, AnalystNote.organization_id == ctx.org_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if note is None:
        raise NotFound()
    return note


def _may_change(ctx: OrgContext, note: AnalystNote) -> None:
    if note.created_by != ctx.user.id and Permission.ORG_UPDATE not in ctx.permissions:
        raise Forbidden("Only the author or an org admin may change this note")


def _audit(
    ctx: OrgContext,
    action: str,
    note: AnalystNote,
    request: HTTPConnection,
    **details: object,
) -> None:
    audit.record(
        ctx.session,
        action=action,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="note",
        target_id=note.id,
        details={"investigation_id": str(note.investigation_id), **details},
        request=request,
    )


async def list_notes(
    ctx: OrgContext,
    investigation_id: uuid.UUID,
    *,
    include_deleted: bool,
    pinned: bool | None,
    cursor: str | None,
    limit: int,
) -> NotePage:
    await _case(ctx.session, ctx.org_id, investigation_id)
    n = AnalystNote
    where: list[ColumnElement[bool]] = [n.investigation_id == investigation_id]
    if not include_deleted:
        where.append(n.deleted_at.is_(None))
    if pinned is not None:
        where.append(n.pinned.is_(pinned))
    if cursor:
        where.append(tuple_(n.created_at, n.id) < tuple_(*paging.decode(cursor)))
    rows = await _rows(ctx.session, ctx.org_id, *where, limit=limit + 1)
    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = page[-1].note
        next_cursor = paging.encode(last.created_at, last.id)
    return NotePage(items=[_out(r) for r in page], next_cursor=next_cursor)


async def create_note(
    ctx: OrgContext, investigation_id: uuid.UUID, data: NoteCreate, request: HTTPConnection
) -> NoteOut:
    case = await _case(ctx.session, ctx.org_id, investigation_id, lock=True)
    _writable(case)
    await refs.check_refs(ctx.session, ctx.org_id, investigation_id, data.refs)
    note = AnalystNote(
        organization_id=ctx.org_id,
        investigation_id=investigation_id,
        created_by=ctx.user.id,
        current_version=1,
        pinned=data.pinned,
        include_in_reports=data.include_in_reports,
    )
    ctx.session.add(note)
    await ctx.session.flush()
    ctx.session.add(
        AnalystNoteVersion(
            note_id=note.id,
            version=1,
            organization_id=ctx.org_id,
            body=data.body,
            refs=refs.dump(data.refs),
            author_id=ctx.user.id,
        )
    )
    _audit(ctx, "note.created", note, request, version=1, ref_count=len(data.refs))
    await ctx.session.flush()
    out = _out(await _one(ctx.session, ctx.org_id, note.id))
    await ctx.session.commit()
    return out


async def get_note(ctx: OrgContext, note_id: uuid.UUID) -> NoteDetail:
    row = await _one(ctx.session, ctx.org_id, note_id)
    if row.note.deleted_at is not None and Permission.ORG_UPDATE not in ctx.permissions:
        # A deleted note's history is for org admins only; the tombstone stays visible.
        return NoteDetail(note=_out(row), versions=[])
    v = AnalystNoteVersion
    versions = await ctx.session.execute(
        select(v, User.display_name)
        .join(User, User.id == v.author_id)
        .where(v.organization_id == ctx.org_id, v.note_id == note_id)
        .order_by(v.version.desc())
    )
    return NoteDetail(
        note=_out(row),
        versions=[
            NoteVersionOut(
                version=version.version,
                body=version.body,
                refs=refs.load(version.refs),
                author_id=version.author_id,
                author_name=name,
                created_at=version.created_at,
            )
            for version, name in versions.all()
        ],
    )


async def update_note(
    ctx: OrgContext, note_id: uuid.UUID, data: NoteUpdate, request: HTTPConnection
) -> NoteOut:
    note = await _locked_note(ctx, note_id)
    case = await _case(ctx.session, ctx.org_id, note.investigation_id, lock=True)
    _may_change(ctx, note)
    _writable(case)
    if note.deleted_at is not None:
        raise Conflict("The note is deleted", code="note_deleted")
    if data.expected_version != note.current_version:
        raise Conflict("The note was changed since this version", code="stale_note")
    current = await ctx.session.scalar(
        select(AnalystNoteVersion).where(
            AnalystNoteVersion.note_id == note.id,
            AnalystNoteVersion.version == note.current_version,
        )
    )
    if current is None:  # never: the current version always exists (append-only versions)
        raise NotFound()
    body = data.body if data.body is not None else current.body
    new_refs = refs.dump(data.refs) if data.refs is not None else current.refs
    content_changed = body != current.body or new_refs != current.refs
    if data.refs is not None and new_refs != current.refs:
        await refs.check_refs(ctx.session, ctx.org_id, note.investigation_id, data.refs)

    changed: list[str] = []
    if content_changed:
        ctx.session.add(
            AnalystNoteVersion(
                note_id=note.id,
                version=note.current_version + 1,
                organization_id=ctx.org_id,
                body=body,
                refs=new_refs,
                author_id=ctx.user.id,
            )
        )
        note.current_version += 1
        changed += [f for f in ("body", "refs") if f in data.model_fields_set]
    for flag in ("pinned", "include_in_reports"):
        value = getattr(data, flag)
        if value is not None and value != getattr(note, flag):
            setattr(note, flag, value)
            changed.append(flag)
    if changed:
        _audit(
            ctx,
            "note.edited",
            note,
            request,
            version=note.current_version,
            new_version=content_changed,
            changed=sorted(changed),
            ref_count=len(new_refs),
        )
    await ctx.session.flush()
    out = _out(await _one(ctx.session, ctx.org_id, note.id))
    await ctx.session.commit()
    return out


async def delete_note(ctx: OrgContext, note_id: uuid.UUID, request: HTTPConnection) -> None:
    note = await _locked_note(ctx, note_id)
    case = await _case(ctx.session, ctx.org_id, note.investigation_id, lock=True)
    _may_change(ctx, note)
    _writable(case)
    if note.deleted_at is not None:
        return  # already deleted: idempotent, the first delete stays recorded
    note.deleted_at = datetime.now(UTC)
    note.deleted_by = ctx.user.id
    _audit(ctx, "note.deleted", note, request, version=note.current_version)
    await ctx.session.commit()
