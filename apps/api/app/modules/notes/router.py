"""Analyst note routes (M6): paths, permissions and models frozen in phase 1; bodies in
`notes/service.py`."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.core.rbac import OrgContext, Permission, require
from app.modules.notes import service
from app.modules.notes.schemas import NoteCreate, NoteDetail, NoteOut, NotePage, NoteUpdate

router = APIRouter(prefix="/orgs/{org_id}", tags=["notes"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]


@router.get("/investigations/{investigation_id}/notes", response_model=NotePage)
async def list_notes(
    investigation_id: uuid.UUID,
    ctx: InvRead,
    include_deleted: bool = False,
    pinned: bool | None = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> NotePage:
    """The current version of each note; deleted notes only with `include_deleted`
    (tombstones without body)."""
    return await service.list_notes(
        ctx,
        investigation_id,
        include_deleted=include_deleted,
        pinned=pinned,
        cursor=cursor,
        limit=limit,
    )


@router.post(
    "/investigations/{investigation_id}/notes",
    response_model=NoteOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_note(
    investigation_id: uuid.UUID, body: NoteCreate, ctx: InvWrite, request: Request
) -> NoteOut:
    """Refs are re-checked in the org and case scope (`422 ref_out_of_scope`); audited
    `note.created` (ids and ref count, never the body)."""
    return await service.create_note(ctx, investigation_id, body, request)


@router.get("/notes/{note_id}", response_model=NoteDetail)
async def get_note(note_id: uuid.UUID, ctx: InvRead) -> NoteDetail:
    """The current version and the full version history."""
    return await service.get_note(ctx, note_id)


@router.put("/notes/{note_id}", response_model=NoteOut)
async def update_note(
    note_id: uuid.UUID, body: NoteUpdate, ctx: InvWrite, request: Request
) -> NoteOut:
    """Author or `org.update` only; `409 stale_note` on a wrong `expected_version`."""
    return await service.update_note(ctx, note_id, body, request)


@router.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(note_id: uuid.UUID, ctx: InvWrite, request: Request) -> None:
    """Soft delete (the versions stay); author or `org.update` only."""
    await service.delete_note(ctx, note_id, request)
