"""Analyst note request and response models (M6 phase 1, FROZEN; routes in phase 2)."""

import uuid
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.modules.notes.models import NOTE_BODY_MAX_CHARS, NOTE_MAX_REFS

NoteRefKind = Literal[
    "finding", "alert", "ioc", "evidence", "job", "timeline", "capability", "signature"
]
# Plain text (newlines and tabs allowed), never NUL; never rendered as Markdown or HTML.
NoteBody = Annotated[
    str,
    StringConstraints(min_length=1, max_length=NOTE_BODY_MAX_CHARS, pattern=r"^[^\x00]*$"),
]
RefId = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
]


class NoteRef(BaseModel):
    """A typed link to a row of the case; re-checked in the org and case scope on write
    (`422 ref_out_of_scope`)."""

    model_config = ConfigDict(extra="forbid")

    kind: NoteRefKind
    ref_id: RefId
    job_id: uuid.UUID | None = None


NoteRefs = Annotated[list[NoteRef], Field(max_length=NOTE_MAX_REFS)]


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: NoteBody
    refs: NoteRefs = []
    pinned: bool = False
    include_in_reports: bool = False


class NoteUpdate(BaseModel):
    """A body or refs change adds a version (`expected_version` must be the current one,
    else `409 stale_note`); flag-only changes update the flags."""

    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    body: NoteBody | None = None
    refs: NoteRefs | None = None
    pinned: bool | None = None
    include_in_reports: bool | None = None

    @model_validator(mode="after")
    def _something_changes(self) -> Self:
        if not self.model_fields_set - {"expected_version"}:
            raise ValueError("at least one field must be provided")
        return self


class NoteOut(BaseModel):
    """The current version of a note. A deleted note (listed only with `include_deleted`)
    shows its tombstone: `deleted=true`, `body=null`, `refs=[]`."""

    id: uuid.UUID
    investigation_id: uuid.UUID
    version: int
    body: str | None
    refs: list[NoteRef]
    pinned: bool
    include_in_reports: bool
    edited: bool
    deleted: bool
    created_by: uuid.UUID
    created_by_name: str
    author_id: uuid.UUID
    author_name: str
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None
    deleted_by: uuid.UUID | None


class NotePage(BaseModel):
    items: list[NoteOut]
    next_cursor: str | None


class NoteVersionOut(BaseModel):
    version: int
    body: str
    refs: list[NoteRef]
    author_id: uuid.UUID
    author_name: str
    created_at: datetime


class NoteDetail(BaseModel):
    note: NoteOut
    versions: list[NoteVersionOut]
