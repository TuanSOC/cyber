"""IOC collection and case-wide IOC models (M6 phase 1, FROZEN; routes in phase 2)."""

import uuid
from datetime import datetime
from typing import Annotated, Literal, Self

from cyberlab_jobs.report import TLP
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.modules.ioc_collections.models import (
    COLLECTION_DESCRIPTION_MAX_CHARS,
    COLLECTION_NAME_MAX_CHARS,
    ITEM_NOTE_MAX_CHARS,
    ITEM_VALUE_MAX_CHARS,
)

MAX_ITEMS_PER_CALL = 500
CollectionName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=COLLECTION_NAME_MAX_CHARS,
        strip_whitespace=True,
        pattern=r"^[^\x00-\x1f\x7f]+$",
    ),
]
CollectionDescription = Annotated[
    str, StringConstraints(max_length=COLLECTION_DESCRIPTION_MAX_CHARS, pattern=r"^[^\x00]*$")
]
ItemNote = Annotated[
    str, StringConstraints(max_length=ITEM_NOTE_MAX_CHARS, pattern=r"^[^\x00]*$")
]
IocTypeName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
IocValue = Annotated[
    str, StringConstraints(min_length=1, max_length=ITEM_VALUE_MAX_CHARS, pattern=r"^[^\x00]+$")
]
ExportFormat = Literal["csv", "json", "stix21"]
ItemOutcome = Literal["added", "duplicate", "invalid"]


class IocCollectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: CollectionName
    description: CollectionDescription = ""


class IocCollectionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: CollectionName | None = None
    description: CollectionDescription | None = None
    archived: bool | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one field must be provided")
        return self


class IocCollectionOut(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    name: str
    description: str
    archived: bool
    item_count: int
    created_by: uuid.UUID
    created_by_name: str
    created_at: datetime
    updated_at: datetime


class IocCollectionPage(BaseModel):
    items: list[IocCollectionOut]
    next_cursor: str | None


class IocCollectionDetail(BaseModel):
    collection: IocCollectionOut
    counts_by_type: dict[str, int]


class TiSummaryOut(BaseModel):
    """The latest provider answer for an item's `ioc_key` (attributed, never a verdict)."""

    provider: str
    status: str
    found: bool
    score: float | None
    score_scale: str | None
    summary: dict[str, object] | None
    fetched_at: datetime


class IocCollectionItemOut(BaseModel):
    id: uuid.UUID
    collection_id: uuid.UUID
    ioc_type: str
    value: str
    ioc_key: str
    source: Literal["job_ioc", "manual"]
    job_id: uuid.UUID | None
    ioc_id: uuid.UUID | None
    note: str | None
    # False when the M4 TI normalizer refuses the value (private IP, internal name): kept in
    # the collection, never sent to a provider.
    ti_eligible: bool
    ti: list[TiSummaryOut]
    added_by: uuid.UUID
    added_by_name: str
    added_at: datetime
    removed_at: datetime | None
    removed_by: uuid.UUID | None


class IocCollectionItemPage(BaseModel):
    items: list[IocCollectionItemOut]
    next_cursor: str | None


class IocItemFromJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc_id: uuid.UUID


class IocItemManual(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IocTypeName
    value: IocValue
    note: ItemNote | None = None


class IocItemsAdd(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: Annotated[
        list[IocItemFromJob | IocItemManual], Field(min_length=1, max_length=MAX_ITEMS_PER_CALL)
    ]


class IocItemResult(BaseModel):
    index: int
    outcome: ItemOutcome
    item_id: uuid.UUID | None
    reason: str | None


class IocItemsAddResult(BaseModel):
    results: list[IocItemResult]
    added: int
    duplicates: int
    invalid: int


class CaseIocOut(BaseModel):
    """One deduplicated IOC of the case (latest succeeded job per evidence)."""

    ioc_type: str
    value: str
    ioc_key: str
    count_jobs: int
    first_seen: datetime | None
    last_seen: datetime | None
    job_ids: Annotated[list[uuid.UUID], Field(max_length=5)]
    in_collections: list[uuid.UUID]


class CaseIocPage(BaseModel):
    items: list[CaseIocOut]
    next_cursor: str | None
    total: int | None = None


class IocExportJson(BaseModel):
    """`format=json`: never redacted (internal values stay in clear), defanged unless
    `defang=false`."""

    tlp: TLP
    collection: IocCollectionOut
    exported_at: datetime
    defanged: bool
    items: list[IocCollectionItemOut]
