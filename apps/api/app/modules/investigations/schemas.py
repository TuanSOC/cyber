import uuid
from datetime import datetime
from typing import Annotated, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.core.pagination import Page
from app.core.validation import SafeName
from app.modules.investigations.models import InvestigationStatus, Severity

# Free text may contain newlines/tabs, never NUL (Postgres text cannot store it).
Description = Annotated[str, StringConstraints(max_length=10_000, pattern=r"^[^\x00]*$")]
Title = Annotated[SafeName, Field(min_length=3, max_length=200)]


def case_ref(case_number: int) -> str:
    return f"CASE-{case_number:05d}"


class InvestigationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Title
    description: Description = ""
    severity: Severity


class InvestigationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Title | None = None
    description: Description | None = None
    severity: Severity | None = None
    status: InvestigationStatus | None = None

    @field_validator("title", "description", "severity", "status", mode="before")
    @classmethod
    def _not_null(cls, value: object) -> object:
        # Fields are optional (omit to keep), but explicit null is not a valid value.
        if value is None:
            raise ValueError("must not be null")
        return value

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one field must be provided")
        return self


class InvestigationOut(BaseModel):
    id: uuid.UUID
    case_number: int
    case_ref: str
    title: str
    description: str
    status: InvestigationStatus
    allowed_transitions: list[InvestigationStatus]
    severity: Severity
    created_by: uuid.UUID
    created_by_name: str
    evidence_count: int
    created_at: datetime
    updated_at: datetime


class InvestigationPage(Page[InvestigationOut]):
    pass
