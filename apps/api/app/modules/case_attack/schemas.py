"""ATT&CK case mapping models (M6 phase 1, FROZEN; routes in phase 5)."""

import uuid
from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.modules.case_attack.models import MAX_SOURCES, RATIONALE_MAX_CHARS, TECHNIQUE_PATTERN

MappingStatus = Literal["confirmed", "suspected", "rejected"]
SourceKind = Literal["capability", "finding", "ai_run"]
TechniqueId = Annotated[str, StringConstraints(pattern=TECHNIQUE_PATTERN)]
Rationale = Annotated[
    str, StringConstraints(max_length=RATIONALE_MAX_CHARS, pattern=r"^[^\x00]*$")
]


class AttackSourceRef(BaseModel):
    """Evidence behind a mapping; re-checked in the case scope (`422 ref_out_of_scope`)."""

    model_config = ConfigDict(extra="forbid")

    kind: SourceKind
    ref_id: Annotated[
        str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    ]
    job_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None


Sources = Annotated[list[AttackSourceRef], Field(max_length=MAX_SOURCES)]


class AttackMappingCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: TechniqueId
    status: MappingStatus
    rationale: Rationale = ""
    sources: Sources = []


class AttackMappingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: MappingStatus | None = None
    rationale: Rationale | None = None
    sources: Sources | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one field must be provided")
        return self


class TechniqueLabel(BaseModel):
    """From the pinned offline ATT&CK index (v20); `url` is shown as text, never fetched."""

    technique_id: str
    name: str | None
    tactics: list[str]
    url: str | None
    revoked: bool
    deprecated: bool


class SourceDescriptor(BaseModel):
    kind: SourceKind
    ref_id: str
    job_id: uuid.UUID | None
    run_id: uuid.UUID | None
    # The in-app path of the cited row (built from ids only), when it resolves in scope.
    path: str | None
    citation_status: str | None = None


class AttackMappingOut(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    technique_id: str
    label: TechniqueLabel
    status: MappingStatus
    rationale: str
    sources: list[SourceDescriptor]
    created_by: uuid.UUID
    updated_by: uuid.UUID
    updated_by_name: str
    created_at: datetime
    updated_at: datetime


class MatrixTactic(BaseModel):
    tactic: str
    techniques: list[AttackMappingOut]


class CaseAttackOut(BaseModel):
    mappings: list[AttackMappingOut]
    # v20 tactic order; confirmed and suspected only (rejected excluded).
    matrix: list[MatrixTactic]
    index_version: str
    notice: str


class AttackSuggestion(BaseModel):
    technique_id: str
    label: TechniqueLabel
    sources: list[SourceDescriptor]
    already_mapped: bool


class AttackSuggestionsOut(BaseModel):
    items: list[AttackSuggestion]
    index_version: str
    notice: str
