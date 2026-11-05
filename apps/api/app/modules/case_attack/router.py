"""ATT&CK case mapping routes (M6). Frozen in phase 1 as `501 not_implemented` stubs with
their final paths, permissions and models; phase 5 fills the bodies."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.case_attack.schemas import (
    AttackMappingCreate,
    AttackMappingOut,
    AttackMappingUpdate,
    AttackSuggestionsOut,
    CaseAttackOut,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["case-attack"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]


@router.get("/investigations/{investigation_id}/attack", response_model=CaseAttackOut)
async def get_case_attack(investigation_id: uuid.UUID, ctx: InvRead) -> CaseAttackOut:
    """Mappings with labels, and the tactic-grouped matrix (v20 order, rejected excluded)."""
    raise not_implemented()


@router.get(
    "/investigations/{investigation_id}/attack/suggestions", response_model=AttackSuggestionsOut
)
async def get_suggestions(investigation_id: uuid.UUID, ctx: InvRead) -> AttackSuggestionsOut:
    """From capa, findings and verified AI techniques of the case; never auto-confirmed."""
    raise not_implemented()


@router.post(
    "/investigations/{investigation_id}/attack",
    response_model=AttackMappingOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_mapping(
    investigation_id: uuid.UUID, body: AttackMappingCreate, ctx: InvWrite, request: Request
) -> AttackMappingOut:
    """`422 invalid_technique` (unknown, revoked or deprecated), `409 mapping_exists`,
    `422 ref_out_of_scope`; audited `case_attack.mapped`."""
    raise not_implemented()


@router.patch("/attack-mappings/{mapping_id}", response_model=AttackMappingOut)
async def update_mapping(
    mapping_id: uuid.UUID, body: AttackMappingUpdate, ctx: InvWrite, request: Request
) -> AttackMappingOut:
    """Audited `case_attack.updated` (from / to status)."""
    raise not_implemented()
