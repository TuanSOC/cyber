"""Memory sensitivity of an evidence item (M8 phase 1 stubs; phase 8 implements them).

A memory image is TLP:RED material by default: the evidence is `restricted` (AI and TI
excluded through the M6 share policy) from a `kind=memory` upload or its first memory job,
until an admin releases it once (acknowledged, with a reason, audited).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.memory_analysis.schemas import MemorySensitivityOut, ReleaseIn

router = APIRouter(prefix="/orgs/{org_id}/evidence/{evidence_id}", tags=["memory-analysis"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
OrgUpdate = Annotated[OrgContext, Depends(require(Permission.ORG_UPDATE), scope="function")]


@router.get("/memory-sensitivity", response_model=MemorySensitivityOut)
async def get_memory_sensitivity(
    evidence_id: uuid.UUID, ctx: EvidenceRead
) -> MemorySensitivityOut:
    raise not_implemented()


@router.post("/memory-sensitivity/release", response_model=MemorySensitivityOut)
async def release_memory_sensitivity(
    evidence_id: uuid.UUID,
    body: ReleaseIn,
    ctx: OrgUpdate,
    request: Request,
) -> MemorySensitivityOut:
    """Once per evidence: `409 memory_sensitivity_released` afterwards; `422
    acknowledgement_required` unless `acknowledge` is true."""
    raise not_implemented()
