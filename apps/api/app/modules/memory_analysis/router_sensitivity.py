"""Memory sensitivity of an evidence item (M8 phase 8; the service is `sensitivity.py`).

A memory image is TLP:RED material by default: the evidence is `restricted` (AI and TI
excluded through the M6 share policy) from a `kind=memory` upload or its first memory job,
until an admin releases it once (acknowledged, with a reason, audited). Releasing does not
clear the share-policy flags: the analyst then uses `PUT /evidence/{id}/share-policy`.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core.rbac import OrgContext, Permission, require
from app.modules.memory_analysis import sensitivity
from app.modules.memory_analysis.schemas import MemorySensitivityOut, ReleaseIn

router = APIRouter(prefix="/orgs/{org_id}/evidence/{evidence_id}", tags=["memory-analysis"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
OrgUpdate = Annotated[OrgContext, Depends(require(Permission.ORG_UPDATE), scope="function")]


@router.get("/memory-sensitivity", response_model=MemorySensitivityOut)
async def get_memory_sensitivity(evidence_id: uuid.UUID, ctx: EvidenceRead) -> MemorySensitivityOut:
    """`state: none` when the evidence was never marked as a memory image."""
    return await sensitivity.get(ctx, evidence_id)


@router.post("/memory-sensitivity/release", response_model=MemorySensitivityOut)
async def release_memory_sensitivity(
    evidence_id: uuid.UUID,
    body: ReleaseIn,
    ctx: OrgUpdate,
    request: Request,
) -> MemorySensitivityOut:
    """Once per evidence: `409 memory_sensitivity_released` afterwards; `422
    acknowledgement_required` unless `acknowledge` is true; 404 for evidence never marked.
    Audited `memory.sensitivity_released`."""
    return await sensitivity.release(ctx, evidence_id, body, request)
