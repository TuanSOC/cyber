"""Generic evidence sensitivity routes (M9 phase 1, RT2; implemented).

Beside M8's `/memory-sensitivity` routes (unchanged, not deprecated): these answer for every
source (`memory`, `disk`, `derived`) with the state and the source. The release keeps M8's
rules (`org.update`, acknowledged, reasoned, once, audited); its code and audit action follow
the source. The batch arm (`job_id`) answers 501 until phase 9.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core.rbac import OrgContext, Permission, require
from app.modules.evidence import sensitivity
from app.modules.evidence.schemas import EvidenceSensitivityDetailOut, SensitivityReleaseIn

router = APIRouter(prefix="/orgs/{org_id}/evidence/{evidence_id}", tags=["evidence"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
OrgUpdate = Annotated[OrgContext, Depends(require(Permission.ORG_UPDATE), scope="function")]


@router.get("/sensitivity", response_model=EvidenceSensitivityDetailOut)
async def get_evidence_sensitivity(
    evidence_id: uuid.UUID, ctx: EvidenceRead
) -> EvidenceSensitivityDetailOut:
    """`state: none` when the evidence was never marked restricted (any source)."""
    return await sensitivity.get(ctx, evidence_id)


@router.post("/sensitivity/release", response_model=EvidenceSensitivityDetailOut)
async def release_evidence_sensitivity(
    evidence_id: uuid.UUID,
    body: SensitivityReleaseIn,
    ctx: OrgUpdate,
    request: Request,
) -> EvidenceSensitivityDetailOut:
    """Once per evidence: 409 `memory_sensitivity_released` / `evidence_sensitivity_released`
    afterwards; `422 acknowledgement_required`; 404 for evidence never marked; 501 with
    `job_id` (batch release, phase 9). Audited `memory.sensitivity_released` or
    `disk.sensitivity_released`."""
    return await sensitivity.release(ctx, evidence_id, body, request)
