"""AI settings and usage routes (M5 phase 7; registered via `router.py`).

Reads need `org.read`; the settings write needs `integrations.manage` (owner/admin).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.core.rbac import OrgContext, Permission, require
from app.modules.ai import service_runs, service_settings
from app.modules.ai.schemas import AiSettingsOut, AiSettingsUpdate, AiUsageOut

router = APIRouter(prefix="/orgs/{org_id}", tags=["ai"])

OrgRead = Annotated[OrgContext, Depends(require(Permission.ORG_READ), scope="function")]
Manage = Annotated[OrgContext, Depends(require(Permission.INTEGRATIONS_MANAGE), scope="function")]


@router.get("/ai/settings", response_model=AiSettingsOut)
async def get_ai_settings(ctx: OrgRead) -> AiSettingsOut:
    """The org's AI settings (the defaults until saved), the ceilings and the privacy notice."""
    return await service_settings.get_ai_settings(ctx)


@router.put("/ai/settings", response_model=AiSettingsOut)
async def update_ai_settings(
    body: AiSettingsUpdate, ctx: Manage, request: Request
) -> AiSettingsOut:
    """Partial update. Turning AI on, or widening what is sent later, needs
    `acknowledge_privacy`; budgets stay within the operator ceilings."""
    out = await service_settings.update_ai_settings(ctx, body, request)
    await ctx.session.commit()
    return out


@router.get("/ai/usage", response_model=AiUsageOut)
async def get_ai_usage(ctx: OrgRead) -> AiUsageOut:
    """Today's (UTC) tokens and estimated cost per provider, against the budget."""
    return await service_runs.usage(ctx)
