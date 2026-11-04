"""Threat intel integrations and TI settings routes (M4 phase 5; registered via `router.py`).

Reads need `org.read` (viewers see status, never secrets); every write needs
`integrations.manage` (owner/admin). Provider keys are write-only.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.rbac import OrgContext, Permission, require
from app.modules.threat_intel import service_integrations as service
from app.modules.threat_intel.providers.base import ProviderName
from app.modules.threat_intel.schemas import (
    IntegrationPage,
    IntegrationSaved,
    IntegrationUpdate,
    TiSettingsOut,
    TiSettingsUpdate,
    VerifyQueued,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/orgs/{org_id}", tags=["threat-intel"])

OrgRead = Annotated[OrgContext, Depends(require(Permission.ORG_READ), scope="function")]
Manage = Annotated[OrgContext, Depends(require(Permission.INTEGRATIONS_MANAGE), scope="function")]


@router.get("/integrations", response_model=IntegrationPage)
async def list_integrations(ctx: OrgRead) -> IntegrationPage:
    """The provider catalog with this org's configuration status (never a key)."""
    return await service.list_integrations(ctx)


@router.put("/integrations/{provider}", response_model=IntegrationSaved)
async def update_integration(
    provider: ProviderName, body: IntegrationUpdate, ctx: Manage, request: Request
) -> IntegrationSaved:
    """Store a key (sealed, write-only), enable/disable, acknowledge terms, set limits or the
    MISP base URL. A new key is checked after the commit (`ti.verify`) within the same
    per-provider limit as POST .../verify; `verify_queued` says whether it was."""
    out, queue_verify = await service.update_integration(ctx, provider, body, request)
    await ctx.session.commit()
    queued = False
    if queue_verify and await service.verify_allowed(ctx.org_id, provider):
        queued = await service.send_verify(ctx.org_id, provider)
        if not queued:
            # The key is stored; the admin can re-run the check (verify_status: unverified).
            log.warning("integration saved but ti.verify was not queued for %s", provider.value)
    return IntegrationSaved(**out.model_dump(), verify_queued=queued)


@router.delete(
    "/integrations/{provider}/key",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={status.HTTP_204_NO_CONTENT: {"description": "The key was removed"}},
)
async def remove_integration_key(provider: ProviderName, ctx: Manage, request: Request) -> Response:
    await service.remove_key(ctx, provider, request)
    await ctx.session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/integrations/{provider}/verify",
    response_model=VerifyQueued,
    status_code=status.HTTP_202_ACCEPTED,
)
async def verify_integration(provider: ProviderName, ctx: Manage) -> VerifyQueued:
    """Queue a check of the stored key (the enrich worker calls the provider)."""
    await service.check_verifiable(ctx, provider)
    await service.check_verify_rate(ctx.org_id, provider)
    await ctx.session.commit()
    if not await service.send_verify(ctx.org_id, provider):
        raise service.BrokerUnavailable(headers={"Retry-After": "5"})
    return VerifyQueued(provider=provider)


@router.get("/ti/settings", response_model=TiSettingsOut)
async def get_ti_settings(ctx: OrgRead) -> TiSettingsOut:
    return await service.get_ti_settings(ctx)


@router.put("/ti/settings", response_model=TiSettingsOut)
async def update_ti_settings(
    body: TiSettingsUpdate, ctx: Manage, request: Request
) -> TiSettingsOut:
    out = await service.update_ti_settings(ctx, body, request)
    await ctx.session.commit()
    return out
