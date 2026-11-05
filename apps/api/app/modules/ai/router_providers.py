"""AI provider routes (M5 phase 7; registered via `router.py`).

Reads need `org.read` (viewers see status, never secrets); every write needs
`integrations.manage` (owner/admin). Provider keys are write-only.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.rbac import OrgContext, Permission, require
from app.modules.ai import service_providers as service
from app.modules.ai.contracts import AiProviderName
from app.modules.ai.schemas import AiProviderPage, AiProviderSaved, AiProviderUpdate, AiVerifyQueued

log = logging.getLogger(__name__)

router = APIRouter(prefix="/orgs/{org_id}", tags=["ai"])

OrgRead = Annotated[OrgContext, Depends(require(Permission.ORG_READ), scope="function")]
Manage = Annotated[OrgContext, Depends(require(Permission.INTEGRATIONS_MANAGE), scope="function")]


@router.get("/ai/providers", response_model=AiProviderPage)
async def list_ai_providers(ctx: OrgRead) -> AiProviderPage:
    """The AI provider catalog with this org's configuration status (never a key)."""
    return await service.list_providers(ctx)


@router.put("/ai/providers/{provider}", response_model=AiProviderSaved)
async def update_ai_provider(
    provider: AiProviderName, body: AiProviderUpdate, ctx: Manage, request: Request
) -> AiProviderSaved:
    """Store a key (sealed, write-only), enable/disable, acknowledge the terms (and, for
    Gemini, the paid tier), pick a model. A new key is checked after the commit
    (`ai.verify`) within the per-provider verify limit; `verify_queued` says whether it was."""
    out, key_version = await service.update_provider(ctx, provider, body, request)
    await ctx.session.commit()
    queued = False
    if key_version is not None and await service.verify_allowed(ctx.org_id, provider):
        queued = await service.send_verify(ctx.org_id, provider, key_version)
        if not queued:
            # The key is stored; the admin can re-run the check (verify_status: unverified).
            log.warning("ai provider saved but ai.verify was not queued for %s", provider.value)
    return AiProviderSaved(**out.model_dump(), verify_queued=queued)


@router.delete(
    "/ai/providers/{provider}/key",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={status.HTTP_204_NO_CONTENT: {"description": "The key was removed"}},
)
async def remove_ai_provider_key(
    provider: AiProviderName, ctx: Manage, request: Request
) -> Response:
    await service.remove_key(ctx, provider, request)
    await ctx.session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/ai/providers/{provider}/verify",
    response_model=AiVerifyQueued,
    status_code=status.HTTP_202_ACCEPTED,
)
async def verify_ai_provider(provider: AiProviderName, ctx: Manage) -> AiVerifyQueued:
    """Queue a check of the stored key (the analyst worker calls the provider)."""
    version = await service.check_verifiable(ctx, provider)
    await service.check_verify_rate(ctx.org_id, provider)
    await ctx.session.commit()
    if not await service.send_verify(ctx.org_id, provider, version):
        raise service.BrokerUnavailable(headers={"Retry-After": "5"})
    return AiVerifyQueued(provider=provider)
