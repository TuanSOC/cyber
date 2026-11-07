"""Invitations API endpoints (M11 phase 3)."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.core.deps import CurrentUserDep
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.identity.schemas import (
    InvitationAcceptIn,
    InvitationAcceptOut,
    InvitationCreate,
    InvitationInspectIn,
    InvitationInspectOut,
    InvitationOut,
    InvitationPage,
)
from app.modules.invitations import service

router = APIRouter(tags=["invitations"])

MembersRead = Annotated[OrgContext, Depends(require(Permission.MEMBERS_READ), scope="function")]
MembersManage = Annotated[OrgContext, Depends(require(Permission.MEMBERS_MANAGE), scope="function")]
_ORG = "/orgs/{org_id}/invitations"


@router.get(_ORG, response_model=InvitationPage)
async def list_invitations(ctx: MembersRead, page: PageParamsDep) -> InvitationPage:
    return await service.list_invitations(ctx, page)


@router.post(_ORG, response_model=InvitationOut, status_code=status.HTTP_201_CREATED)
async def create_invitation(
    body: InvitationCreate, ctx: MembersManage, request: Request
) -> InvitationOut:
    return await service.create_invitation(ctx, body, request)


@router.post(f"{_ORG}/{{invitation_id}}/resend", response_model=InvitationOut)
async def resend_invitation(
    invitation_id: uuid.UUID, ctx: MembersManage, request: Request
) -> InvitationOut:
    return await service.resend_invitation(ctx, invitation_id, request)


@router.post(f"{_ORG}/{{invitation_id}}/revoke", response_model=InvitationOut)
async def revoke_invitation(
    invitation_id: uuid.UUID, ctx: MembersManage, request: Request
) -> InvitationOut:
    return await service.revoke_invitation(ctx, invitation_id, request)


@router.post("/invitations/inspect", response_model=InvitationInspectOut)
async def inspect_invitation(
    body: InvitationInspectIn, request: Request
) -> InvitationInspectOut:
    return await service.inspect_invitation(body.token, request)


@router.post("/invitations/accept", response_model=InvitationAcceptOut)
async def accept_invitation(
    body: InvitationAcceptIn, user: CurrentUserDep, request: Request
) -> InvitationAcceptOut:
    return await service.accept_invitation(user, body.token, request)
