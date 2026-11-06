"""Invitations (M11 phase 3; phase 1 stubs answering 501, on the frozen paths and schemas).

Org routes: list (`members.read`), create / resend / revoke (`members.manage`; inviting an
admin or owner needs step-up `member_elevate`; only owners invite owners). The create answer
is the same `201` whether the email is registered or not. Public: `inspect` (CSRF-exempt,
RT4; 20 / 10 min per IP); signed in: `accept`.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.core.deps import CurrentUserDep
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.identity.schemas import (
    InvitationAcceptIn,
    InvitationAcceptOut,
    InvitationCreate,
    InvitationInspectIn,
    InvitationInspectOut,
    InvitationOut,
    InvitationPage,
)

router = APIRouter(tags=["invitations"])

MembersRead = Annotated[OrgContext, Depends(require(Permission.MEMBERS_READ), scope="function")]
MembersManage = Annotated[OrgContext, Depends(require(Permission.MEMBERS_MANAGE), scope="function")]
_ORG = "/orgs/{org_id}/invitations"


@router.get(_ORG, response_model=InvitationPage)
async def list_invitations(ctx: MembersRead, page: PageParamsDep) -> InvitationPage:
    raise not_implemented()


@router.post(_ORG, response_model=InvitationOut, status_code=status.HTTP_201_CREATED)
async def create_invitation(body: InvitationCreate, ctx: MembersManage) -> InvitationOut:
    raise not_implemented()


@router.post(f"{_ORG}/{{invitation_id}}/resend", response_model=InvitationOut)
async def resend_invitation(invitation_id: uuid.UUID, ctx: MembersManage) -> InvitationOut:
    raise not_implemented()


@router.post(f"{_ORG}/{{invitation_id}}/revoke", response_model=InvitationOut)
async def revoke_invitation(invitation_id: uuid.UUID, ctx: MembersManage) -> InvitationOut:
    raise not_implemented()


@router.post("/invitations/inspect", response_model=InvitationInspectOut)
async def inspect_invitation(body: InvitationInspectIn) -> InvitationInspectOut:
    raise not_implemented()


@router.post("/invitations/accept", response_model=InvitationAcceptOut)
async def accept_invitation(body: InvitationAcceptIn, user: CurrentUserDep) -> InvitationAcceptOut:
    raise not_implemented()
