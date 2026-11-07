import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.core.deps import CurrentUserDep
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.organizations import members, service, storage
from app.modules.organizations.schemas import (
    MemberAdd,
    MemberOut,
    MemberPage,
    MemberUpdate,
    MyOrgOut,
    MyOrgPage,
    OrgCreate,
    OrgUpdate,
    StorageOut,
)

router = APIRouter(prefix="/orgs", tags=["organizations"])

# scope="function": the tenant session ends (commit/rollback) before the response is sent.
OrgRead = Annotated[OrgContext, Depends(require(Permission.ORG_READ), scope="function")]
# M11 (RT13): the org page itself stays reachable when the org security policy blocks the
# session (the web explains why: `mfa_required`, `sso_required`).
OrgReadExempt = Annotated[
    OrgContext, Depends(require(Permission.ORG_READ, policy_exempt=True), scope="function")
]
OrgWrite = Annotated[OrgContext, Depends(require(Permission.ORG_UPDATE), scope="function")]
MembersRead = Annotated[OrgContext, Depends(require(Permission.MEMBERS_READ), scope="function")]
MembersManage = Annotated[OrgContext, Depends(require(Permission.MEMBERS_MANAGE), scope="function")]


@router.get("", response_model=MyOrgPage)
async def list_my_orgs(user: CurrentUserDep, page: PageParamsDep) -> MyOrgPage:
    return await service.list_my_orgs(user, page)


@router.post("", response_model=MyOrgOut, status_code=status.HTTP_201_CREATED)
async def create_org(body: OrgCreate, user: CurrentUserDep, request: Request) -> MyOrgOut:
    return await service.create_org(user, body.name, request)


@router.get("/{org_id}", response_model=MyOrgOut)
async def get_org(ctx: OrgReadExempt) -> MyOrgOut:
    return await service.get_org(ctx)


@router.patch("/{org_id}", response_model=MyOrgOut)
async def update_org(body: OrgUpdate, ctx: OrgWrite, request: Request) -> MyOrgOut:
    return await service.rename_org(ctx, body.name, request)


@router.get("/{org_id}/storage", response_model=StorageOut)
async def get_storage(ctx: OrgRead) -> StorageOut:
    return await storage.get_storage(ctx)


@router.get("/{org_id}/members", response_model=MemberPage)
async def list_members(ctx: MembersRead, page: PageParamsDep) -> MemberPage:
    return await members.list_members(ctx, page)


@router.post("/{org_id}/members", status_code=status.HTTP_410_GONE)
async def add_member(body: MemberAdd, ctx: MembersManage, request: Request) -> None:
    await members.add_member(ctx, str(body.email), body.role, request)


@router.patch("/{org_id}/members/{member_id}", response_model=MemberOut)
async def change_role(
    member_id: uuid.UUID, body: MemberUpdate, ctx: MembersManage, request: Request
) -> MemberOut:
    return await members.change_role(ctx, member_id, body.role, request)


@router.delete("/{org_id}/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(member_id: uuid.UUID, ctx: MembersManage, request: Request) -> None:
    await members.remove_member(ctx, member_id, request)
