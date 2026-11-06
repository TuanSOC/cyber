"""SSO administration: the org's OIDC IdP and its verified domains (M11 phase 7; phase 1
stubs answering 501).

Reads are `org.read`; changes are `security.manage` (owners) with step-up
(`sso_config_update`, `domain_change` on create and delete). The client secret is sealed in
`cyberlab.identity.v1`, URL-bound to the normalized issuer, and never returned (last 4 only).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.identity.schemas import (
    DomainCreate,
    DomainList,
    DomainOut,
    SsoConfigOut,
    SsoConfigUpdate,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["identity"])

OrgRead = Annotated[OrgContext, Depends(require(Permission.ORG_READ), scope="function")]
SecurityManage = Annotated[
    OrgContext, Depends(require(Permission.SECURITY_MANAGE), scope="function")
]


@router.get("/sso", response_model=SsoConfigOut)
async def get_sso_config(ctx: OrgRead) -> SsoConfigOut:
    raise not_implemented()


@router.put("/sso", response_model=SsoConfigOut)
async def update_sso_config(body: SsoConfigUpdate, ctx: SecurityManage) -> SsoConfigOut:
    raise not_implemented()


@router.delete("/sso/secret", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sso_secret(ctx: SecurityManage) -> None:
    raise not_implemented()


@router.post("/sso/refresh-metadata", response_model=SsoConfigOut)
async def refresh_sso_metadata(ctx: SecurityManage) -> SsoConfigOut:
    raise not_implemented()


@router.get("/domains", response_model=DomainList)
async def list_domains(ctx: OrgRead) -> DomainList:
    raise not_implemented()


@router.post("/domains", response_model=DomainOut, status_code=status.HTTP_201_CREATED)
async def create_domain(body: DomainCreate, ctx: SecurityManage) -> DomainOut:
    raise not_implemented()


@router.post("/domains/{domain_id}/verify", response_model=DomainOut)
async def verify_domain(domain_id: uuid.UUID, ctx: SecurityManage) -> DomainOut:
    raise not_implemented()


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(domain_id: uuid.UUID, ctx: SecurityManage) -> None:
    raise not_implemented()
