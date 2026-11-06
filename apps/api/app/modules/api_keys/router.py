"""Platform API keys (M11 phase 9; phase 1 stubs answering 501).

`security.manage` (owners); create needs step-up `api_key_create` and the org policy
`api_keys_enabled`; the key (`clk_…`) is shown once with `Cache-Control: no-store`. Keys are
refused on these routes themselves (role ∩ scopes never holds `security.manage`).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.identity.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyList, ApiKeyOut

router = APIRouter(prefix="/orgs/{org_id}/api-keys", tags=["api-keys"])

SecurityManage = Annotated[
    OrgContext, Depends(require(Permission.SECURITY_MANAGE), scope="function")
]


@router.get("", response_model=ApiKeyList)
async def list_api_keys(ctx: SecurityManage) -> ApiKeyList:
    raise not_implemented()


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(body: ApiKeyCreate, ctx: SecurityManage) -> ApiKeyCreated:
    raise not_implemented()


@router.post("/{key_id}/revoke", response_model=ApiKeyOut)
async def revoke_api_key(key_id: uuid.UUID, ctx: SecurityManage) -> ApiKeyOut:
    raise not_implemented()
