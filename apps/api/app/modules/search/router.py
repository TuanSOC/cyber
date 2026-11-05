"""Org search (M7). Path, permission and models are frozen in phase 1; the body answers
`501 not_implemented` until phase 4 lands (`investigation.read`, RLS-bound, 30 / min per
user, `SET LOCAL statement_timeout`, 20 hits per type)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.search.schemas import SearchIn, SearchOut

router = APIRouter(prefix="/orgs/{org_id}", tags=["search"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]


@router.post("/search", response_model=SearchOut)
async def search(body: SearchIn, ctx: InvRead) -> SearchOut:
    """`422 search_query_invalid` (stripped query outside 2..256 characters)."""
    raise not_implemented()
