"""AI analyst runs routes: empty in phase 1, filled by phase 7 (registered via `router.py`)."""

from fastapi import APIRouter

router = APIRouter(prefix="/orgs/{org_id}", tags=["ai"])
