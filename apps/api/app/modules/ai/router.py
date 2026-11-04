"""Every AI analyst route, registered once in `app/main.py` (M5 phase 1, FROZEN).

Phase 7 fills the sub-routers; nobody else edits this file or `app/main.py`.
"""

from fastapi import APIRouter

from app.modules.ai import router_providers, router_runs, router_settings

router = APIRouter()
router.include_router(router_providers.router)
router.include_router(router_settings.router)
router.include_router(router_runs.router)
