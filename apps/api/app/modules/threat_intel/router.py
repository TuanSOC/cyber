"""Every threat intel route, registered once in `app/main.py` (M4 RT14).

Phase 5 fills the sub-routers; neither it nor phase 4 edits `app/main.py`.
"""

from fastapi import APIRouter

from app.modules.threat_intel import router_integrations, router_results, router_runs

router = APIRouter()
router.include_router(router_integrations.router)
router.include_router(router_runs.router)
router.include_router(router_results.router)
