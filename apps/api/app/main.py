from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from app.core import health
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.csrf import CSRFMiddleware
from app.core.db import get_engine
from app.core.errors import register_error_handlers
from app.core.hashing import sweep_stale_spools
from app.modules.ai.router import router as ai_router
from app.modules.analysis.router import router as analysis_router
from app.modules.attack.router import router as attack_router
from app.modules.audit.router import router as audit_router
from app.modules.auth.router import router as auth_router
from app.modules.case_attack.router import router as case_attack_router
from app.modules.case_timeline.router import router as case_timeline_router
from app.modules.correlation.router import router as correlation_router
from app.modules.evidence.router import router as evidence_router
from app.modules.investigations.router import router as investigations_router
from app.modules.ioc_collections.router import router as ioc_collections_router
from app.modules.notes.router import router as notes_router
from app.modules.ops.internal import router as ops_internal_router
from app.modules.ops.router import router as ops_router
from app.modules.organizations.router import router as orgs_router
from app.modules.pcap_analysis.router import router as pcap_analysis_router
from app.modules.reports import signing as report_signing
from app.modules.reports.router import router as reports_router
from app.modules.reports.router_keys import router as report_keys_router
from app.modules.reports.router_renders import router as report_renders_router
from app.modules.retention.router import router as retention_router
from app.modules.search.router import router as search_router
from app.modules.static_analysis.router import router as static_analysis_router
from app.modules.threat_intel.router import router as threat_intel_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Temp spool files left behind by a crash (normal paths always delete theirs).
    sweep_stale_spools(get_settings().upload_tmp_dir)
    # Prod: the report signing key pair is usable and not the committed dev pair (M6).
    report_signing.check_startup_keys()
    yield
    await get_redis().aclose()
    await get_engine().dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    is_dev = settings.env == "dev"
    app = FastAPI(
        title="CyberLab AI API",
        version="0.1.0",
        openapi_url="/api/openapi.json",
        docs_url="/api/docs" if is_dev else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    register_error_handlers(app)
    app.add_middleware(CSRFMiddleware)

    v1 = APIRouter(prefix="/api/v1")
    v1.include_router(health.router)
    v1.include_router(auth_router)
    v1.include_router(orgs_router)
    v1.include_router(audit_router)
    v1.include_router(investigations_router)
    v1.include_router(evidence_router)
    v1.include_router(analysis_router)
    v1.include_router(pcap_analysis_router)
    v1.include_router(static_analysis_router)
    v1.include_router(threat_intel_router)
    v1.include_router(attack_router)
    v1.include_router(ai_router)
    # M6: case management and reports.
    v1.include_router(notes_router)
    v1.include_router(ioc_collections_router)
    v1.include_router(case_attack_router)
    v1.include_router(case_timeline_router)
    v1.include_router(reports_router)
    v1.include_router(report_renders_router)
    v1.include_router(report_keys_router)
    # M7: platform operations (retention, correlation, search, org metrics).
    v1.include_router(retention_router)
    v1.include_router(correlation_router)
    v1.include_router(search_router)
    v1.include_router(ops_router)
    app.include_router(v1)
    # Outside /api: the gateway never forwards it (bearer METRICS_TOKEN, RT27).
    app.include_router(ops_internal_router)
    return app


app = create_app()
