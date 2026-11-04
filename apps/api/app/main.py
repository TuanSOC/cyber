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
from app.modules.analysis.router import router as analysis_router
from app.modules.audit.router import router as audit_router
from app.modules.auth.router import router as auth_router
from app.modules.evidence.router import router as evidence_router
from app.modules.investigations.router import router as investigations_router
from app.modules.organizations.router import router as orgs_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Temp spool files left behind by a crash (normal paths always delete theirs).
    sweep_stale_spools(get_settings().upload_tmp_dir)
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
    app.include_router(v1)
    return app


app = create_app()
