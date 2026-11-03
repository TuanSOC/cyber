from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from app.core import health
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.db import get_engine


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
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

    v1 = APIRouter(prefix="/api/v1")
    v1.include_router(health.router)
    app.include_router(v1)
    return app


app = create_app()
