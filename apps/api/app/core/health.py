from collections.abc import Awaitable, Callable
from typing import Literal

import anyio
from fastapi import APIRouter, Response, status
from pydantic import BaseModel
from sqlalchemy import text

from app.core.clients import get_minio, get_redis
from app.core.config import get_settings
from app.core.db import get_engine

router = APIRouter(tags=["health"])

Status = Literal["ok", "error"]
CHECK_TIMEOUT_S = 3


class HealthOut(BaseModel):
    db: Status
    redis: Status
    minio: Status


async def _check_db() -> None:
    async with get_engine().connect() as conn:
        await conn.execute(text("SELECT 1"))


async def _check_redis() -> None:
    await get_redis().ping()


async def _check_minio() -> None:
    bucket = get_settings().minio_bucket
    if not await anyio.to_thread.run_sync(get_minio().bucket_exists, bucket):
        raise RuntimeError(f"bucket {bucket} missing")


async def _probe(check: Callable[[], Awaitable[None]]) -> Status:
    try:
        with anyio.fail_after(CHECK_TIMEOUT_S):
            await check()
        return "ok"
    except Exception:
        return "error"


@router.get("/health", response_model=HealthOut)
async def health(response: Response) -> HealthOut:
    results: dict[str, Status] = {}

    async def run(name: str, check: Callable[[], Awaitable[None]]) -> None:
        results[name] = await _probe(check)

    async with anyio.create_task_group() as tg:
        tg.start_soon(run, "db", _check_db)
        tg.start_soon(run, "redis", _check_redis)
        tg.start_soon(run, "minio", _check_minio)

    out = HealthOut(db=results["db"], redis=results["redis"], minio=results["minio"])
    if "error" in results.values():
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return out
