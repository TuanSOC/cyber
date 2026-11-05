from functools import lru_cache

import urllib3
from minio import Minio
from redis.asyncio import Redis

from app.core.config import get_settings


@lru_cache
def get_redis() -> Redis:
    return Redis.from_url(
        get_settings().need("redis_url"), socket_connect_timeout=2, socket_timeout=2
    )


def _http() -> urllib3.PoolManager:
    return urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=2, read=30),
        retries=urllib3.Retry(total=2, backoff_factor=0.2),
    )


@lru_cache
def get_minio() -> Minio:
    s = get_settings()
    return Minio(
        s.need("minio_endpoint"),
        access_key=s.need("minio_access_key"),
        secret_key=s.need("minio_secret_key"),
        secure=s.minio_secure,
        http_client=_http(),
    )


@lru_cache
def get_purge_minio() -> Minio:
    """The retention worker's MinIO user `cyberlab-purge` (M7): delete expired versions,
    read retention, read / set S3 legal holds; no PutObject, no governance bypass. Settings
    accept its keys only with PROCESS_ROLE=retention."""
    s = get_settings()
    if s.minio_purge_access_key is None or s.minio_purge_secret_key is None:
        raise RuntimeError(f"the purge MinIO user is not available to the {s.process_role} process")
    return Minio(
        s.need("minio_endpoint"),
        access_key=s.minio_purge_access_key,
        secret_key=s.minio_purge_secret_key,
        secure=s.minio_secure,
        http_client=_http(),
    )
