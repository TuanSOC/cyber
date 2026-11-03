from functools import lru_cache

import urllib3
from minio import Minio
from redis.asyncio import Redis

from app.core.config import get_settings


@lru_cache
def get_redis() -> Redis:
    return Redis.from_url(get_settings().redis_url, socket_connect_timeout=2, socket_timeout=2)


@lru_cache
def get_minio() -> Minio:
    s = get_settings()
    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=2, read=30),
        retries=urllib3.Retry(total=2, backoff_factor=0.2),
    )
    return Minio(
        s.minio_endpoint,
        access_key=s.minio_access_key,
        secret_key=s.minio_secret_key,
        secure=s.minio_secure,
        http_client=http,
    )
