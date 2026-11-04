from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the API process.

    Deliberately has no owner/migration database URL: the API only ever connects
    as the RLS-bound app role.
    """

    model_config = SettingsConfigDict(extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    cookie_secure: bool = False

    database_url: str
    redis_url: str
    jwt_secret: str = Field(min_length=32)

    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    minio_bucket: str = "evidence"
    minio_secure: bool = False

    max_evidence_bytes: int = 2 * 1024**3
    evidence_lock_days: int = 30
    upload_tmp_dir: str = "/var/lib/cyberlab/upload-tmp"
    max_concurrent_uploads_per_user: int = 2

    # Analysis jobs (broker = separate Redis instance with ACL users; see infra/redis-broker).
    broker_url: str
    queue_prefix: str = ""
    results_bucket: str = "analysis-results"
    pcap_max_bytes: int = 512 * 1024**2
    analysis_timeout_s: int = 900
    analysis_tool_timeout_s: int = 600
    # Presigned URL lifetime == Celery `expires` == reaper's queued deadline.
    analysis_queue_ttl_s: int = 6 * 3600
    max_active_analyses_per_org: int = 5
    # Single FIFO, one job at a time: bounds how long any org can be starved by others.
    max_active_analyses_global: int = 50
    auto_analyses_per_user_per_10min: int = 30
    analysis_max_flows: int = 100_000
    analysis_max_records_per_kind: int = 100_000
    analysis_max_findings: int = 5_000
    analysis_max_result_bytes: int = 256 * 1024**2

    rate_limit_login_per_ip_per_min: int = 20
    rate_limit_login_failures_per_15min: int = 5
    rate_limit_register_per_ip_per_10min: int = 5

    @model_validator(mode="after")
    def _prod_guards(self) -> Self:
        if self.env != "prod":
            return self
        if not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true when ENV=prod")
        placeholders = [
            name
            for name in ("jwt_secret", "minio_secret_key", "database_url")
            if "change-me" in getattr(self, name)
        ]
        if placeholders:
            raise ValueError(f"placeholder values not allowed in prod: {', '.join(placeholders)}")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
