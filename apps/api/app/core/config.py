from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
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
    # Per-org evidence storage (active + archived), unless organizations.storage_quota_bytes
    # overrides it; and how many orgs one user may own (M3 RT8).
    default_storage_quota_bytes: int = Field(default=20 * 1024**3, ge=0)
    max_owned_orgs_per_user: int = Field(default=5, ge=1)

    # Analysis jobs (broker = separate Redis instance with ACL users; see infra/redis-broker).
    broker_url: str
    queue_prefix: str = ""
    results_bucket: str = "analysis-results"
    pcap_max_bytes: int = 512 * 1024**2
    analysis_timeout_s: int = 900
    analysis_tool_timeout_s: int = 600
    # Presigned URL lifetime == Celery `expires` == reaper's queued deadline.
    analysis_queue_ttl_s: int = 6 * 3600
    # Both caps apply per analyzer (each has its own queue and workers): a full pcap queue
    # never blocks static analyses, and the other way round.
    max_active_analyses_per_org: int = 5
    # Single FIFO per analyzer, one job at a time: bounds how long any org can be starved.
    max_active_analyses_global: int = 50
    auto_analyses_per_user_per_10min: int = 30
    analysis_max_flows: int = 100_000
    analysis_max_records_per_kind: int = 100_000
    analysis_max_findings: int = 5_000
    analysis_max_result_bytes: int = 256 * 1024**2
    # Static analysis of one file (never executed): sample size cap and per-kind result caps.
    static_max_bytes: int = 64 * 1024**2
    analysis_static_timeout_s: int = 600
    analysis_static_tool_timeout_s: int = 300
    static_max_sections: int = 2_000
    static_max_imports: int = 20_000
    static_max_exports: int = 20_000
    static_max_resources: int = 5_000
    static_max_strings: int = 20_000
    static_max_signature_matches: int = 1_000
    static_max_capabilities: int = 1_000
    static_max_findings: int = 1_000
    static_max_iocs: int = 5_000
    static_max_result_bytes: int = 64 * 1024**2
    # Ingest: zip-bomb guard on the inflated stream and a cap on its lines (all kinds).
    analysis_max_result_decompressed_bytes: int = 1024**3
    analysis_max_result_lines: int = 400_000
    # Scratch dir for the downloaded result. Required by the ingest worker outside tests
    # (it refuses to start without one); None = the system temp dir (tests only).
    ingest_tmp_dir: str | None = None
    # Free space kept on the scratch volume on top of the result being downloaded.
    ingest_min_free_bytes: int = 64 * 1024**2
    # Timeouts of the one write transaction (SET LOCAL: they end with it).
    ingest_statement_timeout_s: int = 300
    ingest_idle_in_transaction_timeout_s: int = 30

    rate_limit_login_per_ip_per_min: int = 20
    rate_limit_login_failures_per_15min: int = 5
    rate_limit_register_per_ip_per_10min: int = 5

    @field_validator("ingest_tmp_dir", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        # INGEST_TMP_DIR= must not silently mean the current directory.
        return None if isinstance(value, str) and not value.strip() else value

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
