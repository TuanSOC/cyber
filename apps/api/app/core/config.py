import base64
import binascii
from functools import lru_cache
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.modules.threat_intel.catalog import CATALOG, ProviderLimits
from app.modules.threat_intel.providers.base import ProviderName

ProcessRole = Literal["api", "ingest", "enrich"]

# Settings the internet-facing enrich worker must never hold (M4 RT2): a session-forging
# JWT secret, object-store credentials, the app Redis (token denylist, rate limits).
ENRICH_FORBIDDEN = (
    "jwt_secret",
    "minio_endpoint",
    "minio_access_key",
    "minio_secret_key",
    "redis_url",
)
RequiredSetting = Literal[
    "jwt_secret", "minio_endpoint", "minio_access_key", "minio_secret_key", "redis_url"
]


class TiCeiling(BaseModel):
    """Operator override of a provider's catalog ceiling (paid tiers): `TI_CEILINGS` JSON."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    per_minute: int = Field(ge=1, le=100_000)
    per_day: int | None = Field(default=None, ge=1, le=10_000_000)
    concurrency: int = Field(default=4, ge=1, le=4)


class Settings(BaseSettings):
    """Runtime settings for the API process and the trusted workers.

    Deliberately has no owner/migration database URL: the API only ever connects
    as the RLS-bound app role.

    `process_role` decides what a process may hold. The api and ingest roles require the JWT
    secret, MinIO credentials and the app Redis URL as before; the enrich role (the only
    process with internet egress) must not receive them at all (M4 RT2), so they are optional
    at type level and read through `need()`.
    """

    model_config = SettingsConfigDict(extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    process_role: ProcessRole = "api"
    cookie_secure: bool = False

    database_url: str
    redis_url: str | None = None
    jwt_secret: str | None = Field(default=None, min_length=32)

    minio_endpoint: str | None = None
    minio_access_key: str | None = None
    minio_secret_key: str | None = None
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

    # --- Threat intelligence (M4) ---
    ti_enabled: bool = True
    # kid -> base64 raw X25519 public key. The API only seals: it never holds a private key.
    ti_seal_public_keys: dict[str, str] = {}
    ti_seal_active_kid: str | None = None
    # JSON {kid: base64 private key}: the enrich worker only (refused for any other role).
    ti_seal_private_keys_file: str | None = None
    # Dev/test sink (`ti-mock`): refused in prod.
    ti_mock_enabled: bool = False
    ti_mock_base_url: str = "http://ti-mock:8080"
    # MISP: dev-only escape hatches (refused in prod), extra ports, a private CA bundle.
    ti_misp_allow_private: bool = False
    ti_misp_insecure_tls: bool = False
    ti_misp_allowed_ports: list[int] = [443, 8443]
    ti_misp_ca_file: str | None = None
    ti_max_iocs_per_run: int = Field(default=200, ge=1, le=10_000)
    ti_max_lookup_values: int = Field(default=20, ge=1, le=100)
    ti_run_deadline_s: int = Field(default=1800, ge=60)
    ti_slice_s: int = Field(default=20, ge=1, le=300)
    # Per-provider ceiling overrides: JSON {provider: {per_minute, per_day, concurrency}}.
    ti_ceilings: dict[ProviderName, TiCeiling] = {}

    def need(self, name: RequiredSetting) -> str:
        """A setting every role but enrich requires (validated at startup)."""
        value: str | None = getattr(self, name)
        if value is None:
            raise RuntimeError(f"{name} is not available to the {self.process_role} process")
        return value

    def ti_ceiling(self, provider: ProviderName) -> ProviderLimits:
        override = self.ti_ceilings.get(provider)
        if override is None:
            return CATALOG[provider].ceilings
        return ProviderLimits(override.per_minute, override.per_day, override.concurrency)

    @field_validator("ti_seal_public_keys")
    @classmethod
    def _public_keys(cls, value: dict[str, str]) -> dict[str, str]:
        for kid, encoded in value.items():
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                raw = b""
            if len(raw) != 32:
                raise ValueError(f"TI_SEAL_PUBLIC_KEYS[{kid!r}] is not a base64 X25519 key")
        return value

    @field_validator(
        "ti_seal_active_kid", "ti_seal_private_keys_file", "ti_misp_ca_file", mode="before"
    )
    @classmethod
    def _blank_ti_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @model_validator(mode="after")
    def _role_guards(self) -> Self:
        if self.process_role == "enrich":
            present = [name.upper() for name in ENRICH_FORBIDDEN if getattr(self, name)]
            if present:
                raise ValueError(f"PROCESS_ROLE=enrich must not receive: {', '.join(present)}")
            return self
        missing = [name.upper() for name in ENRICH_FORBIDDEN if getattr(self, name) is None]
        if missing:
            raise ValueError(f"missing settings: {', '.join(missing)}")
        if self.ti_seal_private_keys_file is not None:
            raise ValueError("TI_SEAL_PRIVATE_KEYS_FILE is only accepted with PROCESS_ROLE=enrich")
        return self

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
            if "change-me" in (getattr(self, name) or "")
        ]
        if placeholders:
            raise ValueError(f"placeholder values not allowed in prod: {', '.join(placeholders)}")
        unsafe = [
            name.upper()
            for name in ("ti_mock_enabled", "ti_misp_allow_private", "ti_misp_insecure_tls")
            if getattr(self, name)
        ]
        if unsafe:
            raise ValueError(f"dev-only settings not allowed in prod: {', '.join(unsafe)}")
        if self.ti_enabled:
            kid = self.ti_seal_active_kid
            if not kid or kid not in self.ti_seal_public_keys:
                raise ValueError("TI_SEAL_ACTIVE_KID must name a key in TI_SEAL_PUBLIC_KEYS")
            if kid.startswith("dev-"):
                # The committed dev key pair is public: never seal production keys with it.
                raise ValueError("TI_SEAL_ACTIVE_KID: dev- seal keys are not allowed in prod")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
