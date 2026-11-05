import base64
import binascii
from functools import lru_cache
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.sealbox import KID_PATTERN
from app.modules.ai.contracts import AiProviderName
from app.modules.threat_intel.catalog import CATALOG, ProviderLimits
from app.modules.threat_intel.providers.base import ProviderName

ProcessRole = Literal["api", "ingest", "enrich", "analyst"]

# Settings the internet-facing enrich worker must never hold (M4 RT2): a session-forging
# JWT secret, object-store credentials, the app Redis (token denylist, rate limits).
ENRICH_FORBIDDEN = (
    "jwt_secret",
    "minio_endpoint",
    "minio_access_key",
    "minio_secret_key",
    "redis_url",
)
# The committed dev-only seal key pair (infra/ti/dev-seal-private.json, kid dev-1): its
# private half is public, so prod refuses its public key under any kid (review L6).
DEV_SEAL_PUBLIC_KEYS = frozenset({"yzkMNEv4XawVLz1SuyMqEqSDdzMc1QpC7ERo9zFe7Gs="})
# The trusted AI analyst worker (M5) has the same restrictions, and may not open TI keys
# either: `threat_intel.unseal` and `ai.unseal` are never both usable by one process role.
ANALYST_FORBIDDEN = (*ENRICH_FORBIDDEN, "ti_seal_private_keys_file")
# The committed dev-only AI seal key pair (infra/ai/dev-seal-private.json, kid dev-ai-1).
DEV_AI_SEAL_PUBLIC_KEYS = frozenset({"YqrtDS8h4Q5PCQ0wa+0X7Qy72jDi3HYjQfotX+oH6io="})
# The committed dev-only report signing pair (infra/reports/dev-signing-private.json, kid
# dev-report-1, M6): its private half is public, so prod refuses its public key.
DEV_REPORT_SIGNING_PUBLIC_KEYS = frozenset({"zS2iP9napZDeshJwfCiTwYl8amzPuWJEJwHK8CpnF2k="})
# Report defaults shared with the renderer contract (`cyberlab_jobs.report`).
REPORT_DEFAULT_MAX_RENDER_UNITS = 750_000  # ~250 A4 pages; phase 4 calibrates (RT1)
# Per-org AI budget defaults (`ai_org_settings` server defaults, migration 0011, RT9).
AI_DEFAULT_DAILY_TOKEN_BUDGET = 1_000_000
AI_DEFAULT_RUN_TOKEN_CAP = 100_000
AI_DEFAULT_INCIDENT_TOKEN_CAP = 600_000
AnthropicEffort = Literal["low", "medium", "high", "xhigh", "max"]
RequiredSetting = Literal[
    "jwt_secret", "minio_endpoint", "minio_access_key", "minio_secret_key", "redis_url"
]


class TiCeiling(BaseModel):
    """Operator override of a provider's catalog ceiling (paid tiers): `TI_CEILINGS` JSON."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    per_minute: int = Field(ge=1, le=100_000)
    per_day: int | None = Field(default=None, ge=1, le=10_000_000)
    concurrency: int = Field(default=4, ge=1, le=4)


class AiCeilings(BaseModel):
    """Operator ceilings over the per-org AI budgets (`AI_CEILINGS` JSON, RT9): an org admin
    can never set a budget above them. `per_minute` overrides the catalog request ceilings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    daily_token_budget: int = Field(default=20_000_000, ge=1, le=1_000_000_000)
    run_token_cap: int = Field(default=200_000, ge=1, le=10_000_000)
    incident_token_cap: int = Field(default=2_000_000, ge=1, le=100_000_000)
    per_minute: dict[AiProviderName, int] = {}

    @field_validator("per_minute")
    @classmethod
    def _per_minute(cls, value: dict[AiProviderName, int]) -> dict[AiProviderName, int]:
        if any(not 1 <= v <= 100_000 for v in value.values()):
            raise ValueError("AI_CEILINGS.per_minute values must be 1..100000")
        return value


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

    # --- AI analyst (M5) ---
    ai_enabled: bool = True
    # kid -> base64 raw X25519 public key: the API seals AI provider keys with it; the analyst
    # holds it too, for the lazy re-seal under the active kid (RT18).
    ai_seal_public_keys: dict[str, str] = {}
    ai_seal_active_kid: str | None = None
    # JSON {kid: base64 private key}: the analyst worker only (refused for any other role).
    ai_seal_private_keys_file: str | None = None
    # Dev/test platform key (a compose secret file, never an env value): analyst only and
    # refused in prod. `AI_PLATFORM_PROVIDER` names its provider (non-secret: the API reads it
    # to show `platform_key` on the catalog; refused in prod too).
    ai_platform_key_file: str | None = None
    ai_platform_provider: AiProviderName | None = None
    # Global daily ceiling of the platform key (broker counter, RT17).
    ai_platform_daily_tokens: int = Field(default=200_000, ge=1, le=100_000_000)
    # Dev/test sink (`ai-mock`): refused in prod.
    ai_mock_enabled: bool = False
    ai_mock_base_url: str = "http://ai-mock:8080"
    # Operator flag: Gemini only runs with paid-tier billing (and the org's attestation, RT5).
    gemini_billing_enabled: bool = False
    ai_default_provider: AiProviderName = AiProviderName.ANTHROPIC
    ai_anthropic_effort: AnthropicEffort = "medium"
    # Test-only endpoint overrides (replay servers); refused in prod.
    ai_anthropic_base_url: str | None = None
    ai_gemini_base_url: str | None = None
    ai_max_input_tokens: int = Field(default=60_000, ge=1_000, le=1_000_000)
    ai_max_output_tokens: int = Field(default=16_000, ge=256, le=128_000)
    ai_call_timeout_s: int = Field(default=300, ge=5, le=3600)
    ai_call_idle_timeout_s: int = Field(default=60, ge=1, le=600)
    ai_max_calls_per_run: int = Field(default=3, ge=1, le=10)
    ai_run_deadline_s: int = Field(default=1200, ge=60)
    # Incident trees: the children inherit the parent's deadline (RT8).
    ai_incident_deadline_s: int = Field(default=3600, ge=60)
    ai_max_jobs_per_incident: int = Field(default=10, ge=1, le=50)
    ai_ceilings: AiCeilings = AiCeilings()
    ai_runs_per_user_10min: int = Field(default=10, ge=1)
    # Both count every non-final run, incident children included (RT8).
    ai_active_runs_per_org: int = Field(default=12, ge=1)
    ai_active_runs_global: int = Field(default=40, ge=1)

    # --- Reports and case management (M6) ---
    # Object-locked, versioned, no default retention (per-object GOVERNANCE, RT6);
    # api-test uses REPORTS_TEST_BUCKET (`reports-test`).
    reports_bucket: str = "reports"
    report_max_snapshot_bytes: int = Field(default=8 * 1024**2, ge=1024, le=8 * 1024**2)
    report_max_artifact_bytes: int = Field(default=32 * 1024**2, ge=1024, le=32 * 1024**2)
    # The render budget (`cyberlab_jobs.report.render_units`): finalize refuses above it (RT1).
    report_max_render_units: int = Field(default=REPORT_DEFAULT_MAX_RENDER_UNITS, ge=1_000)
    report_max_pages: int = Field(default=300, ge=1, le=300)
    report_render_deadline_s: int = Field(default=600, ge=60)
    report_render_timeout_s: int = Field(default=120, ge=10, le=600)
    report_renders_per_user_10min: int = Field(default=20, ge=1)
    report_finalize_per_user_10min: int = Field(default=10, ge=1)
    report_preview_per_user_10min: int = Field(default=30, ge=1)
    # One report-worker replica renders one report at a time: the global cap scales with
    # the replicas (RT5).
    report_active_renders_per_org: int = Field(default=2, ge=1)
    report_active_renders_global: int = Field(default=4, ge=1)
    timeline_export_max_rows: int = Field(default=50_000, ge=1, le=1_000_000)
    # Origin printed in front of the citation appendix paths (internal profile only, RT8).
    public_base_url: str | None = None
    # Ed25519 report signing (M6): JSON {kid: base64 raw private key}, the api role only.
    report_signing_keys_file: str | None = None
    # kid -> base64 raw 32-byte Ed25519 public key (verification, the public keys route).
    report_signing_public_keys: dict[str, str] = {}
    report_signing_active_kid: str | None = None

    def need(self, name: RequiredSetting) -> str:
        """A setting every role but enrich and analyst requires (validated at startup)."""
        value: str | None = getattr(self, name)
        if value is None:
            raise RuntimeError(f"{name} is not available to the {self.process_role} process")
        return value

    def ti_ceiling(self, provider: ProviderName) -> ProviderLimits:
        override = self.ti_ceilings.get(provider)
        if override is None:
            return CATALOG[provider].ceilings
        return ProviderLimits(override.per_minute, override.per_day, override.concurrency)

    @field_validator("ti_seal_public_keys", "ai_seal_public_keys")
    @classmethod
    def _public_keys(cls, value: dict[str, str], info: ValidationInfo) -> dict[str, str]:
        name = (info.field_name or "").upper()
        for kid, encoded in value.items():
            if not KID_PATTERN.fullmatch(kid):
                raise ValueError(f"{name} has an invalid kid")
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                raw = b""
            if len(raw) != 32:
                raise ValueError(f"{name}[{kid!r}] is not a base64 X25519 key")
        return value

    @field_validator(
        "ti_seal_active_kid",
        "ti_seal_private_keys_file",
        "ti_misp_ca_file",
        "ai_seal_active_kid",
        "ai_seal_private_keys_file",
        "ai_platform_key_file",
        "ai_platform_provider",
        "ai_anthropic_base_url",
        "ai_gemini_base_url",
        "public_base_url",
        "report_signing_keys_file",
        "report_signing_active_kid",
        mode="before",
    )
    @classmethod
    def _blank_ti_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("report_signing_public_keys")
    @classmethod
    def _signing_public_keys(cls, value: dict[str, str]) -> dict[str, str]:
        for kid, encoded in value.items():
            if not KID_PATTERN.fullmatch(kid):
                raise ValueError("REPORT_SIGNING_PUBLIC_KEYS has an invalid kid")
            if len(_key_bytes(encoded)) != 32:
                raise ValueError(
                    f"REPORT_SIGNING_PUBLIC_KEYS[{kid!r}] is not a base64 Ed25519 public key"
                )
        return value

    @field_validator("public_base_url")
    @classmethod
    def _public_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("PUBLIC_BASE_URL must be an origin such as https://cyberlab.example")
        return value.rstrip("/")

    @field_validator("ti_seal_active_kid", "ai_seal_active_kid", "report_signing_active_kid")
    @classmethod
    def _active_kid(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and not KID_PATTERN.fullmatch(value):
            name = (info.field_name or "").upper()
            raise ValueError(f"{name} must match [A-Za-z0-9._-]{{1,64}}")
        return value

    @model_validator(mode="after")
    def _role_guards(self) -> Self:
        role = self.process_role
        # The report signing private key: the api role only (M6). Ingest, enrich, analyst
        # and the report renderer never hold it.
        if role != "api" and self.report_signing_keys_file is not None:
            raise ValueError("REPORT_SIGNING_KEYS_FILE is only accepted with PROCESS_ROLE=api")
        # The AI private and platform keys: the analyst worker only (enrich and the API never
        # open AI keys).
        if role != "analyst":
            for name in ("ai_seal_private_keys_file", "ai_platform_key_file"):
                if getattr(self, name) is not None:
                    raise ValueError(f"{name.upper()} is only accepted with PROCESS_ROLE=analyst")
        if role in ("enrich", "analyst"):
            forbidden = ENRICH_FORBIDDEN if role == "enrich" else ANALYST_FORBIDDEN
            present = [name.upper() for name in forbidden if getattr(self, name)]
            if present:
                raise ValueError(f"PROCESS_ROLE={role} must not receive: {', '.join(present)}")
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
        # Only the API sets cookies; the workers (ingest, enrich) never receive COOKIE_SECURE
        # (the prod enrich worker has no such variable at all, review H1).
        if self.process_role == "api" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true when ENV=prod")
        placeholders = [
            name
            # broker_url (M5 RT25): the dev compose default broker passwords are change-me.
            for name in ("jwt_secret", "minio_secret_key", "database_url", "broker_url")
            if "change-me" in (getattr(self, name) or "")
        ]
        if placeholders:
            raise ValueError(f"placeholder values not allowed in prod: {', '.join(placeholders)}")
        unsafe = [
            name.upper()
            for name in (
                "ti_mock_enabled",
                "ti_misp_allow_private",
                "ti_misp_insecure_tls",
                "ai_mock_enabled",
                "ai_platform_key_file",
                "ai_platform_provider",
                "ai_anthropic_base_url",
                "ai_gemini_base_url",
            )
            if getattr(self, name)
        ]
        if unsafe:
            raise ValueError(f"dev-only settings not allowed in prod: {', '.join(unsafe)}")
        # Role-scoped kid guards (M5 RT6): the kid checks run for the roles that seal or open a
        # domain's keys; the dev public-key refusals apply wherever keys are present.
        if self.ti_enabled and self.process_role in ("api", "enrich"):
            kid = self.ti_seal_active_kid
            if not kid or kid not in self.ti_seal_public_keys:
                raise ValueError("TI_SEAL_ACTIVE_KID must name a key in TI_SEAL_PUBLIC_KEYS")
            if kid.lower().startswith("dev-"):
                # The committed dev key pair is public: never seal production keys with it.
                raise ValueError("TI_SEAL_ACTIVE_KID: dev- seal keys are not allowed in prod")
        if any(_key_bytes(v) in _DEV_KEY_BYTES for v in self.ti_seal_public_keys.values()):
            raise ValueError(
                "TI_SEAL_PUBLIC_KEYS: the committed dev seal key is not allowed in prod"
            )
        if self.ai_enabled and self.process_role in ("api", "analyst"):
            kid = self.ai_seal_active_kid
            if not kid or kid not in self.ai_seal_public_keys:
                raise ValueError("AI_SEAL_ACTIVE_KID must name a key in AI_SEAL_PUBLIC_KEYS")
            if kid.lower().startswith("dev-"):
                raise ValueError("AI_SEAL_ACTIVE_KID: dev- seal keys are not allowed in prod")
        if any(_key_bytes(v) in _DEV_AI_KEY_BYTES for v in self.ai_seal_public_keys.values()):
            raise ValueError(
                "AI_SEAL_PUBLIC_KEYS: the committed dev seal key is not allowed in prod"
            )
        self._report_prod_guards()
        return self

    def _report_prod_guards(self) -> None:
        """M6: prod signs with a real key pair, never the committed dev one, and prints
        https links only (a plain-http PUBLIC_BASE_URL is allowed on localhost only)."""
        if self.process_role == "api":
            kid = self.report_signing_active_kid
            if not kid or kid not in self.report_signing_public_keys:
                raise ValueError(
                    "REPORT_SIGNING_ACTIVE_KID must name a key in REPORT_SIGNING_PUBLIC_KEYS"
                )
            if self.report_signing_keys_file is None:
                raise ValueError("REPORT_SIGNING_KEYS_FILE is required for the api in prod")
        if any(kid.lower().startswith("dev-") for kid in self.report_signing_public_keys) or (
            self.report_signing_active_kid or ""
        ).lower().startswith("dev-"):
            raise ValueError("REPORT_SIGNING_*: dev- signing keys are not allowed in prod")
        if any(
            _key_bytes(v) in _DEV_REPORT_KEY_BYTES for v in self.report_signing_public_keys.values()
        ):
            raise ValueError(
                "REPORT_SIGNING_PUBLIC_KEYS: the committed dev signing key is not allowed in prod"
            )
        url = self.public_base_url
        if url is not None and url.startswith("http://"):
            host = urlsplit(url).hostname or ""
            if host not in ("localhost", "127.0.0.1", "::1"):
                raise ValueError("PUBLIC_BASE_URL must use https in prod (except localhost)")


def _key_bytes(encoded: str) -> bytes:
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return b""


_DEV_KEY_BYTES = frozenset(_key_bytes(k) for k in DEV_SEAL_PUBLIC_KEYS)
_DEV_AI_KEY_BYTES = frozenset(_key_bytes(k) for k in DEV_AI_SEAL_PUBLIC_KEYS)
_DEV_REPORT_KEY_BYTES = frozenset(_key_bytes(k) for k in DEV_REPORT_SIGNING_PUBLIC_KEYS)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
