import base64
import binascii
import uuid
from collections.abc import Mapping
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

ProcessRole = Literal["api", "ingest", "enrich", "analyst", "retention", "mail", "egress_proxy"]

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
REPORT_DEFAULT_MAX_RENDER_UNITS = (
    450_000  # phase 4 calibration: worst 594 MiB RSS of 768, <=214 pages (RT1)
)
# Per-org AI budget defaults (`ai_org_settings` server defaults, migration 0011, RT9).
AI_DEFAULT_DAILY_TOKEN_BUDGET = 1_000_000
AI_DEFAULT_RUN_TOKEN_CAP = 100_000
AI_DEFAULT_INCIDENT_TOKEN_CAP = 600_000
# Platform operations (M7). The least-privilege retention worker (DB role
# `cyberlab_retention`, MinIO user `cyberlab-purge`) must never hold a session-forging secret,
# the app Redis, the api's MinIO user, any seal / signing / platform key or the metrics token.
RETENTION_ROLE = "cyberlab_retention"
RETENTION_FORBIDDEN = (
    "jwt_secret",
    "redis_url",
    "minio_access_key",
    "minio_secret_key",
    "ti_seal_private_keys_file",
    "ai_seal_private_keys_file",
    "ai_platform_key_file",
    "report_signing_keys_file",
    "metrics_token_file",
)
# Policy floors (days, constants of migration 0014's checks); the closed-case floor is also at
# least EVIDENCE_LOCK_DAYS (configuration, so the API enforces it).
RETENTION_FLOOR_DAYS = 30
# The fixed, inactive system user seeded by 0014: the custody actor of purges (RT12).
RETENTION_SYSTEM_USER_ID = uuid.UUID("00000000-0000-4000-8000-00000000a7e0")
RETENTION_SYSTEM_USER_EMAIL = "retention@system.invalid"
# The committed dev KMS key name (infra/minio/dev-kms-key): refused in prod by the env checks.
DEV_KMS_KEY_NAME = "cyberlab-dev-kms"
# Identity and access (M11). The mail worker (`PROCESS_ROLE=mail`) connects as its own DB role
# (`cyberlab_mail`: SELECT / UPDATE on `email_outbox` only, RT9) and holds the broker URL, the
# SMTP credentials and the mail seal private key, nothing else; every other role refuses that
# DB role. The identity seal private key (TOTP secrets, IdP client secrets) is the api's only.
MAIL_ROLE = "cyberlab_mail"
MAIL_FORBIDDEN = (
    "jwt_secret",
    "redis_url",
    "minio_endpoint",
    "minio_access_key",
    "minio_secret_key",
    "ti_seal_private_keys_file",
    "ai_seal_private_keys_file",
    "ai_platform_key_file",
    "report_signing_keys_file",
    "metrics_token_file",
    "identity_seal_private_keys_file",
)
# The committed dev-only seal pairs (infra/identity/dev-seal-private.json, kid dev-id-1, and
# infra/mail/dev-seal-private.json, kid dev-mail-1): prod refuses their public keys.
DEV_IDENTITY_SEAL_PUBLIC_KEYS = frozenset({"inKO/T3b2CUYRA4j18evHiWhy2zedKyFhkgF7EZbo2k="})
DEV_MAIL_SEAL_PUBLIC_KEYS = frozenset({"lu5nrvsk6cgPJRP1y/AzM6dn9fZliHtNr6jx9ftoVyE="})
# ENV=test may only deliver SMTP to the test Mailpit (no test can send real mail).
TEST_SMTP_HOST = "mailpit-test"
RegistrationMode = Literal["open", "invite_only"]
MailTransport = Literal["smtp", "capture", "disabled"]
SmtpTls = Literal["none", "starttls", "implicit"]
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
    # Memory forensics (M8): image size cap (RT14: <= 16 GiB; Caddy's read_body 30m needs
    # >= 4.6 MB/s for 8 GiB), result caps (the `memory.v1` contract ceilings), timeouts and the
    # active-job caps (a run costs minutes to an hour and gigabytes of disk).
    memory_max_bytes: int = Field(default=8 * 1024**3, ge=1, le=16 * 1024**3)
    memory_max_result_bytes: int = Field(default=256 * 1024**2, ge=1024, le=256 * 1024**2)
    # The memory ingest's own framing bounds (RT9); lines = the sum of the caps + 3.
    memory_max_result_decompressed_bytes: int = Field(default=1024**3, ge=1024, le=1024**3)
    analysis_memory_timeout_s: int = Field(default=5_400, ge=60, le=21_600)
    analysis_memory_plugin_timeout_s: int = Field(default=1_200, ge=10)
    analysis_memory_identify_timeout_s: int = Field(default=600, ge=10)
    memory_max_active_per_org: int = Field(default=1, ge=1)
    memory_max_active_total: int = Field(default=2, ge=1)
    memory_max_processes: int = Field(default=20_000, ge=1, le=20_000)
    memory_max_connections: int = Field(default=50_000, ge=1, le=50_000)
    memory_max_injections: int = Field(default=5_000, ge=1, le=5_000)
    memory_max_artifacts: int = Field(default=50_000, ge=1, le=50_000)
    memory_max_findings: int = Field(default=5_000, ge=1, le=5_000)
    memory_max_iocs: int = Field(default=20_000, ge=1, le=20_000)
    memory_max_timeline: int = Field(default=5_000, ge=1, le=5_000)
    # Process tree served by the read API (phase 7): nodes per response.
    memory_tree_max_nodes: int = Field(default=5_000, ge=1, le=20_000)
    # Disk forensics (M9): per-request segment cap (<= 16 GiB: the M8 Caddy bound), segment
    # sets (<= 64 segments, the sum <= DISK_MAX_IMAGE_BYTES: 16 GiB under the 20 GiB default
    # org quota, <= 64 GiB; RT21), the claimed EWF media size (RT6), the result caps (the
    # `disk.v1` contract ceilings), timeouts, active-job caps and file exports (phase 10).
    disk_max_upload_bytes: int = Field(default=8 * 1024**3, ge=1, le=16 * 1024**3)
    disk_max_segments: int = Field(default=64, ge=1, le=64)
    disk_max_image_bytes: int = Field(default=16 * 1024**3, ge=1, le=64 * 1024**3)
    disk_max_media_bytes: int = Field(default=2 * 1024**4, ge=1, le=16 * 1024**4)
    disk_max_result_bytes: int = Field(default=256 * 1024**2, ge=1024, le=256 * 1024**2)
    # The disk ingest's own framing bounds (RT9); lines = the sum of the caps + 3.
    disk_max_result_decompressed_bytes: int = Field(
        default=3 * 1024**3 // 2, ge=1024, le=3 * 1024**3 // 2
    )
    analysis_disk_timeout_s: int = Field(default=14_400, ge=60, le=21_600)
    # The disk ingest worker's budget: the ingest hand-off moves the deadline by this (RT9).
    disk_ingest_timeout_s: int = Field(default=1_800, ge=60, le=7_200)
    disk_max_active_per_org: int = Field(default=1, ge=1)
    disk_max_active_total: int = Field(default=1, ge=1)
    disk_max_partitions: int = Field(default=128, ge=1, le=128)
    disk_max_filesystems: int = Field(default=32, ge=1, le=32)
    disk_max_files: int = Field(default=500_000, ge=1, le=2_000_000)
    disk_max_streams_per_file: int = Field(default=16, ge=1, le=16)
    disk_max_events: int = Field(default=250_000, ge=0, le=1_000_000)
    disk_max_events_read: int = Field(default=20_000_000, ge=0, le=100_000_000)
    disk_max_findings: int = Field(default=5_000, ge=1, le=5_000)
    disk_max_iocs: int = Field(default=20_000, ge=1, le=20_000)
    disk_max_timeline: int = Field(default=5_000, ge=1, le=5_000)
    disk_export_max_bytes: int = Field(default=64 * 1024**2, ge=1, le=64 * 1024**2)
    disk_export_max_files: int = Field(default=20, ge=1, le=20)
    # Unpromoted exports become `expired` after this; the retention worker deletes the object.
    disk_export_ttl_s: int = Field(default=7 * 86_400, ge=3_600)
    # Reverse engineering (M10): sample cap (= the capa cap, <= STATIC_MAX_BYTES), the result
    # caps (the `re.v1` contract ceilings), the RE ingest's own framing bounds, timeouts (the
    # job, Ghidra's auto-analysis, one decompiled function, the radare2 `quick` run), the
    # decompile budget, the work-dir budget (RT5) and the per-org cap.
    re_max_bytes: int = Field(default=16 * 1024**2, ge=1, le=64 * 1024**2)
    re_max_result_bytes: int = Field(default=256 * 1024**2, ge=1024, le=256 * 1024**2)
    re_max_result_decompressed_bytes: int = Field(
        default=768 * 1024**2, ge=1024, le=768 * 1024**2
    )
    analysis_re_timeout_s: int = Field(default=3_600, ge=60, le=21_600)
    re_analysis_timeout_s: int = Field(default=1_500, ge=10)
    re_decompile_timeout_s: int = Field(default=30, ge=1, le=600)
    re_quick_timeout_s: int = Field(default=300, ge=10)
    re_max_decompiled: int = Field(default=300, ge=0, le=2_000)
    re_max_work_bytes: int = Field(default=2 * 1024**3, ge=64 * 1024**2, le=16 * 1024**3)
    re_max_active_per_org: int = Field(default=1, ge=1)
    # `quick` (radare2, phase 3) is refused `422 profile_unavailable` until enabled.
    re_quick_enabled: bool = False
    re_max_functions: int = Field(default=20_000, ge=1, le=20_000)
    re_max_call_edges: int = Field(default=100_000, ge=1, le=100_000)
    re_max_imports: int = Field(default=10_000, ge=1, le=10_000)
    re_max_import_refs: int = Field(default=50_000, ge=1, le=50_000)
    re_max_strings: int = Field(default=20_000, ge=1, le=20_000)
    re_max_string_refs: int = Field(default=50_000, ge=1, le=50_000)
    re_max_findings: int = Field(default=2_000, ge=1, le=2_000)
    re_max_iocs: int = Field(default=10_000, ge=1, le=10_000)
    # Active memory + disk + reverse jobs platform-wide (M10 RT2): one heavy analysis at a
    # time on the 8-12 GB single-node host; DEPLOYMENT gives the sizing to raise it.
    analysis_heavy_max_active: int = Field(default=1, ge=1)
    # The `Q` (decompiled code) item of `explain_function` (phase 9): the one exception to the
    # 256-character field cut of the AI transforms.
    ai_max_code_chars: int = Field(default=12_000, ge=256, le=12_000)
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

    # --- Platform operations (M7) ---
    # Retention (phase 3). DATABASE_URL of the retention worker is the `cyberlab_retention`
    # role's; every other role refuses that role (and the purge MinIO user).
    retention_policy_delay_days: int = Field(default=7, ge=1, le=365)
    retention_batch_rows: int = Field(default=5_000, ge=1, le=50_000)
    retention_batch_objects: int = Field(default=200, ge=1, le=1_000)
    retention_run_slice_s: int = Field(default=120, ge=5, le=3_600)
    retention_sample_limit: int = Field(default=50, ge=0, le=500)
    retention_job_outcomes_days: int = Field(default=90, ge=7, le=3_650)
    retention_system_user_id: uuid.UUID = RETENTION_SYSTEM_USER_ID
    minio_purge_access_key: str | None = None
    minio_purge_secret_key: str | None = None
    # Correlation (phase 4, RT19: the ingest worker is a solo pool shared with result ingest).
    correlation_common_key_jobs: int = Field(default=50, ge=2, le=100_000)
    correlation_max_keys_per_job: int = Field(default=20_000, ge=1, le=200_000)
    correlation_index_budget_s: float = Field(default=10.0, gt=0, le=60)
    correlation_index_batch_jobs: int = Field(default=5, ge=1, le=50)
    # Org search (phase 4, RT13: POST body, never logged).
    search_min_query_chars: int = Field(default=2, ge=1, le=16)
    search_max_query_chars: int = Field(default=256, ge=16, le=1_024)
    search_hits_per_type: int = Field(default=20, ge=1, le=100)
    search_statement_timeout_s: int = Field(default=3, ge=1, le=30)
    search_per_user_per_min: int = Field(default=30, ge=1)
    # Runtime metrics (phase 5): a file holding the bearer token of GET /internal/metrics (the
    # api only); unset or empty = the endpoint answers 404.
    metrics_token_file: str | None = None
    # Global per-user request limit in `current_user` (phase 6; RT14: no anonymous limiter).
    rate_limit_user_per_min: int = Field(default=600, ge=1)
    # Evidence view audit dedupe window (phase 6, `core/audit_dedupe.once_per`).
    evidence_view_audit_dedupe_s: int = Field(default=900, ge=1, le=86_400)
    # MinIO's KMS key file is a secret of the minio service only (RT7): no API process holds
    # it (refused for every role); the backup scripts read only its fingerprint.
    minio_kms_secret_key_file: str | None = None

    # --- Identity and access (M11, frozen in phase 1) ---
    # Registration (phase 3): `open` (dev) or `invite_only` (the prod default when unset).
    # No bootstrap rule (RT12): the first owner comes from `identity:admin bootstrap-owner`.
    registration_mode: RegistrationMode | None = None
    invitation_ttl_days: int = Field(default=7, ge=1, le=14)
    action_token_ttl_email_verify_s: int = Field(default=24 * 3600, ge=600, le=48 * 3600)
    action_token_ttl_password_reset_s: int = Field(default=1800, ge=300, le=7200)
    # Per-flow limits (phases 3-5, 8, 9): fixed windows in `core.rate_limit`.
    rate_limit_invites_per_user_per_10min: int = Field(default=30, ge=1)
    rate_limit_invites_per_user_per_day: int = Field(default=100, ge=1)
    rate_limit_invites_per_org_per_day: int = Field(default=200, ge=1)
    rate_limit_invite_resends_per_day: int = Field(default=3, ge=1)
    rate_limit_invite_inspect_per_ip_per_10min: int = Field(default=20, ge=1)
    rate_limit_email_verify_per_user_per_hour: int = Field(default=3, ge=1)
    rate_limit_forgot_per_ip_per_10min: int = Field(default=5, ge=1)
    rate_limit_forgot_per_email_per_hour: int = Field(default=3, ge=1)
    rate_limit_sso_start_per_ip_per_10min: int = Field(default=30, ge=1)
    rate_limit_api_key_failures_per_ip_per_min: int = Field(default=20, ge=1)
    # Mail (phases 1-2). `capture` writes to the outbox row (test profile only); `disabled`
    # fails rows with `mail_disabled` (RT19).
    mail_transport: MailTransport = "disabled"
    mail_from: str | None = None
    mail_max_attempts: int = Field(default=5, ge=1, le=20)
    smtp_host: str | None = None
    smtp_port: int = Field(default=25, ge=1, le=65_535)
    smtp_username: str | None = None
    smtp_password_file: str | None = None
    smtp_tls: SmtpTls = "none"
    smtp_timeout_s: int = Field(default=20, ge=1, le=120)
    # kid -> base64 X25519 public key: the API seals link tokens for the mail worker.
    mail_seal_public_keys: dict[str, str] = {}
    mail_seal_active_kid: str | None = None
    # JSON {kid: base64 private key}: the mail worker only.
    mail_seal_private_keys_file: str | None = None
    # TOTP secrets and IdP client secrets (`cyberlab.identity.v1`): the api seals AND opens
    # them (decision 1); the private key file is the api role's only.
    identity_seal_public_keys: dict[str, str] = {}
    identity_seal_active_kid: str | None = None
    identity_seal_private_keys_file: str | None = None
    # Step-up and MFA (phases 1, 5). The age is compared in SQL against `now()` (RT21).
    step_up_max_age_s: int = Field(default=600, ge=60, le=3_600)
    mfa_challenge_ttl_s: int = Field(default=300, ge=60, le=900)
    mfa_challenge_max_attempts: int = Field(default=5, ge=1, le=10)
    mfa_user_failures_per_15min: int = Field(default=10, ge=1, le=100)
    mfa_lock_threshold: int = Field(default=100, ge=10, le=1_000)
    # SSO (phases 7-8): session cap, state lifetime, the egress proxy (no direct internet route
    # from the api; unset only with ENV=test), the DoH resolver and the dev/test escape hatches.
    sso_session_max_age_h: int = Field(default=12, ge=1, le=720)
    sso_state_ttl_s: int = Field(default=600, ge=60, le=1_800)
    identity_egress_proxy_url: str | None = None
    identity_doh_url: str | None = None
    identity_allow_private_issuer_hosts: list[str] = []
    identity_extra_ca_file: str | None = None
    identity_http_timeout_s: int = Field(default=10, ge=1, le=30)
    identity_http_max_bytes: int = Field(default=256 * 1024, ge=4_096, le=1024**2)
    # Platform API keys (phase 9).
    api_keys_max_per_org: int = Field(default=20, ge=1, le=100)
    api_key_max_days: int = Field(default=365, ge=1, le=365)

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

    @field_validator(
        "ti_seal_public_keys",
        "ai_seal_public_keys",
        "identity_seal_public_keys",
        "mail_seal_public_keys",
    )
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
        "minio_purge_access_key",
        "minio_purge_secret_key",
        "metrics_token_file",
        "minio_kms_secret_key_file",
        "mail_from",
        "smtp_host",
        "smtp_username",
        "smtp_password_file",
        "mail_seal_active_kid",
        "mail_seal_private_keys_file",
        "identity_seal_active_kid",
        "identity_seal_private_keys_file",
        "identity_egress_proxy_url",
        "identity_doh_url",
        "identity_extra_ca_file",
        "registration_mode",
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

    @field_validator(
        "ti_seal_active_kid",
        "ai_seal_active_kid",
        "report_signing_active_kid",
        "identity_seal_active_kid",
        "mail_seal_active_kid",
    )
    @classmethod
    def _active_kid(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and not KID_PATTERN.fullmatch(value):
            name = (info.field_name or "").upper()
            raise ValueError(f"{name} must match [A-Za-z0-9._-]{{1,64}}")
        return value

    @model_validator(mode="after")
    def _ops_role_guards(self) -> Self:
        """M7: the retention worker's least-privilege env, and the purge credentials and the
        retention DB role confined to it. Runs before the M4-M6 role guards."""
        role = self.process_role
        if self.minio_kms_secret_key_file is not None:
            raise ValueError("MINIO_KMS_SECRET_KEY_FILE is a secret of the minio service only")
        db_user = urlsplit(self.database_url).username
        if role == "retention":
            present = [name.upper() for name in RETENTION_FORBIDDEN if getattr(self, name)]
            if present:
                raise ValueError(f"PROCESS_ROLE=retention must not receive: {', '.join(present)}")
            if db_user != RETENTION_ROLE:
                raise ValueError(
                    f"PROCESS_ROLE=retention needs DATABASE_URL of the {RETENTION_ROLE} role"
                )
            needed = ("minio_endpoint", "minio_purge_access_key", "minio_purge_secret_key")
            missing = [name.upper() for name in needed if getattr(self, name) is None]
            if missing:
                raise ValueError(f"missing settings: {', '.join(missing)}")
            return self
        if db_user == RETENTION_ROLE:
            raise ValueError(f"PROCESS_ROLE={role} must not use the {RETENTION_ROLE} database role")
        purge = [
            name.upper()
            for name in ("minio_purge_access_key", "minio_purge_secret_key")
            if getattr(self, name) is not None
        ]
        if purge:
            raise ValueError(f"PROCESS_ROLE={role} must not receive: {', '.join(purge)}")
        if role != "api" and self.metrics_token_file is not None:
            raise ValueError("METRICS_TOKEN_FILE is only accepted with PROCESS_ROLE=api")
        return self

    @model_validator(mode="after")
    def _identity_role_guards(self) -> Self:
        """M11: the mail worker's least-privilege env (RT9), the egress proxy (which reads
        `EgressProxySettings` only), the identity and mail private keys confined to their
        roles, the mail transport rules (no test can send real mail) and the registration
        mode default (`invite_only` in prod)."""
        role = self.process_role
        if role == "egress_proxy":
            raise ValueError("PROCESS_ROLE=egress_proxy reads EgressProxySettings only")
        db_user = urlsplit(self.database_url).username
        if role == "mail":
            present = [name.upper() for name in MAIL_FORBIDDEN if getattr(self, name)]
            if present:
                raise ValueError(f"PROCESS_ROLE=mail must not receive: {', '.join(present)}")
            if db_user != MAIL_ROLE:
                raise ValueError(f"PROCESS_ROLE=mail needs DATABASE_URL of the {MAIL_ROLE} role")
            if self.mail_transport == "smtp" and self.smtp_host is None:
                raise ValueError("MAIL_TRANSPORT=smtp needs SMTP_HOST")
        else:
            if db_user == MAIL_ROLE:
                raise ValueError(f"PROCESS_ROLE={role} must not use the {MAIL_ROLE} database role")
            for name in ("mail_seal_private_keys_file", "smtp_password_file"):
                if getattr(self, name) is not None:
                    raise ValueError(f"{name.upper()} is only accepted with PROCESS_ROLE=mail")
        if role != "api" and self.identity_seal_private_keys_file is not None:
            raise ValueError(
                "IDENTITY_SEAL_PRIVATE_KEYS_FILE is only accepted with PROCESS_ROLE=api"
            )
        test_smtp = self.env == "test" and self.mail_transport == "smtp"
        if test_smtp and self.smtp_host != TEST_SMTP_HOST:
            raise ValueError(f"ENV=test delivers SMTP to {TEST_SMTP_HOST} only")
        if self.registration_mode is None:
            self.registration_mode = "invite_only" if self.env == "prod" else "open"
        return self

    @model_validator(mode="after")
    def _role_guards(self) -> Self:
        role = self.process_role
        if role in ("retention", "mail", "egress_proxy"):
            return self  # `_ops_role_guards` (M7), `_identity_role_guards` (M11)
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

    @model_validator(mode="after")
    def _memory_timeouts(self) -> Self:
        """M8: a plugin and the identify probe fit in the job, the job in 6 h (MemoryLimits)."""
        timeout = self.analysis_memory_timeout_s
        if not (
            self.analysis_memory_plugin_timeout_s < timeout
            and self.analysis_memory_identify_timeout_s < timeout
        ):
            raise ValueError(
                "ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S and ANALYSIS_MEMORY_IDENTIFY_TIMEOUT_S must be "
                "below ANALYSIS_MEMORY_TIMEOUT_S"
            )
        return self

    @model_validator(mode="after")
    def _disk_limits(self) -> Self:
        """M9: an upload fits a set, a set the media bound, an export the static analyzer
        (the derived evidence gets its normal static job), the events read the stored ones."""
        if self.disk_max_upload_bytes > self.disk_max_image_bytes:
            raise ValueError("DISK_MAX_UPLOAD_BYTES must not exceed DISK_MAX_IMAGE_BYTES")
        if self.disk_max_image_bytes > self.disk_max_media_bytes:
            raise ValueError("DISK_MAX_IMAGE_BYTES must not exceed DISK_MAX_MEDIA_BYTES")
        if self.disk_export_max_bytes > self.static_max_bytes:
            raise ValueError("DISK_EXPORT_MAX_BYTES must not exceed STATIC_MAX_BYTES")
        if self.disk_max_events_read < self.disk_max_events:
            raise ValueError("DISK_MAX_EVENTS_READ must be at least DISK_MAX_EVENTS")
        if self.disk_ingest_timeout_s >= self.analysis_disk_timeout_s:
            raise ValueError("DISK_INGEST_TIMEOUT_S must be below ANALYSIS_DISK_TIMEOUT_S")
        return self

    @model_validator(mode="after")
    def _re_limits(self) -> Self:
        """M10: the sample fits the static analyzer (a static `full` job is the input), one
        decompiled function and the radare2 run fit the analysis, the analysis the job."""
        if self.re_max_bytes > self.static_max_bytes:
            raise ValueError("RE_MAX_BYTES must not exceed STATIC_MAX_BYTES")
        if not (
            self.re_decompile_timeout_s < self.re_analysis_timeout_s < self.analysis_re_timeout_s
        ):
            raise ValueError(
                "RE_DECOMPILE_TIMEOUT_S < RE_ANALYSIS_TIMEOUT_S < ANALYSIS_RE_TIMEOUT_S is required"
            )
        if self.re_quick_timeout_s >= self.analysis_re_timeout_s:
            raise ValueError("RE_QUICK_TIMEOUT_S must be below ANALYSIS_RE_TIMEOUT_S")
        return self

    def re_max_result_lines(self) -> int:
        """The RE ingest's line bound: every per-kind cap plus header, program and trailer."""
        return 3 + sum(
            (
                self.re_max_functions,
                self.re_max_call_edges,
                self.re_max_imports,
                self.re_max_import_refs,
                self.re_max_strings,
                self.re_max_string_refs,
                self.re_max_decompiled,
                self.re_max_findings,
                self.re_max_iocs,
            )
        )

    def disk_max_result_lines(self) -> int:
        """The disk ingest's line bound (RT9): every per-kind cap plus header, trailer and one."""
        return 3 + sum(
            (
                self.disk_max_partitions,
                self.disk_max_files,
                self.disk_max_events,
                self.disk_max_findings,
                self.disk_max_iocs,
                self.disk_max_timeline,
            )
        )

    def memory_max_result_lines(self) -> int:
        """The memory ingest's line bound (RT9): every per-kind cap plus header, image and
        trailer."""
        return 3 + sum(
            (
                self.memory_max_processes,
                self.memory_max_connections,
                self.memory_max_injections,
                self.memory_max_artifacts,
                self.memory_max_findings,
                self.memory_max_iocs,
                self.memory_max_timeline,
            )
        )

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
            for name in (
                "jwt_secret",
                "minio_secret_key",
                "database_url",
                "broker_url",
                "minio_purge_secret_key",
            )
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
        self._identity_prod_guards()
        return self

    def _identity_prod_guards(self) -> None:
        """M11: real seal keys for both new domains, no capture transport, no dev escape
        hatches, invitation links on an https origin, the egress proxy, TLS to the relay."""
        if self.mail_transport == "capture":
            raise ValueError("MAIL_TRANSPORT=capture is not allowed in prod")
        unsafe = [
            name.upper()
            for name in ("identity_allow_private_issuer_hosts", "identity_extra_ca_file")
            if getattr(self, name)
        ]
        if unsafe:
            raise ValueError(f"dev-only settings not allowed in prod: {', '.join(unsafe)}")
        for domain, roles, dev_keys in (
            ("identity", ("api",), _DEV_IDENTITY_KEY_BYTES),
            ("mail", ("api", "mail"), _DEV_MAIL_KEY_BYTES),
        ):
            keys: dict[str, str] = getattr(self, f"{domain}_seal_public_keys")
            kid: str | None = getattr(self, f"{domain}_seal_active_kid")
            name = domain.upper()
            if self.process_role in roles:
                if not kid or kid not in keys:
                    raise ValueError(
                        f"{name}_SEAL_ACTIVE_KID must name a key in {name}_SEAL_PUBLIC_KEYS"
                    )
                if kid.lower().startswith("dev-"):
                    raise ValueError(
                        f"{name}_SEAL_ACTIVE_KID: dev- seal keys are not allowed in prod"
                    )
            if any(_key_bytes(v) in dev_keys for v in keys.values()):
                raise ValueError(
                    f"{name}_SEAL_PUBLIC_KEYS: the committed dev seal key is not allowed in prod"
                )
        if self.process_role == "api":
            # Invitation and reset links (https outside localhost: `_report_prod_guards`).
            if self.public_base_url is None:
                raise ValueError("PUBLIC_BASE_URL is required for the api in prod")
            if self.identity_egress_proxy_url is None:
                raise ValueError("IDENTITY_EGRESS_PROXY_URL is required for the api in prod")
        if self.process_role == "mail" and self.mail_transport == "smtp":
            if self.mail_from is None:
                raise ValueError("MAIL_FROM is required for the mail worker in prod")
            if self.smtp_tls == "none":
                raise ValueError("SMTP_TLS must be starttls or implicit in prod")

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
_DEV_IDENTITY_KEY_BYTES = frozenset(_key_bytes(k) for k in DEV_IDENTITY_SEAL_PUBLIC_KEYS)
_DEV_MAIL_KEY_BYTES = frozenset(_key_bytes(k) for k in DEV_MAIL_SEAL_PUBLIC_KEYS)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment


# Environment variables the egress proxy must never see: it holds no secret, database, Redis,
# broker or object-store access at all (M11 phase 7 refuses to start when one is present).
EGRESS_PROXY_FORBIDDEN_ENV = (
    "DATABASE_URL",
    "REDIS_URL",
    "BROKER_URL",
    "JWT_SECRET",
    "MINIO_ENDPOINT",
    "MINIO_ACCESS_KEY",
    "MINIO_SECRET_KEY",
    "TI_SEAL_PRIVATE_KEYS_FILE",
    "AI_SEAL_PRIVATE_KEYS_FILE",
    "AI_PLATFORM_KEY_FILE",
    "REPORT_SIGNING_KEYS_FILE",
    "METRICS_TOKEN_FILE",
    "IDENTITY_SEAL_PRIVATE_KEYS_FILE",
    "MAIL_SEAL_PRIVATE_KEYS_FILE",
    "SMTP_PASSWORD_FILE",
)


class EgressProxySettings(BaseSettings):
    """The egress proxy's own settings (M11, `PROCESS_ROLE=egress_proxy`; phase 7 runs it).

    `Settings` refuses that role: the proxy reads only these `EGRESS_PROXY_*` caps.
    `allow_private_hosts` is the dev/test-only allowlist of host names (e.g. `idp-mock`) the
    proxy may connect to on a private address; refused in prod. The TI settings are never read
    (RT25)."""

    model_config = SettingsConfigDict(extra="ignore", env_prefix="EGRESS_PROXY_")

    env: Literal["dev", "test", "prod"] = Field(default="dev", validation_alias="ENV")
    listen_host: str = "0.0.0.0"  # noqa: S104 - bound on the internal `idp` network only
    listen_port: int = Field(default=3128, ge=1, le=65_535)
    allowed_ports: list[int] = [443]
    allow_private_hosts: list[str] = []
    connect_timeout_s: float = Field(default=10.0, gt=0, le=30)
    idle_timeout_s: float = Field(default=30.0, gt=0, le=120)
    total_timeout_s: float = Field(default=60.0, gt=0, le=300)
    max_bytes_per_direction: int = Field(default=1024**2, ge=1_024, le=16 * 1024**2)
    max_concurrent: int = Field(default=32, ge=1, le=256)
    max_new_tunnels_per_min: int = Field(default=60, ge=1, le=10_000)

    @model_validator(mode="after")
    def _guards(self) -> Self:
        if any(not 1 <= p <= 65_535 for p in self.allowed_ports):
            raise ValueError("EGRESS_PROXY_ALLOWED_PORTS values must be 1..65535")
        if self.env == "prod":
            if self.allow_private_hosts:
                raise ValueError("EGRESS_PROXY_ALLOW_PRIVATE_HOSTS is not allowed in prod")
            if self.allowed_ports != [443]:
                raise ValueError("EGRESS_PROXY_ALLOWED_PORTS must be [443] in prod")
        return self


def forbidden_env_present(environ: Mapping[str, str]) -> list[str]:
    """The egress proxy's refusal list: secret-bearing variables present (non-empty)."""
    return [name for name in EGRESS_PROXY_FORBIDDEN_ENV if environ.get(name, "").strip()]
