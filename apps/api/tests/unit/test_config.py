import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import (
    DEV_AI_SEAL_PUBLIC_KEYS,
    DEV_REPORT_SIGNING_PUBLIC_KEYS,
    DEV_SEAL_PUBLIC_KEYS,
    RETENTION_SYSTEM_USER_ID,
    Settings,
)
from app.modules.threat_intel.catalog import CATALOG
from app.modules.threat_intel.providers.base import ProviderName

BASE = {
    "database_url": "postgresql+asyncpg://cyberlab_app:s3cret@postgres/cyberlab",
    "redis_url": "redis://redis:6379/0",
    "jwt_secret": "x" * 48,
    "minio_endpoint": "minio:9000",
    "minio_access_key": "cyberlab-api",
    "minio_secret_key": "s3cret-minio",
}
PUBLIC = base64.b64encode(bytes(range(32))).decode()
# The api-test container sets the dev TI values (mock on, dev- kid): prod cases override them.
AI_PUBLIC = base64.b64encode(bytes(range(32, 64))).decode()
REPORT_PUBLIC = base64.b64encode(bytes(range(64, 96))).decode()
# M11: test-only public keys of the identity and mail seal domains (never real keys).
IDENTITY_PUBLIC = base64.b64encode(bytes(range(96, 128))).decode()
MAIL_PUBLIC = base64.b64encode(bytes(range(128, 160))).decode()
PROD_TI: dict[str, Any] = {
    "ti_mock_enabled": False,
    "ti_seal_active_kid": "prod-1",
    "ti_seal_public_keys": {"prod-1": PUBLIC},
    # M5: the api role also needs a prod AI kid (and the test env sets the dev AI values).
    "ai_mock_enabled": False,
    "ai_seal_active_kid": "prod-ai-1",
    "ai_seal_public_keys": {"prod-ai-1": AI_PUBLIC},
    # M6: the prod api signs reports with a real Ed25519 key pair.
    "report_signing_active_kid": "prod-report-1",
    "report_signing_public_keys": {"prod-report-1": REPORT_PUBLIC},
    "report_signing_keys_file": "/run/secrets/report_signing_private",
    # M11: the prod api seals with real identity and mail keys, prints links on its public
    # origin and reaches IdPs through the egress proxy only.
    "identity_seal_active_kid": "prod-id-1",
    "identity_seal_public_keys": {"prod-id-1": IDENTITY_PUBLIC},
    "mail_seal_active_kid": "prod-mail-1",
    "mail_seal_public_keys": {"prod-mail-1": MAIL_PUBLIC},
    "public_base_url": "https://cyberlab.example",
    "identity_egress_proxy_url": "http://egress-proxy:3128",
}
# The enrich worker gets none of the role-gated settings (explicit None beats the test env).
ENRICH = {
    "process_role": "enrich",
    "database_url": BASE["database_url"],
    "broker_url": "redis://enrich:x@redis-broker:6379/0",
    "jwt_secret": None,
    "redis_url": None,
    "minio_endpoint": None,
    "minio_access_key": None,
    "minio_secret_key": None,
}


@pytest.fixture(autouse=True)
def _no_env_seal_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    # pydantic-settings deep-merges dict settings across sources: the api-test env's dev
    # public key would be merged into every `ti_seal_public_keys` passed here.
    monkeypatch.delenv("TI_SEAL_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("AI_SEAL_PUBLIC_KEYS", raising=False)
    # M6: the same for the report signing settings (only the api service sets them).
    for name in (
        "REPORT_SIGNING_PUBLIC_KEYS",
        "REPORT_SIGNING_ACTIVE_KID",
        "REPORT_SIGNING_KEYS_FILE",
        "PUBLIC_BASE_URL",
        # M11 (the api-test env sets the dev identity / mail values and the test transport).
        "IDENTITY_SEAL_PUBLIC_KEYS",
        "IDENTITY_SEAL_ACTIVE_KID",
        "IDENTITY_SEAL_PRIVATE_KEYS_FILE",
        "MAIL_SEAL_PUBLIC_KEYS",
        "MAIL_SEAL_ACTIVE_KID",
        "MAIL_TRANSPORT",
        "SMTP_HOST",
        "IDENTITY_EGRESS_PROXY_URL",
        "IDENTITY_ALLOW_PRIVATE_ISSUER_HOSTS",
        "IDENTITY_EXTRA_CA_FILE",
        "REGISTRATION_MODE",
    ):
        monkeypatch.delenv(name, raising=False)


def test_prod_requires_secure_cookies() -> None:
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        Settings(**BASE, **PROD_TI, env="prod", cookie_secure=False)


def test_prod_rejects_placeholder_secrets() -> None:
    values = {**BASE, "jwt_secret": "change-me-at-least-32-characters-long-secret"}
    with pytest.raises(ValidationError, match="jwt_secret"):
        Settings(**values, **PROD_TI, env="prod", cookie_secure=True)


def test_prod_accepts_real_values() -> None:
    assert Settings(**BASE, **PROD_TI, env="prod", cookie_secure=True).env == "prod"


def test_dev_allows_insecure_cookies() -> None:
    assert Settings(**BASE, env="dev", cookie_secure=False).cookie_secure is False


def test_jwt_secret_minimum_length() -> None:
    with pytest.raises(ValidationError):
        Settings(**{**BASE, "jwt_secret": "short"})


# --- process roles (M4 RT2) ------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("jwt_secret", "y" * 48),
        ("redis_url", "redis://redis:6379/0"),
        ("minio_endpoint", "minio:9000"),
        ("minio_access_key", "cyberlab-api"),
        ("minio_secret_key", "s3cret-minio"),
    ],
)
def test_enrich_role_refuses_api_secrets(name: str, value: str) -> None:
    with pytest.raises(ValidationError, match=name.upper()):
        Settings(**{**ENRICH, name: value})


def test_enrich_role_runs_without_api_secrets() -> None:
    settings = Settings(**ENRICH, ti_seal_private_keys_file="/run/secrets/ti_seal_private")
    assert settings.jwt_secret is None and settings.redis_url is None
    with pytest.raises(RuntimeError, match="not available to the enrich process"):
        settings.need("jwt_secret")


@pytest.mark.parametrize("role", ["api", "ingest"])
def test_only_the_enrich_role_may_load_a_private_key(role: str) -> None:
    with pytest.raises(ValidationError, match="TI_SEAL_PRIVATE_KEYS_FILE"):
        Settings(**BASE, process_role=role, ti_seal_private_keys_file="/run/secrets/x")


def test_private_key_file_refused_even_in_prod_for_the_api() -> None:
    with pytest.raises(ValidationError, match="TI_SEAL_PRIVATE_KEYS_FILE"):
        Settings(
            **BASE,
            **PROD_TI,
            env="prod",
            cookie_secure=True,
            ti_seal_private_keys_file="/run/secrets/x",
        )


@pytest.mark.parametrize("role", ["api", "ingest"])
def test_api_and_ingest_roles_still_require_their_secrets(role: str) -> None:
    with pytest.raises(ValidationError, match="JWT_SECRET"):
        Settings(**{**BASE, "jwt_secret": None}, process_role=role)
    assert Settings(**BASE, process_role=role).need("redis_url") == BASE["redis_url"]


# --- threat intel prod guards ----------------------------------------------------------


@pytest.mark.parametrize(
    "flag", ["ti_mock_enabled", "ti_misp_allow_private", "ti_misp_insecure_tls"]
)
def test_prod_refuses_dev_only_ti_flags(flag: str) -> None:
    with pytest.raises(ValidationError, match=flag.upper()):
        Settings(**BASE, **{**PROD_TI, flag: True}, env="prod", cookie_secure=True)


def test_prod_refuses_a_dev_seal_kid() -> None:
    values = {**PROD_TI, "ti_seal_active_kid": "dev-1", "ti_seal_public_keys": {"dev-1": PUBLIC}}
    with pytest.raises(ValidationError, match="dev- seal keys"):
        Settings(**BASE, **values, env="prod", cookie_secure=True)


def test_prod_refuses_an_active_kid_without_public_key() -> None:
    values = {**PROD_TI, "ti_seal_public_keys": {"other": PUBLIC}}
    with pytest.raises(ValidationError, match="TI_SEAL_ACTIVE_KID"):
        Settings(**BASE, **values, env="prod", cookie_secure=True)


def test_prod_without_ti_needs_no_seal_key() -> None:
    values = {**PROD_TI, "ti_enabled": False, "ti_seal_active_kid": None}
    assert Settings(**BASE, **values, env="prod", cookie_secure=True).ti_enabled is False


def test_dev_allows_the_dev_kid_and_the_mock() -> None:
    settings = Settings(
        **BASE,
        env="dev",
        ti_mock_enabled=True,
        ti_seal_active_kid="dev-1",
        ti_seal_public_keys={"dev-1": PUBLIC},
    )
    assert settings.ti_mock_enabled is True


def test_public_keys_must_be_x25519_keys() -> None:
    with pytest.raises(ValidationError, match="TI_SEAL_PUBLIC_KEYS"):
        Settings(**BASE, ti_seal_public_keys={"k1": "bm90LWEta2V5"})


def test_ceiling_defaults_to_the_catalog_and_can_be_overridden() -> None:
    settings = Settings(**BASE, ti_ceilings={"virustotal": {"per_minute": 500, "per_day": 30000}})
    vt = settings.ti_ceiling(ProviderName.VIRUSTOTAL)
    assert (vt.per_minute, vt.per_day) == (500, 30000)
    assert settings.ti_ceiling(ProviderName.OTX) == CATALOG[ProviderName.OTX].ceilings
    with pytest.raises(ValidationError):
        Settings(**BASE, ti_ceilings={"nope": {"per_minute": 1}})


# --- review fixes (H1, L6) ---------------------------------------------------------------

# The prod enrich-worker env exactly as `docker compose -f docker-compose.yml -f
# docker-compose.prod.yml config enrich-worker` renders it (passwords and the site's seal
# key masked); `scripts/check-enrich-env.mjs` keeps it in sync (verify:prod).
PROD_ENRICH_ENV = (
    Path(__file__).resolve().parents[1] / "fixtures/compose/enrich-worker.prod.env.json"
)


def _only_env(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> None:
    for name in list(os.environ):
        if name.lower() in Settings.model_fields:
            monkeypatch.delenv(name)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


def test_the_prod_enrich_worker_env_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    env = json.loads(PROD_ENRICH_ENV.read_text(encoding="utf-8"))
    assert "COOKIE_SECURE" not in env and "JWT_SECRET" not in env
    _only_env(monkeypatch, env)
    settings = Settings()
    assert (settings.env, settings.process_role) == ("prod", "enrich")
    assert settings.cookie_secure is False  # irrelevant to a worker: not required
    assert settings.ti_mock_enabled is False
    assert settings.ti_seal_private_keys_file == "/run/secrets/ti_seal_private"
    for name in ("jwt_secret", "redis_url", "minio_endpoint", "minio_secret_key"):
        assert getattr(settings, name) is None


def test_the_cookie_guard_still_holds_for_the_api(monkeypatch: pytest.MonkeyPatch) -> None:
    env = json.loads(PROD_ENRICH_ENV.read_text(encoding="utf-8"))
    _only_env(
        monkeypatch,
        {
            **env,
            "PROCESS_ROLE": "api",
            "JWT_SECRET": "x" * 48,
            "REDIS_URL": "redis://redis:6379/0",
            "MINIO_ENDPOINT": "minio:9000",
            "MINIO_ACCESS_KEY": "a",
            "MINIO_SECRET_KEY": "b",
            "TI_SEAL_PRIVATE_KEYS_FILE": "",
        },
    )
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        Settings()


def test_prod_ingest_needs_no_cookie_flag() -> None:
    values = {**PROD_TI, "report_signing_keys_file": None}  # M6: the api role only
    settings = Settings(**BASE, **values, env="prod", process_role="ingest", cookie_secure=False)
    assert settings.process_role == "ingest"


@pytest.mark.parametrize("kid", ["DEV-1", "Dev-prod", "dev-x"])
def test_prod_refuses_dev_kids_in_any_case(kid: str) -> None:
    values = {**PROD_TI, "ti_seal_active_kid": kid, "ti_seal_public_keys": {kid: PUBLIC}}
    with pytest.raises(ValidationError, match="dev- seal keys"):
        Settings(**BASE, **values, env="prod", cookie_secure=True)


def test_prod_refuses_the_committed_dev_public_key_under_any_kid() -> None:
    [dev_key] = DEV_SEAL_PUBLIC_KEYS
    values = {**PROD_TI, "ti_seal_public_keys": {"prod-1": dev_key}}
    with pytest.raises(ValidationError, match="committed dev seal key"):
        Settings(**BASE, **values, env="prod", cookie_secure=True)
    extra = {**PROD_TI, "ti_seal_public_keys": {"prod-1": PUBLIC, "old": dev_key}}
    with pytest.raises(ValidationError, match="committed dev seal key"):
        Settings(**BASE, **extra, env="prod", cookie_secure=True)
    # Dev keeps working with it.
    assert Settings(**BASE, ti_seal_active_kid="dev-1", ti_seal_public_keys={"dev-1": dev_key})


@pytest.mark.parametrize("kid", ["bad kid", "a/b", "x" * 65, "ü"])
def test_kids_must_match_the_seal_pattern(kid: str) -> None:
    with pytest.raises(ValidationError, match="TI_SEAL_ACTIVE_KID"):
        Settings(**BASE, ti_seal_active_kid=kid, ti_seal_public_keys={"k1": PUBLIC})
    with pytest.raises(ValidationError, match="invalid kid"):
        Settings(**BASE, ti_seal_public_keys={kid: PUBLIC})


# --- M5: the analyst role, AI settings and role-scoped prod guards (RT6) -------------------

# The api-test env sets the dev TI/AI values (mocks on): explicit values beat it.
ANALYST = {
    **ENRICH,
    "process_role": "analyst",
    "broker_url": "redis://analyst:x@b:6379/0",
    "ti_mock_enabled": False,
    "ai_mock_enabled": False,
}
COMPOSE = Path(__file__).resolve().parents[1] / "fixtures/compose"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("jwt_secret", "y" * 48),
        ("redis_url", "redis://redis:6379/0"),
        ("minio_endpoint", "minio:9000"),
        ("minio_access_key", "cyberlab-api"),
        ("minio_secret_key", "s3cret-minio"),
        ("ti_seal_private_keys_file", "/run/secrets/ti_seal_private"),
    ],
)
def test_analyst_role_refuses_api_secrets_and_ti_keys(name: str, value: str) -> None:
    with pytest.raises(ValidationError, match=name.upper()):
        Settings(**{**ANALYST, name: value})


def test_analyst_role_runs_without_api_secrets() -> None:
    settings = Settings(
        **ANALYST,
        ai_seal_private_keys_file="/run/secrets/ai_seal_private",
        ai_platform_key_file="/run/secrets/ai_platform_key",
    )
    assert settings.jwt_secret is None and settings.redis_url is None
    with pytest.raises(RuntimeError, match="not available to the analyst process"):
        settings.need("minio_secret_key")


@pytest.mark.parametrize("role", ["api", "ingest", "enrich"])
@pytest.mark.parametrize("name", ["ai_seal_private_keys_file", "ai_platform_key_file"])
def test_only_the_analyst_may_hold_ai_private_or_platform_keys(role: str, name: str) -> None:
    values = ENRICH if role == "enrich" else BASE
    with pytest.raises(ValidationError, match=name.upper()):
        Settings(**{**values, "process_role": role, name: "/run/secrets/x"})


@pytest.mark.parametrize(
    "flag",
    [
        ("ai_mock_enabled", True),
        ("ai_platform_provider", "anthropic"),
        ("ai_anthropic_base_url", "http://replay:8080"),
        ("ai_gemini_base_url", "http://replay:8080"),
    ],
)
def test_prod_refuses_dev_only_ai_settings(flag: tuple[str, object]) -> None:
    name, value = flag
    with pytest.raises(ValidationError, match=name.upper()):
        Settings(**BASE, **{**PROD_TI, name: value}, env="prod", cookie_secure=True)


def test_prod_refuses_the_platform_key_even_for_the_analyst() -> None:
    values = {**ANALYST, **_prod_ai(), "ai_platform_key_file": "/run/secrets/k"}
    with pytest.raises(ValidationError, match="AI_PLATFORM_KEY_FILE"):
        Settings(**values, env="prod")


def _prod_ai(**overrides: object) -> dict[str, object]:
    return {
        "ai_mock_enabled": False,
        "ai_seal_active_kid": "prod-ai-1",
        "ai_seal_public_keys": {"prod-ai-1": AI_PUBLIC},
        **overrides,
    }


@pytest.mark.parametrize("kid", ["dev-ai-1", "DEV-x", "Dev-prod"])
@pytest.mark.parametrize("role", ["api", "analyst"])
def test_prod_refuses_dev_ai_kids(kid: str, role: str) -> None:
    base = {**BASE, **PROD_TI} if role == "api" else ANALYST
    values = {
        **base,
        **_prod_ai(ai_seal_active_kid=kid, ai_seal_public_keys={kid: AI_PUBLIC}),
        "process_role": role,
    }
    with pytest.raises(ValidationError, match="AI_SEAL_ACTIVE_KID: dev- seal keys"):
        Settings(**values, env="prod", cookie_secure=True)


@pytest.mark.parametrize("role", ["api", "analyst"])
def test_prod_needs_the_active_ai_kid_for_the_roles_that_seal_or_open(role: str) -> None:
    base = {**BASE, **PROD_TI} if role == "api" else ANALYST
    values = {**base, **_prod_ai(ai_seal_public_keys={"other": AI_PUBLIC}), "process_role": role}
    with pytest.raises(ValidationError, match="AI_SEAL_ACTIVE_KID must name"):
        Settings(**values, env="prod", cookie_secure=True)
    # AI_ENABLED=false needs no AI key.
    values = {**base, "ai_enabled": False, "ai_mock_enabled": False, "process_role": role}
    assert Settings(**values, env="prod", cookie_secure=True).ai_enabled is False


def test_role_scoped_kid_guards() -> None:
    """RT6: the enrich env has no AI keys and the analyst env no TI keys; both start in
    prod. Ingest checks neither kid (it seals and opens nothing)."""
    ti = {k: v for k, v in PROD_TI.items() if k.startswith("ti_")}
    enrich = {**ENRICH, **ti, "ai_mock_enabled": False}
    assert Settings(**enrich, ti_seal_private_keys_file="/run/secrets/ti", env="prod")
    assert Settings(**{**ANALYST, **_prod_ai()}, env="prod").process_role == "analyst"
    ingest = {**BASE, "ti_mock_enabled": False, "ai_mock_enabled": False, "process_role": "ingest"}
    assert Settings(**ingest, env="prod").process_role == "ingest"


def test_prod_refuses_the_committed_dev_ai_public_key_in_any_role() -> None:
    [dev_key] = DEV_AI_SEAL_PUBLIC_KEYS
    for role, base in (("api", {**BASE, **PROD_TI}), ("analyst", ANALYST), ("ingest", BASE)):
        values = {
            **base,
            **_prod_ai(ai_seal_public_keys={"prod-ai-1": AI_PUBLIC, "old": dev_key}),
            "ti_mock_enabled": False,
            "process_role": role,
        }
        with pytest.raises(ValidationError, match="AI_SEAL_PUBLIC_KEYS: the committed dev"):
            Settings(**values, env="prod", cookie_secure=True)


def test_prod_refuses_change_me_broker_passwords() -> None:
    values = {**ANALYST, **_prod_ai(), "broker_url": "redis://analyst:change-me-broker-analyst@b/0"}
    with pytest.raises(ValidationError, match="broker_url"):
        Settings(**values, env="prod")


def test_ai_public_keys_and_kid_are_validated() -> None:
    with pytest.raises(ValidationError, match="AI_SEAL_PUBLIC_KEYS"):
        Settings(**BASE, ai_seal_public_keys={"k1": "bm90LWEta2V5"})
    with pytest.raises(ValidationError, match="AI_SEAL_ACTIVE_KID"):
        Settings(**BASE, ai_seal_active_kid="bad kid")


def test_ai_defaults_and_ceilings() -> None:
    settings = Settings(**BASE)
    assert (settings.ai_max_output_tokens, settings.ai_call_timeout_s) == (16_000, 300)
    assert (settings.ai_call_idle_timeout_s, settings.ai_max_calls_per_run) == (60, 3)
    assert (settings.ai_run_deadline_s, settings.ai_incident_deadline_s) == (1200, 3600)
    assert settings.ai_ceilings.daily_token_budget == 20_000_000
    assert settings.ai_ceilings.run_token_cap == 200_000
    assert settings.ai_ceilings.incident_token_cap == 2_000_000
    assert settings.ai_platform_daily_tokens == 200_000
    custom = Settings(**BASE, ai_ceilings={"daily_token_budget": 5, "per_minute": {"gemini": 9}})
    assert custom.ai_ceilings.daily_token_budget == 5
    with pytest.raises(ValidationError):
        Settings(**BASE, ai_ceilings={"per_minute": {"openai": 1}})
    with pytest.raises(ValidationError):
        Settings(**BASE, ai_ceilings={"surprise": 1})


@pytest.mark.parametrize(
    ("fixture", "role"),
    [
        ("api.prod.env.json", "api"),
        ("ingest-worker.prod.env.json", "ingest"),
        ("enrich-worker.prod.env.json", "enrich"),
        ("analyst-worker.prod.env.json", "analyst"),
    ],
)
def test_the_rendered_prod_env_of_every_role_is_accepted(
    fixture: str, role: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RT6: each prod env exactly as compose renders it (secrets masked) starts."""
    env = json.loads((COMPOSE / fixture).read_text(encoding="utf-8"))
    _only_env(monkeypatch, env)
    settings = Settings()
    assert (settings.env, settings.process_role) == ("prod", role)
    assert settings.ai_mock_enabled is False and settings.ai_platform_key_file is None
    if role in ("enrich", "analyst"):
        for name in ("jwt_secret", "redis_url", "minio_endpoint", "minio_secret_key"):
            assert getattr(settings, name) is None
    if role == "analyst":
        assert settings.ti_seal_private_keys_file is None and not settings.ti_seal_public_keys
        assert settings.ai_seal_private_keys_file == "/run/secrets/ai_seal_private"
        assert settings.broker_url.startswith("redis://analyst:")
    if role == "enrich":
        assert settings.ai_seal_private_keys_file is None and not settings.ai_seal_public_keys
    # M6: only the api holds the report signing private key file.
    if role == "api":
        assert settings.report_signing_keys_file == "/run/secrets/report_signing_private"
    else:
        assert settings.report_signing_keys_file is None


# --- report signing and reports (M6) ---------------------------------------------------


@pytest.mark.parametrize("role", ["ingest", "enrich", "analyst"])
def test_only_the_api_role_may_hold_the_signing_key_file(role: str) -> None:
    base = {"ingest": {**BASE, "process_role": "ingest"}, "enrich": ENRICH, "analyst": ANALYST}
    with pytest.raises(ValidationError, match="REPORT_SIGNING_KEYS_FILE"):
        Settings(**base[role], report_signing_keys_file="/run/secrets/report_signing_private")


def test_the_api_may_hold_the_signing_key_file_in_dev() -> None:
    settings = Settings(**BASE, report_signing_keys_file="/run/secrets/report_signing_private")
    assert settings.report_signing_keys_file == "/run/secrets/report_signing_private"


@pytest.mark.parametrize("kid", ["dev-report-1", "DEV-x"])
def test_prod_refuses_dev_signing_kids(kid: str) -> None:
    values = {
        **PROD_TI,
        "report_signing_active_kid": kid,
        "report_signing_public_keys": {kid: REPORT_PUBLIC},
    }
    with pytest.raises(ValidationError, match="dev- signing keys"):
        Settings(**BASE, **values, env="prod", cookie_secure=True)


def test_prod_refuses_the_committed_dev_signing_public_key() -> None:
    [dev_key] = DEV_REPORT_SIGNING_PUBLIC_KEYS
    values = {
        **PROD_TI,
        "report_signing_public_keys": {"prod-report-1": REPORT_PUBLIC, "old": dev_key},
    }
    with pytest.raises(ValidationError, match="committed dev signing key"):
        Settings(**BASE, **values, env="prod", cookie_secure=True)


def test_prod_api_needs_an_active_signing_kid_and_the_key_file() -> None:
    with pytest.raises(ValidationError, match="REPORT_SIGNING_ACTIVE_KID"):
        Settings(
            **BASE, **{**PROD_TI, "report_signing_active_kid": None}, env="prod", cookie_secure=True
        )
    with pytest.raises(ValidationError, match="REPORT_SIGNING_KEYS_FILE is required"):
        Settings(
            **BASE, **{**PROD_TI, "report_signing_keys_file": None}, env="prod", cookie_secure=True
        )


def test_signing_public_keys_are_validated() -> None:
    with pytest.raises(ValidationError, match="Ed25519"):
        Settings(**BASE, report_signing_public_keys={"k1": "c2hvcnQ="})
    with pytest.raises(ValidationError, match="invalid kid"):
        Settings(**BASE, report_signing_public_keys={"bad kid": REPORT_PUBLIC})


@pytest.mark.parametrize(
    "url",
    ["ftp://x.example", "https://user:pw@x.example", "https://x.example/path", "https://x?q=1"],
)
def test_public_base_url_must_be_an_origin(url: str) -> None:
    with pytest.raises(ValidationError, match="PUBLIC_BASE_URL"):
        Settings(**BASE, public_base_url=url)


def test_prod_public_base_url_needs_https_outside_localhost() -> None:
    with pytest.raises(ValidationError, match="https in prod"):
        Settings(
            **BASE, **{**PROD_TI, "public_base_url": "http://cyberlab.example"}, env="prod",
            cookie_secure=True,
        )  # fmt: skip
    for ok in ("https://cyberlab.example/", "http://localhost:8080"):
        values = {**PROD_TI, "public_base_url": ok}
        settings = Settings(**BASE, **values, env="prod", cookie_secure=True)
        assert settings.public_base_url == ok.rstrip("/")


def test_report_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REPORTS_BUCKET", raising=False)  # api-test sets `reports-test`
    settings = Settings(**BASE)
    assert settings.reports_bucket == "reports"
    assert settings.report_max_snapshot_bytes == 8 * 1024**2
    assert settings.report_max_artifact_bytes == 32 * 1024**2
    assert settings.report_max_pages == 300
    assert (settings.report_render_deadline_s, settings.report_render_timeout_s) == (600, 120)
    assert (settings.report_active_renders_per_org, settings.report_active_renders_global) == (
        2,
        4,
    )
    assert settings.timeline_export_max_rows == 50_000


# --- M7: the retention worker's least-privilege env (the settings matrix) --------------------

RETENTION_DB = "postgresql+asyncpg://cyberlab_retention:s3cret@postgres/cyberlab"
# Explicit None beats the api-test env for every role-gated setting.
RETENTION: dict[str, Any] = {
    "process_role": "retention",
    "database_url": RETENTION_DB,
    "broker_url": "redis://retention:x@redis-broker:6379/0",
    "jwt_secret": None,
    "redis_url": None,
    "minio_endpoint": "minio:9000",
    "minio_access_key": None,
    "minio_secret_key": None,
    "minio_purge_access_key": "cyberlab-purge",
    "minio_purge_secret_key": "s3cret-purge",
}
PURGE = {"minio_purge_access_key": "cyberlab-purge", "minio_purge_secret_key": "s3cret-purge"}


def _role_env(role: str) -> dict[str, Any]:
    if role in ("enrich", "analyst"):
        return {**ENRICH, "process_role": role}
    return {**BASE, "process_role": role}


def test_retention_role_runs_with_its_least_privilege_env() -> None:
    settings = Settings(**RETENTION)
    assert settings.process_role == "retention"
    assert settings.minio_purge_access_key == "cyberlab-purge"
    with pytest.raises(RuntimeError, match="not available to the retention process"):
        settings.need("jwt_secret")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("jwt_secret", "y" * 48),
        ("redis_url", "redis://redis:6379/0"),
        ("minio_access_key", "cyberlab-api"),
        ("minio_secret_key", "s3cret-minio"),
        ("ti_seal_private_keys_file", "/run/secrets/ti_seal_private"),
        ("ai_seal_private_keys_file", "/run/secrets/ai_seal_private"),
        ("ai_platform_key_file", "/run/secrets/ai_platform_key"),
        ("report_signing_keys_file", "/run/secrets/report_signing_private"),
        ("metrics_token_file", "/run/secrets/metrics_token"),
    ],
)
def test_retention_role_refuses_every_other_secret(name: str, value: str) -> None:
    with pytest.raises(ValidationError, match=f"must not receive: {name.upper()}"):
        Settings(**{**RETENTION, name: value})


def test_retention_role_needs_the_retention_db_role() -> None:
    with pytest.raises(ValidationError, match="needs DATABASE_URL of the cyberlab_retention"):
        Settings(**{**RETENTION, "database_url": BASE["database_url"]})


@pytest.mark.parametrize(
    "name", ["minio_endpoint", "minio_purge_access_key", "minio_purge_secret_key"]
)
def test_retention_role_needs_minio_and_the_purge_user(name: str) -> None:
    with pytest.raises(ValidationError, match=f"missing settings: {name.upper()}"):
        Settings(**{**RETENTION, name: None})


@pytest.mark.parametrize("role", ["api", "ingest", "enrich", "analyst"])
def test_other_roles_refuse_the_purge_user(role: str) -> None:
    with pytest.raises(ValidationError, match="must not receive: MINIO_PURGE_ACCESS_KEY"):
        Settings(**_role_env(role), **PURGE)


@pytest.mark.parametrize("role", ["api", "ingest", "enrich", "analyst"])
def test_other_roles_refuse_the_retention_db_role(role: str) -> None:
    with pytest.raises(ValidationError, match="must not use the cyberlab_retention"):
        Settings(**{**_role_env(role), "database_url": RETENTION_DB})


@pytest.mark.parametrize("role", ["ingest", "enrich", "analyst"])
def test_only_the_api_holds_the_metrics_token(role: str) -> None:
    with pytest.raises(ValidationError, match="METRICS_TOKEN_FILE"):
        Settings(**_role_env(role), metrics_token_file="/run/secrets/metrics_token")
    assert Settings(**BASE, metrics_token_file="/run/secrets/metrics_token").metrics_token_file


@pytest.mark.parametrize("role", ["api", "ingest", "enrich", "analyst", "retention"])
def test_no_role_holds_the_minio_kms_key(role: str) -> None:
    env = RETENTION if role == "retention" else _role_env(role)
    with pytest.raises(ValidationError, match="MINIO_KMS_SECRET_KEY_FILE"):
        Settings(**env, minio_kms_secret_key_file="/run/secrets/minio_kms_key")


def test_blank_purge_and_token_settings_are_unset() -> None:
    settings = Settings(**BASE, minio_purge_access_key=" ", metrics_token_file="")
    assert settings.minio_purge_access_key is None and settings.metrics_token_file is None


def test_prod_retention_refuses_placeholder_secrets() -> None:
    with pytest.raises(ValidationError, match="minio_purge_secret_key"):
        Settings(**{**RETENTION, "minio_purge_secret_key": "change-me-minio-purge"}, env="prod")
    with pytest.raises(ValidationError, match="database_url"):
        Settings(
            **{
                **RETENTION,
                "database_url": "postgresql+asyncpg://cyberlab_retention:change-me-retention@p/c",
            },
            env="prod",
        )
    # The api-test env turns the TI / AI mocks on: a prod worker has them off.
    prod = Settings(**RETENTION, env="prod", ti_mock_enabled=False, ai_mock_enabled=False)
    assert prod.env == "prod"


def test_m7_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("RATE_LIMIT_USER_PER_MIN", "RETENTION_POLICY_DELAY_DAYS"):
        monkeypatch.delenv(name, raising=False)  # api-test raises the limit
    settings = Settings(**BASE)
    assert settings.retention_policy_delay_days == 7
    assert (settings.retention_batch_rows, settings.retention_batch_objects) == (5_000, 200)
    assert settings.retention_system_user_id == RETENTION_SYSTEM_USER_ID
    assert (settings.correlation_common_key_jobs, settings.correlation_index_batch_jobs) == (50, 5)
    assert settings.correlation_index_budget_s == 10
    assert (settings.search_min_query_chars, settings.search_max_query_chars) == (2, 256)
    assert (settings.search_hits_per_type, settings.search_statement_timeout_s) == (20, 3)
    assert settings.rate_limit_user_per_min == 600
    assert settings.metrics_token_file is None
