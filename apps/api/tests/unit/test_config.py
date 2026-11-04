import base64
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import Settings
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
PROD_TI: dict[str, Any] = {
    "ti_mock_enabled": False,
    "ti_seal_active_kid": "prod-1",
    "ti_seal_public_keys": {"prod-1": PUBLIC},
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
