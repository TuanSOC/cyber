"""M11 settings and process roles (phase 1): the mail worker's least-privilege env and DB role
(RT9), the egress proxy's secret-free env, the identity / mail private keys confined to their
roles, no real mail from tests, the prod refusals of the dev seal keys, `capture` and missing
links, and the registration-mode default. Test values only (never real keys)."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import (
    DEV_IDENTITY_SEAL_PUBLIC_KEYS,
    DEV_MAIL_SEAL_PUBLIC_KEYS,
    EGRESS_PROXY_FORBIDDEN_ENV,
    MAIL_FORBIDDEN,
    EgressProxySettings,
    Settings,
    forbidden_env_present,
)
from tests.unit.test_config import BASE, PROD_TI

MAIL_DB = "postgresql+asyncpg://cyberlab_mail:s3cret@postgres/cyberlab"
MAIL: dict[str, Any] = {
    "process_role": "mail",
    "database_url": MAIL_DB,
    "broker_url": "redis://mail:x@redis-broker:6379/0",
    "jwt_secret": None,
    "redis_url": None,
    "minio_endpoint": None,
    "minio_access_key": None,
    "minio_secret_key": None,
    "mail_transport": "disabled",
}
_ENV = (
    "IDENTITY_SEAL_PUBLIC_KEYS",
    "IDENTITY_SEAL_ACTIVE_KID",
    "IDENTITY_SEAL_PRIVATE_KEYS_FILE",
    "MAIL_SEAL_PUBLIC_KEYS",
    "MAIL_SEAL_ACTIVE_KID",
    "MAIL_SEAL_PRIVATE_KEYS_FILE",
    "MAIL_TRANSPORT",
    "SMTP_HOST",
    "SMTP_PASSWORD_FILE",
    "REGISTRATION_MODE",
    "IDENTITY_EGRESS_PROXY_URL",
    "IDENTITY_ALLOW_PRIVATE_ISSUER_HOSTS",
    "IDENTITY_EXTRA_CA_FILE",
    "PUBLIC_BASE_URL",
    "TI_SEAL_PUBLIC_KEYS",
    "AI_SEAL_PUBLIC_KEYS",
    "REPORT_SIGNING_PUBLIC_KEYS",
    "REPORT_SIGNING_ACTIVE_KID",
    "REPORT_SIGNING_KEYS_FILE",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)


def test_the_mail_worker_starts_with_its_own_role_only() -> None:
    settings = Settings(**MAIL, mail_seal_private_keys_file="/run/secrets/mail_seal_private")
    assert settings.process_role == "mail"


@pytest.mark.parametrize("name", MAIL_FORBIDDEN)
def test_the_mail_worker_refuses_every_other_secret(name: str) -> None:
    value: object = "redis://redis:6379/0" if name == "redis_url" else "x" * 48
    # METRICS_TOKEN_FILE is refused earlier by the M7 guard (api role only).
    with pytest.raises(ValidationError, match="must not receive|only accepted"):
        Settings(**{**MAIL, name: value})


def test_the_mail_worker_needs_the_mail_db_role() -> None:
    with pytest.raises(ValidationError, match="cyberlab_mail role"):
        Settings(**{**MAIL, "database_url": BASE["database_url"]})


@pytest.mark.parametrize("role", ["api", "ingest", "enrich", "analyst"])
def test_no_other_role_may_use_the_mail_db_role(role: str) -> None:
    values: dict[str, Any] = {**BASE, "process_role": role, "database_url": MAIL_DB}
    if role in ("enrich", "analyst"):
        values.update(jwt_secret=None, redis_url=None, minio_endpoint=None)
        values.update(minio_access_key=None, minio_secret_key=None)
    with pytest.raises(ValidationError, match="must not use the cyberlab_mail"):
        Settings(**values)


@pytest.mark.parametrize("name", ["mail_seal_private_keys_file", "smtp_password_file"])
def test_mail_secrets_belong_to_the_mail_worker(name: str) -> None:
    with pytest.raises(ValidationError, match="PROCESS_ROLE=mail"):
        Settings(**BASE, **{name: "/run/secrets/x"})


def test_the_identity_private_key_is_the_api_roles_only() -> None:
    assert Settings(**BASE, identity_seal_private_keys_file="/run/secrets/id").process_role
    with pytest.raises(ValidationError, match="IDENTITY_SEAL_PRIVATE_KEYS_FILE"):
        Settings(**{**BASE, "process_role": "ingest"}, identity_seal_private_keys_file="/x")
    with pytest.raises(ValidationError, match="must not receive"):
        Settings(**MAIL, identity_seal_private_keys_file="/run/secrets/id")


def test_the_egress_proxy_never_reads_the_main_settings() -> None:
    with pytest.raises(ValidationError, match="EgressProxySettings"):
        Settings(**{**BASE, "process_role": "egress_proxy"})


def test_egress_proxy_settings_and_its_refusal_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENV", "prod")
    settings = EgressProxySettings()
    assert settings.allowed_ports == [443] and settings.allow_private_hosts == []
    with pytest.raises(ValidationError, match="ALLOW_PRIVATE_HOSTS"):
        EgressProxySettings(allow_private_hosts=["idp-mock"])
    with pytest.raises(ValidationError, match="ALLOWED_PORTS"):
        EgressProxySettings(allowed_ports=[443, 8443])
    monkeypatch.setenv("ENV", "test")
    assert EgressProxySettings(allow_private_hosts=["idp-mock"]).allow_private_hosts
    assert forbidden_env_present({"DATABASE_URL": "x", "PATH": "/bin", "JWT_SECRET": " "}) == [
        "DATABASE_URL"
    ]
    assert set(EGRESS_PROXY_FORBIDDEN_ENV) >= {"BROKER_URL", "IDENTITY_SEAL_PRIVATE_KEYS_FILE"}


def test_tests_can_only_send_smtp_to_the_test_mailpit() -> None:
    with pytest.raises(ValidationError, match="mailpit-test"):
        Settings(**BASE, env="test", mail_transport="smtp", smtp_host="smtp.example.com")
    assert Settings(**BASE, env="test", mail_transport="smtp", smtp_host="mailpit-test")
    assert Settings(**BASE, env="test", mail_transport="capture").mail_transport == "capture"


def test_the_mail_worker_needs_an_smtp_host_for_smtp() -> None:
    with pytest.raises(ValidationError, match="SMTP_HOST"):
        Settings(**{**MAIL, "mail_transport": "smtp"}, env="dev")


def test_registration_mode_defaults_by_environment() -> None:
    assert Settings(**BASE, env="dev").registration_mode == "open"
    prod = Settings(**BASE, **PROD_TI, env="prod", cookie_secure=True)
    assert prod.registration_mode == "invite_only"
    open_prod = Settings(
        **BASE, **PROD_TI, registration_mode="open", env="prod", cookie_secure=True
    )
    assert open_prod.registration_mode == "open"


def test_prod_refuses_capture_and_the_dev_escape_hatches() -> None:
    for extra in (
        {"mail_transport": "capture"},
        {"identity_allow_private_issuer_hosts": ["idp-mock"]},
        {"identity_extra_ca_file": "/run/secrets/idp-mock-ca.pem"},
    ):
        with pytest.raises(ValidationError):
            Settings(**BASE, **PROD_TI, **extra, env="prod", cookie_secure=True)


@pytest.mark.parametrize(
    ("domain", "dev_keys", "dev_kid"),
    [
        ("identity", DEV_IDENTITY_SEAL_PUBLIC_KEYS, "dev-id-1"),
        ("mail", DEV_MAIL_SEAL_PUBLIC_KEYS, "dev-mail-1"),
    ],
)
def test_prod_refuses_the_committed_dev_seal_keys(
    domain: str, dev_keys: frozenset[str], dev_kid: str
) -> None:
    [dev_public] = dev_keys
    name = domain.upper()
    committed = {**PROD_TI, f"{domain}_seal_public_keys": {"prod-x": dev_public}}
    committed[f"{domain}_seal_active_kid"] = "prod-x"
    with pytest.raises(ValidationError, match=f"{name}_SEAL_PUBLIC_KEYS: the committed dev"):
        Settings(**BASE, **committed, env="prod", cookie_secure=True)
    [real_public] = PROD_TI[f"{domain}_seal_public_keys"].values()
    dev_kid_values = {
        **PROD_TI,
        f"{domain}_seal_active_kid": dev_kid,
        f"{domain}_seal_public_keys": {dev_kid: real_public},
    }
    with pytest.raises(ValidationError, match=f"{name}_SEAL_ACTIVE_KID: dev- seal keys"):
        Settings(**BASE, **dev_kid_values, env="prod", cookie_secure=True)
    missing = {**PROD_TI, f"{domain}_seal_active_kid": None}
    with pytest.raises(ValidationError, match=f"{name}_SEAL_ACTIVE_KID must name"):
        Settings(**BASE, **missing, env="prod", cookie_secure=True)


@pytest.mark.parametrize("name", ["public_base_url", "identity_egress_proxy_url"])
def test_the_prod_api_needs_its_link_origin_and_the_egress_proxy(name: str) -> None:
    with pytest.raises(ValidationError, match=name.upper()):
        Settings(**BASE, **{**PROD_TI, name: None}, env="prod", cookie_secure=True)


def test_the_prod_mail_worker_needs_a_sender_and_tls() -> None:
    prod_mail = {
        **MAIL,
        "mail_transport": "smtp",
        "smtp_host": "smtp-relay.example",
        "mail_seal_active_kid": "prod-mail-1",
        "mail_seal_public_keys": PROD_TI["mail_seal_public_keys"],
        "ti_mock_enabled": False,
        "ai_mock_enabled": False,
    }
    with pytest.raises(ValidationError, match="MAIL_FROM"):
        Settings(**prod_mail, smtp_tls="starttls", env="prod")
    with pytest.raises(ValidationError, match="SMTP_TLS"):
        Settings(**prod_mail, mail_from="CyberLab <noreply@example.com>", env="prod")
    ok = Settings(
        **prod_mail, mail_from="CyberLab <noreply@example.com>", smtp_tls="starttls", env="prod"
    )
    assert ok.process_role == "mail"
