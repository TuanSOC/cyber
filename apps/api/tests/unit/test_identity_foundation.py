"""M11 phase 1 building blocks without a database: the API key format, the seal domains (dev
test keys only), the mail outbox insert and templates, the CSRF exempt list (RT4), the
frozen error codes, schemas and step-up actions, the operator dispatcher."""

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from app.core.csrf import EXEMPT_PATHS
from app.core.sealbox import SealError
from app.core.sealbox_open import UnsealError, load_private_keys
from app.core.stepup import StepUpAction
from app.modules.api_keys.auth import (
    ParsedKey,
    format_key,
    is_bearer_attempt,
    new_key,
    parse_bearer,
    secret_hash,
    secret_matches,
)
from app.modules.auth.schemas import RegisterIn
from app.modules.identity import errors as identity_errors
from app.modules.identity import seal as identity_seal
from app.modules.identity.schemas import ApiKeyCreate, MfaVerifyIn, SecurityPolicyUpdate, StepUpIn
from app.modules.mail import outbox
from app.modules.mail import seal as mail_seal
from app.modules.mail.models import EmailOutbox
from app.modules.mail.templates import LINK_PATHS, SUBJECTS, TEMPLATE_PARAMS, MailTemplate
from app.modules.mail.unseal import open_link_token
from app.scripts import identity_admin

REPO = Path(__file__).resolve().parents[4]
DEV_IDENTITY = REPO / "infra" / "identity"
DEV_MAIL = REPO / "infra" / "mail"


# --- API keys -----------------------------------------------------------------------------


def test_new_keys_parse_back() -> None:
    key, parsed = new_key()
    assert key.startswith("clk_") and len(key) == 4 + 12 + 1 + 43
    assert parse_bearer(f"Bearer {key}") == parsed
    assert parse_bearer(f"bearer {key}") == parsed
    assert format_key(parsed) == key
    assert secret_matches(parsed.secret, secret_hash(parsed.secret))
    assert not secret_matches(parsed.secret + "x", secret_hash(parsed.secret))


def test_parsed_keys_never_print_the_secret() -> None:
    _, parsed = new_key()
    assert parsed.secret not in repr(parsed) and parsed.secret not in str(parsed)


@pytest.mark.parametrize(
    "value",
    [
        "Bearer",
        "Bearer ",
        "Basic clk_abcdefabcdef_" + "A" * 43,
        "Bearer clk_ABCDEFABCDEF_" + "A" * 43,  # public id is lowercase
        "Bearer clk_abcdefabcde_" + "A" * 43,  # 11 chars
        "Bearer clk_abcdefabcdef_" + "A" * 42,
        "Bearer clk_abcdefabcdef_" + "A" * 43 + " extra",
        "Bearer  clk_abcdefabcdef_" + "A" * 43,  # two spaces
        "Bearer clk_abcdefabcdef_" + "A" * 42 + "=",
        "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x",
    ],
)
def test_malformed_bearer_values_are_refused(value: str) -> None:
    assert parse_bearer(value) is None


def test_bearer_attempt_detection() -> None:
    assert is_bearer_attempt("Bearer x") and is_bearer_attempt("bearer x")
    assert not is_bearer_attempt(None) and not is_bearer_attempt("Basic x")


# --- seal domains (committed dev test keys only) ------------------------------------------


def _dev_settings(monkeypatch: pytest.MonkeyPatch, domain: str, folder: Path) -> None:
    from app.core import config

    public = json.loads((folder / "dev-seal-public.json").read_text(encoding="utf-8"))
    [(kid, key)] = public.items()
    settings = config.Settings(
        **{
            "database_url": "postgresql+asyncpg://cyberlab_app:x@postgres/cyberlab_test",
            "broker_url": "redis://api:x@redis-broker:6379/1",
            "redis_url": "redis://redis:6379/1",
            "jwt_secret": "x" * 48,
            "minio_endpoint": "minio:9000",
            "minio_access_key": "a",
            "minio_secret_key": "b",
            f"{domain}_seal_public_keys": {kid: key},
            f"{domain}_seal_active_kid": kid,
        }
    )
    monkeypatch.setattr(config, "get_settings", lambda: settings)
    monkeypatch.setattr(identity_seal, "get_settings", lambda: settings)
    monkeypatch.setattr(mail_seal, "get_settings", lambda: settings)


def test_the_dev_key_pairs_match_the_refused_constants() -> None:
    from app.core.config import DEV_IDENTITY_SEAL_PUBLIC_KEYS, DEV_MAIL_SEAL_PUBLIC_KEYS

    for folder, constant, kid in (
        (DEV_IDENTITY, DEV_IDENTITY_SEAL_PUBLIC_KEYS, "dev-id-1"),
        (DEV_MAIL, DEV_MAIL_SEAL_PUBLIC_KEYS, "dev-mail-1"),
    ):
        public = json.loads((folder / "dev-seal-public.json").read_text(encoding="utf-8"))
        assert set(public) == {kid} and set(public.values()) == constant
        private = load_private_keys(folder / "dev-seal-private.json")
        assert set(private) == {kid}


def test_totp_and_oidc_secrets_round_trip_in_their_own_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.sealbox_open import open_in

    _dev_settings(monkeypatch, "identity", DEV_IDENTITY)
    keys = load_private_keys(DEV_IDENTITY / "dev-seal-private.json")
    user, org = uuid.uuid4(), uuid.uuid4()
    totp = identity_seal.seal_totp_secret("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", user)
    domain = identity_seal.IDENTITY_DOMAIN
    assert open_in(domain, totp, user, "totp", "", keys).get_secret_value().startswith("JBSW")
    with pytest.raises(UnsealError):
        open_in(domain, totp, uuid.uuid4(), "totp", "", keys)  # another user
    oidc = identity_seal.seal_client_secret(
        SecretStr("test-client-secret-1234"), org, "https://idp.example"
    )
    assert oidc.last4 == "1234"
    assert open_in(domain, oidc, org, "oidc", "https://idp.example", keys).get_secret_value()
    with pytest.raises(UnsealError):
        open_in(domain, oidc, org, "oidc", "https://other.example", keys)  # URL-bound
    with pytest.raises(SealError):
        identity_seal.seal_client_secret("short", org, "https://idp.example")


def test_identity_sealing_refuses_without_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core import config

    settings = config.Settings(
        database_url="postgresql+asyncpg://cyberlab_app:x@postgres/cyberlab_test",
        broker_url="redis://api:x@redis-broker:6379/1",
        redis_url="redis://redis:6379/1",
        jwt_secret="x" * 48,
        minio_endpoint="minio:9000",
        minio_access_key="a",
        minio_secret_key="b",
        identity_seal_public_keys={},
        identity_seal_active_kid=None,
    )
    monkeypatch.setattr(identity_seal, "get_settings", lambda: settings)
    with pytest.raises(SealError, match="identity_seal_unconfigured"):
        identity_seal.seal_totp_secret("JBSWY3DPEHPK3PXP", uuid.uuid4())


def test_mail_link_tokens_open_only_for_their_row(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_settings(monkeypatch, "mail", DEV_MAIL)
    keys = load_private_keys(DEV_MAIL / "dev-seal-private.json")
    row = uuid.uuid4()
    token = "t" * 43
    sealed = mail_seal.seal_link_token(token, row)
    assert open_link_token(sealed, row, keys).get_secret_value() == token
    with pytest.raises(UnsealError):
        open_link_token(sealed, uuid.uuid4(), keys)
    identity_keys = load_private_keys(DEV_IDENTITY / "dev-seal-private.json")
    with pytest.raises(UnsealError):
        open_link_token(sealed, row, identity_keys)  # another domain's key pair


# --- mail outbox and templates ------------------------------------------------------------


class _Session:
    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, row: Any) -> None:
        self.added.append(row)


def test_every_template_has_params_and_a_subject() -> None:
    assert set(TEMPLATE_PARAMS) == set(MailTemplate) == set(SUBJECTS)
    assert set(LINK_PATHS) == {
        MailTemplate.INVITE,
        MailTemplate.EMAIL_VERIFY,
        MailTemplate.PASSWORD_RESET,
    }
    assert all("\n" not in s and "\r" not in s for s in SUBJECTS.values())


async def test_enqueue_validates_seals_and_inserts(monkeypatch: pytest.MonkeyPatch) -> None:
    _dev_settings(monkeypatch, "mail", DEV_MAIL)
    session = _Session()
    params = {
        "org_name": "Acme IR",
        "inviter_name": "Alice",
        "role": "analyst",
        "expires_at": "2026-11-14T12:00:00Z",
    }
    outbox_id = await outbox.enqueue(
        session,  # type: ignore[arg-type]
        template=MailTemplate.INVITE,
        to="bob@example.com",
        params=params,
        secret="t" * 43,
    )
    [row] = session.added
    assert isinstance(row, EmailOutbox) and row.id == outbox_id
    assert row.params["role"] == "analyst" and row.secret_ct and row.secret_kid == "dev-mail-1"
    assert "t" * 43 not in json.dumps(row.params)
    plain = await outbox.enqueue(
        session,  # type: ignore[arg-type]
        template=MailTemplate.MFA_ENABLED,
        to="bob@example.com",
        params={"display_name": "Bob"},
    )
    assert session.added[-1].secret_ct is None and plain != outbox_id


@pytest.mark.parametrize(
    ("template", "params", "secret"),
    [
        (MailTemplate.INVITE, {"org_name": "Acme"}, "t" * 43),  # missing params
        (MailTemplate.MFA_ENABLED, {"display_name": "Bob", "extra": 1}, None),  # extra field
        (MailTemplate.MFA_ENABLED, {"display_name": "Bob‮"}, None),  # bidi override
        (MailTemplate.MFA_ENABLED, {"display_name": "Bob"}, "t" * 43),  # unexpected secret
        (MailTemplate.EMAIL_VERIFY, {"display_name": "Bob"}, None),  # missing link token
    ],
)
async def test_enqueue_refuses_bad_combinations(
    template: MailTemplate, params: dict[str, Any], secret: str | None
) -> None:
    with pytest.raises(outbox.OutboxRefused):
        await outbox.enqueue(
            _Session(),  # type: ignore[arg-type]
            template=template,
            to="bob@example.com",
            params=params,
            secret=secret,
        )


# --- CSRF, errors, schemas, actions, scripts ----------------------------------------------


def test_the_four_public_posts_are_csrf_exempt_and_nothing_else() -> None:
    """RT4: signed-out browsers hold no `cl_csrf`; MFA verify, step-up, accept and email
    verify stay checked."""
    assert EXEMPT_PATHS == {
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/sso/start",
        "/api/v1/auth/password/forgot",
        "/api/v1/auth/password/reset",
        "/api/v1/invitations/inspect",
    }


def test_every_error_class_code_is_frozen() -> None:
    codes = {
        cls.code
        for cls in vars(identity_errors).values()
        if isinstance(cls, type)
        and issubclass(cls, identity_errors.AppError)
        and cls.__module__ == identity_errors.__name__
        and cls not in (identity_errors.BadRequest, identity_errors.Unprocessable)
    }
    assert codes == identity_errors.ERROR_CODES
    assert {"sso_not_member", "sso_link_requires_verified_email"} <= set(
        identity_errors.SSO_REDIRECT_CODES
    )


def test_step_up_actions_are_frozen() -> None:
    assert len(StepUpAction) == 15
    assert StepUpAction("tlp_downgrade") is StepUpAction.TLP_DOWNGRADE


def test_register_needs_an_org_name_or_an_invitation() -> None:
    base = {"email": "a@example.com", "password": "correct horse battery", "display_name": "A"}
    with pytest.raises(ValidationError, match="organization_name"):
        RegisterIn.model_validate(base)
    invited = RegisterIn.model_validate({**base, "invitation_token": "x" * 43})
    assert invited.organization_name is None
    with pytest.raises(ValidationError):
        RegisterIn.model_validate({**base, "invitation_token": "short"})


def test_code_inputs_take_exactly_one_method() -> None:
    assert MfaVerifyIn(code="123456").recovery_code is None
    assert MfaVerifyIn(recovery_code="ABCD-EFGH-JKMN-PQRS").code is None
    for bad in ({}, {"code": "123456", "recovery_code": "ABCD-EFGH-JKMN-PQRS"}, {"code": "12345"}):
        with pytest.raises(ValidationError):
            MfaVerifyIn.model_validate(bad)
    assert StepUpIn(password="pw").password == "pw"
    with pytest.raises(ValidationError):
        StepUpIn(password="pw", code="123456")


def test_policy_and_key_inputs() -> None:
    ok = {"require_mfa": True, "sso_enforced": False, "owners_break_glass": True}
    ok |= {"api_keys_enabled": False, "invite_domain_allowlist": ["corp.example"]}
    assert SecurityPolicyUpdate.model_validate(ok)
    with pytest.raises(ValidationError):
        SecurityPolicyUpdate.model_validate({**ok, "invite_domain_allowlist": ["Corp.Example"]})
    key = {"name": "CI", "role": "analyst", "scopes": ["evidence.read"], "expires_in_days": 30}
    assert ApiKeyCreate.model_validate(key)
    for bad in (
        {**key, "role": "admin"},
        {**key, "scopes": ["members.manage"]},
        {**key, "scopes": ["evidence.read", "evidence.read"]},
        {**key, "expires_in_days": 366},
    ):
        with pytest.raises(ValidationError):
            ApiKeyCreate.model_validate(bad)


@pytest.mark.parametrize(
    "argv",
    [
        ["bootstrap-owner", "--email", "a@example.com", "--org-name", "Acme", "--yes"],
        ["reset-mfa", "--email", "a@example.com"],
        ["approve-domain", "--org", str(uuid.uuid4()), "--domain", "corp.example"],
        ["recheck-domains"],
    ],
)
def test_the_operator_stubs_exit_2(argv: list[str]) -> None:
    assert identity_admin.main(argv) == 2


def test_parsed_key_equality_is_by_value() -> None:
    assert ParsedKey("a" * 12, "s") == ParsedKey("a" * 12, "s")
