"""Identity tables (migration 0019, M11 phase 1, FROZEN).

User-scoped (no RLS, like `refresh_tokens`): `user_sessions` (one row per refresh family, PK =
the family id), `user_mfa_factors` (the TOTP secret sealed in `cyberlab.identity.v1`),
`user_recovery_codes` (sha256 of the normalized code), `user_action_tokens` (email
verification and password reset, sha256).

Tenant (FORCE RLS): `org_security_policies` (members also read their own orgs' rows, RT13),
`org_domains`, `org_idp_configs` (the client secret sealed, URL-bound to the issuer),
`user_identities` (keyed by (config, issuer, subject), RT11).

System lookup (`app_org_id() IS NULL OR organization_id = app_org_id()`): `sso_domain_index`
(domain -> org and IdP config, read by `POST /auth/sso/start`).

Every timestamp is written as the DB `now()` (RT21). The models mirror the columns; the
migration owns the checks.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, BYTEA, CHAR, CITEXT, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk, pg_enum
from app.modules.auth.models import RevokedReason


class SessionMethod(enum.StrEnum):
    PASSWORD = "password"
    SSO = "sso"


class Amr(enum.StrEnum):
    """Authentication methods of a session (RFC 8176 names where one exists)."""

    PWD = "pwd"
    OTP = "otp"
    RECOVERY = "recovery"
    SSO = "sso"


class MfaType(enum.StrEnum):
    TOTP = "totp"


class MfaStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    LOCKED = "locked"
    DISABLED = "disabled"


class ActionPurpose(enum.StrEnum):
    EMAIL_VERIFY = "email_verify"
    PASSWORD_RESET = "password_reset"


class DomainStatus(enum.StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    REMOVED = "removed"


class DomainMethod(enum.StrEnum):
    DNS = "dns"
    OPERATOR = "operator"


class ClientAuth(enum.StrEnum):
    BASIC = "client_secret_basic"
    POST = "client_secret_post"


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)  # = refresh_tokens.family_id
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    method: Mapped[str] = mapped_column(Text)
    amr: Mapped[list[str]] = mapped_column(ARRAY(Text))
    mfa_at: Mapped[datetime | None]
    step_up_at: Mapped[datetime | None]
    sso_org_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id"))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[RevokedReason | None] = mapped_column(
        pg_enum(RevokedReason, "refresh_revoked_reason")
    )


class MfaFactor(UUIDPk, Base):
    __tablename__ = "user_mfa_factors"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    type: Mapped[str] = mapped_column(Text, server_default="totp", default=MfaType.TOTP.value)
    status: Mapped[str] = mapped_column(
        Text, server_default="pending", default=MfaStatus.PENDING.value
    )
    kid: Mapped[str] = mapped_column(String(64))
    key_version: Mapped[int] = mapped_column(Integer)
    epk: Mapped[bytes] = mapped_column(BYTEA)
    nonce: Mapped[bytes] = mapped_column(BYTEA)
    ct: Mapped[bytes] = mapped_column(BYTEA)
    last_used_step: Mapped[int] = mapped_column(BigInteger, server_default="0", default=0)
    consecutive_failures: Mapped[int] = mapped_column(server_default="0", default=0)
    recovery_batch_id: Mapped[uuid.UUID | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    confirmed_at: Mapped[datetime | None]
    disabled_at: Mapped[datetime | None]


class RecoveryCode(UUIDPk, Base):
    __tablename__ = "user_recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    batch_id: Mapped[uuid.UUID]
    code_hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    used_at: Mapped[datetime | None]


class ActionToken(UUIDPk, Base):
    __tablename__ = "user_action_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    purpose: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    email: Mapped[str] = mapped_column(CITEXT)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]


class OrgSecurityPolicy(Base):
    __tablename__ = "org_security_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id"), primary_key=True
    )
    require_mfa: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    sso_enforced: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    owners_break_glass: Mapped[bool] = mapped_column(Boolean, server_default="true", default=True)
    api_keys_enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    invite_domain_allowlist: Mapped[list[str]] = mapped_column(
        ARRAY(Text), server_default="{}", default=list
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class OrgDomain(UUIDPk, Base):
    __tablename__ = "org_domains"
    __table_args__ = (UniqueConstraint("id", "organization_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    domain: Mapped[str] = mapped_column(String(253))
    challenge: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(
        Text, server_default="pending", default=DomainStatus.PENDING.value
    )
    method: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    verified_at: Mapped[datetime | None]
    last_checked_at: Mapped[datetime | None]


class OrgIdpConfig(UUIDPk, Base):
    __tablename__ = "org_idp_configs"
    __table_args__ = (UniqueConstraint("id", "organization_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"), unique=True)
    issuer: Mapped[str] = mapped_column(String(512))
    client_id: Mapped[str] = mapped_column(String(255))
    secret_kid: Mapped[str | None] = mapped_column(String(64))
    secret_key_version: Mapped[int | None]
    secret_epk: Mapped[bytes | None] = mapped_column(BYTEA)
    secret_nonce: Mapped[bytes | None] = mapped_column(BYTEA)
    secret_ct: Mapped[bytes | None] = mapped_column(BYTEA)
    secret_last4: Mapped[str | None] = mapped_column(String(4))
    client_auth: Mapped[str] = mapped_column(
        Text, server_default="client_secret_basic", default=ClientAuth.BASIC.value
    )
    scopes: Mapped[str] = mapped_column(
        String(200), server_default="openid email profile", default="openid email profile"
    )
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    jit_enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    jit_default_role: Mapped[str] = mapped_column(Text, server_default="viewer", default="viewer")
    discovery: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    jwks: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    fetched_at: Mapped[datetime | None]
    config_version: Mapped[int] = mapped_column(server_default="1", default=1)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class SsoDomainIndex(Base):
    __tablename__ = "sso_domain_index"
    __table_args__ = (
        ForeignKeyConstraint(
            ["idp_config_id", "organization_id"],
            ["org_idp_configs.id", "org_idp_configs.organization_id"],
            name="fk_sso_domain_index_idp_config_id_org_idp_configs",
        ),
    )

    domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    idp_config_id: Mapped[uuid.UUID | None]
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class UserIdentity(UUIDPk, Base):
    __tablename__ = "user_identities"
    __table_args__ = (
        ForeignKeyConstraint(
            ["idp_config_id", "organization_id"],
            ["org_idp_configs.id", "org_idp_configs.organization_id"],
            name="fk_user_identities_idp_config_id_org_idp_configs",
            ondelete="CASCADE",
        ),
        UniqueConstraint("idp_config_id", "issuer", "subject"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    idp_config_id: Mapped[uuid.UUID]
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))
    email_at_link: Mapped[str] = mapped_column(CITEXT)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_login_at: Mapped[datetime | None]


TENANT_TABLES = (
    "org_security_policies",
    "org_domains",
    "org_idp_configs",
    "user_identities",
)
USER_TABLES = ("user_sessions", "user_mfa_factors", "user_recovery_codes", "user_action_tokens")
