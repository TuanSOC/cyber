"""identity and access: user kinds and verification, sessions, MFA factors and recovery codes,
action tokens, the mail outbox, invitations, org security policies, SSO (domains, IdP configs,
identities) and platform API keys

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-07 18:00:00

Frozen in M11 phase 1 (later schema needs go into the next number, assigned by the parent). The
M4-M10 conventions:
- `auth_event_type` gains the M11 events and `refresh_revoked_reason` gains `password_reset`,
  `user_revoked`, `mfa_change`, `operator` (RT18), both in one autocommit block (0006's rule,
  M7 RT12): nothing in this migration uses them; the downgrade cannot drop them.
- `users` gains `kind` (`human` / `service` / `system`; the M7 retention user is backfilled
  `system`), `email_verified_at` and `password_changed_at`. Existing users stay unverified
  (they verify once before TOTP or an SSO link, RT8). The app role already has UPDATE on users.
- User-scoped tables (no RLS, like `refresh_tokens`): `user_sessions` (one row per refresh
  family; backfilled from the live families, RT7), `user_mfa_factors`, `user_recovery_codes`,
  `user_action_tokens`.
- `email_outbox` is a system table (no RLS): its org column is `context_org_id` (audit context
  only, never tenant data). The app role S/I; the mail worker's role `cyberlab_mail` SELECT and
  UPDATE of the status, scheduling, sealed and `captured` columns only (RT9); the migration
  refuses to run while that role is missing (`infra/postgres/bootstrap.sh`).
- Tenant tables (FORCE RLS on `organization_id = app_org_id()`, composite same-org FKs):
  `org_invitations`, `org_domains`, `org_idp_configs`, `user_identities`, `api_keys`;
  `org_security_policies` also lets a member read its own orgs' rows (the `orgs_select`
  pattern, RT13).
- System lookups with the `analysis_job_index` policy (`app_org_id() IS NULL OR
  organization_id = app_org_id()`): `invitation_index`, `sso_domain_index`.
- Grants: the app role SELECT / INSERT plus per-column UPDATE, never DELETE.
- Every timestamp defaults to the DB `now()`; the API compares against DB time (RT21).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import SchemaItem

from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
MAIL_ROLE = "cyberlab_mail"
# app.core.config.RETENTION_SYSTEM_USER_ID (fixed: 0014 seeded it).
SYSTEM_USER_ID = "00000000-0000-4000-8000-00000000a7e0"

AUTH_EVENTS_M11 = (
    "mfa_challenge",
    "mfa_success",
    "mfa_failure",
    "mfa_locked",
    "mfa_enabled",
    "mfa_disabled",
    "mfa_reset_by_operator",
    "recovery_code_used",
    "recovery_codes_regenerated",
    "step_up_success",
    "step_up_failure",
    "password_reset_requested",
    "password_reset",
    "password_changed",
    "email_verified",
    "session_revoked",
    "sso_login",
    "sso_failure",
    "sso_linked",
    "invitation_accepted",
    "api_key_auth_failure",
)
REVOKED_REASONS_M11 = ("password_reset", "user_revoked", "mfa_change", "operator")
USER_KINDS = ("human", "service", "system")
SESSION_METHODS = ("password", "sso")
AMR_VALUES = ("pwd", "otp", "recovery", "sso")
MFA_TYPES = ("totp",)
MFA_STATUSES = ("pending", "active", "locked", "disabled")
ACTION_PURPOSES = ("email_verify", "password_reset")
MAIL_TEMPLATES = (
    "invite",
    "email_verify",
    "password_reset",
    "password_changed",
    "mfa_enabled",
    "mfa_disabled",
    "mfa_locked",
    "recovery_code_used",
    "mfa_reset_by_operator",
    "sso_account_linked",
    "api_key_created",
    "new_owner_security_change",
)
MAIL_STATUSES = ("pending", "sending", "sent", "failed")
MAIL_ERRORS = (
    "smtp_transient",
    "smtp_permanent",
    "render_refused",
    "unseal_failed",
    "mail_disabled",
    "max_attempts",
)
DOMAIN_STATUSES = ("pending", "verified", "failed", "removed")
DOMAIN_METHODS = ("dns", "operator")
CLIENT_AUTH = ("client_secret_basic", "client_secret_post")
JIT_ROLES = ("viewer", "analyst")
API_KEY_ROLES = ("analyst", "viewer")
API_KEY_SCOPES = (
    "org.read",
    "investigation.read",
    "investigation.write",
    "evidence.read",
    "evidence.write",
)
TENANT_TABLES = (
    "org_invitations",
    "org_domains",
    "org_idp_configs",
    "user_identities",
    "api_keys",
)
SYSTEM_LOOKUPS = ("invitation_index", "sso_domain_index")
USER_TABLES = ("user_sessions", "user_mfa_factors", "user_recovery_codes", "user_action_tokens")
# Per-column UPDATE grants of the app role (everything else is insert-only).
APP_UPDATE_COLUMNS = {
    "user_sessions": "last_seen_at, amr, mfa_at, step_up_at, revoked_at, revoked_reason",
    "user_mfa_factors": (
        "status, last_used_step, consecutive_failures, confirmed_at, disabled_at, "
        "recovery_batch_id"
    ),
    "user_recovery_codes": "used_at",
    "user_action_tokens": "consumed_at",
    "org_invitations": (
        "accepted_at, accepted_by, revoked_at, revoked_by, token_hash, expires_at, "
        "resend_count, last_sent_at"
    ),
    "invitation_index": "token_hash, expires_at",
    "org_security_policies": (
        "require_mfa, sso_enforced, owners_break_glass, api_keys_enabled, "
        "invite_domain_allowlist, updated_by, updated_at"
    ),
    "org_domains": "status, verified_at, method, last_checked_at",
    "sso_domain_index": "organization_id, idp_config_id, enabled, updated_at",
    "org_idp_configs": (
        "issuer, client_id, secret_kid, secret_key_version, secret_epk, secret_nonce, "
        "secret_ct, secret_last4, client_auth, scopes, enabled, jit_enabled, jit_default_role, "
        "discovery, jwks, fetched_at, config_version, updated_by, updated_at"
    ),
    "user_identities": "last_login_at",
    "api_keys": "last_used_at, last_used_ip, revoked_at, revoked_by",
}
MAIL_UPDATE_COLUMNS = (
    "status, attempts, next_attempt_at, claimed_at, sent_at, last_error, secret_kid, "
    "secret_key_version, secret_epk, secret_nonce, secret_ct, captured"
)
# The sealed columns (`core/sealbox.SealedKey`): all set or all NULL.
SEALED = ("kid", "key_version", "epk", "nonce", "ct")
DOMAIN_PATTERN = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$"

ROLE_GUARD = f"""DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{MAIL_ROLE}') THEN
    RAISE EXCEPTION 'role {MAIL_ROLE} does not exist: run db-bootstrap first '
      '(docker compose run --rm db-bootstrap; infra/postgres/bootstrap.sh)';
  END IF;
END $$"""

# RT7: one session row per live refresh family (a token neither revoked nor expired), so
# refresh re-issues `sid` / `amr` tokens after the deploy without a forced logout.
SESSION_BACKFILL = """INSERT INTO user_sessions
  (id, user_id, method, amr, ip, user_agent, created_at, last_seen_at, expires_at)
SELECT family_id, user_id, 'password', ARRAY['pwd']::text[],
       (array_agg(ip ORDER BY created_at DESC))[1],
       (array_agg(user_agent ORDER BY created_at DESC))[1],
       min(created_at), max(created_at), min(created_at) + interval '30 days'
FROM refresh_tokens
GROUP BY family_id, user_id
HAVING bool_or(revoked_at IS NULL AND expires_at > now())
ON CONFLICT (id) DO NOTHING"""

# RT13: a member reads the policy rows of every org it belongs to (the MFA-disable rule),
# writes only the current org's row. Self-contained like `orgs_select` (no recursion).
POLICY_STATEMENTS = (
    """CREATE POLICY security_policies_select ON org_security_policies FOR SELECT
  USING (
    organization_id = app_org_id()
    OR organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = app_user_id()
    )
  )""",
    """CREATE POLICY security_policies_insert ON org_security_policies FOR INSERT
  WITH CHECK (organization_id = app_org_id())""",
    """CREATE POLICY security_policies_update ON org_security_policies FOR UPDATE
  USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id())""",
)


def _ts(name: str, *, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=None if nullable else sa.text("now()"),
        nullable=nullable,
    )


def _uuid_pk() -> sa.Column[object]:
    return sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False)


def _ck(table: str, name: str, sql: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(sql, name=op.f(f"ck_{table}_{name}"))


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _array_subset(column: str, values: Sequence[str]) -> str:
    return f"{column} <@ ARRAY[{', '.join(repr(v) for v in values)}]::text[]"


def _text_max(table: str, column: str, limit: int) -> sa.CheckConstraint:
    return _ck(table, f"{column}_length", f"{column} IS NULL OR octet_length({column}) <= {limit}")


def _hex64(table: str, column: str) -> sa.CheckConstraint:
    return _ck(table, column, f"{column} ~ '^[0-9a-f]{{64}}$'")


def _jsonb(table: str, column: str, kind: str, limit: int) -> sa.CheckConstraint:
    return _ck(
        table,
        column,
        f"{column} IS NULL OR (jsonb_typeof({column}) = '{kind}' "
        f"AND octet_length({column}::text) <= {limit})",
    )


def _user_fk(table: str, column: str, *, cascade: bool = False) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column],
        ["users.id"],
        name=op.f(f"fk_{table}_{column}_users"),
        ondelete="CASCADE" if cascade else None,
    )


def _org_fk(table: str, column: str = "organization_id") -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column], ["organizations.id"], name=op.f(f"fk_{table}_{column}_organizations")
    )


def _sealed(prefix: str) -> list[SchemaItem]:
    return [
        sa.Column(f"{prefix}kid", sa.String(length=64), nullable=True),
        sa.Column(f"{prefix}key_version", sa.Integer(), nullable=True),
        sa.Column(f"{prefix}epk", postgresql.BYTEA(), nullable=True),
        sa.Column(f"{prefix}nonce", postgresql.BYTEA(), nullable=True),
        sa.Column(f"{prefix}ct", postgresql.BYTEA(), nullable=True),
    ]


def _sealed_checks(table: str, prefix: str, *, required: bool) -> list[sa.CheckConstraint]:
    cols = [f"{prefix}{c}" for c in SEALED]
    all_set = " AND ".join(f"{c} IS NOT NULL" for c in cols)
    all_null = " AND ".join(f"{c} IS NULL" for c in cols)
    shape = (
        f"{prefix}kid ~ '^[A-Za-z0-9._-]{{1,64}}$' AND {prefix}key_version >= 1 "
        f"AND octet_length({prefix}epk) = 32 AND octet_length({prefix}nonce) = 12 "
        f"AND octet_length({prefix}ct) BETWEEN 17 AND 1024"
    )
    presence = f"({all_set})" if required else f"({all_null}) OR ({all_set})"
    return [
        _ck(table, f"{prefix}sealed_presence", presence),
        _ck(table, f"{prefix}sealed_shape", f"{prefix}kid IS NULL OR ({shape})"),
    ]


def upgrade() -> None:
    op.execute(ROLE_GUARD)
    # Enum values first, committed on their own (0006's rule, M7 RT12); nothing below uses them.
    with op.get_context().autocommit_block():
        for value in AUTH_EVENTS_M11:
            op.execute(f"ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS '{value}'")
        for value in REVOKED_REASONS_M11:
            op.execute(f"ALTER TYPE refresh_revoked_reason ADD VALUE IF NOT EXISTS '{value}'")
    op.execute(ROLE_GUARD)  # the autocommit block ended the guarded transaction
    _alter_users()
    _create_user_tables()
    _create_outbox()
    _create_invitations()
    _create_policies_and_sso()
    _create_api_keys()
    _create_security()
    op.execute(SESSION_BACKFILL)


def _alter_users() -> None:
    t = "users"
    op.add_column(t, sa.Column("kind", sa.Text(), server_default="human", nullable=False))
    op.create_check_constraint(op.f("ck_users_kind"), t, _in("kind", USER_KINDS))
    op.add_column(t, sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(t, sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
    # The M7 retention user (inactive, unusable hash) is the one system account.
    op.execute(f"UPDATE users SET kind = 'system' WHERE id = '{SYSTEM_USER_ID}'")


def _create_user_tables() -> None:
    t = "user_sessions"
    op.create_table(
        t,
        sa.Column("id", sa.Uuid(), nullable=False),  # = the refresh family id
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("amr", postgresql.ARRAY(sa.Text()), nullable=False),
        _ts("mfa_at", nullable=True),
        _ts("step_up_at", nullable=True),
        sa.Column("sso_org_id", sa.Uuid(), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        _ts("created_at"),
        _ts("last_seen_at"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _ts("revoked_at", nullable=True),
        sa.Column(
            "revoked_reason",
            postgresql.ENUM(name="refresh_revoked_reason", create_type=False),
            nullable=True,
        ),
        _ck(t, "method", _in("method", SESSION_METHODS)),
        _ck(t, "amr", f"cardinality(amr) BETWEEN 1 AND 8 AND {_array_subset('amr', AMR_VALUES)}"),
        _ck(t, "sso_iff_method", "(sso_org_id IS NOT NULL) = (method = 'sso')"),
        _ck(t, "revoked_pair", "(revoked_at IS NULL) = (revoked_reason IS NULL)"),
        _ck(t, "expiry", "expires_at > created_at"),
        _user_fk(t, "user_id"),
        _org_fk(t, "sso_org_id"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_user_id_revoked_at"), t, ["user_id", "revoked_at"])

    t = "user_mfa_factors"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.Text(), server_default="totp", nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        *_sealed(""),
        # The last accepted TOTP step: `UPDATE ... WHERE last_used_step < :s` is the replay guard.
        sa.Column("last_used_step", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("recovery_batch_id", sa.Uuid(), nullable=True),
        _ts("created_at"),
        _ts("confirmed_at", nullable=True),
        _ts("disabled_at", nullable=True),
        _ck(t, "type", _in("type", MFA_TYPES)),
        _ck(t, "status", _in("status", MFA_STATUSES)),
        *_sealed_checks(t, "", required=True),
        _ck(t, "counters", "last_used_step >= 0 AND consecutive_failures >= 0"),
        _ck(
            t,
            "confirmed",
            "status IN ('pending', 'disabled') OR confirmed_at IS NOT NULL",
        ),
        _ck(t, "disabled_pair", "(status = 'disabled') = (disabled_at IS NOT NULL)"),
        _user_fk(t, "user_id"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
    )
    op.create_index(
        "ux_user_mfa_factors_user_id_type_live",
        t,
        ["user_id", "type"],
        unique=True,
        postgresql_where=sa.text("status <> 'disabled'"),
    )

    t = "user_recovery_codes"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.CHAR(length=64), nullable=False),
        _ts("created_at"),
        _ts("used_at", nullable=True),
        _hex64(t, "code_hash"),
        _user_fk(t, "user_id"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("code_hash", name=op.f(f"uq_{t}_code_hash")),
    )
    op.create_index(op.f(f"ix_{t}_user_id_batch_id"), t, ["user_id", "batch_id"])

    t = "user_action_tokens"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("email", postgresql.CITEXT(), nullable=False),
        _ts("created_at"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _ts("consumed_at", nullable=True),
        _ck(t, "purpose", _in("purpose", ACTION_PURPOSES)),
        _hex64(t, "token_hash"),
        _text_max(t, "email", 320),
        _ck(
            t,
            "expiry",
            "expires_at > created_at AND expires_at <= created_at + interval '2 days'",
        ),
        _user_fk(t, "user_id"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("token_hash", name=op.f(f"uq_{t}_token_hash")),
    )
    # One live token per (user, purpose): issuing a new one consumes the old one first.
    op.create_index(
        "ux_user_action_tokens_user_id_purpose_live",
        t,
        ["user_id", "purpose"],
        unique=True,
        postgresql_where=sa.text("consumed_at IS NULL"),
    )


def _create_outbox() -> None:
    t = "email_outbox"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("to_email", postgresql.CITEXT(), nullable=False),
        sa.Column(
            "params",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        *_sealed("secret_"),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        _ts("next_attempt_at"),
        _ts("claimed_at", nullable=True),
        _ts("sent_at", nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("context_org_id", sa.Uuid(), nullable=True),
        sa.Column("captured", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        _ts("created_at"),
        _ck(t, "template", _in("template", MAIL_TEMPLATES)),
        _ck(t, "status", _in("status", MAIL_STATUSES)),
        _ck(t, "last_error", f"last_error IS NULL OR {_in('last_error', MAIL_ERRORS)}"),
        _ck(t, "attempts", "attempts BETWEEN 0 AND 100"),
        _text_max(t, "to_email", 320),
        _jsonb(t, "params", "object", 4096),
        _jsonb(t, "captured", "object", 16384),
        *_sealed_checks(t, "secret_", required=False),
        _ck(t, "sent", "(status = 'sent') = (sent_at IS NOT NULL)"),
        _ck(t, "claimed", "status <> 'sending' OR claimed_at IS NOT NULL"),
        _user_fk(t, "user_id"),
        _org_fk(t, "context_org_id"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_status_next_attempt_at"), t, ["status", "next_attempt_at"])


def _create_invitations() -> None:
    t = "org_invitations"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("email", postgresql.CITEXT(), nullable=False),
        sa.Column("role", postgresql.ENUM(name="member_role", create_type=False), nullable=False),
        sa.Column("token_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("invited_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _ts("accepted_at", nullable=True),
        sa.Column("accepted_by", sa.Uuid(), nullable=True),
        _ts("revoked_at", nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("resend_count", sa.Integer(), server_default="0", nullable=False),
        _ts("last_sent_at"),
        _hex64(t, "token_hash"),
        _text_max(t, "email", 320),
        _ck(t, "expiry", "expires_at > created_at"),
        _ck(t, "one_outcome", "accepted_at IS NULL OR revoked_at IS NULL"),
        _ck(t, "accepted_pair", "(accepted_at IS NULL) = (accepted_by IS NULL)"),
        _ck(t, "resend_count", "resend_count BETWEEN 0 AND 1000"),
        _org_fk(t),
        _user_fk(t, "invited_by"),
        _user_fk(t, "accepted_by"),
        _user_fk(t, "revoked_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("token_hash", name=op.f(f"uq_{t}_token_hash")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    # One pending invitation per (org, email): re-inviting revokes the previous one first.
    op.create_index(
        "ux_org_invitations_organization_id_email_pending",
        t,
        ["organization_id", "email"],
        unique=True,
        postgresql_where=sa.text("accepted_at IS NULL AND revoked_at IS NULL"),
    )

    t = "invitation_index"
    op.create_table(
        t,
        sa.Column("invitation_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _hex64(t, "token_hash"),
        sa.ForeignKeyConstraint(
            ["invitation_id", "organization_id"],
            ["org_invitations.id", "org_invitations.organization_id"],
            name=op.f(f"fk_{t}_invitation_id_org_invitations"),
            ondelete="CASCADE",
        ),
        _org_fk(t),
        sa.PrimaryKeyConstraint("invitation_id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("token_hash", name=op.f(f"uq_{t}_token_hash")),
    )


def _create_policies_and_sso() -> None:
    t = "org_security_policies"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("require_mfa", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("sso_enforced", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("owners_break_glass", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("api_keys_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "invite_domain_allowlist",
            postgresql.ARRAY(sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        _ts("updated_at"),
        _ck(
            t,
            "invite_domain_allowlist",
            "cardinality(invite_domain_allowlist) <= 20 "
            "AND octet_length(array_to_string(invite_domain_allowlist, ',')) <= 5200",
        ),
        _org_fk(t),
        _user_fk(t, "updated_by"),
        sa.PrimaryKeyConstraint("organization_id", name=op.f(f"pk_{t}")),
    )

    t = "org_domains"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("challenge", sa.String(length=64), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("method", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        _ts("verified_at", nullable=True),
        _ts("last_checked_at", nullable=True),
        _ck(t, "domain", f"domain ~ '{DOMAIN_PATTERN}' AND octet_length(domain) <= 253"),
        _ck(t, "challenge", "challenge ~ '^[A-Za-z0-9_-]{43}$'"),
        _ck(t, "status", _in("status", DOMAIN_STATUSES)),
        _ck(t, "method", f"method IS NULL OR {_in('method', DOMAIN_METHODS)}"),
        _ck(
            t,
            "verified",
            "status <> 'verified' OR (verified_at IS NOT NULL AND method IS NOT NULL)",
        ),
        _org_fk(t),
        _user_fk(t, "created_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    # A verified domain belongs to one org platform-wide (constraints ignore RLS):
    # `409 domain_claimed`.
    op.create_index(
        "ux_org_domains_domain_verified",
        t,
        ["domain"],
        unique=True,
        postgresql_where=sa.text("status = 'verified'"),
    )
    op.create_index(
        "ux_org_domains_organization_id_domain_live",
        t,
        ["organization_id", "domain"],
        unique=True,
        postgresql_where=sa.text("status <> 'removed'"),
    )

    t = "org_idp_configs"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        *_sealed("secret_"),
        sa.Column("secret_last4", sa.String(length=4), nullable=True),
        sa.Column(
            "client_auth", sa.Text(), server_default="client_secret_basic", nullable=False
        ),
        sa.Column(
            "scopes", sa.String(length=200), server_default="openid email profile", nullable=False
        ),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("jit_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("jit_default_role", sa.Text(), server_default="viewer", nullable=False),
        sa.Column("discovery", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("jwks", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        _ts("fetched_at", nullable=True),
        sa.Column("config_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        _ts("updated_at"),
        _ck(t, "issuer", "issuer ~ '^https://' AND octet_length(issuer) <= 512"),
        _ck(t, "client_id", "octet_length(client_id) BETWEEN 1 AND 255"),
        *_sealed_checks(t, "secret_", required=False),
        _ck(t, "secret_last4", "(secret_kid IS NULL) = (secret_last4 IS NULL)"),
        _ck(t, "client_auth", _in("client_auth", CLIENT_AUTH)),
        _ck(t, "scopes", "scopes ~ '^openid( [A-Za-z0-9_.:-]{1,64}){0,15}$'"),
        _ck(t, "jit_default_role", _in("jit_default_role", JIT_ROLES)),
        _jsonb(t, "discovery", "object", 65536),
        _jsonb(t, "jwks", "object", 65536),
        _ck(t, "config_version", "config_version >= 1"),
        _org_fk(t),
        _user_fk(t, "created_by"),
        _user_fk(t, "updated_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("organization_id", name=op.f(f"uq_{t}_organization_id")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )

    t = "sso_domain_index"
    op.create_table(
        t,
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("idp_config_id", sa.Uuid(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        _ts("updated_at"),
        _ck(t, "domain", f"domain ~ '{DOMAIN_PATTERN}'"),
        _ck(t, "enabled_needs_idp", "NOT enabled OR idp_config_id IS NOT NULL"),
        _org_fk(t),
        sa.ForeignKeyConstraint(
            ["idp_config_id", "organization_id"],
            ["org_idp_configs.id", "org_idp_configs.organization_id"],
            name=op.f(f"fk_{t}_idp_config_id_org_idp_configs"),
        ),
        sa.PrimaryKeyConstraint("domain", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "user_identities"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("idp_config_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("email_at_link", postgresql.CITEXT(), nullable=False),
        _ts("created_at"),
        _ts("last_login_at", nullable=True),
        _ck(t, "subject", "octet_length(subject) BETWEEN 1 AND 255"),
        _text_max(t, "email_at_link", 320),
        _org_fk(t),
        _user_fk(t, "user_id"),
        sa.ForeignKeyConstraint(
            ["idp_config_id", "organization_id"],
            ["org_idp_configs.id", "org_idp_configs.organization_id"],
            name=op.f(f"fk_{t}_idp_config_id_org_idp_configs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        # RT11: keyed by the issuer too, so an issuer change never maps colliding `sub` values.
        sa.UniqueConstraint(
            "idp_config_id", "issuer", "subject", name=op.f(f"uq_{t}_idp_config_id_issuer_subject")
        ),
    )
    op.create_index(op.f(f"ix_{t}_user_id"), t, ["user_id"])
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])


def _create_api_keys() -> None:
    t = "api_keys"
    op.create_table(
        t,
        _uuid_pk(),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("service_user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("public_id", sa.CHAR(length=12), nullable=False),
        sa.Column("secret_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _ts("last_used_at", nullable=True),
        sa.Column("last_used_ip", postgresql.INET(), nullable=True),
        _ts("revoked_at", nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        _ck(t, "name", "octet_length(name) BETWEEN 1 AND 400"),
        _ck(t, "public_id", "public_id ~ '^[a-z0-9]{12}$'"),
        _hex64(t, "secret_hash"),
        _ck(t, "role", _in("role", API_KEY_ROLES)),
        _ck(
            t,
            "scopes",
            f"cardinality(scopes) BETWEEN 1 AND 5 AND {_array_subset('scopes', API_KEY_SCOPES)}",
        ),
        _ck(
            t,
            "expiry",
            "expires_at > created_at AND expires_at <= created_at + interval '366 days'",
        ),
        _ck(t, "revoked_pair", "(revoked_at IS NULL) = (revoked_by IS NULL)"),
        _org_fk(t),
        _user_fk(t, "service_user_id"),
        _user_fk(t, "created_by"),
        _user_fk(t, "revoked_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("public_id", name=op.f(f"uq_{t}_public_id")),
        sa.UniqueConstraint("service_user_id", name=op.f(f"uq_{t}_service_user_id")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(
        op.f(f"ix_{t}_organization_id_revoked_at"), t, ["organization_id", "revoked_at"]
    )


def _create_security() -> None:
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_org_id()) "
            "WITH CHECK (organization_id = app_org_id())"
        )
    op.execute("ALTER TABLE org_security_policies ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE org_security_policies FORCE ROW LEVEL SECURITY")
    for statement in POLICY_STATEMENTS:
        op.execute(statement)
    for table in SYSTEM_LOOKUPS:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY lookup_scope ON {table} "
            "USING (app_org_id() IS NULL OR organization_id = app_org_id()) "
            "WITH CHECK (app_org_id() IS NULL OR organization_id = app_org_id())"
        )
    for table in (*USER_TABLES, *TENANT_TABLES, *SYSTEM_LOOKUPS, "org_security_policies"):
        op.execute(f"GRANT SELECT, INSERT ON {table} TO {APP_ROLE}")
    for table, columns in APP_UPDATE_COLUMNS.items():
        op.execute(f"GRANT UPDATE ({columns}) ON {table} TO {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON email_outbox TO {APP_ROLE}")
    # RT9: the mail worker reads and updates the outbox only; nothing else at all.
    op.execute(f"GRANT USAGE ON SCHEMA public TO {MAIL_ROLE}")
    op.execute(f"GRANT SELECT ON email_outbox TO {MAIL_ROLE}")
    op.execute(f"GRANT UPDATE ({MAIL_UPDATE_COLUMNS}) ON email_outbox TO {MAIL_ROLE}")


def downgrade() -> None:
    # Postgres cannot drop enum values: the M11 `auth_event_type` and `refresh_revoked_reason`
    # values stay (unused by 0018 code; existing rows may carry them), as in 0014 (RT12).
    for table in (
        "api_keys",
        "user_identities",
        "sso_domain_index",
        "org_idp_configs",
        "org_domains",
        "org_security_policies",
        "invitation_index",
        "org_invitations",
        "email_outbox",
        "user_action_tokens",
        "user_recovery_codes",
        "user_mfa_factors",
        "user_sessions",
    ):
        op.drop_table(table)  # indexes, policies and grants go with the table
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {MAIL_ROLE}")
    op.drop_column("users", "password_changed_at")
    op.drop_column("users", "email_verified_at")
    op.drop_constraint(op.f("ck_users_kind"), "users", type_="check")
    op.drop_column("users", "kind")
