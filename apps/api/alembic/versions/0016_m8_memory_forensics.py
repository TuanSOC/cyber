"""memory forensics: the `memory` analyzer, memory job profiles and the OS hint, the memory
result tables and the per-evidence memory sensitivity

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-07 03:00:00

Frozen in M8 phase 1 (later schema needs go into 0017, assigned by the parent; 0015 is the M7
review's hold-sync revision). The M4-M7
conventions:
- `analyzer` gains `memory` in an autocommit block (0006's rule: one alembic run is one
  transaction, which may not use a value it added); nothing here parses the literal as an
  `analyzer` (comparisons go through `analyzer::text`). The downgrade cannot drop it.
- `analysis_jobs.profile`: static `full` / `av`, memory `triage` / `full`, NULL for pcap (the
  0006 checks are replaced); `os_hint` (`auto` / `windows` / `linux`) is NOT NULL iff the
  analyzer is memory, and write-once like the profile (job guard).
- `job_outcomes.kind` gains `memory` (the trigger already copies `analyzer::text`).
- Every tenant table has FORCE RLS on `organization_id = app_org_id()` and composite
  (id, organization_id) FKs to its parent. The four bulk tables carry `id`,
  `organization_id` and `job_id` (retention counts by them, citations reference `id`; RT23).
- Grants: the app role SELECT / INSERT (and UPDATE of the release columns of
  `memory_sensitivity`), never DELETE; `cyberlab_retention` SELECT on every memory table and
  DELETE on the four bulk tables only (never `memory_images` / `memory_sensitivity`).
- `memory_sensitivity`: `restricted -> released` once (admin release, phase 8), no other
  UPDATE, no DELETE (trigger, also for the owner).
- Text and jsonb sizes are named checks (`octet_length`); artifact attributes are scalar
  values only (`memory_attributes_scalar`).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import SchemaItem

from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
RETENTION_ROLE = "cyberlab_retention"
BULK_TABLES = ("memory_processes", "memory_connections", "memory_injections", "memory_artifacts")
TENANT_TABLES = ("memory_images", *BULK_TABLES, "memory_sensitivity")
ARTIFACT_TYPES = (
    "module",
    "service",
    "hive",
    "userassist",
    "ldr_unlinked",
    "bash",
    "open_file",
    "syscall_hook",
    "hidden_module",
)
OLD_KINDS = "('pcap', 'static', 'ti', 'ai', 'report')"
NEW_KINDS = "('pcap', 'static', 'memory', 'ti', 'ai', 'report')"

ROLE_GUARD = f"""DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{RETENTION_ROLE}') THEN
    RAISE EXCEPTION 'role {RETENTION_ROLE} does not exist: run db-bootstrap first '
      '(docker compose run --rm db-bootstrap; infra/postgres/bootstrap.sh)';
  END IF;
END $$"""

_GUARD = """CREATE OR REPLACE FUNCTION analysis_job_terminal() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'analysis job % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'queued' AND NEW.status IN ('running', 'succeeded', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed'))
  ) THEN
    RAISE EXCEPTION 'illegal analysis job transition % -> %', OLD.status, NEW.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.evidence_id, NEW.analyzer, NEW.requested_by,
      NEW.auto, NEW.ingest_token_sha256, NEW.created_at{new_extra})
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.evidence_id, OLD.analyzer, OLD.requested_by,
      OLD.auto, OLD.ingest_token_sha256, OLD.created_at{old_extra}) THEN
    RAISE EXCEPTION 'analysis job identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""
# The profile and the OS hint are part of a job's identity (what was asked for).
GUARD_M8 = _GUARD.format(
    new_extra=", NEW.profile, NEW.os_hint", old_extra=", OLD.profile, OLD.os_hint"
)
GUARD_0006 = _GUARD.format(new_extra=", NEW.profile", old_extra=", OLD.profile")

PROFILE_VALID_M8 = "profile IS NULL OR profile IN ('full', 'av', 'triage')"
PROFILE_FOR_ANALYZER = (
    "CASE WHEN analyzer::text = 'static' THEN profile IS NOT NULL AND profile IN ('full', 'av') "
    "WHEN analyzer::text = 'memory' THEN profile IS NOT NULL AND profile IN ('triage', 'full') "
    "ELSE profile IS NULL END"
)

# Artifact attributes: an object of at most 32 scalar values (the contract's rule).
ATTRIBUTES_FUNCTION = """CREATE FUNCTION memory_attributes_scalar(value jsonb) RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
  -- CASE fixes the evaluation order: jsonb_each raises on a non-object.
  SELECT CASE WHEN jsonb_typeof(value) IS DISTINCT FROM 'object' THEN false
    ELSE (SELECT count(*) FROM jsonb_each(value)) <= 32
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_each(value) AS e
       WHERE jsonb_typeof(e.value) NOT IN ('string', 'number', 'boolean', 'null')
     )
  END
$$"""

SENSITIVITY_GUARD = """CREATE FUNCTION memory_sensitivity_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  -- Not SECURITY DEFINER: applies to every role, the owner included.
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'memory sensitivity rows are never deleted'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.state <> 'restricted' OR NEW.state <> 'released' THEN
    RAISE EXCEPTION 'memory sensitivity of evidence % may only be released once', OLD.evidence_id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.evidence_id, NEW.organization_id, NEW.defaulted_by, NEW.defaulted_at)
     IS DISTINCT FROM
     (OLD.evidence_id, OLD.organization_id, OLD.defaulted_by, OLD.defaulted_at) THEN
    RAISE EXCEPTION 'memory sensitivity identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

APP_GRANTS = {table: "SELECT, INSERT" for table in TENANT_TABLES}
APP_UPDATE_COLUMNS = {"memory_sensitivity": "state, released_by, released_at, release_reason"}


def _ts(name: str, *, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=None if nullable else sa.text("now()"),
        nullable=nullable,
    )


def _org_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["organization_id"],
        ["organizations.id"],
        name=op.f(f"fk_{table}_organization_id_organizations"),
    )


def _user_fk(table: str, column: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint([column], ["users.id"], name=op.f(f"fk_{table}_{column}_users"))


def _job_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["job_id", "organization_id"],
        ["analysis_jobs.id", "analysis_jobs.organization_id"],
        name=op.f(f"fk_{table}_job_id_organization_id_analysis_jobs"),
        ondelete="CASCADE",
    )


def _ck(table: str, name: str, sql: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(sql, name=op.f(f"ck_{table}_{name}"))


def _text_max(table: str, column: str, limit: int) -> sa.CheckConstraint:
    return _ck(table, f"{column}_length", f"{column} IS NULL OR octet_length({column}) <= {limit}")


def _bulk(table: str) -> list[SchemaItem]:
    """`id`, `organization_id`, `job_id` (RT23), the job FK and the PK."""
    return [
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        _job_fk(table),
        _org_fk(table),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")),
    ]


def _address(name: str, *, nullable: bool = True) -> sa.Column[object]:
    # Unsigned 64-bit addresses do not fit a bigint (the static tables' rule).
    return sa.Column(name, sa.Numeric(20, 0), nullable=nullable)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def upgrade() -> None:
    op.execute(ROLE_GUARD)
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE analyzer ADD VALUE IF NOT EXISTS 'memory'")
    op.execute(ROLE_GUARD)  # the autocommit block ended the guarded transaction
    _alter_existing()
    _create_tables()
    _create_security()


def _alter_existing() -> None:
    t = "analysis_jobs"
    op.drop_constraint(op.f("ck_analysis_jobs_profile_iff_static"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_valid"), t, type_="check")
    op.create_check_constraint(op.f("ck_analysis_jobs_profile_valid"), t, PROFILE_VALID_M8)
    op.create_check_constraint(
        op.f("ck_analysis_jobs_profile_matches_analyzer"), t, PROFILE_FOR_ANALYZER
    )
    op.add_column(t, sa.Column("os_hint", sa.String(16), nullable=True))
    op.create_check_constraint(
        op.f("ck_analysis_jobs_os_hint_valid"),
        t,
        "os_hint IS NULL OR os_hint IN ('auto', 'windows', 'linux')",
    )
    op.create_check_constraint(
        op.f("ck_analysis_jobs_os_hint_iff_memory"),
        t,
        "(os_hint IS NOT NULL) = (analyzer::text = 'memory')",
    )
    op.execute(GUARD_M8)

    op.drop_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", type_="check")
    op.create_check_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", f"kind IN {NEW_KINDS}")


def _create_tables() -> None:
    op.execute(ATTRIBUTES_FUNCTION)

    t = "memory_images"
    op.create_table(
        t,
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("os", sa.String(16), nullable=False),
        sa.Column("arch", sa.String(8), nullable=True),
        sa.Column("layer", sa.String(64), nullable=True),
        sa.Column("engine", sa.String(16), nullable=False),
        sa.Column("nt_build", sa.String(64), nullable=True),
        sa.Column("kernel_banner", sa.Text(), nullable=True),
        sa.Column("pdb_name", sa.String(32), nullable=True),
        sa.Column("pdb_guid", sa.String(32), nullable=True),
        sa.Column("pdb_age", sa.Integer(), nullable=True),
        _ts("system_time", nullable=True),
        sa.Column("symbols_status", sa.String(16), nullable=False),
        sa.Column("isf_sha256", sa.String(64), nullable=True),
        sa.Column("volatility_version", sa.String(64), nullable=True),
        sa.Column(
            "plugins", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False
        ),
        sa.Column(
            "counts", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        _ts("created_at"),
        _ck(t, "os", "os IN ('windows', 'linux')"),
        _ck(t, "arch", "arch IS NULL OR arch IN ('x86', 'x64')"),
        _ck(t, "engine", "engine IN ('volatility3', 'replay')"),
        _ck(t, "symbols_status", "symbols_status IN ('resolved', 'missing')"),
        _ck(t, "isf_sha256", "isf_sha256 IS NULL OR isf_sha256 ~ '^[0-9a-f]{64}$'"),
        _ck(t, "pdb_guid", "pdb_guid IS NULL OR pdb_guid ~ '^[0-9A-F]{32}$'"),
        _ck(t, "pdb_age", "pdb_age IS NULL OR pdb_age BETWEEN 0 AND 65535"),
        _ck(
            t,
            "pdb_triple",
            "(pdb_name IS NULL) = (pdb_guid IS NULL) AND (pdb_guid IS NULL) = (pdb_age IS NULL)",
        ),
        _text_max(t, "kernel_banner", 512),
        _ck(
            t,
            "plugins",
            "jsonb_typeof(plugins) = 'array' AND octet_length(plugins::text) <= 16384",
        ),
        _ck(t, "counts", "jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 4096"),
        _job_fk(t),
        _org_fk(t),
        sa.PrimaryKeyConstraint("job_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "memory_processes"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("pid", sa.BigInteger(), nullable=False),
        sa.Column("ppid", sa.BigInteger(), nullable=True),
        sa.Column("name", sa.String(64), nullable=False),
        _address("offset"),
        _ts("create_time", nullable=True),
        _ts("exit_time", nullable=True),
        sa.Column("threads", sa.BigInteger(), nullable=True),
        sa.Column("handles", sa.BigInteger(), nullable=True),
        sa.Column("session_id", sa.BigInteger(), nullable=True),
        sa.Column("wow64", sa.Boolean(), nullable=True),
        # Bitmask of the listings that saw it: 1 pslist, 2 psscan, 4 pstree.
        sa.Column("sources", sa.SmallInteger(), nullable=False),
        sa.Column("cmdline", sa.Text(), nullable=True),
        sa.Column("image_path", sa.Text(), nullable=True),
        _ck(t, "pid_range", "pid BETWEEN 0 AND 4294967295"),
        _ck(t, "ppid_range", "ppid IS NULL OR ppid BETWEEN 0 AND 4294967295"),
        _ck(t, "sources", "sources BETWEEN 1 AND 7"),
        _text_max(t, "cmdline", 4096 * 4),  # 4096 characters of UTF-8
        _text_max(t, "image_path", 1024 * 4),
    )
    op.execute(
        f'CREATE UNIQUE INDEX uq_{t}_job_id_pid_offset ON {t} (job_id, pid, "offset") '
        "NULLS NOT DISTINCT"
    )
    op.create_index(op.f(f"ix_{t}_job_id_ppid"), t, ["job_id", "ppid"])

    t = "memory_connections"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("proto", sa.String(8), nullable=False),
        sa.Column("local_addr", postgresql.INET(), nullable=True),
        sa.Column("local_port", sa.Integer(), nullable=True),
        sa.Column("remote_addr", postgresql.INET(), nullable=True),
        sa.Column("remote_port", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(16), nullable=True),
        sa.Column("pid", sa.BigInteger(), nullable=True),
        sa.Column("owner", sa.String(64), nullable=True),
        _ts("created", nullable=True),
        _address("offset"),
        _ck(t, "proto", "proto IN ('tcp', 'udp', 'raw', 'unix', 'other')"),
        _ck(
            t,
            "ports",
            "coalesce(local_port, 0) BETWEEN 0 AND 65535 "
            "AND coalesce(remote_port, 0) BETWEEN 0 AND 65535",
        ),
    )
    op.create_index(op.f(f"ix_{t}_job_id_pid"), t, ["job_id", "pid"])

    t = "memory_injections"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("pid", sa.BigInteger(), nullable=False),
        sa.Column("process", sa.String(64), nullable=True),
        _address("start", nullable=False),
        _address("end", nullable=False),
        sa.Column("protection", sa.String(64), nullable=True),
        sa.Column("tag", sa.String(16), nullable=True),
        sa.Column("private", sa.Boolean(), nullable=True),
        sa.Column("commit_charge", sa.BigInteger(), nullable=True),
        sa.Column("has_pe", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("head_hex", sa.String(128), server_default="", nullable=False),
        sa.Column("disasm", sa.Text(), nullable=True),
        _ck(t, "head_hex", "head_hex ~ '^[0-9a-f]{0,128}$'"),
        _ck(t, "region", '"end" >= start'),
        _text_max(t, "disasm", 1024 * 4),
    )
    op.create_index(op.f(f"ix_{t}_job_id_pid"), t, ["job_id", "pid"])

    t = "memory_artifacts"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("pid", sa.BigInteger(), nullable=True),
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        _ck(t, "type", _in("type", ARTIFACT_TYPES)),
        _ck(t, "attributes_size", "octet_length(attributes::text) <= 4096"),
        _ck(t, "attributes_scalar", "memory_attributes_scalar(attributes)"),
    )
    op.create_index(op.f(f"ix_{t}_job_id_type_id"), t, ["job_id", "type", "id"])

    t = "memory_sensitivity"
    op.create_table(
        t,
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(16), server_default="restricted", nullable=False),
        sa.Column("defaulted_by", sa.Uuid(), nullable=False),
        _ts("defaulted_at"),
        sa.Column("released_by", sa.Uuid(), nullable=True),
        _ts("released_at", nullable=True),
        sa.Column("release_reason", sa.Text(), nullable=True),
        _ck(t, "state", "state IN ('restricted', 'released')"),
        _ck(
            t,
            "released_fields",
            "(state = 'released') = (released_at IS NOT NULL) "
            "AND (released_at IS NULL) = (released_by IS NULL) "
            "AND (released_at IS NULL) = (release_reason IS NULL)",
        ),
        _ck(
            t,
            "release_reason_length",
            "release_reason IS NULL OR char_length(release_reason) BETWEEN 1 AND 500",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name=op.f(f"fk_{t}_evidence_id_organization_id_evidence"),
        ),
        _org_fk(t),
        _user_fk(t, "defaulted_by"),
        _user_fk(t, "released_by"),
        sa.PrimaryKeyConstraint("evidence_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])


def _create_security() -> None:
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_org_id()) "
            "WITH CHECK (organization_id = app_org_id())"
        )
    op.execute(SENSITIVITY_GUARD)
    op.execute(
        "CREATE TRIGGER memory_sensitivity_guard BEFORE UPDATE OR DELETE ON memory_sensitivity "
        "FOR EACH ROW EXECUTE FUNCTION memory_sensitivity_guard()"
    )
    for table, privileges in APP_GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {APP_ROLE}")
    for table, columns in APP_UPDATE_COLUMNS.items():
        op.execute(f"GRANT UPDATE ({columns}) ON {table} TO {APP_ROLE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION memory_attributes_scalar(jsonb) TO {APP_ROLE}")
    op.execute(f"GRANT SELECT ON {', '.join(TENANT_TABLES)} TO {RETENTION_ROLE}")
    op.execute(f"GRANT DELETE ON {', '.join(BULK_TABLES)} TO {RETENTION_ROLE}")


def downgrade() -> None:
    # Postgres cannot drop an enum value: 'memory' stays in `analyzer` (unused by 0015 code).
    # Memory jobs already recorded keep analyzer = 'memory'; FORCE RLS hides them from the
    # owner here, so the restored 0006 / 0014 checks are NOT VALID (they bind new rows only,
    # 0014's precedent).
    for table in ("memory_sensitivity", *reversed(BULK_TABLES), "memory_images"):
        op.drop_table(table)  # indexes, policies, triggers and grants go with the table
    op.execute("DROP FUNCTION IF EXISTS memory_sensitivity_guard()")
    op.execute("DROP FUNCTION IF EXISTS memory_attributes_scalar(jsonb)")

    op.drop_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", type_="check")
    op.execute(
        f"ALTER TABLE job_outcomes ADD CONSTRAINT ck_job_outcomes_kind CHECK (kind IN {OLD_KINDS}) "
        "NOT VALID"
    )

    t = "analysis_jobs"
    op.execute(GUARD_0006)
    op.drop_constraint(op.f("ck_analysis_jobs_os_hint_iff_memory"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_os_hint_valid"), t, type_="check")
    op.drop_column(t, "os_hint")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_matches_analyzer"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_valid"), t, type_="check")
    op.execute(
        "ALTER TABLE analysis_jobs ADD CONSTRAINT ck_analysis_jobs_profile_valid "
        "CHECK (profile IS NULL OR profile IN ('full', 'av')) NOT VALID"
    )
    op.execute(
        "ALTER TABLE analysis_jobs ADD CONSTRAINT ck_analysis_jobs_profile_iff_static "
        "CHECK ((profile IS NOT NULL) = (analyzer::text = 'static')) NOT VALID"
    )
