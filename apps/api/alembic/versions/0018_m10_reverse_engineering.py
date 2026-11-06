"""reverse engineering: the `reverse` analyzer and its profiles, the source static job and the
request parameters of an RE job, capa locations on the static tables, the RE result tables

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-07 12:00:00

Frozen in M10 phase 1 (later schema needs go into the next number, assigned by the parent; M11
expects 0019). The M4-M9 conventions:
- `analyzer` gains `reverse` in an autocommit block (0006's rule); comparisons go through
  `analyzer::text`. The downgrade cannot drop it.
- `analysis_jobs.profile`: reverse `quick` / `full` (RT10: no `targeted`) is added to the 0017
  checks. `source_job_id` (composite same-org FK to the static job of the same evidence,
  trigger) and `re_params` (`{"decompile_addresses": [decimal strings]}`, <= 2 KiB, non-empty
  only for `full`) are NOT NULL iff the analyzer is reverse; the job guard keeps both
  write-once.
- `job_outcomes.kind` gains `reverse`.
- AI (frozen values, the run path is phase 9's): `ai_runs.task` gains `explain_function`,
  `ai_runs.target_kind` gains `function`, `ai_context_refs.kind` / `ai_citations.kind` gain
  `function` (G) and `code` (Q).
- `malware_capabilities.locations` (a jsonb array of <= 32 decimal strings, default `[]`) and
  `malware_samples.capa_base_address` (M3 tables, additive; RT8 / RT18); a unique
  (id, organization_id) on `malware_capabilities` for the capability links' same-org FK.
- Every tenant table has FORCE RLS on `organization_id = app_org_id()` and composite
  (id, organization_id) FKs; the bulk tables carry `id`, `organization_id`, `job_id`.
- Grants: the app role SELECT / INSERT, never UPDATE or DELETE; `cyberlab_retention` SELECT on
  every RE table and DELETE on the bulk ones (never on `re_programs`).
- Addresses are NUMERIC(20, 0) (the M3 rule): an unsigned 64-bit value does not fit a bigint.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import SchemaItem

from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
RETENTION_ROLE = "cyberlab_retention"
BULK_TABLES = (
    "re_functions",
    "re_call_edges",
    "re_imports",
    "re_import_refs",
    "re_strings",
    "re_string_refs",
    "re_decompilations",
    "re_function_capabilities",
)
TENANT_TABLES = ("re_programs", *BULK_TABLES)
M9_KINDS = "('pcap', 'static', 'memory', 'disk', 'ti', 'ai', 'report')"
M10_KINDS = "('pcap', 'static', 'memory', 'disk', 'reverse', 'ti', 'ai', 'report')"
AI_TASKS_M5 = (
    "explain_finding",
    "explain_alert",
    "summarize_pcap",
    "explain_static",
    "ioc_correlation",
    "attack_mapping",
    "incident_summary",
    "job_digest",
)
AI_TASKS_M10 = (*AI_TASKS_M5, "explain_function")
REF_KINDS_M5 = (
    "job",
    "finding",
    "alert",
    "flow",
    "record",
    "ioc",
    "ti_result",
    "sample",
    "signature",
    "capability",
    "pe_summary",
    "string",
    "timeline",
    "evidence",
    "investigation",
    "digest_claim",
)
REF_KINDS_M10 = (*REF_KINDS_M5, "function", "code")
TARGET_KINDS_M5 = ("finding", "alert")
TARGET_KINDS_M10 = (*TARGET_KINDS_M5, "function")
NAME_SOURCES = ("export", "import", "symbol", "debug", "fid_library", "generated")
DECOMPILE_STATUSES = ("ok", "timeout", "failed", "truncated", "skipped_budget")
# `not_selected`: the function was not on the decompile list (or the profile is quick).
FUNCTION_DECOMPILE_STATUSES = (*DECOMPILE_STATUSES, "not_selected")
STRING_ENCODINGS = ("ascii", "utf8", "utf16le", "utf16be", "utf32")
MAX_ADDRESS = "18446744073709551615"

ROLE_GUARD = f"""DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{RETENTION_ROLE}') THEN
    RAISE EXCEPTION 'role {RETENTION_ROLE} does not exist: run db-bootstrap first '
      '(docker compose run --rm db-bootstrap; infra/postgres/bootstrap.sh)';
  END IF;
END $$"""

PROFILE_VALID_M9 = "profile IS NULL OR profile IN ('full', 'av', 'triage', 'extract')"
PROFILE_VALID_M10 = "profile IS NULL OR profile IN ('full', 'av', 'triage', 'extract', 'quick')"
_PROFILE_ARMS = (
    "CASE WHEN analyzer::text = 'static' THEN profile IS NOT NULL AND profile IN ('full', 'av') "
    "WHEN analyzer::text = 'memory' THEN profile IS NOT NULL AND profile IN ('triage', 'full') "
    "WHEN analyzer::text = 'disk' THEN profile IS NOT NULL "
    "AND profile IN ('triage', 'full', 'extract') "
)
PROFILE_FOR_ANALYZER_M9 = _PROFILE_ARMS + "ELSE profile IS NULL END"
PROFILE_FOR_ANALYZER_M10 = (
    _PROFILE_ARMS
    + "WHEN analyzer::text = 'reverse' THEN profile IS NOT NULL AND profile IN ('quick', 'full') "
    + "ELSE profile IS NULL END"
)
RE_FIELDS_IFF = (
    "(source_job_id IS NOT NULL) = (analyzer::text = 'reverse') "
    "AND (re_params IS NOT NULL) = (analyzer::text = 'reverse')"
)

# 0016's guard (the M8 identity columns) with the M10 ones: what an RE job was asked for.
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
GUARD_M10 = _GUARD.format(
    new_extra=", NEW.profile, NEW.os_hint, NEW.source_job_id, NEW.re_params",
    old_extra=", OLD.profile, OLD.os_hint, OLD.source_job_id, OLD.re_params",
)
GUARD_M8 = _GUARD.format(
    new_extra=", NEW.profile, NEW.os_hint", old_extra=", OLD.profile, OLD.os_hint"
)

SOURCE_GUARD = """CREATE FUNCTION analysis_jobs_re_source() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  source_analyzer text;
  source_evidence uuid;
BEGIN
  -- Not SECURITY DEFINER: the source is read under the caller's RLS (same org only).
  IF NEW.source_job_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT j.analyzer::text, j.evidence_id INTO source_analyzer, source_evidence
    FROM public.analysis_jobs j
   WHERE j.id = NEW.source_job_id AND j.organization_id = NEW.organization_id;
  IF source_analyzer IS DISTINCT FROM 'static' OR source_evidence IS DISTINCT FROM NEW.evidence_id
  THEN
    RAISE EXCEPTION 'the source of an RE job is a static job of the same evidence'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$"""

# `{"decompile_addresses": [...]}`: <= 64 unsigned 64-bit decimal strings, non-empty only for
# `full` (RT10). CASE fixes the evaluation order (jsonb_array_* raise on a non-array).
RE_PARAMS_FUNCTION = f"""CREATE FUNCTION re_params_valid(value jsonb, profile text)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
  SELECT CASE
    WHEN jsonb_typeof(value) IS DISTINCT FROM 'object' THEN false
    WHEN jsonb_typeof(value -> 'decompile_addresses') IS DISTINCT FROM 'array' THEN false
    ELSE (SELECT count(*) FROM jsonb_object_keys(value)) = 1
     AND jsonb_array_length(value -> 'decompile_addresses') <= 64
     AND (profile = 'full' OR jsonb_array_length(value -> 'decompile_addresses') = 0)
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(value -> 'decompile_addresses') AS e
       -- CASE again: OR does not fix the order, and the cast must only see digits.
       WHERE CASE
         WHEN jsonb_typeof(e) IS DISTINCT FROM 'string' THEN true
         WHEN (e #>> '{{}}') !~ '^[0-9]{{1,20}}$' THEN true
         ELSE (e #>> '{{}}')::numeric > {MAX_ADDRESS}
       END
     )
  END
$$"""

# `malware_capabilities.locations`: <= 32 unsigned 64-bit decimal strings.
LOCATIONS_FUNCTION = f"""CREATE FUNCTION capability_locations_valid(value jsonb)
  RETURNS boolean
  LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
  SELECT CASE
    WHEN jsonb_typeof(value) IS DISTINCT FROM 'array' THEN false
    ELSE jsonb_array_length(value) <= 32
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(value) AS e
       -- CASE again: OR does not fix the order, and the cast must only see digits.
       WHERE CASE
         WHEN jsonb_typeof(e) IS DISTINCT FROM 'string' THEN true
         WHEN (e #>> '{{}}') !~ '^[0-9]{{1,20}}$' THEN true
         ELSE (e #>> '{{}}')::numeric > {MAX_ADDRESS}
       END
     )
  END
$$"""


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


# The conventional names of these two would exceed Postgres' 63-character identifier limit
# (the models name them the same way).
SHORT_FK_NAMES = {
    "fk_re_function_capabilities_job_id_organization_id_analysis_jobs": (
        "fk_re_function_capabilities_job_id_analysis_jobs"
    ),
    "fk_re_function_capabilities_capability_id_organization_id_malware_capabilities": (
        "fk_re_function_capabilities_capability_id_malware_capabilities"
    ),
}


def _fk_name(name: str) -> str:
    return SHORT_FK_NAMES.get(name, name)


def _job_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["job_id", "organization_id"],
        ["analysis_jobs.id", "analysis_jobs.organization_id"],
        name=op.f(_fk_name(f"fk_{table}_job_id_organization_id_analysis_jobs")),
        ondelete="CASCADE",
    )


def _same_org_fk(table: str, column: str, target: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column, "organization_id"],
        [f"{target}.id", f"{target}.organization_id"],
        name=op.f(_fk_name(f"fk_{table}_{column}_organization_id_{target}")),
        ondelete="CASCADE",
    )


def _ck(table: str, name: str, sql: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(sql, name=op.f(f"ck_{table}_{name}"))


def _text_max(table: str, column: str, limit: int) -> sa.CheckConstraint:
    return _ck(table, f"{column}_length", f"{column} IS NULL OR octet_length({column}) <= {limit}")


def _jsonb(table: str, column: str, kind: str, limit: int) -> sa.CheckConstraint:
    return _ck(
        table,
        column,
        f"jsonb_typeof({column}) = '{kind}' AND octet_length({column}::text) <= {limit}",
    )


def _jsonb_col(name: str, default: str) -> sa.Column[object]:
    return sa.Column(
        name, postgresql.JSONB(astext_type=sa.Text()), server_default=default, nullable=False
    )


def _hex(table: str, column: str, n: int) -> sa.CheckConstraint:
    return _ck(table, column, f"{column} IS NULL OR {column} ~ '^[0-9a-f]{{{n}}}$'")


def _bulk(table: str) -> list[SchemaItem]:
    """`id`, `organization_id`, `job_id` (M8 RT23), the job FK and the PK."""
    return [
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        _job_fk(table),
        _org_fk(table),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")),
    ]


def _address(name: str, *, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.Numeric(20, 0), nullable=nullable)


def _address_ck(table: str, column: str) -> sa.CheckConstraint:
    return _ck(
        table,
        f"{column}_range",
        f"{column} IS NULL OR ({column} >= 0 AND {column} <= {MAX_ADDRESS})",
    )


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def upgrade() -> None:
    op.execute(ROLE_GUARD)
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE analyzer ADD VALUE IF NOT EXISTS 'reverse'")
    op.execute(ROLE_GUARD)  # the autocommit block ended the guarded transaction
    op.execute(RE_PARAMS_FUNCTION)
    op.execute(LOCATIONS_FUNCTION)
    _alter_existing()
    _create_tables()
    _create_security()


def _alter_existing() -> None:
    t = "analysis_jobs"
    op.drop_constraint(op.f("ck_analysis_jobs_profile_matches_analyzer"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_valid"), t, type_="check")
    op.create_check_constraint(op.f("ck_analysis_jobs_profile_valid"), t, PROFILE_VALID_M10)
    op.create_check_constraint(
        op.f("ck_analysis_jobs_profile_matches_analyzer"), t, PROFILE_FOR_ANALYZER_M10
    )
    op.add_column(t, sa.Column("source_job_id", sa.Uuid(), nullable=True))
    op.add_column(t, sa.Column("re_params", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_foreign_key(
        op.f("fk_analysis_jobs_source_job_id_organization_id_analysis_jobs"),
        t,
        t,
        ["source_job_id", "organization_id"],
        ["id", "organization_id"],
        ondelete="CASCADE",
    )
    op.create_index(op.f("ix_analysis_jobs_source_job_id"), t, ["source_job_id"])
    op.create_check_constraint(op.f("ck_analysis_jobs_re_fields_iff_reverse"), t, RE_FIELDS_IFF)
    op.create_check_constraint(
        op.f("ck_analysis_jobs_re_params"),
        t,
        "re_params IS NULL OR (octet_length(re_params::text) <= 2048 "
        "AND re_params_valid(re_params, profile))",
    )
    op.execute(GUARD_M10)
    op.execute(SOURCE_GUARD)
    op.execute(
        "CREATE TRIGGER analysis_jobs_re_source BEFORE INSERT ON analysis_jobs "
        "FOR EACH ROW EXECUTE FUNCTION analysis_jobs_re_source()"
    )

    op.drop_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", type_="check")
    op.create_check_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", f"kind IN {M10_KINDS}")
    _ai_checks(AI_TASKS_M10, TARGET_KINDS_M10, REF_KINDS_M10)

    t = "malware_capabilities"
    op.add_column(
        t,
        sa.Column(
            "locations",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
    )
    op.create_check_constraint(
        op.f("ck_malware_capabilities_locations"), t, "capability_locations_valid(locations)"
    )
    op.create_unique_constraint(
        op.f("uq_malware_capabilities_id_organization_id"), t, ["id", "organization_id"]
    )
    t = "malware_samples"
    op.add_column(t, sa.Column("capa_base_address", sa.Numeric(20, 0), nullable=True))
    op.create_check_constraint(
        op.f("ck_malware_samples_capa_base_address_range"),
        t,
        f"capa_base_address IS NULL OR (capa_base_address >= 0 AND capa_base_address <= "
        f"{MAX_ADDRESS})",
    )


def _ai_checks(
    tasks: Sequence[str], targets: Sequence[str], kinds: Sequence[str], *, not_valid: bool = False
) -> None:
    checks = (
        ("ai_runs", "ck_ai_runs_task", _in("task", tasks)),
        (
            "ai_runs",
            "ck_ai_runs_target",
            "(target_id IS NULL) = (target_kind IS NULL) AND "
            f"(target_kind IS NULL OR {_in('target_kind', targets)})",
        ),
        ("ai_context_refs", "ck_ai_context_refs_kind", _in("kind", kinds)),
        ("ai_citations", "ck_ai_citations_kind", f"kind IS NULL OR {_in('kind', kinds)}"),
    )
    for table, name, sql in checks:
        op.drop_constraint(op.f(name), table, type_="check")
        if not_valid:
            op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({sql}) NOT VALID")
        else:
            op.create_check_constraint(op.f(name), table, sql)


def _create_tables() -> None:
    t = "re_programs"
    op.create_table(
        t,
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("format", sa.String(8), nullable=False),
        sa.Column("arch", sa.String(16), nullable=False),
        sa.Column("machine", sa.String(64), nullable=True),
        sa.Column("bits", sa.SmallInteger(), nullable=False),
        sa.Column("endianness", sa.String(8), nullable=False),
        sa.Column("language_id", sa.String(64), nullable=True),
        sa.Column("compiler_spec", sa.String(32), nullable=True),
        _address("image_base"),
        _address("preferred_base"),  # RT8: PE ImageBase / ELF lowest PT_LOAD vaddr
        _address("entry", nullable=True),
        sa.Column("analysis_status", sa.String(16), nullable=False),
        sa.Column("peak_memory_bytes", sa.BigInteger(), nullable=True),  # cgroup, RT14
        sa.Column("engine", sa.String(16), nullable=False),
        sa.Column("engine_version", sa.String(32), nullable=True),
        sa.Column("code_kind", sa.String(16), nullable=False),
        _jsonb_col("stages", "[]"),
        _jsonb_col("counts", "{}"),
        _jsonb_col("truncated", "{}"),
        _jsonb_col("tool_versions", "{}"),
        _jsonb_col("audit", "{}"),
        _jsonb_col("jvm_args", "[]"),
        _ts("created_at"),
        _ck(t, "format", "format IN ('pe', 'elf')"),
        _ck(t, "arch", "arch IN ('x86', 'x86_64', 'other')"),
        _ck(t, "bits", "bits IN (16, 32, 64)"),
        _ck(t, "endianness", "endianness IN ('little', 'big')"),
        _address_ck(t, "image_base"),
        _address_ck(t, "preferred_base"),
        _address_ck(t, "entry"),
        _ck(t, "analysis_status", "analysis_status IN ('complete', 'timeout', 'failed', 'not_run')"),
        _ck(t, "peak_memory_bytes", "peak_memory_bytes IS NULL OR peak_memory_bytes >= 0"),
        _ck(t, "engine", "engine IN ('ghidra', 'radare2', 'replay')"),
        _ck(t, "code_kind", "code_kind IN ('pseudo_c', 'disasm')"),
        _jsonb(t, "stages", "array", 8192),
        _jsonb(t, "counts", "object", 4096),
        _jsonb(t, "truncated", "object", 2048),
        _jsonb(t, "tool_versions", "object", 2048),
        _jsonb(t, "audit", "object", 2048),
        _jsonb(t, "jvm_args", "array", 16384),
        _job_fk(t),
        _org_fk(t),
        sa.PrimaryKeyConstraint("job_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "re_functions"
    op.create_table(
        t,
        *_bulk(t),
        _address("entry"),
        _address("rva"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("name_source", sa.String(16), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        _jsonb_col("body", "[]"),
        sa.Column("body_truncated", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("is_thunk", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("is_external", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("is_library", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("signature", sa.String(512), nullable=True),
        sa.Column("calling_convention", sa.String(32), nullable=True),
        sa.Column("instructions", sa.BigInteger(), nullable=False),
        sa.Column("callers", sa.BigInteger(), nullable=False),
        sa.Column("callees", sa.BigInteger(), nullable=False),
        sa.Column("decompile_status", sa.String(16), nullable=False),
        sa.Column("priority_rank", sa.Integer(), nullable=True),
        _address_ck(t, "entry"),
        _address_ck(t, "rva"),
        _ck(t, "name_source", _in("name_source", NAME_SOURCES)),
        _ck(t, "counts", "size >= 0 AND instructions >= 0 AND callers >= 0 AND callees >= 0"),
        _jsonb(t, "body", "array", 2048),
        _ck(t, "body_ranges", "jsonb_array_length(body) <= 16"),
        _ck(t, "decompile_status", _in("decompile_status", FUNCTION_DECOMPILE_STATUSES)),
        _ck(t, "priority_rank", "priority_rank IS NULL OR priority_rank BETWEEN 0 AND 19999"),
        sa.UniqueConstraint("job_id", "entry", name=op.f(f"uq_{t}_job_id_entry")),
    )
    op.create_index(op.f(f"ix_{t}_job_id_name"), t, ["job_id", "name"])
    op.create_index(op.f(f"ix_{t}_job_id_priority_rank"), t, ["job_id", "priority_rank"])

    t = "re_call_edges"
    op.create_table(
        t,
        *_bulk(t),
        _address("caller_entry"),
        _address("callee_entry"),
        sa.Column("sites", sa.BigInteger(), nullable=False),
        _address_ck(t, "caller_entry"),
        _address_ck(t, "callee_entry"),
        _ck(t, "sites", "sites >= 1"),
        sa.UniqueConstraint(
            "job_id",
            "caller_entry",
            "callee_entry",
            name=op.f(f"uq_{t}_job_id_caller_entry_callee_entry"),
        ),
    )
    op.create_index(op.f(f"ix_{t}_job_id_callee_entry"), t, ["job_id", "callee_entry"])

    t = "re_imports"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("library", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("ordinal", sa.Integer(), nullable=True),
        _address("address", nullable=True),
        _ck(t, "named", "name IS NOT NULL OR ordinal IS NOT NULL"),
        _ck(t, "ordinal", "ordinal IS NULL OR ordinal BETWEEN 0 AND 65535"),
        _address_ck(t, "address"),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(op.f(f"ix_{t}_job_id_library_name"), t, ["job_id", "library", "name"])

    t = "re_import_refs"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("import_id", sa.Uuid(), nullable=False),
        _address("function_entry"),
        sa.Column("count", sa.BigInteger(), nullable=False),
        _address_ck(t, "function_entry"),
        _ck(t, "count", "count >= 1"),
        _same_org_fk(t, "import_id", "re_imports"),
        sa.UniqueConstraint(
            "import_id", "function_entry", name=op.f(f"uq_{t}_import_id_function_entry")
        ),
    )
    op.create_index(op.f(f"ix_{t}_job_id_function_entry"), t, ["job_id", "function_entry"])

    t = "re_strings"
    op.create_table(
        t,
        *_bulk(t),
        _address("address"),
        sa.Column("encoding", sa.String(8), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("length", sa.BigInteger(), nullable=False),
        _address_ck(t, "address"),
        _ck(t, "encoding", _in("encoding", STRING_ENCODINGS)),
        _ck(t, "length", "length >= 0"),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(op.f(f"ix_{t}_job_id_address"), t, ["job_id", "address"])

    t = "re_string_refs"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("string_id", sa.Uuid(), nullable=False),
        _address("function_entry"),
        sa.Column("count", sa.BigInteger(), nullable=False),
        _address_ck(t, "function_entry"),
        _ck(t, "count", "count >= 1"),
        _same_org_fk(t, "string_id", "re_strings"),
        sa.UniqueConstraint(
            "string_id", "function_entry", name=op.f(f"uq_{t}_string_id_function_entry")
        ),
    )
    op.create_index(op.f(f"ix_{t}_job_id_function_entry"), t, ["job_id", "function_entry"])

    t = "re_decompilations"
    op.create_table(
        t,
        *_bulk(t),
        _address("function_entry"),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("code_kind", sa.String(16), nullable=False),
        sa.Column("code", sa.Text(), nullable=True),  # TOAST-compressed
        sa.Column("lines", sa.Integer(), nullable=False),
        sa.Column("code_sha256", sa.String(64), nullable=True),
        sa.Column("truncated_bytes", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("duration_ms", sa.BigInteger(), server_default="0", nullable=False),
        _address_ck(t, "function_entry"),
        _ck(t, "status", _in("status", DECOMPILE_STATUSES)),
        _ck(t, "code_kind", "code_kind IN ('pseudo_c', 'disasm')"),
        _text_max(t, "code", 65536),
        _ck(t, "code_iff_status", "(code IS NOT NULL) = (status IN ('ok', 'truncated'))"),
        _ck(t, "sha_iff_code", "(code IS NULL) = (code_sha256 IS NULL)"),
        _hex(t, "code_sha256", 64),
        _ck(t, "lines", "lines >= 0"),
        _ck(t, "truncated_bytes", "truncated_bytes >= 0 AND duration_ms >= 0"),
        sa.UniqueConstraint(
            "job_id", "function_entry", name=op.f(f"uq_{t}_job_id_function_entry")
        ),
    )

    t = "re_function_capabilities"
    op.create_table(
        t,
        *_bulk(t),
        _address("function_entry"),
        sa.Column("capability_id", sa.Uuid(), nullable=False),
        _address("file_va"),  # RT8: the joined file virtual address
        _address_ck(t, "function_entry"),
        _address_ck(t, "file_va"),
        _same_org_fk(t, "capability_id", "malware_capabilities"),
        sa.UniqueConstraint(
            "job_id",
            "capability_id",
            "function_entry",
            name=op.f(f"uq_{t}_job_id_capability_id_function_entry"),
        ),
    )
    op.create_index(op.f(f"ix_{t}_capability_id"), t, ["capability_id"])
    op.create_index(op.f(f"ix_{t}_job_id_function_entry"), t, ["job_id", "function_entry"])


def _create_security() -> None:
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_org_id()) "
            "WITH CHECK (organization_id = app_org_id())"
        )
        op.execute(f"GRANT SELECT, INSERT ON {table} TO {APP_ROLE}")
    op.execute(f"GRANT SELECT ON {', '.join(TENANT_TABLES)} TO {RETENTION_ROLE}")
    op.execute(f"GRANT DELETE ON {', '.join(BULK_TABLES)} TO {RETENTION_ROLE}")


def downgrade() -> None:
    # Postgres cannot drop an enum value: 'reverse' stays in `analyzer` (unused by 0017 code).
    # RE jobs already recorded keep analyzer = 'reverse'; the restored 0017 checks are NOT
    # VALID (they bind new rows only, 0014 / 0016 / 0017's precedent).
    for table in (
        "re_function_capabilities",
        "re_decompilations",
        "re_string_refs",
        "re_strings",
        "re_import_refs",
        "re_imports",
        "re_call_edges",
        "re_functions",
        "re_programs",
    ):
        op.drop_table(table)  # indexes, policies and grants go with the table

    t = "malware_samples"
    op.drop_constraint(op.f("ck_malware_samples_capa_base_address_range"), t, type_="check")
    op.drop_column(t, "capa_base_address")
    t = "malware_capabilities"
    op.drop_constraint(op.f("uq_malware_capabilities_id_organization_id"), t, type_="unique")
    op.drop_constraint(op.f("ck_malware_capabilities_locations"), t, type_="check")
    op.drop_column(t, "locations")

    op.drop_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", type_="check")
    op.execute(
        f"ALTER TABLE job_outcomes ADD CONSTRAINT ck_job_outcomes_kind CHECK (kind IN {M9_KINDS}) "
        "NOT VALID"
    )
    _ai_checks(AI_TASKS_M5, TARGET_KINDS_M5, REF_KINDS_M5, not_valid=True)

    t = "analysis_jobs"
    op.execute("DROP TRIGGER IF EXISTS analysis_jobs_re_source ON analysis_jobs")
    op.execute("DROP FUNCTION IF EXISTS analysis_jobs_re_source()")
    op.execute(GUARD_M8)
    op.drop_constraint(op.f("ck_analysis_jobs_re_params"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_re_fields_iff_reverse"), t, type_="check")
    op.drop_index(op.f("ix_analysis_jobs_source_job_id"), t)
    op.drop_constraint(
        op.f("fk_analysis_jobs_source_job_id_organization_id_analysis_jobs"), t, type_="foreignkey"
    )
    op.drop_column(t, "re_params")
    op.drop_column(t, "source_job_id")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_matches_analyzer"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_valid"), t, type_="check")
    for name, sql in (
        ("ck_analysis_jobs_profile_valid", PROFILE_VALID_M9),
        ("ck_analysis_jobs_profile_matches_analyzer", PROFILE_FOR_ANALYZER_M9),
    ):
        op.execute(f"ALTER TABLE analysis_jobs ADD CONSTRAINT {name} CHECK ({sql}) NOT VALID")

    op.execute("DROP FUNCTION IF EXISTS capability_locations_valid(jsonb)")
    op.execute("DROP FUNCTION IF EXISTS re_params_valid(jsonb, text)")
