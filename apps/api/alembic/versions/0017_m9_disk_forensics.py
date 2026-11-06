"""disk forensics: the `disk` analyzer and its profiles, segment sets, the disk result tables,
file exports and the `source` of the (M8) evidence sensitivity

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-07 12:00:00

Frozen in M9 phase 1 (later schema needs go into the next number, assigned by the parent; M10
expects 0018, M11 0019). The M4-M8 conventions:
- `analyzer` gains `disk` in an autocommit block (0006's rule); comparisons go through
  `analyzer::text`. The downgrade cannot drop it.
- `analysis_jobs.profile`: disk `triage` / `full` / `extract` is added to the 0016 checks;
  `os_hint` is NOT NULL iff the analyzer is memory or disk (`auto` for `extract`); the job
  guard keeps both write-once (0016's guard, unchanged).
- `job_outcomes.kind` gains `disk`.
- `analysis_job_segments`: the ordered segment set of a disk job (ordinal 0 is
  `analysis_jobs.evidence_id`); every segment's investigation equals the job's (trigger);
  insert-only (no UPDATE / DELETE grant, trigger for the owner too).
- Every tenant table has FORCE RLS on `organization_id = app_org_id()` and composite
  (id, organization_id) FKs; the bulk tables carry `id`, `organization_id`, `job_id`.
- `disk_exports`: forward-only states (`pending -> ready | failed`, `ready -> promoted |
  expired`); `object_deleted_at` is set once (the retention worker, RT19).
- `memory_sensitivity` is **not renamed** (RT2): it gains `source` (`memory` / `disk` /
  `derived`, default `memory` for every existing row). Its guard, policy and grants are
  untouched (the app role's table-level INSERT covers the new column).
- Grants: the app role SELECT / INSERT (+ UPDATE of the export columns), never DELETE;
  `cyberlab_retention` SELECT on every disk table, DELETE on `disk_files` / `disk_events`
  only, UPDATE (`object_deleted_at`) on `disk_exports`.
- Event attributes are scalar values only (0016's `memory_attributes_scalar`).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import SchemaItem

from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
RETENTION_ROLE = "cyberlab_retention"
BULK_TABLES = ("disk_files", "disk_events")
TENANT_TABLES = (
    "analysis_job_segments",
    "disk_images",
    "disk_partitions",
    *BULK_TABLES,
    "disk_exports",
)
ARTIFACTS = (
    "evtx",
    "registry_system",
    "registry_user",
    "prefetch",
    "lnk",
    "mft",
    "amcache",
    "browser",
    "recycle_bin",
    "syslog",
    "auth_log",
    "utmp",
    "shell_history",
    "cron",
    "systemd_journal",
    "packages",
    "preprocess",
)
FS_TYPES = ("ntfs", "fat12", "fat16", "fat32", "exfat", "ext2", "ext3", "ext4")
M8_KINDS = "('pcap', 'static', 'memory', 'ti', 'ai', 'report')"
M9_KINDS = "('pcap', 'static', 'memory', 'disk', 'ti', 'ai', 'report')"

ROLE_GUARD = f"""DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{RETENTION_ROLE}') THEN
    RAISE EXCEPTION 'role {RETENTION_ROLE} does not exist: run db-bootstrap first '
      '(docker compose run --rm db-bootstrap; infra/postgres/bootstrap.sh)';
  END IF;
END $$"""

PROFILE_VALID_M8 = "profile IS NULL OR profile IN ('full', 'av', 'triage')"
PROFILE_VALID_M9 = "profile IS NULL OR profile IN ('full', 'av', 'triage', 'extract')"
PROFILE_FOR_ANALYZER_M8 = (
    "CASE WHEN analyzer::text = 'static' THEN profile IS NOT NULL AND profile IN ('full', 'av') "
    "WHEN analyzer::text = 'memory' THEN profile IS NOT NULL AND profile IN ('triage', 'full') "
    "ELSE profile IS NULL END"
)
PROFILE_FOR_ANALYZER_M9 = (
    "CASE WHEN analyzer::text = 'static' THEN profile IS NOT NULL AND profile IN ('full', 'av') "
    "WHEN analyzer::text = 'memory' THEN profile IS NOT NULL AND profile IN ('triage', 'full') "
    "WHEN analyzer::text = 'disk' THEN profile IS NOT NULL "
    "AND profile IN ('triage', 'full', 'extract') "
    "ELSE profile IS NULL END"
)
OS_HINT_IFF_M8 = "(os_hint IS NOT NULL) = (analyzer::text = 'memory')"
OS_HINT_IFF_M9 = (
    "(os_hint IS NOT NULL) = (analyzer::text IN ('memory', 'disk')) "
    "AND (profile IS DISTINCT FROM 'extract' OR os_hint = 'auto')"
)

SEGMENTS_GUARD = """CREATE FUNCTION analysis_job_segments_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  job_investigation uuid;
  segment_investigation uuid;
BEGIN
  -- Not SECURITY DEFINER: applies to every role, the owner included.
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'analysis job segments are insert-only'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  SELECT e.investigation_id INTO job_investigation
    FROM public.analysis_jobs j JOIN public.evidence e
      ON e.id = j.evidence_id AND e.organization_id = j.organization_id
   WHERE j.id = NEW.job_id AND j.organization_id = NEW.organization_id;
  SELECT e.investigation_id INTO segment_investigation
    FROM public.evidence e
   WHERE e.id = NEW.evidence_id AND e.organization_id = NEW.organization_id;
  IF job_investigation IS NULL OR segment_investigation IS DISTINCT FROM job_investigation THEN
    RAISE EXCEPTION 'a segment must belong to the job''s investigation'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$"""

EXPORT_TRANSITIONS = """CREATE FUNCTION disk_exports_transition() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'disk exports are never deleted' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'pending' AND NEW.state IN ('ready', 'failed'))
    OR (OLD.state = 'ready' AND NEW.state IN ('promoted', 'expired'))
  ) THEN
    RAISE EXCEPTION 'illegal disk export transition % -> %', OLD.state, NEW.state
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.object_deleted_at IS NOT NULL
     AND NEW.object_deleted_at IS DISTINCT FROM OLD.object_deleted_at THEN
    RAISE EXCEPTION 'object_deleted_at is set once' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.export_job_id, NEW.source_job_id, NEW.file_id,
      NEW.path, NEW.requested_by, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.export_job_id, OLD.source_job_id, OLD.file_id,
      OLD.path, OLD.requested_by, OLD.created_at) THEN
    RAISE EXCEPTION 'disk export identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

APP_GRANTS = {table: "SELECT, INSERT" for table in TENANT_TABLES}
APP_UPDATE_COLUMNS = {
    "disk_exports": (
        "state, object_key, object_version_id, size, worker_sha256, evidence_id, "
        "promoted_by, promoted_at, error_code, object_deleted_at"
    )
}


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


def _job_fk(table: str, column: str = "job_id") -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column, "organization_id"],
        ["analysis_jobs.id", "analysis_jobs.organization_id"],
        name=op.f(f"fk_{table}_{column}_organization_id_analysis_jobs"),
        ondelete="CASCADE",
    )


def _evidence_fk(table: str, column: str = "evidence_id") -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column, "organization_id"],
        ["evidence.id", "evidence.organization_id"],
        name=op.f(f"fk_{table}_{column}_organization_id_evidence"),
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
    return [
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        _job_fk(table),
        _org_fk(table),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")),
    ]


def _address(name: str, *, nullable: bool = True) -> sa.Column[object]:
    return sa.Column(name, sa.Numeric(20, 0), nullable=nullable)


def _address_ck(table: str, column: str) -> sa.CheckConstraint:
    return _ck(
        table,
        f"{column}_range",
        f"{column} IS NULL OR ({column} >= 0 AND {column} <= 18446744073709551615)",
    )


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def upgrade() -> None:
    op.execute(ROLE_GUARD)
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE analyzer ADD VALUE IF NOT EXISTS 'disk'")
    op.execute(ROLE_GUARD)  # the autocommit block ended the guarded transaction
    _alter_existing()
    _create_tables()
    _create_security()


def _alter_existing() -> None:
    t = "analysis_jobs"
    op.drop_constraint(op.f("ck_analysis_jobs_profile_matches_analyzer"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_valid"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_os_hint_iff_memory"), t, type_="check")
    op.create_check_constraint(op.f("ck_analysis_jobs_profile_valid"), t, PROFILE_VALID_M9)
    op.create_check_constraint(
        op.f("ck_analysis_jobs_profile_matches_analyzer"), t, PROFILE_FOR_ANALYZER_M9
    )
    op.create_check_constraint(op.f("ck_analysis_jobs_os_hint_iff_analyzer"), t, OS_HINT_IFF_M9)
    # The 0016 job guard already keeps `profile` and `os_hint` write-once: unchanged.

    op.drop_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", type_="check")
    op.create_check_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", f"kind IN {M9_KINDS}")

    t = "memory_sensitivity"
    op.add_column(t, sa.Column("source", sa.String(16), server_default="memory", nullable=False))
    op.create_check_constraint(
        op.f("ck_memory_sensitivity_source"), t, "source IN ('memory', 'disk', 'derived')"
    )


def _create_tables() -> None:
    t = "analysis_job_segments"
    op.create_table(
        t,
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("ordinal", sa.SmallInteger(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        _ts("created_at"),
        _ck(t, "ordinal", "ordinal BETWEEN 0 AND 63"),
        _job_fk(t),
        _evidence_fk(t),
        _org_fk(t),
        sa.PrimaryKeyConstraint("job_id", "ordinal", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("job_id", "evidence_id", name=op.f(f"uq_{t}_job_id_evidence_id")),
    )
    op.create_index(op.f(f"ix_{t}_evidence_id"), t, ["evidence_id"])
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "disk_images"
    op.create_table(
        t,
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("segments", sa.SmallInteger(), nullable=False),
        sa.Column("media_size", sa.Numeric(20, 0), nullable=False),
        sa.Column("sector_size", sa.Integer(), nullable=False),
        sa.Column("media_sha256", sa.String(64), nullable=True),
        sa.Column("ewf_md5", sa.String(32), nullable=True),
        sa.Column("ewf_sha1", sa.String(40), nullable=True),
        # Worker-reported (RT17): never shown as "verified".
        sa.Column("media_hash_status", sa.String(16), nullable=True),
        _jsonb_col("ewf_meta", "{}"),
        sa.Column("volume_system", sa.String(16), nullable=True),
        _jsonb_col("stages", "[]"),
        _jsonb_col("counts", "{}"),
        _jsonb_col("tool_versions", "{}"),
        _jsonb_col("hashsets", "[]"),
        sa.Column("engine", sa.String(16), nullable=False),
        sa.Column("timeline_engine", sa.String(16), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default="false", nullable=False),
        _ts("created_at"),
        _ck(t, "format", "format IN ('raw', 'split_raw', 'ewf')"),
        _ck(t, "segments", "segments BETWEEN 1 AND 64"),
        _ck(t, "media_size", "media_size >= 0"),
        _ck(t, "sector_size", "sector_size BETWEEN 1 AND 65536"),
        _hex(t, "media_sha256", 64),
        _hex(t, "ewf_md5", 32),
        _hex(t, "ewf_sha1", 40),
        _ck(
            t,
            "media_hash_status",
            "media_hash_status IS NULL OR "
            "media_hash_status IN ('matched', 'mismatch', 'absent', 'not_verified')",
        ),
        _ck(t, "ewf_iff", "(format = 'ewf') = (media_hash_status IS NOT NULL)"),
        _ck(t, "volume_system", "volume_system IS NULL OR volume_system IN ('dos', 'gpt', 'none')"),
        _ck(t, "engine", "engine IN ('tsk')"),
        _ck(t, "timeline_engine", "timeline_engine IN ('plaso', 'replay', 'none')"),
        _jsonb(t, "ewf_meta", "object", 2048),
        _jsonb(t, "stages", "array", 16384),
        _jsonb(t, "counts", "object", 4096),
        _jsonb(t, "tool_versions", "object", 2048),
        _jsonb(t, "hashsets", "array", 4096),
        _job_fk(t),
        _org_fk(t),
        sa.PrimaryKeyConstraint("job_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "disk_partitions"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("index", sa.SmallInteger(), nullable=False),
        _address("start_sector", nullable=False),
        _address("length_sectors", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("vs_flags", sa.String(16), nullable=False),
        sa.Column("fs_type", sa.String(16), nullable=True),
        sa.Column("fs_status", sa.String(16), nullable=False),
        sa.Column("fs_label", sa.Text(), nullable=True),
        sa.Column("fs_uuid", sa.Text(), nullable=True),
        sa.Column("block_size", sa.Integer(), nullable=True),
        sa.Column("os", sa.String(16), nullable=False),
        sa.Column("os_name", sa.Text(), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        _jsonb_col("counts", "{}"),
        _ck(t, "index", '"index" BETWEEN 0 AND 127'),
        _address_ck(t, "start_sector"),
        _address_ck(t, "length_sectors"),
        _text_max(t, "description", 128 * 4),
        _text_max(t, "fs_label", 128 * 4),
        _text_max(t, "fs_uuid", 64 * 4),
        _text_max(t, "os_name", 128 * 4),
        _ck(t, "vs_flags", "vs_flags IN ('alloc', 'unalloc', 'meta', 'none')"),
        _ck(t, "fs_type", f"fs_type IS NULL OR {_in('fs_type', FS_TYPES)}"),
        _ck(
            t,
            "fs_status",
            "fs_status IN ('ok', 'unsupported', 'encrypted', 'undetermined', 'error', 'truncated')",
        ),
        _ck(t, "os", "os IN ('windows', 'linux', 'none')"),
        _jsonb(t, "counts", "object", 4096),
        sa.UniqueConstraint("job_id", "index", name=op.f(f"uq_{t}_job_id_index")),
    )

    t = "disk_files"
    op.create_table(
        t,
        *_bulk(t),
        sa.Column("partition_index", sa.SmallInteger(), nullable=False),
        _address("meta_addr", nullable=False),
        sa.Column("meta_seq", sa.BigInteger(), nullable=True),
        sa.Column("stream", sa.Text(), nullable=True),
        sa.Column("path", sa.Text(), nullable=False),
        _address("parent_addr"),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("ext", sa.String(32), nullable=True),
        sa.Column("type", sa.String(8), nullable=False),
        # Bitmask: 1 allocated, 2 deleted, 4 orphan, 8 reallocated, 16 name_lossy,
        # 32 path_truncated, 64 hard_linked (cyberlab_jobs.disk.FILE_FLAG_BITS).
        sa.Column("flags", sa.SmallInteger(), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=True),
        sa.Column("mode", sa.Integer(), nullable=True),
        sa.Column("uid", sa.BigInteger(), nullable=True),
        sa.Column("gid", sa.BigInteger(), nullable=True),
        _ts("mtime", nullable=True),
        _ts("atime", nullable=True),
        _ts("ctime", nullable=True),
        _ts("crtime", nullable=True),
        sa.Column("time_basis", sa.String(16), server_default="utc", nullable=False),
        sa.Column("magic", sa.String(16), nullable=True),
        sa.Column("hash_status", sa.String(16), nullable=True),
        sa.Column("md5", sa.String(32), nullable=True),
        sa.Column("sha1", sa.String(40), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("known", sa.String(8), nullable=True),
        sa.Column("known_set", sa.String(64), nullable=True),
        sa.Column("yara_rules", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        _ck(t, "partition_index", "partition_index BETWEEN 0 AND 127"),
        _address_ck(t, "meta_addr"),
        _address_ck(t, "parent_addr"),
        _ck(t, "meta_seq", "meta_seq IS NULL OR meta_seq BETWEEN 0 AND 4294967295"),
        _text_max(t, "stream", 255),
        _text_max(t, "path", 4096),
        _text_max(t, "name", 1024),
        _ck(t, "type", "type IN ('reg', 'dir', 'lnk', 'other')"),
        _ck(t, "flags", "flags BETWEEN 0 AND 127"),
        _ck(t, "size", "size IS NULL OR size >= 0"),
        _ck(t, "time_basis", "time_basis IN ('utc', 'local_unknown')"),
        _ck(
            t,
            "magic",
            "magic IS NULL OR "
            "magic IN ('pe', 'elf', 'script', 'archive', 'document', 'other', 'empty')",
        ),
        _ck(
            t,
            "hash_status",
            "hash_status IS NULL OR hash_status IN "
            "('hashed', 'too_large', 'budget', 'not_allocated', 'not_regular', 'error')",
        ),
        _hex(t, "md5", 32),
        _hex(t, "sha1", 40),
        _hex(t, "sha256", 64),
        _ck(t, "known", "known IS NULL OR known IN ('good', 'bad', 'notable')"),
        _ck(t, "known_pair", "(known IS NULL) = (known_set IS NULL)"),
        _ck(t, "yara_rules", "cardinality(yara_rules) <= 16"),
        _ck(t, "deleted_unhashed", "(flags & 2) = 0 OR sha256 IS NULL"),
    )
    op.create_index(
        op.f(f"ix_{t}_job_id_partition_index_parent_addr_id"),
        t,
        ["job_id", "partition_index", "parent_addr", "id"],
    )
    op.create_index(
        op.f(f"ix_{t}_job_id_partition_index_meta_addr"),
        t,
        ["job_id", "partition_index", "meta_addr"],
    )
    op.create_index(op.f(f"ix_{t}_job_id_sha256"), t, ["job_id", "sha256"])
    for column in ("mtime", "atime", "ctime", "crtime"):  # the merged timeline (RT14)
        op.create_index(op.f(f"ix_{t}_job_id_{column}_id"), t, ["job_id", column, "id"])
    # Flagged rows: anything beyond a plain allocated entry (deleted, orphan, streams of
    # interest are filtered by the read API).
    op.create_index(
        op.f(f"ix_{t}_job_id_flags"),
        t,
        ["job_id", "flags"],
        postgresql_where=sa.text("flags <> 1"),
    )

    t = "disk_events"
    op.create_table(
        t,
        *_bulk(t),
        _ts("ts", nullable=False),
        sa.Column("ts_desc", sa.String(64), nullable=False),
        sa.Column("artifact", sa.String(32), nullable=False),
        sa.Column("parser", sa.String(64), nullable=False),
        sa.Column("data_type", sa.String(64), nullable=False),
        sa.Column("partition_index", sa.SmallInteger(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=True),
        sa.Column("ordinal", sa.BigInteger(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        _jsonb_col("attributes", "{}"),
        _ck(t, "artifact", _in("artifact", ARTIFACTS)),
        _ck(t, "partition_index", "partition_index BETWEEN 0 AND 127"),
        _ck(t, "ordinal", "ordinal >= 0"),
        _text_max(t, "path", 1024),
        _text_max(t, "message", 2048 * 4),
        _ck(t, "attributes_size", "octet_length(attributes::text) <= 4096"),
        _ck(t, "attributes_scalar", "memory_attributes_scalar(attributes)"),
        # `file_id` is a soft reference (no FK): retention deletes `disk_files` rows per job.
    )
    op.create_index(op.f(f"ix_{t}_job_id_ts_id"), t, ["job_id", "ts", "id"])
    op.create_index(op.f(f"ix_{t}_job_id_artifact_ts_id"), t, ["job_id", "artifact", "ts", "id"])

    t = "disk_exports"
    op.create_table(
        t,
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("export_job_id", sa.Uuid(), nullable=False),
        sa.Column("source_job_id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),  # snapshot of the listed path
        sa.Column("state", sa.String(16), server_default="pending", nullable=False),
        sa.Column("object_key", sa.Text(), nullable=True),
        sa.Column("object_version_id", sa.String(255), nullable=True),  # RT19
        sa.Column("size", sa.BigInteger(), nullable=True),
        sa.Column("worker_sha256", sa.String(64), nullable=True),  # untrusted, display only
        sa.Column("evidence_id", sa.Uuid(), nullable=True),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("promoted_by", sa.Uuid(), nullable=True),
        _ts("promoted_at", nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        _ts("object_deleted_at", nullable=True),
        _ts("created_at"),
        _ck(t, "state", "state IN ('pending', 'ready', 'failed', 'promoted', 'expired')"),
        _text_max(t, "path", 4096),
        _text_max(t, "object_key", 1024),
        _ck(t, "size", "size IS NULL OR (size >= 0 AND size <= 67108864)"),
        _hex(t, "worker_sha256", 64),
        _ck(
            t,
            "promoted_fields",
            "(state = 'promoted') = (evidence_id IS NOT NULL) "
            "AND (evidence_id IS NULL) = (promoted_by IS NULL) "
            "AND (promoted_by IS NULL) = (promoted_at IS NULL)",
        ),
        _ck(t, "failed_code", "(state = 'failed') = (error_code IS NOT NULL)"),
        _job_fk(t, "export_job_id"),
        _job_fk(t, "source_job_id"),
        _evidence_fk(t),
        # `file_id` is a soft reference (the `path` snapshot survives retention of the listing).
        _org_fk(t),
        _user_fk(t, "requested_by"),
        _user_fk(t, "promoted_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(op.f(f"ix_{t}_source_job_id_created_at"), t, ["source_job_id", "created_at"])
    op.create_index(op.f(f"ix_{t}_export_job_id"), t, ["export_job_id"])
    op.create_index(op.f(f"ix_{t}_state_created_at"), t, ["state", "created_at"])
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
    op.execute(SEGMENTS_GUARD)
    op.execute(
        "CREATE TRIGGER analysis_job_segments_guard "
        "BEFORE INSERT OR UPDATE OR DELETE ON analysis_job_segments "
        "FOR EACH ROW EXECUTE FUNCTION analysis_job_segments_guard()"
    )
    op.execute(EXPORT_TRANSITIONS)
    op.execute(
        "CREATE TRIGGER disk_exports_transition BEFORE UPDATE OR DELETE ON disk_exports "
        "FOR EACH ROW EXECUTE FUNCTION disk_exports_transition()"
    )
    for table, privileges in APP_GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {APP_ROLE}")
    for table, columns in APP_UPDATE_COLUMNS.items():
        op.execute(f"GRANT UPDATE ({columns}) ON {table} TO {APP_ROLE}")
    op.execute(f"GRANT SELECT ON {', '.join(TENANT_TABLES)} TO {RETENTION_ROLE}")
    op.execute(f"GRANT DELETE ON {', '.join(BULK_TABLES)} TO {RETENTION_ROLE}")
    op.execute(f"GRANT UPDATE (object_deleted_at) ON disk_exports TO {RETENTION_ROLE}")


def downgrade() -> None:
    # Postgres cannot drop an enum value: 'disk' stays in `analyzer` (unused by 0016 code).
    # Disk jobs already recorded keep analyzer = 'disk'; the restored 0016 checks are NOT
    # VALID (they bind new rows only, 0014 / 0016's precedent).
    for table in ("disk_exports", "disk_events", "disk_files", "disk_partitions", "disk_images",
                  "analysis_job_segments"):
        op.drop_table(table)  # indexes, policies, triggers and grants go with the table
    op.execute("DROP FUNCTION IF EXISTS disk_exports_transition()")
    op.execute("DROP FUNCTION IF EXISTS analysis_job_segments_guard()")

    op.drop_constraint(op.f("ck_memory_sensitivity_source"), "memory_sensitivity", type_="check")
    op.drop_column("memory_sensitivity", "source")

    op.drop_constraint(op.f("ck_job_outcomes_kind"), "job_outcomes", type_="check")
    op.execute(
        f"ALTER TABLE job_outcomes ADD CONSTRAINT ck_job_outcomes_kind CHECK (kind IN {M8_KINDS}) "
        "NOT VALID"
    )

    t = "analysis_jobs"
    op.drop_constraint(op.f("ck_analysis_jobs_os_hint_iff_analyzer"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_matches_analyzer"), t, type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_valid"), t, type_="check")
    for name, sql in (
        ("ck_analysis_jobs_profile_valid", PROFILE_VALID_M8),
        ("ck_analysis_jobs_profile_matches_analyzer", PROFILE_FOR_ANALYZER_M8),
        ("ck_analysis_jobs_os_hint_iff_memory", OS_HINT_IFF_M8),
    ):
        op.execute(f"ALTER TABLE analysis_jobs ADD CONSTRAINT {name} CHECK ({sql}) NOT VALID")
