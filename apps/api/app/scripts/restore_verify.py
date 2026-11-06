"""Integrity and security proof of a restore (M7 phase 2; `pnpm restore`, `pnpm restore:drill`).

Runs in the api image as a one-off container (`docker compose run --rm --no-deps -T api python
-m app.scripts.restore_verify ...`). Three verify phases (RT4), each runnable alone, plus the
helpers the backup and restore scripts call so that capture and check share one code path:

- `--db --baseline -`: recompute the catalog fingerprint (`security.json`) and the exact row
  counts (`tables.json`) and compare them with the backup's (stdin `{"security", "tables"}`).
  Run right after `pg_restore`, before `migrate` and before any service writes.
- `--objects --baseline -`: every object version of `objects.json` (stdin `{"objects"}`)
  exists with the same size, etag, retention mode, retain-until, legal hold and latest flag,
  and no version was added. Every evidence row without an `evidence_purges` tombstone has
  its pinned version, which re-hashes to `evidence_hashes` (a missing pinned version without
  a tombstone is an error: it also catches an out-of-band delete, RT5); tombstoned evidence
  is absent, or present as the warning `purged_pending_delete` (RT22). Every report version
  snapshot re-hashes to `snapshot_sha256` and its manifest signature verifies with
  `REPORT_SIGNING_PUBLIC_KEYS`; every succeeded render re-hashes; every succeeded job's
  result version exists. `--sample N` hashes a random sample of the evidence instead.
- `--rls`: as `cyberlab_app` (`DATABASE_URL`), org A sees no row of org B in one table per
  module, `UPDATE audit_logs` and `DELETE FROM ti_results` are refused with SQLSTATE 42501
  (any other error is a finding: it proves nothing about the write barrier).
- `--capture-objects`: print `{"objects": [...]}` (the backup's `objects.json`).
- `--manifest-build` / `--manifest-check`: build `manifest.json` from the file facts on stdin;
  check a manifest against the files, the configured KMS key fingerprint (RT7) and the
  alembic revisions of this image (a newer backup is refused).

Environment: `RESTORE_DATABASE_URL` (the Postgres superuser, asyncpg URL; RLS is switched off
so a bound role fails loudly), `DATABASE_URL` (the app role, `--rls`),
`RESTORE_MINIO_ACCESS_KEY` / `RESTORE_MINIO_SECRET_KEY` (credentials that read retention and
legal holds: the root user in the restore helper), `MINIO_ENDPOINT`, `MINIO_BUCKET`,
`RESULTS_BUCKET`, `REPORTS_BUCKET`, `REPORT_SIGNING_PUBLIC_KEYS`. It never prints a secret.
Output: one JSON report on stdout; exit 0 clean (warnings allowed), 1 on any error, 2 on a
usage or input problem.
"""

import argparse
import asyncio
import hashlib
import json
import os
import random
import re
import sys
import uuid
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cyberlab_jobs.report import Manifest, manifest_bytes
from minio import Minio
from minio.error import S3Error
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.signing import load_public_keys, verify

TOOL_VERSION = 1
CHUNK = 1024 * 1024
API_ROOT = Path(__file__).resolve().parents[2]
# Every file a backup holds (manifest.json describes them and is not listed in itself).
BACKUP_FILES = (
    "postgres.dump",
    "globals.sql",
    "security.json",
    "tables.json",
    "objects.json",
    "minio-data.tar",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KMS_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MISSING = {"NoSuchKey", "NoSuchVersion", "NoSuchObject"}
_NO_LOCK = {"ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"}

# The statements of infra/backup/security.sql and tables.sql (their comments aside);
# scripts/lib/stack.test.mjs fails when they drift apart.
SECURITY_SQL = """\
SELECT json_build_object(
  'database', (
    SELECT json_build_object(
      'owner', pg_get_userbyid(d.datdba),
      'acl', CASE WHEN d.datacl IS NULL THEN NULL ELSE (
        SELECT json_agg(a ORDER BY a) FROM unnest(d.datacl::text[]) AS a) END)
    FROM pg_database d WHERE d.datname = current_database()),
  'schemas', (
    SELECT coalesce(json_agg(json_build_object(
      'name', n.nspname,
      'owner', pg_get_userbyid(n.nspowner),
      'acl', CASE WHEN n.nspacl IS NULL THEN NULL ELSE (
        SELECT json_agg(a ORDER BY a) FROM unnest(n.nspacl::text[]) AS a) END
    ) ORDER BY n.nspname), '[]'::json)
    FROM pg_namespace n WHERE n.nspname = 'public'),
  'tables', (
    SELECT coalesce(json_agg(json_build_object(
      'name', c.relname,
      'kind', c.relkind::text,
      'owner', pg_get_userbyid(c.relowner),
      'rls', c.relrowsecurity,
      'force_rls', c.relforcerowsecurity,
      'acl', CASE WHEN c.relacl IS NULL THEN NULL ELSE (
        SELECT json_agg(a ORDER BY a) FROM unnest(c.relacl::text[]) AS a) END
    ) ORDER BY c.relname), '[]'::json)
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend dep
        WHERE dep.classid = 'pg_class'::regclass AND dep.objid = c.oid AND dep.deptype = 'e')),
  'columns', (
    SELECT coalesce(json_agg(json_build_object(
      'table', c.relname,
      'column', a.attname,
      'acl', (SELECT json_agg(x ORDER BY x) FROM unnest(a.attacl::text[]) AS x)
    ) ORDER BY c.relname, a.attname), '[]'::json)
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND a.attnum > 0 AND NOT a.attisdropped
      AND a.attacl IS NOT NULL),
  'policies', (
    SELECT coalesce(json_agg(json_build_object(
      'table', p.tablename,
      'name', p.policyname,
      'permissive', p.permissive,
      'roles', (SELECT json_agg(r ORDER BY r) FROM unnest(p.roles::text[]) AS r),
      'cmd', p.cmd,
      'qual', p.qual,
      'with_check', p.with_check
    ) ORDER BY p.tablename, p.policyname), '[]'::json)
    FROM pg_policies p WHERE p.schemaname = 'public'),
  'triggers', (
    SELECT coalesce(json_agg(json_build_object(
      'table', c.relname,
      'name', t.tgname,
      'enabled', t.tgenabled::text,
      'definition', pg_get_triggerdef(t.oid)
    ) ORDER BY c.relname, t.tgname), '[]'::json)
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND NOT t.tgisinternal),
  'functions', (
    SELECT coalesce(json_agg(json_build_object(
      'signature', p.oid::regprocedure::text,
      'owner', pg_get_userbyid(p.proowner),
      'security_definer', p.prosecdef,
      'config', (SELECT json_agg(x ORDER BY x) FROM unnest(p.proconfig) AS x),
      'acl', CASE WHEN p.proacl IS NULL THEN NULL ELSE (
        SELECT json_agg(x ORDER BY x) FROM unnest(p.proacl::text[]) AS x) END
    ) ORDER BY p.oid::regprocedure::text), '[]'::json)
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend dep
        WHERE dep.classid = 'pg_proc'::regclass AND dep.objid = p.oid AND dep.deptype = 'e')),
  'default_acl', (
    SELECT coalesce(json_agg(json_build_object(
      'role', pg_get_userbyid(d.defaclrole),
      'schema', coalesce(n.nspname, ''),
      'objtype', d.defaclobjtype::text,
      'acl', (SELECT json_agg(x ORDER BY x) FROM unnest(d.defaclacl::text[]) AS x)
    ) ORDER BY pg_get_userbyid(d.defaclrole), coalesce(n.nspname, ''), d.defaclobjtype::text),
      '[]'::json)
    FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace),
  'extensions', (
    SELECT coalesce(json_agg(json_build_object(
      'name', e.extname,
      'version', e.extversion,
      'schema', n.nspname
    ) ORDER BY e.extname), '[]'::json)
    FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace),
  'roles', (
    SELECT coalesce(json_agg(json_build_object(
      'name', r.rolname,
      'superuser', r.rolsuper,
      'inherit', r.rolinherit,
      'createrole', r.rolcreaterole,
      'createdb', r.rolcreatedb,
      'login', r.rolcanlogin,
      'replication', r.rolreplication,
      'bypassrls', r.rolbypassrls,
      'connlimit', r.rolconnlimit
    ) ORDER BY r.rolname), '[]'::json)
    FROM pg_roles r WHERE r.rolname !~ '^pg_'),
  'memberships', (
    SELECT coalesce(json_agg(json_build_object(
      'role', pg_get_userbyid(m.roleid),
      'member', pg_get_userbyid(m.member),
      'admin', m.admin_option
    ) ORDER BY pg_get_userbyid(m.roleid), pg_get_userbyid(m.member)), '[]'::json)
    FROM pg_auth_members m
    WHERE pg_get_userbyid(m.roleid) !~ '^pg_' OR pg_get_userbyid(m.member) !~ '^pg_'),
  'role_settings', (
    SELECT coalesce(json_agg(json_build_object(
      'role', CASE WHEN s.setrole = 0 THEN '' ELSE pg_get_userbyid(s.setrole) END,
      'database', CASE WHEN s.setdatabase = 0 THEN '' ELSE current_database() END,
      'settings', (SELECT json_agg(x ORDER BY x) FROM unnest(s.setconfig) AS x)
    ) ORDER BY CASE WHEN s.setrole = 0 THEN '' ELSE pg_get_userbyid(s.setrole) END,
      s.setdatabase), '[]'::json)
    FROM pg_db_role_setting s
    WHERE s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database())))
)::text;
"""

TABLES_SQL = """\
SELECT coalesce(json_object_agg(
  c.relname,
  (xpath('/row/n/text()', query_to_xml(
    format('SELECT count(*) AS n FROM %I.%I', n.nspname, c.relname), false, true, '')))[1]
    ::text::bigint
  ORDER BY c.relname), '{}'::json)::text
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p');
"""

# How each fingerprint section is keyed (a row missing, extra or changed is one finding).
SECURITY_KEYS: Mapping[str, tuple[str, tuple[str, ...]]] = {
    "schemas": ("schema", ("name",)),
    "tables": ("table", ("name",)),
    "columns": ("column_acl", ("table", "column")),
    "policies": ("policy", ("table", "name")),
    "triggers": ("trigger", ("table", "name")),
    "functions": ("function", ("signature",)),
    "default_acl": ("default_acl", ("role", "schema", "objtype")),
    "extensions": ("extension", ("name",)),
    "roles": ("role", ("name",)),
    "memberships": ("membership", ("role", "member")),
    "role_settings": ("role_setting", ("role", "database")),
}
OBJECT_FIELDS = ("delete_marker", "size", "etag", "mode", "retain_until", "legal_hold", "latest")
# One tenant table per module for the RLS probe (absent tables are skipped).
RLS_PROBE_TABLES = (
    "investigations",
    "evidence",
    "evidence_hashes",
    "evidence_custody_events",
    "analysis_jobs",
    "network_records",
    "iocs",
    "malware_samples",
    "ti_enrichment_runs",
    "ti_results",
    "ai_runs",
    "ai_outputs",
    "analyst_notes",
    "ioc_collections",
    "reports",
    "report_versions",
    "audit_logs",
    "legal_holds",
    "org_retention_policies",
    "correlation_keys",
)

Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class Finding:
    check: str
    code: str
    detail: Mapping[str, Any] = field(default_factory=dict)
    severity: Severity = "error"

    def as_json(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "code": self.code,
            "severity": self.severity,
            "detail": dict(self.detail),
        }


def errors(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity == "error"]


def report(phase: str, findings: Sequence[Finding], stats: Mapping[str, Any]) -> dict[str, Any]:
    errs = len(errors(findings))
    return {
        "phase": phase,
        "ok": errs == 0,
        "errors": errs,
        "warnings": len(findings) - errs,
        "findings": [f.as_json() for f in findings],
        "stats": dict(stats),
    }


# --- manifest (RT7) ------------------------------------------------------------------------


def kms_fingerprint(key_file_content: str) -> tuple[str, str]:
    """`(name, sha256 hex)` of a MinIO KMS key file `<name>:<base64 key>`: the name and the
    sha256 of the content without surrounding whitespace. The key is never returned."""
    content = key_file_content.strip()
    name, sep, _ = content.partition(":")
    if not sep or not KMS_NAME_RE.fullmatch(name):
        raise ValueError("kms key file must be <name>:<base64 key>")
    return name, hashlib.sha256(content.encode()).hexdigest()


def _file_facts(files: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    facts: dict[str, dict[str, Any]] = {}
    for name, fact in files.items():
        if not isinstance(fact, Mapping):
            raise ValueError(f"file {name}: expected {{sha256, bytes}}")
        sha, size = fact.get("sha256"), fact.get("bytes")
        if not isinstance(sha, str) or not SHA256_RE.fullmatch(sha):
            raise ValueError(f"file {name}: sha256 must be 64 lowercase hex characters")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"file {name}: bytes must be a non-negative integer")
        facts[name] = {"sha256": sha, "bytes": size}
    return facts


def build_manifest(
    *,
    files: Mapping[str, Any],
    alembic_head: str,
    images: Mapping[str, str],
    minio_image: str,
    minio_data_dir: str,
    evidence_lock_days: int,
    kms_key_name: str,
    kms_key_fingerprint: str,
    source_project: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    """`manifest.json`: per-file sha256 and bytes, the alembic head, the image ids, the MinIO
    image and data dir, the evidence lock days, the KMS key name and fingerprint (never the
    key), the source project, the time and `tool_version`. Raises `ValueError`."""
    facts = _file_facts(files)
    missing = [name for name in BACKUP_FILES if name not in facts]
    if missing:
        raise ValueError(f"backup files missing: {', '.join(missing)}")
    if not alembic_head or not re.fullmatch(r"[A-Za-z0-9_]{1,64}", alembic_head):
        raise ValueError("alembic_head is not a revision id")
    if not KMS_NAME_RE.fullmatch(kms_key_name):
        raise ValueError("kms_key_name is invalid")
    if not SHA256_RE.fullmatch(kms_key_fingerprint):
        raise ValueError("kms_key_fingerprint must be a sha256 hex digest")
    if not minio_data_dir.startswith("/"):
        raise ValueError("minio_data_dir must be an absolute container path")
    if evidence_lock_days < 0:
        raise ValueError("evidence_lock_days must be >= 0")
    return {
        "tool_version": TOOL_VERSION,
        "created_at": created_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "source_project": source_project,
        "alembic_head": alembic_head,
        "images": dict(sorted(images.items())),
        "minio_image": minio_image,
        "minio_data_dir": minio_data_dir,
        "evidence_lock_days": evidence_lock_days,
        "kms": {"name": kms_key_name, "fingerprint": kms_key_fingerprint},
        "files": {name: facts[name] for name in sorted(facts)},
    }


def image_revisions() -> tuple[str | None, set[str]]:
    """The alembic head of this image and every revision it knows (its migration scripts)."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(API_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(API_ROOT / "alembic"))
    script = ScriptDirectory.from_config(config)
    return script.get_current_head(), {rev.revision for rev in script.walk_revisions()}


def check_manifest(
    manifest: Mapping[str, Any],
    actual_files: Mapping[str, Any],
    *,
    kms_key_fingerprint: str | None,
    known_revisions: Collection[str],
    image_head: str | None,
) -> list[Finding]:
    """A restore's preconditions: the tool version, every listed file present with its sha256
    and size, every backup file listed, the configured KMS key equal to the backup's (RT7),
    and the backup's alembic head known to this image (an older image is refused)."""
    found: list[Finding] = []
    if manifest.get("tool_version") != TOOL_VERSION:
        found.append(
            Finding("manifest", "tool_version", {"tool_version": manifest.get("tool_version")})
        )
    listed = manifest.get("files")
    if not isinstance(listed, Mapping):
        return [*found, Finding("manifest", "files_missing")]
    actual = _file_facts(actual_files)
    for name in BACKUP_FILES:
        if name not in listed:
            found.append(Finding("manifest", "file_not_listed", {"file": name}))
    for name, fact in sorted(listed.items()):
        got = actual.get(name)
        if got is None:
            found.append(Finding("manifest", "file_missing", {"file": name}))
            continue
        if not isinstance(fact, Mapping):
            found.append(Finding("manifest", "file_entry_invalid", {"file": name}))
            continue
        if got["bytes"] != fact.get("bytes"):
            found.append(
                Finding(
                    "manifest",
                    "file_size_mismatch",
                    {"file": name, "expected": fact.get("bytes"), "actual": got["bytes"]},
                )
            )
        if got["sha256"] != fact.get("sha256"):
            found.append(Finding("manifest", "file_hash_mismatch", {"file": name}))
    kms = manifest.get("kms")
    expected_fp = kms.get("fingerprint") if isinstance(kms, Mapping) else None
    if kms_key_fingerprint is None or expected_fp != kms_key_fingerprint:
        found.append(
            Finding(
                "manifest",
                "kms_key_mismatch",
                {"backup_key_name": kms.get("name") if isinstance(kms, Mapping) else None},
            )
        )
    head = manifest.get("alembic_head")
    if not isinstance(head, str) or head not in known_revisions:
        found.append(
            Finding(
                "manifest",
                "backup_newer_than_image",
                {"backup_head": head, "image_head": image_head},
            )
        )
    return found


# --- catalog fingerprint and row counts (--db) ---------------------------------------------


async def _json_scalar(conn: AsyncConnection, sql: str) -> Any:
    value = (await conn.execute(text(sql))).scalar_one()
    return json.loads(value)


async def capture_security(conn: AsyncConnection) -> dict[str, Any]:
    data: dict[str, Any] = await _json_scalar(conn, SECURITY_SQL)
    return data


async def capture_tables(conn: AsyncConnection) -> dict[str, int]:
    data: dict[str, int] = await _json_scalar(conn, TABLES_SQL)
    return data


def _row_key(row: Mapping[str, Any], fields: tuple[str, ...]) -> tuple[Any, ...]:
    return tuple(row.get(f) for f in fields)


def compare_security(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> list[Finding]:
    """Every section of the fingerprint, row by row: `<kind>_missing` (in the backup, not
    here), `<kind>_extra` and `<kind>_changed` (with the changed fields)."""
    found: list[Finding] = []
    if expected.get("database") != actual.get("database"):
        found.append(
            Finding(
                "security",
                "database_changed",
                {"expected": expected.get("database"), "actual": actual.get("database")},
            )
        )
    for section, (kind, key_fields) in SECURITY_KEYS.items():
        before = {_row_key(r, key_fields): r for r in expected.get(section) or []}
        after = {_row_key(r, key_fields): r for r in actual.get(section) or []}
        for key in sorted(before.keys() | after.keys(), key=lambda k: json.dumps(k)):
            ident = dict(zip(key_fields, key, strict=True))
            old, new = before.get(key), after.get(key)
            if new is None:
                found.append(Finding("security", f"{kind}_missing", ident))
            elif old is None:
                found.append(Finding("security", f"{kind}_extra", ident))
            elif old != new:
                changed = {
                    name: {"expected": old.get(name), "actual": new.get(name)}
                    for name in sorted(old.keys() | new.keys())
                    if old.get(name) != new.get(name)
                }
                found.append(Finding("security", f"{kind}_changed", {**ident, "fields": changed}))
    return found


def compare_tables(expected: Mapping[str, int], actual: Mapping[str, int]) -> list[Finding]:
    found: list[Finding] = []
    for table in sorted(expected.keys() | actual.keys()):
        if table not in actual:
            found.append(Finding("tables", "table_missing", {"table": table}))
        elif table not in expected:
            found.append(Finding("tables", "table_extra", {"table": table}))
        elif int(expected[table]) != int(actual[table]):
            found.append(
                Finding(
                    "tables",
                    "row_count_changed",
                    {"table": table, "expected": expected[table], "actual": actual[table]},
                )
            )
    return found


async def verify_db(
    conn: AsyncConnection, baseline: Mapping[str, Any]
) -> tuple[list[Finding], dict[str, Any]]:
    security = await capture_security(conn)
    tables = await capture_tables(conn)
    found = compare_security(baseline["security"], security)
    found += compare_tables(baseline["tables"], tables)
    return found, {"tables": len(tables), "rows": sum(int(v) for v in tables.values())}


# --- object versions (--objects) -----------------------------------------------------------


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="milliseconds")


def _bucket_locked(client: Minio, bucket: str) -> bool:
    try:
        client.get_object_lock_config(bucket)
    except S3Error as exc:
        if exc.code in _NO_LOCK:
            return False
        raise
    return True


def _retention(client: Minio, bucket: str, key: str, version_id: str) -> tuple[str | None, Any]:
    try:
        retention = client.get_object_retention(bucket, key, version_id=version_id)
    except S3Error as exc:
        if exc.code in _NO_LOCK:
            return None, None
        raise
    if retention is None:
        return None, None
    return retention.mode, retention.retain_until_date


def _legal_hold(client: Minio, bucket: str, key: str, version_id: str) -> bool:
    try:
        return bool(client.is_object_legal_hold_enabled(bucket, key, version_id=version_id))
    except S3Error as exc:
        if exc.code in _NO_LOCK:
            return False
        raise


def capture_objects(
    client: Minio,
    buckets: Sequence[str],
    prefixes: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Every version (delete markers too) of the buckets, sorted: bucket, key, version id,
    delete marker, size, etag, retention mode, retain-until, legal hold and the latest flag.
    Retention and legal holds are read only in object-locked buckets."""
    rows: list[dict[str, Any]] = []
    for bucket in buckets:
        locked = _bucket_locked(client, bucket)
        prefix = (prefixes or {}).get(bucket) or None
        for obj in client.list_objects(bucket, prefix=prefix, recursive=True, include_version=True):
            key, version_id = obj.object_name, obj.version_id
            if not key or not version_id:
                continue
            mode: str | None = None
            until: Any = None
            hold = False
            if locked and not obj.is_delete_marker:
                mode, until = _retention(client, bucket, key, version_id)
                hold = _legal_hold(client, bucket, key, version_id)
            rows.append(
                {
                    "bucket": bucket,
                    "key": key,
                    "version_id": version_id,
                    "delete_marker": bool(obj.is_delete_marker),
                    "size": None if obj.is_delete_marker else obj.size,
                    "etag": (obj.etag or "").strip('"') or None,
                    "mode": mode,
                    "retain_until": _iso(until),
                    "legal_hold": hold,
                    "latest": str(obj.is_latest).lower() == "true",
                }
            )
    rows.sort(key=lambda r: (r["bucket"], r["key"], r["version_id"]))
    return rows


def compare_objects(
    expected: Sequence[Mapping[str, Any]],
    actual: Sequence[Mapping[str, Any]],
    *,
    tombstoned: Collection[tuple[str, str, str]] = (),
) -> list[Finding]:
    """`object_version_missing` (a tombstoned one only warns), `object_version_changed`
    (size, etag, retention mode, retain-until, legal hold, delete marker or latest flag) and
    `object_version_extra` (a version written after the backup)."""
    found: list[Finding] = []

    def ident(row: Mapping[str, Any]) -> tuple[str, str, str]:
        return (str(row["bucket"]), str(row["key"]), str(row["version_id"]))

    before = {ident(r): r for r in expected}
    after = {ident(r): r for r in actual}
    for key in sorted(before.keys() | after.keys()):
        where = {"bucket": key[0], "key": key[1], "version_id": key[2]}
        old, new = before.get(key), after.get(key)
        if new is None:
            if key in tombstoned:
                found.append(Finding("objects", "purged_version_absent", where, "warning"))
            else:
                found.append(Finding("objects", "object_version_missing", where))
        elif old is None:
            found.append(Finding("objects", "object_version_extra", where))
        else:
            changed = {
                name: {"expected": old.get(name), "actual": new.get(name)}
                for name in OBJECT_FIELDS
                if old.get(name) != new.get(name)
            }
            if changed:
                found.append(
                    Finding("objects", "object_version_changed", {**where, "fields": changed})
                )
    return found


def _stat_exists(client: Minio, bucket: str, key: str, version_id: str) -> bool:
    try:
        client.stat_object(bucket, key, version_id=version_id)
    except S3Error as exc:
        if exc.code in _MISSING:
            return False
        raise
    return True


def _sha256_version(client: Minio, bucket: str, key: str, version_id: str) -> str | None:
    """The sha256 of one exact version, or None when the version is gone."""
    try:
        response = client.get_object(bucket, key, version_id=version_id)
    except S3Error as exc:
        if exc.code in _MISSING:
            return None
        raise
    digest = hashlib.sha256()
    try:
        while chunk := response.read(CHUNK):
            digest.update(chunk)
    finally:
        response.close()
        response.release_conn()
    return digest.hexdigest()


EVIDENCE_SQL = """\
SELECT e.id, e.organization_id, e.storage_bucket, e.storage_key, e.storage_version_id,
       h.value AS sha256, p.evidence_id IS NOT NULL AS tombstoned
FROM evidence e
LEFT JOIN evidence_hashes h
  ON h.evidence_id = e.id AND h.organization_id = e.organization_id AND h.algorithm = 'sha256'
LEFT JOIN evidence_purges p ON p.evidence_id = e.id AND p.organization_id = e.organization_id
ORDER BY e.id
"""

REPORT_VERSIONS_SQL = """\
SELECT id, organization_id, report_id, version, object_key, object_version_id,
       snapshot_sha256, manifest, signature, kid
FROM report_versions ORDER BY id
"""

# The key is `reports.dispatch.render_key` (also re-derived by reconcile_orphans).
RENDERS_SQL = """\
SELECT r.id, r.sha256, r.object_version_id,
       v.organization_id::text || '/' || v.report_id::text || '/' || v.version::text
       || '/' || r.id::text || '.' || r.format AS object_key
FROM report_renders r
JOIN report_versions v ON v.id = r.version_id AND v.organization_id = r.organization_id
WHERE r.status = 'succeeded'
ORDER BY r.id
"""

# The key is `analysis.dispatch.result_key`.
RESULTS_SQL = """\
SELECT id, 'results/' || organization_id::text || '/' || id::text || '.ndjson.gz' AS object_key,
       result_version_id
FROM analysis_jobs
WHERE status = 'succeeded' AND result_version_id IS NOT NULL
ORDER BY id
"""


async def tombstoned_versions(
    conn: AsyncConnection,
) -> set[tuple[str, str, str]]:
    rows = await conn.execute(
        text(
            "SELECT e.storage_bucket, e.storage_key, e.storage_version_id FROM evidence e "
            "JOIN evidence_purges p ON p.evidence_id = e.id "
            "AND p.organization_id = e.organization_id"
        )
    )
    return {(str(b), str(k), str(v)) for b, k, v in rows}


async def check_evidence(
    conn: AsyncConnection,
    client: Minio,
    *,
    sample: int | None = None,
    rng: random.Random | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    rows = list((await conn.execute(text(EVIDENCE_SQL))).mappings())
    live = [r for r in rows if not r["tombstoned"]]
    to_hash = {r["id"] for r in live}
    if sample is not None and sample < len(live):
        to_hash = {r["id"] for r in (rng or random.SystemRandom()).sample(live, sample)}
    found: list[Finding] = []
    hashed = 0
    for row in rows:
        where = {"evidence_id": str(row["id"]), "organization_id": str(row["organization_id"])}
        bucket, key, version = row["storage_bucket"], row["storage_key"], row["storage_version_id"]
        if row["tombstoned"]:
            if _stat_exists(client, bucket, key, version):
                found.append(Finding("evidence", "purged_pending_delete", where, "warning"))
            continue
        if row["id"] not in to_hash:
            if not _stat_exists(client, bucket, key, version):
                found.append(Finding("evidence", "pinned_version_missing", where))
            continue
        digest = _sha256_version(client, bucket, key, version)
        hashed += 1
        if digest is None:
            found.append(Finding("evidence", "pinned_version_missing", where))
        elif row["sha256"] is None:
            found.append(Finding("evidence", "evidence_hash_missing", where))
        elif digest != row["sha256"]:
            found.append(Finding("evidence", "evidence_hash_mismatch", where))
    stats = {"evidence": len(rows), "tombstoned": len(rows) - len(live), "hashed": hashed}
    return found, stats


def signature_ok(
    manifest: Mapping[str, Any],
    signature_b64: str,
    kid: str,
    snapshot_sha256: str,
    public_keys: Mapping[str, Any],
) -> bool:
    """`reports.signing.verify_stored` with explicit public keys (no api settings), plus the
    manifest naming the row's snapshot digest."""
    try:
        parsed = Manifest.model_validate(dict(manifest))
    except ValidationError:
        return False
    if parsed.kid != kid or parsed.snapshot_sha256 != snapshot_sha256:
        return False
    return verify(manifest_bytes(parsed), signature_b64, kid, public_keys)


async def check_reports(
    conn: AsyncConnection,
    client: Minio,
    *,
    reports_bucket: str,
    public_keys: Mapping[str, Any],
) -> tuple[list[Finding], dict[str, Any]]:
    found: list[Finding] = []
    versions = list((await conn.execute(text(REPORT_VERSIONS_SQL))).mappings())
    for row in versions:
        where = {"version_id": str(row["id"]), "organization_id": str(row["organization_id"])}
        digest = _sha256_version(
            client, reports_bucket, row["object_key"], row["object_version_id"]
        )
        if digest is None:
            found.append(Finding("reports", "report_snapshot_missing", where))
        elif digest != row["snapshot_sha256"]:
            found.append(Finding("reports", "report_snapshot_mismatch", where))
        manifest = row["manifest"]
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        if not signature_ok(
            manifest, row["signature"], row["kid"], row["snapshot_sha256"], public_keys
        ):
            found.append(
                Finding("reports", "report_signature_invalid", {**where, "kid": row["kid"]})
            )
    renders = list((await conn.execute(text(RENDERS_SQL))).mappings())
    for row in renders:
        where = {"render_id": str(row["id"])}
        if not row["object_version_id"]:
            found.append(Finding("reports", "render_missing", where))
            continue
        digest = _sha256_version(
            client, reports_bucket, row["object_key"], row["object_version_id"]
        )
        if digest is None:
            found.append(Finding("reports", "render_missing", where))
        elif digest != row["sha256"]:
            found.append(Finding("reports", "render_hash_mismatch", where))
    return found, {"report_versions": len(versions), "renders": len(renders)}


async def check_job_results(
    conn: AsyncConnection, client: Minio, *, results_bucket: str
) -> tuple[list[Finding], dict[str, Any]]:
    found: list[Finding] = []
    rows = list((await conn.execute(text(RESULTS_SQL))).mappings())
    for row in rows:
        if not _stat_exists(client, results_bucket, row["object_key"], row["result_version_id"]):
            found.append(Finding("results", "job_result_missing", {"job_id": str(row["id"])}))
    return found, {"job_results": len(rows)}


@dataclass(frozen=True)
class Buckets:
    evidence: str
    results: str
    reports: str

    @property
    def all(self) -> tuple[str, str, str]:
        return (self.evidence, self.results, self.reports)


async def verify_objects(
    conn: AsyncConnection,
    client: Minio,
    baseline: Mapping[str, Any],
    *,
    buckets: Buckets,
    public_keys: Mapping[str, Any],
    prefixes: Mapping[str, str] | None = None,
    sample: int | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    tombstoned = await tombstoned_versions(conn)
    actual = capture_objects(client, buckets.all, prefixes)
    found = compare_objects(baseline["objects"], actual, tombstoned=tombstoned)
    stats: dict[str, Any] = {"object_versions": len(actual)}
    evidence, s1 = await check_evidence(conn, client, sample=sample)
    reports, s2 = await check_reports(
        conn, client, reports_bucket=buckets.reports, public_keys=public_keys
    )
    results, s3 = await check_job_results(conn, client, results_bucket=buckets.results)
    stats.update(s1, **s2, **s3)
    return [*found, *evidence, *reports, *results], stats


# --- RLS probe (--rls) ---------------------------------------------------------------------


# The SQLSTATE of a refused write: a missing table privilege and the append-only triggers
# (`RAISE ... USING ERRCODE = 'insufficient_privilege'`) both raise it.
INSUFFICIENT_PRIVILEGE = "42501"


def sqlstate(exc: BaseException) -> str | None:
    """The Postgres SQLSTATE behind a SQLAlchemy error (asyncpg: `.sqlstate`, psycopg:
    `.pgcode` / `.sqlstate`), following `.orig` and the cause chain; None when there is none."""
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo:
        cur = todo.pop(0)
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        for attr in ("sqlstate", "pgcode"):
            value = getattr(cur, attr, None)
            if isinstance(value, str) and value:
                return value
        todo.extend([getattr(cur, "orig", None), cur.__cause__, cur.__context__])
    return None


async def probe_orgs(conn: AsyncConnection) -> list[uuid.UUID]:
    """The two orgs holding the most evidence (a probe against an empty org proves little)."""
    rows = await conn.execute(
        text(
            "SELECT o.id FROM organizations o ORDER BY "
            "(SELECT count(*) FROM evidence e WHERE e.organization_id = o.id) DESC, "
            "o.created_at, o.id LIMIT 2"
        )
    )
    return [uuid.UUID(str(r[0])) for r in rows]


async def _existing_tables(conn: AsyncConnection, names: Sequence[str]) -> list[str]:
    rows = await conn.execute(
        text(
            "SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace "
            "AND relkind IN ('r', 'p') AND relname = ANY(:names)"
        ),
        {"names": list(names)},
    )
    present = {str(r[0]) for r in rows}
    return [n for n in names if n in present]


async def rls_probe(
    app_engine: AsyncEngine,
    org_a: uuid.UUID,
    org_b: uuid.UUID,
    *,
    org_b_rows: Mapping[str, int] | None = None,
    tables: Sequence[str] = RLS_PROBE_TABLES,
) -> tuple[list[Finding], dict[str, Any]]:
    """As the app role in org A: no table shows a row of org B, UPDATE on `audit_logs` and
    DELETE on `ti_results` are refused. `org_b_rows` (the superuser's per-table counts of org
    B) tells whether the probe saw real rows; nothing is ever committed."""
    found: list[Finding] = []
    async with app_engine.connect() as conn:
        tx = await conn.begin()
        try:
            await conn.execute(
                text(
                    "SELECT set_config('app.org_id', :org, true), "
                    "set_config('app.user_id', '', true)"
                ),
                {"org": str(org_a)},
            )
            probed = await _existing_tables(conn, tables)
            for table in probed:
                count = (
                    await conn.execute(
                        text(f"SELECT count(*) FROM {table} WHERE organization_id = :b"),  # noqa: S608
                        {"b": org_b},
                    )
                ).scalar_one()
                if count:
                    found.append(
                        Finding("rls", "cross_org_rows_visible", {"table": table, "rows": count})
                    )
            for code, statement in (
                (
                    "audit_update_allowed",
                    "UPDATE audit_logs SET action = action WHERE organization_id = :a",
                ),
                ("ti_results_delete_allowed", "DELETE FROM ti_results WHERE organization_id = :a"),
            ):
                nested = await conn.begin_nested()
                try:
                    await conn.execute(text(statement), {"a": org_a})
                except DBAPIError as exc:
                    await nested.rollback()
                    state = sqlstate(exc)
                    # Only a refusal passes: a missing grant and the append-only trigger both
                    # raise 42501. Any other error (a dropped column, a lost connection, a
                    # typo) proves nothing about the write barrier.
                    if state != INSUFFICIENT_PRIVILEGE:
                        found.append(
                            Finding(
                                "rls",
                                f"{code}_unexpected_error",
                                {"organization_id": str(org_a), "sqlstate": state},
                            )
                        )
                else:
                    await nested.rollback()
                    found.append(Finding("rls", code, {"organization_id": str(org_a)}))
        finally:
            await tx.rollback()
    nonzero = sorted(t for t, n in (org_b_rows or {}).items() if n)
    if org_b_rows is not None and not nonzero:
        found.append(Finding("rls", "probe_saw_no_rows", {"org_b": str(org_b)}, "warning"))
    return found, {"tables_probed": len(probed), "tables_with_org_b_rows": len(nonzero)}


async def org_rows(conn: AsyncConnection, org: uuid.UUID, tables: Sequence[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in await _existing_tables(conn, tables):
        counts[table] = int(
            (
                await conn.execute(
                    text(f"SELECT count(*) FROM {table} WHERE organization_id = :o"),  # noqa: S608
                    {"o": org},
                )
            ).scalar_one()
        )
    return counts


# --- CLI -----------------------------------------------------------------------------------


class UsageError(Exception):
    pass


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise UsageError(f"{name} is not set")
    return value


def _superuser_engine() -> AsyncEngine:
    url = _env("RESTORE_DATABASE_URL")
    if make_url(url).get_backend_name() != "postgresql":
        raise UsageError("RESTORE_DATABASE_URL must be a postgresql URL")
    return create_async_engine(url, poolclass=NullPool, hide_parameters=True)


def _minio() -> Minio:
    return Minio(
        _env("MINIO_ENDPOINT"),
        access_key=_env("RESTORE_MINIO_ACCESS_KEY"),
        secret_key=_env("RESTORE_MINIO_SECRET_KEY"),
        secure=os.environ.get("RESTORE_MINIO_SECURE", "false").lower() == "true",
    )


def _buckets() -> Buckets:
    return Buckets(
        evidence=_env("MINIO_BUCKET"),
        results=_env("RESULTS_BUCKET"),
        reports=os.environ.get("REPORTS_BUCKET") or "reports",
    )


async def _bypass(conn: AsyncConnection) -> None:
    # A role bound by RLS fails here instead of verifying a filtered view.
    await conn.execute(text("SET row_security = off"))


def _read_stdin_json() -> Any:
    try:
        return json.loads(sys.stdin.read())
    except ValueError:
        raise UsageError("stdin is not JSON") from None


async def _run_db(baseline: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(baseline.get("security"), Mapping) or not isinstance(
        baseline.get("tables"), Mapping
    ):
        raise UsageError("--db needs the baseline {security, tables} on stdin")
    engine = _superuser_engine()
    try:
        async with engine.connect() as conn:
            await _bypass(conn)
            found, stats = await verify_db(conn, baseline)
    finally:
        await engine.dispose()
    return report("db", found, stats)


async def _run_objects(baseline: Mapping[str, Any], sample: int | None) -> dict[str, Any]:
    if not isinstance(baseline.get("objects"), list):
        raise UsageError("--objects needs the baseline {objects} on stdin")
    public_keys = load_public_keys(_env("REPORT_SIGNING_PUBLIC_KEYS"))
    engine = _superuser_engine()
    try:
        async with engine.connect() as conn:
            await _bypass(conn)
            found, stats = await verify_objects(
                conn,
                _minio(),
                baseline,
                buckets=_buckets(),
                public_keys=public_keys,
                sample=sample,
            )
    finally:
        await engine.dispose()
    return report("objects", found, stats)


async def _run_rls() -> dict[str, Any]:
    superuser = _superuser_engine()
    app = create_async_engine(_env("DATABASE_URL"), poolclass=NullPool, hide_parameters=True)
    try:
        async with superuser.connect() as conn:
            await _bypass(conn)
            orgs = await probe_orgs(conn)
            single = len(orgs) < 2
            org_a = orgs[0] if orgs else uuid.uuid4()
            org_b = orgs[1] if not single else uuid.uuid4()
            counts = await org_rows(conn, org_b, RLS_PROBE_TABLES)
        found, stats = await rls_probe(app, org_a, org_b, org_b_rows=counts)
        if single:
            found.append(Finding("rls", "single_org", {"orgs": len(orgs)}, "warning"))
    finally:
        await superuser.dispose()
        await app.dispose()
    return report("rls", found, stats)


def _run_capture_objects() -> dict[str, Any]:
    return {"objects": capture_objects(_minio(), _buckets().all)}


def _run_manifest_build(payload: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return build_manifest(
            files=payload["files"],
            alembic_head=str(payload["alembic_head"]),
            images=payload.get("images") or {},
            minio_image=str(payload["minio_image"]),
            minio_data_dir=str(payload["minio_data_dir"]),
            evidence_lock_days=int(payload["evidence_lock_days"]),
            kms_key_name=str(payload["kms"]["name"]),
            kms_key_fingerprint=str(payload["kms"]["fingerprint"]),
            source_project=str(payload["source_project"]),
            created_at=payload.get("created_at"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise UsageError(f"manifest facts invalid: {exc}") from None


def _run_manifest_check(payload: Mapping[str, Any]) -> dict[str, Any]:
    head, known = image_revisions()
    try:
        found = check_manifest(
            payload["manifest"],
            payload["files"],
            kms_key_fingerprint=payload.get("kms_fingerprint"),
            known_revisions=known,
            image_head=head,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise UsageError(f"manifest check input invalid: {exc}") from None
    return report("manifest", found, {"image_head": head})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="restore_verify", description="Integrity and security proof of a restore (M7)."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    for flag in (
        "--db",
        "--objects",
        "--rls",
        "--capture-objects",
        "--manifest-build",
        "--manifest-check",
    ):
        mode.add_argument(flag, action="store_true")
    parser.add_argument("--baseline", choices=["-"], help="read the baseline JSON from stdin")
    parser.add_argument("--sample", type=int, default=None, help="hash N random evidence objects")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.sample is not None and args.sample < 1:
        print(json.dumps({"error": "--sample must be >= 1"}))
        return 2
    try:
        result: dict[str, Any]
        if args.db or args.objects:
            if args.baseline != "-":
                raise UsageError("--db / --objects need --baseline -")
            baseline = _read_stdin_json()
            if not isinstance(baseline, Mapping):
                raise UsageError("the baseline must be a JSON object")
            runner: Callable[[], Any] = (
                (lambda: _run_db(baseline))
                if args.db
                else (lambda: _run_objects(baseline, args.sample))
            )
            result = asyncio.run(runner())
        elif args.rls:
            result = asyncio.run(_run_rls())
        elif args.capture_objects:
            result = _run_capture_objects()
        elif args.manifest_build:
            result = _run_manifest_build(_read_stdin_json())
        else:
            result = _run_manifest_check(_read_stdin_json())
    except UsageError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    if "ok" in result:
        return 0 if result["ok"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
