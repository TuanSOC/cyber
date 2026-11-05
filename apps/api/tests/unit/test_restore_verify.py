"""restore_verify's comparison logic on fixture JSON (M7 phase 2, RT4): the catalog
fingerprint (a policy missing, a grant changed, FORCE RLS lost), the row counts and the object
versions (retain-until shortened, a legal hold lost, a version added or missing, a tombstoned
version absent)."""

import copy
import json
from typing import Any

import pytest

from app.scripts import restore_verify as rv

SECURITY: dict[str, Any] = {
    "database": {"owner": "cyberlab_owner", "acl": ["=Tc/cyberlab_owner", "cyberlab_app=c/x"]},
    "schemas": [{"name": "public", "owner": "pg_database_owner", "acl": None}],
    "tables": [
        {
            "name": "audit_logs",
            "kind": "r",
            "owner": "cyberlab_owner",
            "rls": True,
            "force_rls": True,
            "acl": ["cyberlab_app=ar/cyberlab_owner", "cyberlab_owner=arwdDxtm/cyberlab_owner"],
        },
        {
            "name": "evidence",
            "kind": "r",
            "owner": "cyberlab_owner",
            "rls": True,
            "force_rls": True,
            "acl": ["cyberlab_app=arw/cyberlab_owner"],
        },
    ],
    "columns": [],
    "policies": [
        {
            "table": "evidence",
            "name": "tenant_isolation",
            "permissive": "PERMISSIVE",
            "roles": ["public"],
            "cmd": "ALL",
            "qual": "(organization_id = app_org_id())",
            "with_check": "(organization_id = app_org_id())",
        }
    ],
    "triggers": [
        {
            "table": "audit_logs",
            "name": "audit_logs_append_only",
            "enabled": "O",
            "definition": "CREATE TRIGGER audit_logs_append_only ...",
        }
    ],
    "functions": [],
    "default_acl": [],
    "extensions": [{"name": "pg_trgm", "version": "1.6", "schema": "public"}],
    "roles": [{"name": "cyberlab_app", "superuser": False, "bypassrls": False, "login": True}],
    "memberships": [],
    "role_settings": [
        {"role": "cyberlab_app", "database": "", "settings": ["statement_timeout=30s"]}
    ],
}

OBJECTS: list[dict[str, Any]] = [
    {
        "bucket": "evidence",
        "key": "org/e1",
        "version_id": "v1",
        "delete_marker": False,
        "size": 100,
        "etag": "abc",
        "mode": "GOVERNANCE",
        "retain_until": "2026-12-06T10:00:00.000+00:00",
        "legal_hold": True,
        "latest": True,
    },
    {
        "bucket": "results",
        "key": "results/org/j1.ndjson.gz",
        "version_id": "r1",
        "delete_marker": False,
        "size": 5,
        "etag": "def",
        "mode": None,
        "retain_until": None,
        "legal_hold": False,
        "latest": True,
    },
]


def _codes(found: list[rv.Finding]) -> list[str]:
    return [f.code for f in found]


def _security(**changes: Any) -> dict[str, Any]:
    data = copy.deepcopy(SECURITY)
    data.update(changes)
    return data


def test_identical_fingerprints_pass() -> None:
    # The JSON round trip is what the backup file and the recomputation go through.
    assert rv.compare_security(SECURITY, json.loads(json.dumps(SECURITY))) == []


def test_a_missing_policy_is_named() -> None:
    found = rv.compare_security(SECURITY, _security(policies=[]))
    assert _codes(found) == ["policy_missing"]
    assert found[0].detail == {"table": "evidence", "name": "tenant_isolation"}
    assert found[0].severity == "error"


def test_an_extra_policy_is_reported() -> None:
    extra = copy.deepcopy(SECURITY["policies"]) + [
        {**SECURITY["policies"][0], "name": "allow_all", "qual": "true"}
    ]
    assert _codes(rv.compare_security(SECURITY, _security(policies=extra))) == ["policy_extra"]


def test_a_changed_grant_lists_the_field() -> None:
    tables = copy.deepcopy(SECURITY["tables"])
    tables[0]["acl"] = ["cyberlab_app=arw/cyberlab_owner", *tables[0]["acl"][1:]]
    found = rv.compare_security(SECURITY, _security(tables=tables))
    assert _codes(found) == ["table_changed"]
    assert found[0].detail["name"] == "audit_logs"
    assert set(found[0].detail["fields"]) == {"acl"}


def test_lost_force_rls_and_a_changed_policy_expression() -> None:
    tables = copy.deepcopy(SECURITY["tables"])
    tables[1]["force_rls"] = False
    policies = copy.deepcopy(SECURITY["policies"])
    policies[0]["qual"] = "true"
    found = rv.compare_security(SECURITY, _security(tables=tables, policies=policies))
    assert sorted(_codes(found)) == ["policy_changed", "table_changed"]
    by_code = {f.code: f for f in found}
    assert by_code["table_changed"].detail["fields"] == {
        "force_rls": {"expected": True, "actual": False}
    }


def test_triggers_roles_and_role_settings_are_compared() -> None:
    roles = [{**SECURITY["roles"][0], "bypassrls": True}]
    found = rv.compare_security(
        SECURITY, _security(triggers=[], roles=roles, role_settings=[], database={"owner": "x"})
    )
    assert sorted(_codes(found)) == [
        "database_changed",
        "role_changed",
        "role_setting_missing",
        "trigger_missing",
    ]


def test_row_counts() -> None:
    expected = {"evidence": 3, "audit_logs": 10, "refresh_tokens": 2}
    assert rv.compare_tables(expected, dict(expected)) == []
    found = rv.compare_tables(expected, {"evidence": 3, "audit_logs": 9, "extra": 0})
    assert sorted(_codes(found)) == ["row_count_changed", "table_extra", "table_missing"]
    changed = next(f for f in found if f.code == "row_count_changed")
    assert changed.detail == {"table": "audit_logs", "expected": 10, "actual": 9}


def test_identical_objects_pass() -> None:
    assert rv.compare_objects(OBJECTS, copy.deepcopy(OBJECTS)) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("retain_until", "2026-11-07T10:00:00.000+00:00"),
        ("legal_hold", False),
        ("mode", None),
        ("size", 99),
        ("etag", "zzz"),
        ("latest", False),
    ],
)
def test_a_changed_version_attribute_fails(field: str, value: Any) -> None:
    actual = copy.deepcopy(OBJECTS)
    actual[0][field] = value
    found = rv.compare_objects(OBJECTS, actual)
    assert _codes(found) == ["object_version_changed"]
    assert found[0].detail["fields"] == {field: {"expected": OBJECTS[0][field], "actual": value}}
    assert found[0].detail["version_id"] == "v1"


def test_a_missing_and_an_added_version_fail() -> None:
    added = {**OBJECTS[0], "version_id": "v2"}
    found = rv.compare_objects(OBJECTS, [OBJECTS[1], added])
    assert sorted(_codes(found)) == ["object_version_extra", "object_version_missing"]


def test_a_tombstoned_version_absent_only_warns() -> None:
    found = rv.compare_objects(OBJECTS, [OBJECTS[1]], tombstoned={("evidence", "org/e1", "v1")})
    assert _codes(found) == ["purged_version_absent"]
    assert rv.errors(found) == []


def test_report_counts_errors_and_warnings() -> None:
    found = [
        rv.Finding("objects", "object_version_missing", {"key": "k"}),
        rv.Finding("evidence", "purged_pending_delete", {}, "warning"),
    ]
    out = rv.report("objects", found, {"n": 1})
    assert out["ok"] is False and out["errors"] == 1 and out["warnings"] == 1
    assert out["findings"][1] == {
        "check": "evidence",
        "code": "purged_pending_delete",
        "severity": "warning",
        "detail": {},
    }
    assert rv.report("objects", found[1:], {})["ok"] is True


def test_cli_rejects_a_mode_without_its_baseline(capsys: pytest.CaptureFixture[str]) -> None:
    assert rv.main(["--db"]) == 2
    assert "baseline" in json.loads(capsys.readouterr().out)["error"]
    assert rv.main(["--objects", "--baseline", "-", "--sample", "0"]) == 2


def test_cli_rls_needs_the_superuser_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("RESTORE_DATABASE_URL", raising=False)
    assert rv.main(["--rls"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "RESTORE_DATABASE_URL is not set"}


# --- the RLS write probe: only SQLSTATE 42501 is a refusal ---------------------------------


class _PgError(Exception):
    def __init__(self, sqlstate: str | None) -> None:
        super().__init__(f"pg error {sqlstate}")
        self.sqlstate = sqlstate


def _dbapi_error(sqlstate: str | None) -> Exception:
    from sqlalchemy.exc import DBAPIError

    return DBAPIError("UPDATE ...", {}, _PgError(sqlstate))


def test_sqlstate_follows_orig_and_the_cause_chain() -> None:
    assert rv.sqlstate(_dbapi_error("42501")) == "42501"
    assert rv.sqlstate(_dbapi_error(None)) is None
    wrapped = RuntimeError("adapted")
    wrapped.__cause__ = _PgError("42703")
    from sqlalchemy.exc import DBAPIError

    assert rv.sqlstate(DBAPIError("x", {}, wrapped)) == "42703"

    class Psycopg(Exception):
        pgcode = "42501"

    assert rv.sqlstate(DBAPIError("x", {}, Psycopg())) == "42501"


class _Result:
    def __init__(self, rows: list[tuple[Any, ...]] | None = None, scalar: Any = 0) -> None:
        self._rows, self._scalar = rows or [], scalar

    def __iter__(self) -> Any:
        return iter(self._rows)

    def scalar_one(self) -> Any:
        return self._scalar


class _Tx:
    async def rollback(self) -> None:
        return None


class _Conn:
    def __init__(self, writes: dict[str, Exception | None]) -> None:
        self.writes = writes

    async def __aenter__(self) -> "_Conn":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def begin(self) -> _Tx:
        return _Tx()

    async def begin_nested(self) -> _Tx:
        return _Tx()

    async def execute(self, statement: Any, params: Any = None) -> _Result:
        sql = str(statement)
        for prefix, error in self.writes.items():
            if sql.startswith(prefix):
                if error is not None:
                    raise error
                return _Result()
        if "pg_class" in sql:
            return _Result(rows=[("evidence",)])
        return _Result(scalar=0)


class _Engine:
    def __init__(self, writes: dict[str, Exception | None]) -> None:
        self.writes = writes

    def connect(self) -> _Conn:
        return _Conn(self.writes)


async def _probe(update: Exception | None, delete: Exception | None) -> list[str]:
    import uuid

    engine = _Engine({"UPDATE audit_logs": update, "DELETE FROM ti_results": delete})
    found, stats = await rv.rls_probe(
        engine,  # type: ignore[arg-type]
        uuid.uuid4(),
        uuid.uuid4(),
        tables=("evidence",),
    )
    assert stats["tables_probed"] == 1
    return [f.code for f in found]


async def test_rls_write_probe_passes_only_on_insufficient_privilege() -> None:
    refused = _dbapi_error("42501")
    assert await _probe(refused, _dbapi_error("42501")) == []
    # A write that succeeds is the finding it always was.
    assert await _probe(None, refused) == ["audit_update_allowed"]
    assert await _probe(refused, None) == ["ti_results_delete_allowed"]


async def test_rls_write_probe_fails_on_any_other_error() -> None:
    refused = _dbapi_error("42501")
    # A dropped column (42703), a missing table (42P01) or no SQLSTATE at all proves nothing.
    assert await _probe(_dbapi_error("42703"), refused) == ["audit_update_allowed_unexpected_error"]
    assert await _probe(refused, _dbapi_error("42P01")) == [
        "ti_results_delete_allowed_unexpected_error"
    ]
    assert await _probe(_dbapi_error(None), refused) == ["audit_update_allowed_unexpected_error"]
