"""restore_verify against the lane database and the test buckets (M7 phase 2, RT4).

The verifier runs as the superuser with RLS off in a restore; here its queries run on the
owner connection scoped to one tenant (`app.org_id`), and the object listing under that
tenant's key prefixes, so other tests' rows and objects never count. The checks pass on seeded
data; a new version written under a key, a pinned version deleted without a tombstone and a
dropped policy (rolled back) fail; a tombstoned version still present is only a warning."""

import hashlib
import io
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.core.config import get_settings
from app.core.db import get_engine
from app.core.tenancy import tenant_session
from app.modules.reports import dispatch
from app.modules.reports.models import ReportRender
from app.scripts import restore_verify as rv
from tests.integration.seed import Tenant, seed_tenant
from tests.ops_helpers import _stored_evidence
from tests.report_helpers import (
    REPORTS_TEST_BUCKET,
    SigningKeys,
    new_signing_keys,
    purge_reports_test_bucket,
    seed_render,
    seed_report,
    seed_version,
)
from tests.storage_helpers import evidence_test_bucket, overwrite, root_minio


@dataclass(frozen=True)
class Seeded:
    a: Tenant
    b: Tenant
    keys: SigningKeys
    evidence: tuple[tuple[uuid.UUID, tuple[str, str, str]], ...]


def _buckets() -> rv.Buckets:
    s = get_settings()
    return rv.Buckets(
        evidence=evidence_test_bucket(), results=s.results_bucket, reports=s.reports_bucket
    )


def _prefixes(org: uuid.UUID) -> dict[str, str]:
    b = _buckets()
    return {b.evidence: f"{org}/", b.reports: f"{org}/", b.results: f"results/{org}/"}


async def _succeeded_render(
    t: Tenant, report_id: uuid.UUID, version: int, version_id: uuid.UUID
) -> None:
    render_id, _ = await seed_render(t, version_id)
    data = b"%PDF-1.7 restore verify\n"
    key = dispatch.render_key(t.org_id, report_id, version, render_id, "pdf")
    stored = root_minio().put_object(REPORTS_TEST_BUCKET, key, io.BytesIO(data), len(data))
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(status="running", started_at=datetime.now(UTC))
        )
        await s.execute(
            update(ReportRender)
            .where(ReportRender.id == render_id)
            .values(
                status="succeeded",
                sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data),
                pages=1,
                object_version_id=str(stored.version_id),
                finished_at=datetime.now(UTC),
            )
        )


@pytest_asyncio.fixture(loop_scope="session")
async def seeded() -> AsyncIterator[Seeded]:
    a, b = (
        await seed_tenant(f"rv-a-{uuid.uuid4().hex[:6]}"),
        await seed_tenant(f"rv-b-{uuid.uuid4().hex[:6]}"),
    )
    evidence = tuple(
        [
            await _stored_evidence(
                a, a.investigation_id, f"evidence {i}".encode() * 50, f"e{i}.bin"
            )
            for i in range(2)
        ]
    )
    await _stored_evidence(b, b.investigation_id, b"other tenant", "b.bin")
    keys = new_signing_keys()
    report_id = await seed_report(a)
    version = await seed_version(a, report_id, keys)
    await _succeeded_render(a, report_id, version.version, version.version_id)
    yield Seeded(a, b, keys, evidence)
    purge_reports_test_bucket()


async def _scoped(conn: AsyncConnection, org: uuid.UUID) -> None:
    await conn.execute(
        text("SELECT set_config('app.org_id', :o, true), set_config('app.user_id', '', true)"),
        {"o": str(org)},
    )


async def _verify_objects(
    owner_engine: AsyncEngine, s: Seeded, baseline: list[dict[str, object]]
) -> list[rv.Finding]:
    async with owner_engine.connect() as conn, conn.begin():
        await _scoped(conn, s.a.org_id)
        found, stats = await rv.verify_objects(
            conn,
            root_minio(),
            {"objects": baseline},
            buckets=_buckets(),
            public_keys={s.keys.kid: s.keys.private.public_key()},
            prefixes=_prefixes(s.a.org_id),
        )
    assert stats["evidence"] == 2 and stats["report_versions"] == 1 and stats["renders"] == 1
    return found


def _baseline(org: uuid.UUID) -> list[dict[str, object]]:
    return rv.capture_objects(root_minio(), _buckets().all, _prefixes(org))


def _codes(found: list[rv.Finding]) -> list[str]:
    return sorted(f.code for f in found)


async def test_db_phase_passes_then_detects_a_dropped_policy_and_a_new_row(
    owner_engine: AsyncEngine, seeded: Seeded
) -> None:
    async with owner_engine.connect() as conn, conn.begin():
        await _scoped(conn, seeded.a.org_id)
        baseline = {
            "security": await rv.capture_security(conn),
            "tables": await rv.capture_tables(conn),
        }
        assert baseline["tables"]["evidence"] == 2
        assert any(p["name"] == "tenant_isolation" for p in baseline["security"]["policies"])
        assert (await rv.verify_db(conn, baseline))[0] == []

        nested = await conn.begin_nested()
        await conn.execute(text("DROP POLICY tenant_isolation ON ioc_collections"))
        found, _ = await rv.verify_db(conn, baseline)
        await nested.rollback()
        assert [(f.code, dict(f.detail)) for f in found] == [
            ("policy_missing", {"table": "ioc_collections", "name": "tenant_isolation"})
        ]
        assert (await rv.verify_db(conn, baseline))[0] == []

    await _stored_evidence(seeded.a, seeded.a.investigation_id, b"late", "late.bin")
    async with owner_engine.connect() as conn, conn.begin():
        await _scoped(conn, seeded.a.org_id)
        found, _ = await rv.verify_db(conn, baseline)
    changed = {f.detail.get("table") for f in found}
    assert {f.code for f in found} == {"row_count_changed"}
    assert {"evidence", "evidence_hashes"} <= changed


async def test_objects_phase_passes_on_seeded_data(
    owner_engine: AsyncEngine, seeded: Seeded
) -> None:
    baseline = _baseline(seeded.a.org_id)
    assert len(baseline) == 4  # two evidence versions, a snapshot and a render
    evidence_rows = [r for r in baseline if r["bucket"] == evidence_test_bucket()]
    assert all(r["legal_hold"] is False and r["latest"] for r in evidence_rows)
    assert await _verify_objects(owner_engine, seeded, baseline) == []


async def test_a_new_version_under_a_key_fails(owner_engine: AsyncEngine, seeded: Seeded) -> None:
    baseline = _baseline(seeded.a.org_id)
    _, (_, key, version) = seeded.evidence[0]
    overwrite(key, b"replacement bytes")
    found = await _verify_objects(owner_engine, seeded, baseline)
    assert _codes(found) == ["object_version_changed", "object_version_extra"]
    changed = next(f for f in found if f.code == "object_version_changed")
    assert changed.detail["version_id"] == version
    assert changed.detail["fields"] == {"latest": {"expected": True, "actual": False}}
    # The pinned version itself still re-hashes: only the listing comparison catches it.
    assert not any(f.check == "evidence" for f in found)


async def test_a_pinned_version_deleted_without_a_tombstone_fails(
    owner_engine: AsyncEngine, seeded: Seeded
) -> None:
    baseline = _baseline(seeded.a.org_id)
    evidence_id, (bucket, key, version) = seeded.evidence[1]
    root_minio().remove_object(bucket, key, version_id=version)
    found = await _verify_objects(owner_engine, seeded, baseline)
    assert _codes(found) == ["object_version_missing", "pinned_version_missing"]
    pinned = next(f for f in found if f.code == "pinned_version_missing")
    assert pinned.detail["evidence_id"] == str(evidence_id)


async def test_a_tombstoned_version_still_present_is_a_warning(
    owner_engine: AsyncEngine, seeded: Seeded
) -> None:
    evidence_id, (bucket, key, version) = seeded.evidence[1]
    run_id = uuid.uuid4()
    # The tombstone as the retention worker writes it (the app role cannot), here the owner's.
    async with owner_engine.connect() as conn, conn.begin():
        await _scoped(conn, seeded.a.org_id)
        await conn.execute(
            text(
                "INSERT INTO retention_runs (id, organization_id, mode, trigger, status) "
                "VALUES (:id, :org, 'enforce', 'schedule', 'completed')"
            ),
            {"id": run_id, "org": seeded.a.org_id},
        )
        await conn.execute(
            text(
                "INSERT INTO evidence_purges "
                "(evidence_id, organization_id, run_id, object_version_id, sha256) "
                "VALUES (:e, :org, :run, :v, :sha)"
            ),
            {
                "e": evidence_id,
                "org": seeded.a.org_id,
                "run": run_id,
                "v": version,
                "sha": "0" * 64,
            },
        )
    baseline = _baseline(seeded.a.org_id)
    found = await _verify_objects(owner_engine, seeded, baseline)
    assert [(f.code, f.severity) for f in found] == [("purged_pending_delete", "warning")]

    # Once the purge deletes it, the tombstoned version is simply absent (no finding at all).
    root_minio().remove_object(bucket, key, version_id=version)
    found = await _verify_objects(owner_engine, seeded, baseline)
    assert [(f.code, f.severity) for f in found] == [("purged_version_absent", "warning")]


async def test_a_bad_report_signature_fails(owner_engine: AsyncEngine, seeded: Seeded) -> None:
    baseline = _baseline(seeded.a.org_id)
    other = new_signing_keys(seeded.keys.kid)
    async with owner_engine.connect() as conn, conn.begin():
        await _scoped(conn, seeded.a.org_id)
        found, _ = await rv.verify_objects(
            conn,
            root_minio(),
            {"objects": baseline},
            buckets=_buckets(),
            public_keys={other.kid: other.private.public_key()},
            prefixes=_prefixes(seeded.a.org_id),
        )
    assert _codes(found) == ["report_signature_invalid"]


async def test_rls_probe_is_clean_for_the_app_role(
    owner_engine: AsyncEngine, seeded: Seeded
) -> None:
    async with owner_engine.connect() as conn, conn.begin():
        await _scoped(conn, seeded.b.org_id)
        b_rows = await rv.org_rows(conn, seeded.b.org_id, rv.RLS_PROBE_TABLES)
    assert b_rows["evidence"] == 1 and b_rows["investigations"] == 1
    found, stats = await rv.rls_probe(
        get_engine(), seeded.a.org_id, seeded.b.org_id, org_b_rows=b_rows
    )
    assert found == []
    assert stats["tables_probed"] == len(rv.RLS_PROBE_TABLES)
    assert stats["tables_with_org_b_rows"] >= 3


async def test_rls_probe_warns_when_it_saw_nothing(seeded: Seeded) -> None:
    found, _ = await rv.rls_probe(get_engine(), seeded.a.org_id, uuid.uuid4(), org_b_rows={})
    assert [(f.code, f.severity) for f in found] == [("probe_saw_no_rows", "warning")]


@pytest.mark.parametrize("phase", ["--db", "--objects"])
def test_cli_phases_refuse_a_baseline_that_is_not_an_object(
    phase: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("[1, 2]"))
    assert rv.main([phase, "--baseline", "-"]) == 2
    assert "error" in capsys.readouterr().out


async def test_drill_seeder_owner_rows_and_tombstone(
    owner_engine: AsyncEngine, seeded: Seeded, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The drill seeder's owner SQL (synthetic TI / AI rows, the tombstone and its governance
    bypass delete, RT17) runs on the lane DB, and the verifier accepts the result."""
    from app.scripts import drill_seed

    baseline = _baseline(seeded.a.org_id)
    with pytest.raises(drill_seed.DrillError, match="CYBERLAB_DRILL"):
        await drill_seed._seed_owner_rows({})
    monkeypatch.setenv("CYBERLAB_DRILL", "1")
    monkeypatch.setenv("CYBERLAB_DRILL_PROJECT", drill_seed.DRILL_PROJECT)
    monkeypatch.setenv("EVIDENCE_LOCK_DAYS", "1")
    monkeypatch.setenv("DRILL_OWNER_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    monkeypatch.setenv("DRILL_MINIO_ROOT_USER", os.environ["TEST_MINIO_ROOT_USER"])
    monkeypatch.setenv("DRILL_MINIO_ROOT_PASSWORD", os.environ["TEST_MINIO_ROOT_PASSWORD"])
    monkeypatch.setattr(drill_seed, "EVIDENCE_PER_ORG", 2)
    (e0, _), (e1, (_, key, version)) = seeded.evidence
    seed = {
        "orgs": {"a": str(seeded.a.org_id)},
        "cases": {"a": str(seeded.a.investigation_id)},
        "users": {"owner": {"id": str(seeded.a.owner_id)}},
        "evidence": [
            {"id": str(e0), "sha256": "0" * 64},
            {"id": str(e1), "sha256": hashlib.sha256(b"evidence 1" * 50).hexdigest()},
        ],
    }
    await drill_seed._seed_owner_rows(seed)
    assert seed["tombstoned_evidence"] == str(e1)
    found = await _verify_objects(owner_engine, seeded, baseline)
    # The deleted version was in the baseline: the tombstone turns it into a warning.
    assert [(f.code, f.detail["version_id"]) for f in found] == [("purged_version_absent", version)]
    async with owner_engine.connect() as conn, conn.begin():
        await _scoped(conn, seeded.a.org_id)
        counts = await rv.org_rows(conn, seeded.a.org_id, ("ti_results", "ai_runs", "ai_outputs"))
    assert counts == {"ti_results": 1, "ai_runs": 1, "ai_outputs": 1}
    assert key
